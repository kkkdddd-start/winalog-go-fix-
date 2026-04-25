package live

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type LiveCollector struct {
	mu          sync.RWMutex
	bookmark    *Bookmark
	filters     []EventFilter
	stats       *CollectStats
	ctx         context.Context
	cancel      context.CancelFunc
	isRunning   bool
	collectors  []Collector
	subscribers []chan *types.Event
	eventCh     chan *types.Event
}

type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]interface{}, error)
	RequiresAdmin() bool
}

func NewLiveCollector() *LiveCollector {
	ctx, cancel := context.WithCancel(context.Background())
	return &LiveCollector{
		bookmark:    NewBookmark(),
		filters:     make([]EventFilter, 0),
		stats:       NewCollectStats(),
		ctx:         ctx,
		cancel:      cancel,
		isRunning:   false,
		collectors: make([]Collector, 0),
		subscribers: make([]chan *types.Event, 0),
		eventCh:    make(chan *types.Event, 1000),
	}
}

func (lc *LiveCollector) Subscribe(ch chan *types.Event) func() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.subscribers = append(lc.subscribers, ch)
	return func() {
		lc.mu.Lock()
		defer lc.mu.Unlock()
		for i, c := range lc.subscribers {
			if c == ch {
				lc.subscribers = append(lc.subscribers[:i], lc.subscribers[i+1:]...)
				break
			}
		}
		close(ch)
	}
}

func (lc *LiveCollector) GetEvents(filter *EventFilter) ([]*types.Event, int64) {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	return nil, 0
}

func (lc *LiveCollector) AddCollector(c Collector) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.collectors = append(lc.collectors, c)
}

func (lc *LiveCollector) Start(interval time.Duration) error {
	lc.mu.Lock()
	if lc.isRunning {
		lc.mu.Unlock()
		return nil
	}
	lc.isRunning = true
	lc.mu.Unlock()

	go lc.run(interval)
	return nil
}

func (lc *LiveCollector) Stop() {
	lc.mu.Lock()
	if !lc.isRunning {
		lc.mu.Unlock()
		return
	}
	lc.isRunning = false
	lc.mu.Unlock()

	lc.cancel()

	lc.mu.Lock()
	lc.subscribers = nil
	lc.mu.Unlock()
}

func (lc *LiveCollector) run(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-lc.ctx.Done():
			return
		case <-ticker.C:
			lc.collect()
		}
	}
}

func (lc *LiveCollector) collect() {
	lc.mu.RLock()
	ctx := lc.ctx
	lc.mu.RUnlock()

	for _, collector := range lc.collectors {
		select {
		case <-ctx.Done():
			return
		default:
		}

		results, err := collector.Collect(ctx)
		if err != nil {
			lc.stats.RecordError(err)
			observability.LogServiceError("live_collector", fmt.Sprintf("%s: %v", collector.Name(), err))
			continue
		}

		for _, result := range results {
			if event, ok := result.(*types.Event); ok {
				if lc.shouldProcess(event) {
					lc.processEvent(event)
				}
			}
		}

		lc.stats.RecordCollect(collector.Name(), len(results))
	}
}

func (lc *LiveCollector) shouldProcess(event *types.Event) bool {
	lc.mu.RLock()
	defer lc.mu.RUnlock()

	for _, filter := range lc.filters {
		if !filter.Accept(event) {
			return false
		}
	}

	if lc.bookmark != nil {
		lastTime := lc.bookmark.GetLastTime()
		lastID := lc.bookmark.GetLastID()
		if !event.Timestamp.After(lastTime) && !(event.Timestamp.Equal(lastTime) && event.ID > lastID) {
			return false
		}
	}

	return true
}

func (lc *LiveCollector) processEvent(event *types.Event) {
	lc.bookmark.Update(event)

	lc.mu.RLock()
	defer lc.mu.RUnlock()
	for _, ch := range lc.subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}

func (lc *LiveCollector) AddFilter(filter EventFilter) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.filters = append(lc.filters, filter)
}

func (lc *LiveCollector) ClearFilters() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.filters = make([]EventFilter, 0)
}

func (lc *LiveCollector) GetStats() *CollectStats {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	return lc.stats
}

func (lc *LiveCollector) GetBookmark() *Bookmark {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	return lc.bookmark
}

func (lc *LiveCollector) SetBookmark(b *Bookmark) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.bookmark = b
}

func (lc *LiveCollector) IsRunning() bool {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	return lc.isRunning
}
