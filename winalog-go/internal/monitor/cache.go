package monitor

import (
	"sync"

	"github.com/kkkdddd-start/winalog-go/internal/monitor/types"
)

const DefaultMaxCacheSize = 10000

type EventCache struct {
	mu      sync.RWMutex
	events  []*types.MonitorEvent
	maxSize int
	stats   *CacheStats
}

type CacheStats struct {
	TotalAdded   uint64
	TotalDropped uint64
}

func NewEventCache(maxSize int) *EventCache {
	if maxSize <= 0 {
		maxSize = DefaultMaxCacheSize
	}
	return &EventCache{
		events:  make([]*types.MonitorEvent, 0, maxSize),
		maxSize: maxSize,
		stats:   &CacheStats{},
	}
}

func (c *EventCache) Add(event *types.MonitorEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if event == nil {
		return
	}

	if len(c.events) >= c.maxSize {
		c.events = c.events[1:]
		c.stats.TotalDropped++
	}

	c.events = append(c.events, event)
	c.stats.TotalAdded++
}

func matchFilter(e *types.MonitorEvent, f *EventFilter) bool {
	if f == nil {
		return true
	}
	if f.Type != "" && e.Type != f.Type {
		return false
	}
	if f.Severity != "" && e.Severity != f.Severity {
		return false
	}
	if !f.StartTime.IsZero() && e.Timestamp.Before(f.StartTime) {
		return false
	}
	if !f.EndTime.IsZero() && e.Timestamp.After(f.EndTime) {
		return false
	}
	return true
}

func (c *EventCache) Get(filter *EventFilter) ([]*types.MonitorEvent, int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// 先计算匹配总数
	total := int64(0)
	for _, e := range c.events {
		if matchFilter(e, filter) {
			total++
		}
	}

	// 解析分页参数
	offset := 0
	limit := 0
	if filter != nil {
		if filter.Offset > 0 {
			offset = filter.Offset
		}
		if filter.Limit > 0 {
			limit = filter.Limit
		}
	}

	// 先分页再收集，避免全量复制
	skipped := 0
	collected := 0
	result := make([]*types.MonitorEvent, 0)

	for _, e := range c.events {
		if !matchFilter(e, filter) {
			continue
		}
		skipped++
		if skipped <= offset {
			continue
		}
		result = append(result, e)
		collected++
		if limit > 0 && collected >= limit {
			break
		}
	}

	return result, total
}

func (c *EventCache) GetAll() []*types.MonitorEvent {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]*types.MonitorEvent, len(c.events))
	copy(result, c.events)
	return result
}

func (c *EventCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = make([]*types.MonitorEvent, 0, c.maxSize)
}

func (c *EventCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.events)
}

func (c *EventCache) GetStats() *CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return &CacheStats{
		TotalAdded:   c.stats.TotalAdded,
		TotalDropped: c.stats.TotalDropped,
	}
}
