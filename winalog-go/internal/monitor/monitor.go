//go:build windows

package monitor

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/monitor/types"
	"github.com/kkkdddd-start/winalog-go/internal/observability"
)

type MonitorEngine struct {
	mu           sync.RWMutex
	config       *ConfigManager
	eventCache   *EventCache
	subscribers  []chan *types.MonitorEvent
	ctx          context.Context
	cancel       context.CancelFunc
	processWatch interface {
		Start() error
		Stop() error
		Subscribe(ch chan *types.MonitorEvent) func()
	}
	networkPoll interface {
		Start() error
		Stop() error
		Subscribe(ch chan *types.MonitorEvent) func()
	}
	isRunning bool
	startTime time.Time
	stats     *types.MonitorStats
	eventCh   chan *types.MonitorEvent
	metrics   *observability.MetricsLogger
	wg        sync.WaitGroup
}

func NewMonitorEngine(configPath string) (*MonitorEngine, error) {
	configMgr := NewConfigManager(configPath)

	engine := &MonitorEngine{
		config:     configMgr,
		eventCache: NewEventCache(DefaultMaxCacheSize),
		isRunning:  false,
		stats: &types.MonitorStats{
			ProcessCount: 0,
			NetworkCount: 0,
			AlertCount:   0,
		},
		eventCh: make(chan *types.MonitorEvent, 1000),
		metrics: observability.GetMetricsLogger(),
	}

	return engine, nil
}

func (e *MonitorEngine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.isRunning {
		return nil
	}

	e.ctx, e.cancel = context.WithCancel(ctx)

	config := e.config.Get()
	e.startTime = time.Now()

	var err error

	if config.ProcessEnabled {
		e.processWatch, err = e.createProcessWatcher()
		if err == nil && e.processWatch != nil {
			e.processWatch.Subscribe(e.eventCh)
			if err := e.processWatch.Start(); err != nil {
				log.Printf("[MONITOR] Process watcher start failed: %v", err)
			}
		} else if err != nil {
			log.Printf("[MONITOR] Process watcher creation failed: %v", err)
		}
	}

	if config.NetworkEnabled {
		e.networkPoll = e.createNetworkPoller(config.PollInterval)
		if e.networkPoll != nil {
			e.networkPoll.Subscribe(e.eventCh)
			if err := e.networkPoll.Start(); err != nil {
				log.Printf("[MONITOR] Network poller start failed: %v", err)
			}
		}
	}

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.processEvents()
	}()

	e.isRunning = true
	e.stats.IsRunning = true
	e.stats.StartTime = e.startTime

	e.updateConfigStats()

	return nil
}

func (e *MonitorEngine) Stop() error {
	e.mu.Lock()
	if !e.isRunning {
		e.mu.Unlock()
		return nil
	}
	e.isRunning = false
	cancel := e.cancel
	e.subscribers = nil
	e.ctx = nil
	e.mu.Unlock()

	// 1. 通知 goroutine 退出
	if cancel != nil {
		cancel()
	}

	// 2. 等待 processEvents 完全退出
	e.wg.Wait()

	// 3. 安全关闭 channel（此时不再有写入者）
	close(e.eventCh)

	// 4. 清理子组件
	if e.processWatch != nil {
		e.processWatch.Stop()
		e.processWatch = nil
	}

	if e.networkPoll != nil {
		e.networkPoll.Stop()
		e.networkPoll = nil
	}

	return nil
}

func (e *MonitorEngine) processEvents() {
	for {
		select {
		case <-e.ctx.Done():
			return
		case event, ok := <-e.eventCh:
			if !ok {
				return
			}
			e.eventCache.Add(event)
			e.updateStats(event)

			e.mu.Lock()
			for _, sub := range e.subscribers {
				select {
				case sub <- event:
				default:
				}
			}
			e.mu.Unlock()

			e.logMonitorEvent(event)
		}
	}
}

func (e *MonitorEngine) logMonitorEvent(event *types.MonitorEvent) {
	if e.metrics == nil {
		return
	}

	entry := observability.MonitorLogEntry{
		Timestamp:   time.Now().Format(time.RFC3339),
		Level:       string(event.Severity),
		Message:     "[MONITOR]",
		MonitorType: string(event.Type),
		ProcessName: event.Data["process_name"],
		CommandLine: event.Data["command"],
		SrcAddress:  event.Data["src_address"],
		DstAddress:  event.Data["dst_address"],
		Details:     event.Data,
	}

	e.metrics.LogMonitorEvent(entry)
}

func (e *MonitorEngine) updateStats(event *types.MonitorEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()

	switch event.Type {
	case types.EventTypeProcess:
		e.stats.ProcessCount++
	case types.EventTypeNetwork:
		e.stats.NetworkCount++
	}

	if event.Severity == types.SeverityHigh || event.Severity == types.SeverityCritical {
		e.stats.AlertCount++
	}
}

func (e *MonitorEngine) updateConfigStats() {
	config := e.config.Get()
	e.stats.ProcessEnabled = config.ProcessEnabled
	e.stats.NetworkEnabled = config.NetworkEnabled
}

func (e *MonitorEngine) UpdateConfig(req *MonitorConfigRequest) error {
	if err := e.config.UpdateFromRequest(req); err != nil {
		log.Printf("[MONITOR] UpdateConfig failed: %v", err)
		return err
	}

	config := e.config.Get()

	e.mu.Lock()
	e.stats.ProcessEnabled = config.ProcessEnabled
	e.stats.NetworkEnabled = config.NetworkEnabled

	if config.ProcessEnabled && e.processWatch == nil {
		e.processWatch, _ = e.createProcessWatcher()
		if e.processWatch != nil {
			e.processWatch.Subscribe(e.eventCh)
			if err := e.processWatch.Start(); err != nil {
				log.Printf("[MONITOR] Process watcher start failed: %v", err)
			}
		}
	} else if !config.ProcessEnabled && e.processWatch != nil {
		e.processWatch.Stop()
		e.processWatch = nil
	}

	if config.NetworkEnabled && e.networkPoll == nil {
		e.networkPoll = e.createNetworkPoller(config.PollInterval)
		if e.networkPoll != nil {
			e.networkPoll.Subscribe(e.eventCh)
			if err := e.networkPoll.Start(); err != nil {
				log.Printf("[MONITOR] Network poller start failed: %v", err)
			}
		}
	} else if !config.NetworkEnabled && e.networkPoll != nil {
		e.networkPoll.Stop()
		e.networkPoll = nil
	}

	e.mu.Unlock()

	return nil
}

func (e *MonitorEngine) GetStats() *types.MonitorStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	stats := *e.stats
	stats.IsRunning = e.isRunning
	return &stats
}

func (e *MonitorEngine) GetEvents(filter *EventFilter) ([]*types.MonitorEvent, int64) {
	return e.eventCache.Get(filter)
}

func (e *MonitorEngine) Subscribe(ch chan *types.MonitorEvent) func() {
	e.mu.Lock()
	e.subscribers = append(e.subscribers, ch)
	e.mu.Unlock()

	return func() {
		e.mu.Lock()
		for i, sub := range e.subscribers {
			if sub == ch {
				e.subscribers = append(e.subscribers[:i], e.subscribers[i+1:]...)
				break
			}
		}
		e.mu.Unlock()
		close(ch)
	}
}

func (e *MonitorEngine) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.isRunning
}
