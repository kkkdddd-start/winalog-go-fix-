//go:build windows

package monitor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/monitor/types"
	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"go.uber.org/zap"
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
		eventCh: make(chan *types.MonitorEvent, 5000),
		metrics: observability.GetMetricsLogger(),
	}

	return engine, nil
}

func (e *MonitorEngine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.isRunning {
		observability.Debug("Start called but already running", zap.String("module", "monitor"))
		return nil
	}

	observability.Info("Starting monitor engine...", zap.String("module", "monitor"))

	e.ctx, e.cancel = context.WithCancel(ctx)

	config := e.config.Get()
	e.startTime = time.Now()

	observability.Info("Config loaded",
		zap.String("module", "monitor"),
		zap.Bool("process_enabled", config.ProcessEnabled),
		zap.Bool("network_enabled", config.NetworkEnabled),
		zap.Duration("poll_interval", config.PollInterval))

	var err error

	if config.ProcessEnabled {
		observability.Info("Creating process watcher...", zap.String("module", "monitor"))
		e.processWatch, err = e.createProcessWatcher()
		if err == nil && e.processWatch != nil {
			observability.Debug("About to subscribe processWatch to eventCh",
				zap.String("module", "monitor"),
				zap.String("eventCh", fmt.Sprintf("%p", e.eventCh)))
			e.processWatch.Subscribe(e.eventCh)
			observability.Debug("processWatch subscription completed", zap.String("module", "monitor"))
			if err := e.processWatch.Start(); err != nil {
				observability.Error("Process watcher start failed", zap.String("module", "monitor"), zap.Error(err))
			} else {
				observability.Info("Process watcher started successfully", zap.String("module", "monitor"))
			}
		} else if err != nil {
			observability.Error("Process watcher creation failed", zap.String("module", "monitor"), zap.Error(err))
		}
	}

	if config.NetworkEnabled {
		observability.Info("Creating network poller...", zap.String("module", "monitor"))
		e.networkPoll = e.createNetworkPoller(config.PollInterval)
		if e.networkPoll != nil {
			e.networkPoll.Subscribe(e.eventCh)
			if err := e.networkPoll.Start(); err != nil {
				observability.Error("Network poller start failed", zap.String("module", "monitor"), zap.Error(err))
			} else {
				observability.Info("Network poller started successfully", zap.String("module", "monitor"))
			}
		}
	}

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.processEvents()
	}()

	e.isRunning = true
	e.stats.IsCollecting = true
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

	observability.Info("Stop called, shutting down...", zap.String("module", "monitor"))

	// 1. 通知 goroutine 退出
	if cancel != nil {
		cancel()
		observability.Info("Cancel function called", zap.String("module", "monitor"))
	} else {
		observability.Warn("Cancel function is nil", zap.String("module", "monitor"))
	}

	// 2. 等待 processEvents 完全退出
	observability.Info("Waiting for processEvents goroutine to exit...", zap.String("module", "monitor"))
	e.wg.Wait()
	observability.Info("processEvents goroutine exited", zap.String("module", "monitor"))

	// 3. 安全关闭 channel（此时不再有写入者）
	close(e.eventCh)
	observability.Info("Event channel closed", zap.String("module", "monitor"))

	// 4. 清理子组件
	if e.processWatch != nil {
		observability.Info("Stopping process watcher...", zap.String("module", "monitor"))
		e.processWatch.Stop()
		e.processWatch = nil
		observability.Info("Process watcher stopped", zap.String("module", "monitor"))
	}

	if e.networkPoll != nil {
		observability.Info("Stopping network poller...", zap.String("module", "monitor"))
		e.networkPoll.Stop()
		e.networkPoll = nil
		observability.Info("Network poller stopped", zap.String("module", "monitor"))
	}

	observability.Info("Stop completed successfully", zap.String("module", "monitor"))
	return nil
}

func (e *MonitorEngine) processEvents() {
	observability.Debug("processEvents goroutine started", zap.String("module", "monitor"))
	eventCount := 0
	observability.Debug("processEvents starting",
		zap.String("module", "monitor"),
		zap.String("eventCh", fmt.Sprintf("%p", e.eventCh)),
		zap.String("eventCache", fmt.Sprintf("%p", e.eventCache)))
	for {
		select {
		case <-e.ctx.Done():
			observability.Debug("processEvents goroutine stopping",
				zap.String("module", "monitor"),
				zap.Int("processed_events", eventCount))
			return
		case event, ok := <-e.eventCh:
			if !ok {
				observability.Info("eventCh closed",
					zap.String("module", "monitor"),
					zap.Int("processed_events", eventCount))
				return
			}
			eventCount++
			observability.Debug("Received event",
				zap.String("module", "monitor"),
				zap.Int("event_number", eventCount),
				zap.String("event_type", string(event.Type)),
				zap.Int("channel_len", len(e.eventCh)))
			e.eventCache.Add(event)
			observability.Debug("After Add",
				zap.String("module", "monitor"),
				zap.Int("cache_size", e.eventCache.Size()))
			e.updateStats(event)

			e.mu.Lock()
			for _, sub := range e.subscribers {
				select {
				case sub <- event:
				case <-time.After(1 * time.Second):
					observability.Warn("Failed to send event to subscriber (timeout)", zap.String("module", "monitor"))
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
		Category:    "monitor",
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

	e.stats.TotalCount++

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
		observability.Error("UpdateConfig failed", zap.String("module", "monitor"), zap.Error(err))
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
				observability.Error("Process watcher start failed", zap.String("module", "monitor"), zap.Error(err))
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
				observability.Error("Network poller start failed", zap.String("module", "monitor"), zap.Error(err))
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
	stats.IsCollecting = e.isRunning
	return &stats
}

func (e *MonitorEngine) GetEvents(filter *EventFilter) ([]*types.MonitorEvent, int64) {
	events, total := e.eventCache.Get(filter)
	observability.Info("GetEvents called",
		zap.String("module", "monitor"),
		zap.Int("returning", len(events)),
		zap.Int64("total", total),
		zap.Int("cache_size", e.eventCache.Size()))
	return events, total
}

func (e *MonitorEngine) Subscribe(ch chan *types.MonitorEvent) func() {
	e.mu.Lock()
	e.subscribers = append(e.subscribers, ch)
	observability.Debug("Subscribe called",
		zap.String("module", "monitor"),
		zap.Int("total_subscribers", len(e.subscribers)),
		zap.String("ch", fmt.Sprintf("%p", ch)))
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
