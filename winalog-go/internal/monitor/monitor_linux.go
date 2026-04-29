//go:build !windows

package monitor

import (
	"context"
	"sync"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/monitor/types"
)

type MonitorEngine struct {
	mu           sync.RWMutex
	config       *ConfigManager
	eventCache   *EventCache
	processWatch interface{}
	networkPoll  interface{}
	isRunning    bool
	startTime    time.Time
	stats        *types.MonitorStats
	eventCh      chan *types.MonitorEvent
}

func NewMonitorEngine(configPath string) (*MonitorEngine, error) {
	return &MonitorEngine{
		config:     NewConfigManager(configPath),
		eventCache: NewEventCache(DefaultMaxCacheSize),
		isRunning:  false,
		stats: &types.MonitorStats{
			ProcessCount: 0,
			NetworkCount: 0,
			AlertCount:   0,
		},
		eventCh: make(chan *types.MonitorEvent, 1000),
	}, nil
}

func (e *MonitorEngine) Start(ctx context.Context) error {
	return nil
}

func (e *MonitorEngine) Stop() error {
	return nil
}

func (e *MonitorEngine) UpdateConfig(req *MonitorConfigRequest) error {
	return nil
}

func (e *MonitorEngine) GetStats() *types.MonitorStats {
	return &types.MonitorStats{
		IsCollecting: false,
	}
}

func (e *MonitorEngine) GetEvents(filter *EventFilter) ([]*types.MonitorEvent, int64) {
	return []*types.MonitorEvent{}, 0
}

func (e *MonitorEngine) Subscribe(ch chan *types.MonitorEvent) func() {
	return func() {}
}

func (e *MonitorEngine) IsRunning() bool {
	return false
}
