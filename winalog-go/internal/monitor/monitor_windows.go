//go:build windows

package monitor

import (
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/monitor/poll"
	"github.com/kkkdddd-start/winalog-go/internal/monitor/types"
	"github.com/kkkdddd-start/winalog-go/internal/monitor/wmi"
	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"go.uber.org/zap"
)

func (e *MonitorEngine) createProcessWatcher() (interface {
	Start() error
	Stop() error
	Subscribe(ch chan *types.MonitorEvent) func()
}, error) {
	observability.Info("Creating process watcher...", zap.String("module", "monitor"))
	watcher, err := wmi.NewProcessWatcher()
	if err != nil {
		observability.Error("createProcessWatcher: failed to create watcher",
			zap.String("module", "monitor"),
			zap.Error(err))
		return nil, err
	}
	observability.Info("createProcessWatcher: created successfully", zap.String("module", "monitor"))
	return watcher, nil
}

func (e *MonitorEngine) createNetworkPoller(interval time.Duration) interface {
	Start() error
	Stop() error
	Subscribe(ch chan *types.MonitorEvent) func()
} {
	poller, err := poll.NewNetworkPoller(interval)
	if err != nil {
		observability.Error("Failed to create network poller",
			zap.String("module", "monitor"),
			zap.Error(err))
		return nil
	}
	return poller
}
