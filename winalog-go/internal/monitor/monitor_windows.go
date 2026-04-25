//go:build windows

package monitor

import (
	"log"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/monitor/poll"
	"github.com/kkkdddd-start/winalog-go/internal/monitor/types"
	"github.com/kkkdddd-start/winalog-go/internal/monitor/wmi"
)

func (e *MonitorEngine) createProcessWatcher() (interface {
	Start() error
	Stop() error
	Subscribe(ch chan *types.MonitorEvent) func()
}, error) {
	log.Printf("[MONITOR] Creating process watcher...")
	watcher, err := wmi.NewProcessWatcher()
	if err != nil {
		log.Printf("[MONITOR] createProcessWatcher: failed to create watcher: %v", err)
		return nil, err
	}
	log.Printf("[MONITOR] createProcessWatcher: created successfully")
	return watcher, nil
}

func (e *MonitorEngine) createNetworkPoller(interval time.Duration) interface {
	Start() error
	Stop() error
	Subscribe(ch chan *types.MonitorEvent) func()
} {
	poller, err := poll.NewNetworkPoller(interval)
	if err != nil {
		log.Printf("[ERROR] failed to create network poller: %v", err)
		return nil
	}
	return poller
}
