//go:build windows

package live

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"github.com/kkkdddd-start/winalog-go/internal/types"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

func ListAvailableChannels() ([]string, error) {
	cmd := exec.Command("wevtutil", "el")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("wevtutil el failed: %w", err)
	}

	var channels []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		if name != "" {
			channels = append(channels, name)
		}
	}
	return channels, scanner.Err()
}

type EvtPollCollector struct {
	channels      []ChannelConfig
	buffer        *EventBuffer
	pollInterval  time.Duration
	ctx           context.Context
	cancel        context.CancelFunc
	isRunning     atomic.Bool
	mu            sync.RWMutex
	startTime     time.Time              // events before this time are ignored (real-time only)
	channelCursor map[string]uint64      // highest EventRecordID seen per channel (dedup)
	channelLastPoll map[string]time.Time // last poll completion time per channel
}

func NewEvtPollCollector(channels []ChannelConfig, buffer *EventBuffer, pollInterval time.Duration) *EvtPollCollector {
	return &EvtPollCollector{
		channels:        channels,
		buffer:          buffer,
		pollInterval:    pollInterval,
		channelCursor:   make(map[string]uint64),
		channelLastPoll: make(map[string]time.Time),
	}
}

func (c *EvtPollCollector) Start(ctx context.Context) error {
	if c.isRunning.Load() {
		return nil
	}

	c.ctx, c.cancel = context.WithCancel(ctx)
	c.isRunning.Store(true)
	c.startTime = time.Now()

	observability.Info("EvtPollCollector started",
		zap.String("module", "collector_poll"),
		zap.Int("channels", len(c.channels)),
		zap.Time("start_time", c.startTime))

	go c.run()

	return nil
}

func (c *EvtPollCollector) Stop() {
	if !c.isRunning.Load() {
		return
	}

	c.isRunning.Store(false)
	if c.cancel != nil {
		c.cancel()
	}

	if c.buffer != nil {
		c.buffer.Flush()
	}

	observability.Info("EvtPollCollector stopped",
		zap.String("module", "collector_poll"))
}

func (c *EvtPollCollector) IsRunning() bool {
	return c.isRunning.Load()
}

func (c *EvtPollCollector) run() {
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	c.poll()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.poll()
		}
	}
}

func (c *EvtPollCollector) poll() {
	if !c.isRunning.Load() {
		observability.Info("Poll cycle skipped: not running",
			zap.String("module", "collector_poll"))
		return
	}

	observability.DebugPrintf("[DEBUG] [EvtPollCollector] Poll cycle started")

	c.mu.RLock()
	channels := make([]ChannelConfig, len(c.channels))
	copy(channels, c.channels)
	c.mu.RUnlock()

	for _, channel := range channels {
		if !channel.Enabled {
			continue
		}

		if !c.isRunning.Load() {
			return
		}

		// Use per-channel last poll time to avoid missing events between channel queries
		c.mu.RLock()
		queryTime := c.channelLastPoll[channel.Name]
		c.mu.RUnlock()

		// Fall back to global startTime for first poll
		if queryTime.IsZero() {
			c.mu.RLock()
			queryTime = c.startTime
			c.mu.RUnlock()
		}

		events, err := c.queryEvents(channel.Name, channel.EventIDs, queryTime)
		if err != nil {
			observability.LogServiceError("EvtPollCollector", fmt.Sprintf("queryEvents failed for %s: %v", channel.Name, err))
			observability.Warn("Failed to query channel",
				zap.String("module", "collector_poll"),
				zap.String("channel", channel.Name),
				zap.Error(err))
			continue
		}

		observability.Info("Channel query returned new events",
			zap.String("module", "collector_poll"),
			zap.String("channel", channel.Name),
			zap.Int("count", len(events)))

		if len(events) > 0 {
			c.buffer.AddBatch(events)

			// Track highest record ID per channel for dedup
			c.mu.Lock()
			for _, e := range events {
				if e.WindowsRecordID > c.channelCursor[channel.Name] {
					c.channelCursor[channel.Name] = e.WindowsRecordID
				}
			}
			// Update per-channel last poll time after successful query
			c.channelLastPoll[channel.Name] = time.Now()
			c.mu.Unlock()
		}
	}

	observability.DebugPrintf("[DEBUG] [EvtPollCollector] Poll cycle completed")
}

func (c *EvtPollCollector) queryEvents(channelName, eventIDs string, startTime time.Time) ([]*types.Event, error) {
	observability.DebugPrintf("[DEBUG] [EvtPollCollector] queryEvents: channel=%s, eventIDs=%s, startTime=%s", channelName, eventIDs, startTime.Format(time.RFC3339))

	channelPtr, err := windows.UTF16PtrFromString(channelName)
	if err != nil {
		return nil, fmt.Errorf("failed to convert channel name: %w", err)
	}

	var queryPtr uintptr
	var queryStr string
	if eventIDs != "" {
		eventIDList := strings.ReplaceAll(eventIDs, ",", " or ")
		xpath := buildEventIDXPath(eventIDList)
		queryStr = fmt.Sprintf("*[System[(%s)]]", xpath)
		queryPtrVal, err := windows.UTF16PtrFromString(queryStr)
		if err != nil {
			return nil, fmt.Errorf("failed to convert query: %w", err)
		}
		queryPtr = uintptr(unsafe.Pointer(queryPtrVal))
	} else {
		queryStr = "*"
		queryPtr = 0
	}

	session := windows.Handle(0)
	flags := uintptr(EvtQueryChannelPath)

	observability.DebugPrintf("[DEBUG] [EvtPollCollector] queryEvents EvtQuery: path=%s, query=%q, flags=0x%x", channelName, queryStr, flags)

	queryHandle, r2, lastErr := procEvtQuery.Call(
		uintptr(session),
		uintptr(unsafe.Pointer(channelPtr)),
		queryPtr,
		flags,
	)

	observability.DebugPrintf("[DEBUG] [EvtPollCollector] queryEvents EvtQuery result: handle=%d, r2=%d, lastErr=%v", queryHandle, r2, lastErr)

	if queryHandle == 0 {
		return nil, fmt.Errorf("EvtQuery failed: path=%s, query=%q, flags=0x%x, r2=%d, lastErr=%v", channelName, queryStr, flags, r2, lastErr)
	}
	defer procEvtClose.Call(queryHandle)

	observability.DebugPrintf("[DEBUG] [EvtPollCollector] queryEvents: EvtQuery SUCCESS for channel=%s", channelName)

	var events []*types.Event
	var skippedByTime int
	const batchSize = 256

	eventHandles := make([]windows.Handle, batchSize)
	for {
		var returned uint32
		ret, _, _ := procEvtNext.Call(
			uintptr(queryHandle),
			uintptr(len(eventHandles)),
			uintptr(unsafe.Pointer(&eventHandles[0])),
			uintptr(3000),
			0,
			uintptr(unsafe.Pointer(&returned)),
		)

		if ret == 0 {
			errCode := windows.GetLastError()
			if errCode != windows.ERROR_NO_MORE_ITEMS {
				observability.Warn("EvtNext error",
					zap.String("module", "collector_poll"),
					zap.Error(errCode))
			}
			break
		}

		for i := 0; i < int(returned); i++ {
			event := renderEvent(eventHandles[i])
			procEvtClose.Call(uintptr(eventHandles[i]))
			eventHandles[i] = 0

			if event == nil {
				continue
			}

			if !event.Timestamp.After(startTime) {
				skippedByTime++
				continue
			}

			c.mu.RLock()
			cursor := c.channelCursor[channelName]
			c.mu.RUnlock()
			if event.WindowsRecordID <= cursor {
				continue
			}

			events = append(events, event)
		}
	}

	if skippedByTime > 0 {
		observability.DebugPrintf("[DEBUG] [EvtPollCollector] Channel [%s]: skipped %d historical events (before %s)", channelName, skippedByTime, startTime.Format(time.RFC3339))
	}

	observability.DebugPrintf("[DEBUG] [EvtPollCollector] queryEvents: collected %d new events", len(events))
	return events, nil
}

func buildEventIDXPath(eventIDList string) string {
	parts := strings.Split(eventIDList, " or ")
	var clauses []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			clauses = append(clauses, fmt.Sprintf("(EventID=%s)", part))
		}
	}
	return strings.Join(clauses, " or ")
}

func (c *EvtPollCollector) GetLastRecordID() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var maxID uint64
	for _, id := range c.channelCursor {
		if id > maxID {
			maxID = id
		}
	}
	return maxID
}

func (c *EvtPollCollector) SetChannels(channels []ChannelConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.channels = channels
}

func (c *EvtPollCollector) Name() string {
	return "EvtPollCollector"
}

func (c *EvtPollCollector) ChannelName() string {
	if len(c.channels) > 0 {
		return c.channels[0].Name
	}
	return ""
}

func (c *EvtPollCollector) Events() <-chan *types.Event {
	ch := make(chan *types.Event, 100)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				close(ch)
				return
			case <-ticker.C:
				if !c.isRunning.Load() {
					close(ch)
					return
				}
			}
		}
	}()
	return ch
}
