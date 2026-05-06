//go:build windows

package live

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"github.com/kkkdddd-start/winalog-go/internal/types"
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
	channels         []ChannelConfig
	buffer           *EventBuffer
	pollInterval     time.Duration
	ctx              context.Context
	cancel           context.CancelFunc
	isRunning        atomic.Bool
	mu               sync.RWMutex
	channelRecordIDs map[string]uint64
}

func NewEvtPollCollector(channels []ChannelConfig, buffer *EventBuffer, pollInterval time.Duration) *EvtPollCollector {
	return &EvtPollCollector{
		channels:    channels,
		buffer:      buffer,
		pollInterval: pollInterval,
		channelRecordIDs: make(map[string]uint64),
	}
}

func (c *EvtPollCollector) Start(ctx context.Context) error {
	if c.isRunning.Load() {
		return nil
	}

	c.ctx, c.cancel = context.WithCancel(ctx)
	c.isRunning.Store(true)

	// Initialize cursors to skip full history scan
	c.initRecordIDs()

	go c.run()

	log.Printf("[INFO] [EvtPollCollector] Started with %d channels", len(c.channels))
	return nil
}

func (c *EvtPollCollector) initRecordIDs() {
	log.Printf("[INFO] [EvtPollCollector] Initializing record ID cursors...")

	c.mu.RLock()
	channels := make([]ChannelConfig, len(c.channels))
	copy(channels, c.channels)
	c.mu.RUnlock()

	for _, channel := range channels {
		if !channel.Enabled {
			continue
		}

		maxID, err := c.queryMaxRecordID(channel.Name)
		if err != nil {
			log.Printf("[WARN] [EvtPollCollector] Failed to init cursor for %s: %v (will start from 0)", channel.Name, err)
			continue
		}

		c.mu.Lock()
		c.channelRecordIDs[channel.Name] = maxID
		c.mu.Unlock()
		log.Printf("[INFO] [EvtPollCollector] Initialized cursor for %s to %d", channel.Name, maxID)
	}
}

func (c *EvtPollCollector) queryMaxRecordID(channelName string) (uint64, error) {
	log.Printf("[DEBUG] [EvtPollCollector] Initializing cursor for %s", channelName)

	channelPtr, err := windows.UTF16PtrFromString(channelName)
	if err != nil {
		return 0, fmt.Errorf("failed to convert channel name: %w", err)
	}

	// Use a generic query to ensure compatibility with EvtQueryReverseDirection
	// Passing NULL query with Reverse flag caused failures in some environments
	queryStr := "*[System[(EventRecordID > 0)]]"
	queryPtr, err := windows.UTF16PtrFromString(queryStr)
	if err != nil {
		return 0, fmt.Errorf("failed to convert query: %w", err)
	}

	session := windows.Handle(0)
	flags := uintptr(EvtQueryChannelPath | EvtQueryReverseDirection)

	queryHandle, r2, err := procEvtQuery.Call(
		uintptr(session),
		uintptr(unsafe.Pointer(channelPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		flags,
	)

	if queryHandle == 0 {
		log.Printf("[WARN] [EvtPollCollector] EvtQuery failed for init: channel=%s, r2=%v, err=%v", channelName, r2, err)
		return 0, fmt.Errorf("EvtQuery failed (r2=%v): %w", r2, err)
	}
	defer procEvtClose.Call(queryHandle)

	// Fetch only 1 event (the latest one)
	var eventHandle windows.Handle
	var returned uint32

	ret, _, _ := procEvtNext.Call(
		uintptr(queryHandle),
		1,
		uintptr(unsafe.Pointer(&eventHandle)),
		1000, // 1 second timeout
		0,
		uintptr(unsafe.Pointer(&returned)),
	)

	if ret == 0 || returned == 0 {
		// No events in this channel yet, start from 0
		return 0, nil
	}
	defer procEvtClose.Call(uintptr(eventHandle))

	// Render the event to get EventRecordID directly
	event := renderEvent(eventHandle)
	if event == nil {
		return 0, fmt.Errorf("failed to render event")
	}

	return event.WindowsRecordID, nil
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

	log.Printf("[INFO] [EvtPollCollector] Stopped")
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
		log.Printf("[INFO] [EvtPollCollector] Poll cycle skipped: not running")
		return
	}

	log.Printf("[INFO] [EvtPollCollector] Poll cycle started")

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

		// Get the last record ID for this channel
		c.mu.RLock()
		minID := c.channelRecordIDs[channel.Name]
		c.mu.RUnlock()

		events, err := c.queryEvents(channel.Name, channel.EventIDs, minID)
		if err != nil {
			observability.LogServiceError("EvtPollCollector", fmt.Sprintf("queryEvents failed for %s: %v", channel.Name, err))
			log.Printf("[WARN] [EvtPollCollector] Failed to query %s: %v", channel.Name, err)
			continue
		}

		log.Printf("[INFO] [EvtPollCollector] Channel [%s]: Query returned %d new events", channel.Name, len(events))

		if len(events) > 0 {
			c.buffer.AddBatch(events)
			
			// Update the max record ID for this channel
			var maxID uint64
			for _, e := range events {
				if e.WindowsRecordID > maxID {
					maxID = e.WindowsRecordID
				}
			}
			
			c.mu.Lock()
			c.channelRecordIDs[channel.Name] = maxID
			log.Printf("[INFO] [EvtPollCollector] Channel [%s]: Updated cursor to %d (was %d)", channel.Name, maxID, minID)
			c.mu.Unlock()
		}
	}

	log.Printf("[INFO] [EvtPollCollector] Poll cycle completed")
}

func (c *EvtPollCollector) queryEvents(channelName, eventIDs string, minRecordID uint64) ([]*types.Event, error) {
	query := BuildEventQuery(channelName, eventIDs, minRecordID)
	log.Printf("[DEBUG] [EvtPollCollector] Querying channel [%s] with query: %s", channelName, query)

	channelPtr, err := windows.UTF16PtrFromString(channelName)
	if err != nil {
		return nil, fmt.Errorf("failed to convert channel name: %w", err)
	}

	var queryPtr *uint16
	if query != "" {
		queryPtr, err = windows.UTF16PtrFromString(query)
		if err != nil {
			return nil, fmt.Errorf("failed to convert query: %w", err)
		}
	}

	session := windows.Handle(0)
	flags := uintptr(EvtQueryChannelPath)

	var queryArg uintptr
	if queryPtr != nil {
		queryArg = uintptr(unsafe.Pointer(queryPtr))
	}
	// When queryPtr is nil (no filter), pass 0 (C NULL) explicitly

	queryHandle, _, err := procEvtQuery.Call(
		uintptr(session),
		uintptr(unsafe.Pointer(channelPtr)),
		queryArg,
		uintptr(flags),
	)

	if queryHandle == 0 {
		if err != nil {
			return nil, fmt.Errorf("EvtQuery failed for channel %s: %v", channelName, err)
		}
		return nil, fmt.Errorf("EvtQuery failed for channel %s (unknown error)", channelName)
	}

	log.Printf("[DEBUG] [EvtPollCollector] queryEvents: EvtQuery SUCCESS for channel=%s, query=%s", channelName, query)

	defer procEvtClose.Call(queryHandle)

	events, err := c.fetchEvents(windows.Handle(queryHandle))
	if err != nil {
		return nil, fmt.Errorf("fetchEvents failed: %w", err)
	}

	return events, nil
}

func (c *EvtPollCollector) fetchEvents(queryHandle windows.Handle) ([]*types.Event, error) {
	events := make([]*types.Event, 0)
	eventHandles := make([]windows.Handle, 256)

	log.Printf("[DEBUG] [EvtPollCollector] fetchEvents: starting to fetch events")

	for {
		var returned uint32

		ret, _, err := procEvtNext.Call(
			uintptr(queryHandle),
			uintptr(len(eventHandles)),
			uintptr(unsafe.Pointer(&eventHandles[0])),
			uintptr(5000),
			0,
			uintptr(unsafe.Pointer(&returned)),
		)

		if ret == 0 {
			errCode := windows.GetLastError()
			log.Printf("[DEBUG] [EvtPollCollector] fetchEvents: EvtNext returned 0, errCode=%v, err=%v", errCode, err)
			if errCode == windows.ERROR_NO_MORE_ITEMS {
				log.Printf("[DEBUG] [EvtPollCollector] fetchEvents: ERROR_NO_MORE_ITEMS - no more events")
				break
			}
			if err != nil && strings.Contains(err.Error(), "operation completed") {
				log.Printf("[DEBUG] [EvtPollCollector] fetchEvents: operation completed")
				break
			}
			log.Printf("[DEBUG] [EvtPollCollector] fetchEvents: EvtNext failed with errCode=%v, breaking", errCode)
			break
		}

		log.Printf("[DEBUG] [EvtPollCollector] fetchEvents: EvtNext returned %d events", returned)

		for i := 0; i < int(returned); i++ {
			event := renderEvent(eventHandles[i])
			if event != nil {
				events = append(events, event)
			}
			procEvtClose.Call(uintptr(eventHandles[i]))
		}
	}

	log.Printf("[DEBUG] [EvtPollCollector] fetchEvents: total collected %d events", len(events))
	return events, nil
}

func (c *EvtPollCollector) GetLastRecordID() uint64 {
	// Return the max record ID across all channels for stats
	c.mu.RLock()
	defer c.mu.RUnlock()
	var maxID uint64
	for _, id := range c.channelRecordIDs {
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
