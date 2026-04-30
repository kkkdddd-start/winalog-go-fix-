//go:build windows

package live

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"github.com/kkkdddd-start/winalog-go/internal/types"
	"golang.org/x/sys/windows"
)

var (
	wevtapi            = windows.NewLazyDLL("wevtapi.dll")
	procEvtQuery       = wevtapi.NewProc("EvtQuery")
	procEvtNext        = wevtapi.NewProc("EvtNext")
	procEvtClose       = wevtapi.NewProc("EvtClose")
	procEvtRender      = wevtapi.NewProc("EvtRender")
	procEvtCreateBookmark  = wevtapi.NewProc("EvtCreateBookmark")
	procEvtUpdateBookmark = wevtapi.NewProc("EvtUpdateBookmark")
	procEvtOpenChannelEnum = wevtapi.NewProc("EvtOpenChannelEnum")
	procEvtNextChannelPath = wevtapi.NewProc("EvtNextChannelPath")
)

const (
	EvtQueryChannelPath       = 1
	EvtQueryForwardDirection  = 1
	EvtRenderEventXML         = 1
)

func ListAvailableChannels() ([]string, error) {
	var channels []string

	enumHandle, _, err := procEvtOpenChannelEnum.Call(0, 0)
	if enumHandle == 0 {
		return nil, fmt.Errorf("EvtOpenChannelEnum failed: %w", err)
	}
	defer procEvtClose.Call(enumHandle)

	bufferSize := 0
	for {
		pathPtr := make([]*uint16, 1)
		ret, _, _ := procEvtNextChannelPath.Call(
			enumHandle,
			uintptr(len(pathPtr)),
			uintptr(unsafe.Pointer(&pathPtr[0])),
			0,
			uintptr(unsafe.Pointer(&bufferSize)),
		)

		if ret == 0 {
			errCode := windows.GetLastError()
			errno, _ := errCode.(syscall.Errno)
			if errCode == windows.ERROR_NO_MORE_ITEMS || errno == 259 {
				break
			}
			if bufferSize == 0 {
				break
			}
			continue
		}

		if pathPtr[0] != nil {
			channelName := windows.UTF16PtrToString(pathPtr[0])
			if channelName != "" {
				channels = append(channels, channelName)
			}
		}

		if bufferSize == 0 {
			break
		}
	}

	return channels, nil
}

type EvtPollCollector struct {
	channels     []ChannelConfig
	buffer       *EventBuffer
	pollInterval time.Duration
	ctx          context.Context
	cancel       context.CancelFunc
	isRunning    atomic.Bool
	lastRecordID atomic.Uint64
	mu           sync.RWMutex
}

func NewEvtPollCollector(channels []ChannelConfig, buffer *EventBuffer, pollInterval time.Duration) *EvtPollCollector {
	return &EvtPollCollector{
		channels:    channels,
		buffer:      buffer,
		pollInterval: pollInterval,
	}
}

func (c *EvtPollCollector) Start(ctx context.Context) error {
	if c.isRunning.Load() {
		return nil
	}

	c.ctx, c.cancel = context.WithCancel(ctx)
	c.isRunning.Store(true)

	go c.run()

	log.Printf("[INFO] [EvtPollCollector] Started with %d channels", len(c.channels))
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
		log.Printf("[DEBUG] [EvtPollCollector] poll() skipped: not running")
		return
	}

	log.Printf("[DEBUG] [EvtPollCollector] poll() started, isRunning=true")

	c.mu.RLock()
	channels := c.channels
	c.mu.RUnlock()

	for _, channel := range channels {
		if !channel.Enabled {
			continue
		}

		if !c.isRunning.Load() {
			log.Printf("[DEBUG] [EvtPollCollector] poll() interrupted: not running")
			return
		}

		events, err := c.queryEvents(channel.Name, channel.EventIDs)
		if err != nil {
			observability.LogServiceError("EvtPollCollector", fmt.Sprintf("queryEvents failed for %s: %v", channel.Name, err))
			log.Printf("[DEBUG] [EvtPollCollector] queryEvents error for channel %s: %v", channel.Name, err)
			continue
		}

		log.Printf("[DEBUG] [EvtPollCollector] queryEvents returned %d events from %s (query: %s)", len(events), channel.Name, BuildEventQuery(channel.Name, channel.EventIDs))

		if len(events) > 0 {
			c.buffer.AddBatch(events)
			log.Printf("[DEBUG] [EvtPollCollector] Collected %d events from %s", len(events), channel.Name)
		}
	}

	log.Printf("[DEBUG] [EvtPollCollector] poll() completed")
}

func (c *EvtPollCollector) queryEvents(channelName, eventIDs string) ([]*types.Event, error) {
	query := BuildEventQuery(channelName, eventIDs)

	log.Printf("[DEBUG] [EvtPollCollector] queryEvents: channel=%s, eventIDs=%q, query=%s", channelName, eventIDs, query)

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
	flags := uintptr(EvtQueryChannelPath | EvtQueryForwardDirection)

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
		errCode := windows.GetLastError()
		if errCode != nil {
			log.Printf("[DEBUG] [EvtPollCollector] queryEvents: EvtQuery FAILED for channel=%s, query=%s, err=%v", channelName, query, errCode)
		} else {
			log.Printf("[DEBUG] [EvtPollCollector] queryEvents: EvtQuery FAILED for channel=%s, query=%s, err=nil (unknown)", channelName, query)
		}
		return nil, fmt.Errorf("EvtQuery failed for channel %s with query '%s'", channelName, query)
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
			uintptr(unsafe.Pointer(&eventHandles[0])),
			uintptr(len(eventHandles)),
			uintptr(5000),
			0,
			uintptr(unsafe.Pointer(&returned)),
		)

		if ret == 0 {
			errCode := windows.GetLastError()
			log.Printf("[DEBUG] [EvtPollCollector] fetchEvents: EvtNext returned 0, errCode=%d, err=%v", errCode, err)
			if errCode == windows.ERROR_NO_MORE_ITEMS {
				log.Printf("[DEBUG] [EvtPollCollector] fetchEvents: ERROR_NO_MORE_ITEMS - no more events")
				break
			}
			if err != nil && strings.Contains(err.Error(), "operation completed") {
				log.Printf("[DEBUG] [EvtPollCollector] fetchEvents: operation completed")
				break
			}
			log.Printf("[DEBUG] [EvtPollCollector] fetchEvents: EvtNext failed with errCode=%d, breaking", errCode)
			break
		}

		log.Printf("[DEBUG] [EvtPollCollector] fetchEvents: EvtNext returned %d events", returned)

		for i := 0; i < int(returned); i++ {
			event := renderEvent(eventHandles[i])
			if event != nil {
				events = append(events, event)

				eventID := uint64(event.ID)
				if eventID > c.lastRecordID.Load() {
					c.lastRecordID.Store(eventID)
				}
			}
			procEvtClose.Call(uintptr(eventHandles[i]))
		}
	}

	log.Printf("[DEBUG] [EvtPollCollector] fetchEvents: total collected %d events", len(events))
	return events, nil
}

func (c *EvtPollCollector) GetLastRecordID() uint64 {
	return c.lastRecordID.Load()
}

func (c *EvtPollCollector) SetChannels(channels []ChannelConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.channels = channels
}

func renderEvent(eventHandle windows.Handle) *types.Event {
	if eventHandle == 0 {
		return nil
	}

	var bufferSize uint32
	procEvtRender.Call(
		uintptr(eventHandle),
		0,
		uintptr(EvtRenderEventXML),
		0,
		0,
		uintptr(unsafe.Pointer(&bufferSize)),
		0,
	)

	if bufferSize == 0 {
		return nil
	}

	buffer := make([]byte, bufferSize)
	ret, _, _ := procEvtRender.Call(
		uintptr(eventHandle),
		0,
		uintptr(EvtRenderEventXML),
		uintptr(bufferSize),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&bufferSize)),
		0,
	)

	if ret == 0 {
		return nil
	}

	return ParseEventXML(string(buffer))
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
		for {
			if !c.isRunning.Load() {
				close(ch)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	return ch
}

func NewEvtLiveCollector(channel, query string) EventCollector {
	buffer := NewEventBuffer(1000, 5*time.Second, func(events []*types.Event) {})
	channels := []ChannelConfig{{Name: channel, EventIDs: query, Enabled: true}}
	return NewEvtPollCollector(channels, buffer, 2*time.Second)
}
