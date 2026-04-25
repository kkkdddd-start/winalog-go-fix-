//go:build windows

package live

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"unsafe"

	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"github.com/kkkdddd-start/winalog-go/internal/types"
	"golang.org/x/sys/windows"
)

const (
	EvtSubscribeActionStartAtBeginning   = 0
	EvtSubscribeActionStartAfterBookmark = 1

	EvtRenderEventXML = 1

	INFINITE = 0xFFFFFFFF
)

var (
	wevtapi          = windows.NewLazyDLL("wevtapi.dll")
	procEvtSubscribe = wevtapi.NewProc("EvtSubscribe")
	procEvtNext      = wevtapi.NewProc("EvtNext")
	procEvtClose     = wevtapi.NewProc("EvtClose")
	procEvtRender    = wevtapi.NewProc("EvtRender")
)

type EvtLiveCollector struct {
	channelName  string
	query        string
	session      windows.Handle
	signalEvent  windows.Handle
	bookmark     windows.Handle
	bookmarkFile string
	events       chan *types.Event
	mu           sync.RWMutex
	isRunning    bool
	ctx          context.Context
	cancel       context.CancelFunc
	lastRecordID uint64
}

func NewEvtLiveCollector(channelName string, query string) *EvtLiveCollector {
	return &EvtLiveCollector{
		channelName: channelName,
		query:       query,
		events:      make(chan *types.Event, 100),
	}
}

func (c *EvtLiveCollector) Name() string {
	return "evt_live_" + c.channelName
}

func (c *EvtLiveCollector) Collect(ctx context.Context) ([]interface{}, error) {
	results := make([]interface{}, 0)
	select {
	case e := <-c.events:
		if e != nil {
			results = append(results, e)
		}
	case <-ctx.Done():
		return results, ctx.Err()
	default:
	}
	return results, nil
}

func (c *EvtLiveCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.isRunning {
		c.mu.Unlock()
		return nil
	}

	signalEvent, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	c.signalEvent = signalEvent

	subscriptionCtx, subscriptionCancel := context.WithCancel(ctx)
	c.ctx = subscriptionCtx
	c.cancel = subscriptionCancel

	c.isRunning = true
	c.mu.Unlock()

	if c.bookmarkFile != "" {
		c.loadBookmark()
	}

	if err := c.subscribe(); err != nil {
		c.Stop()
		return err
	}

	go c.runLoop()
	return nil
}

func (c *EvtLiveCollector) subscribe() error {
	c.mu.RLock()
	signalEvent := c.signalEvent
	bookmark := c.bookmark
	c.mu.RUnlock()

	channelPtr, _ := windows.UTF16PtrFromString(c.channelName)

	var queryPtr *uint16
	if c.query != "" {
		queryPtr, _ = windows.UTF16PtrFromString(c.query)
	}

	flags := EvtSubscribeActionStartAtBeginning
	if bookmark != 0 {
		flags = EvtSubscribeActionStartAfterBookmark
	}

	ret, _, err := procEvtSubscribe.Call(
		0,
		uintptr(unsafe.Pointer(channelPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		uintptr(signalEvent),
		0,
		uintptr(bookmark),
		uintptr(flags),
	)

	if ret == 0 {
		observability.LogServiceError("evt_live_collector", fmt.Sprintf("EvtSubscribe failed for channel %s: %v", c.channelName, err))
		return err
	}

	c.mu.Lock()
	c.session = windows.Handle(ret)
	c.mu.Unlock()

	return nil
}

func (c *EvtLiveCollector) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isRunning {
		return
	}
	c.isRunning = false

	if c.cancel != nil {
		c.cancel()
	}

	if c.session != 0 {
		procEvtClose.Call(uintptr(c.session))
		c.session = 0
	}

	if c.signalEvent != 0 {
		windows.CloseHandle(c.signalEvent)
		c.signalEvent = 0
	}

	if c.bookmark != 0 {
		procEvtClose.Call(uintptr(c.bookmark))
		c.bookmark = 0
	}

	if c.bookmarkFile != "" && c.lastRecordID > 0 {
		c.saveBookmark()
	}
}

func (c *EvtLiveCollector) runLoop() {
	for {
		c.mu.RLock()
		signalEvent := c.signalEvent
		session := c.session
		ctx := c.ctx
		c.mu.RUnlock()

		if session == 0 || signalEvent == 0 {
			return
		}

		waitResult, err := windows.WaitForSingleObject(signalEvent, INFINITE)
		if err != nil {
			return
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		if waitResult == windows.WAIT_OBJECT_0 {
			events, _ := c.fetchNext(0)
			for _, e := range events {
				c.updateBookmarkFromEvent(e)

				select {
				case c.events <- e:
				case <-ctx.Done():
					return
				default:
					log.Printf("[WARN] evt_live_collector: event channel full, dropping event: %s/%d", e.LogName, e.ID)
				}
			}

			windows.ResetEvent(signalEvent)
		}
	}
}

func (c *EvtLiveCollector) fetchNext(timeout uint32) ([]*types.Event, error) {
	c.mu.RLock()
	session := c.session
	c.mu.RUnlock()

	if session == 0 {
		return nil, nil
	}

	eventHandles := make([]windows.Handle, 256)
	var returned uint32

	ret, _, err := procEvtNext.Call(
		uintptr(session),
		uintptr(timeout),
		0,
		uintptr(unsafe.Pointer(&eventHandles[0])),
		uintptr(unsafe.Pointer(&returned)),
	)

	if ret == 0 && err != nil && err != windows.ERROR_NO_MORE_ITEMS {
		observability.LogServiceError("evt_live_collector", fmt.Sprintf("EvtNext failed: %v", err))
		return nil, err
	}

	events := make([]*types.Event, 0, returned)
	for i := 0; i < int(returned); i++ {
		event := renderEvent(eventHandles[i])
		if event != nil {
			events = append(events, event)
		}
		procEvtClose.Call(uintptr(eventHandles[i]))
	}

	return events, nil
}

func (c *EvtLiveCollector) updateBookmarkFromEvent(event *types.Event) {
	if event == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if event.ID > 0 && uint64(event.ID) > c.lastRecordID {
		c.lastRecordID = uint64(event.ID)
	}
}

func (c *EvtLiveCollector) SetBookmarkFile(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bookmarkFile = path
}

func (c *EvtLiveCollector) saveBookmark() {
	if c.bookmarkFile == "" || c.lastRecordID == 0 {
		return
	}

	content := strings.Builder{}
	content.WriteString("Channel=\"")
	content.WriteString(c.channelName)
	content.WriteString("\"\n")
	content.WriteString("RecordID=\"")
	content.WriteString(formatUint64(c.lastRecordID))
	content.WriteString("\"\n")

	os.WriteFile(c.bookmarkFile, []byte(content.String()), 0644)
}

func (c *EvtLiveCollector) loadBookmark() {
	if c.bookmarkFile == "" {
		return
	}

	data, err := os.ReadFile(c.bookmarkFile)
	if err != nil {
		return
	}

	content := string(data)
	if !strings.Contains(content, "Channel=\"") || !strings.Contains(content, "RecordID=\"") {
		return
	}

	bookmarkHandle, err := CreateEvtBookmarkFromXML(content)
	if err != nil {
		return
	}

	c.mu.Lock()
	c.bookmark = bookmarkHandle
	c.mu.Unlock()
}

func renderEvent(eventHandle windows.Handle) *types.Event {
	if eventHandle == 0 {
		return nil
	}

	var bufferSize uint32
	procEvtRender.Call(
		uintptr(eventHandle),
		0,
		EvtRenderEventXML,
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
		EvtRenderEventXML,
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

func formatUint64(n uint64) string {
	return fmt.Sprintf("%d", n)
}

func (c *EvtLiveCollector) Events() <-chan *types.Event {
	return c.events
}

func (c *EvtLiveCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isRunning
}

func (c *EvtLiveCollector) ChannelName() string {
	return c.channelName
}
