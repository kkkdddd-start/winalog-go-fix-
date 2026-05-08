package live

import (
	"sync"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"github.com/kkkdddd-start/winalog-go/internal/types"
	"go.uber.org/zap"
)

type EventBuffer struct {
	mu             sync.Mutex
	events         []*types.Event
	maxSize        int
	flushInterval  time.Duration
	lastFlush      time.Time
	onFlush        func(events []*types.Event)
}

func NewEventBuffer(maxSize int, flushInterval time.Duration, onFlush func(events []*types.Event)) *EventBuffer {
	return &EventBuffer{
		events:        make([]*types.Event, 0, maxSize),
		maxSize:       maxSize,
		flushInterval: flushInterval,
		lastFlush:     time.Now(),
		onFlush:       onFlush,
	}
}

func (b *EventBuffer) Add(event *types.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.events = append(b.events, event)

	if len(b.events) >= b.maxSize || b.shouldFlush() {
		b.flushLocked()
	}
}

func (b *EventBuffer) AddBatch(events []*types.Event) {
	if len(events) == 0 {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.events = append(b.events, events...)
	observability.Debug("AddBatch: added events",
		zap.String("module", "buffer"),
		zap.Int("added", len(events)),
		zap.Int("buffer_size", len(b.events)),
		zap.Int("max_size", b.maxSize))

	if len(b.events) >= b.maxSize || b.shouldFlush() {
		observability.Debug("Triggering flush",
			zap.String("module", "buffer"),
			zap.Int("len", len(b.events)),
			zap.Int("max_size", b.maxSize),
			zap.Bool("should_flush", b.shouldFlush()))
		b.flushLocked()
	}
}

func (b *EventBuffer) shouldFlush() bool {
	return time.Since(b.lastFlush) >= b.flushInterval && len(b.events) > 0
}

func (b *EventBuffer) Flush() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flushLocked()
}

func (b *EventBuffer) flushLocked() {
	if len(b.events) == 0 {
		return
	}

	events := make([]*types.Event, len(b.events))
	copy(events, b.events)
	b.events = b.events[:0]
	b.lastFlush = time.Now()

	observability.Debug("flushLocked: flushing events",
		zap.String("module", "buffer"),
		zap.Int("count", len(events)))

	if b.onFlush != nil {
		go b.onFlush(events)
	} else {
		observability.Warn("flushLocked: onFlush callback is nil, dropping events",
			zap.String("module", "buffer"),
			zap.Int("count", len(events)))
	}
}

func (b *EventBuffer) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.events)
}

func (b *EventBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = b.events[:0]
}
