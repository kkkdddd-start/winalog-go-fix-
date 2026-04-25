package live

import (
	"context"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type EventCollector interface {
	Name() string
	Start(ctx context.Context) error
	Stop()
	Events() <-chan *types.Event
	IsRunning() bool
	ChannelName() string
}
