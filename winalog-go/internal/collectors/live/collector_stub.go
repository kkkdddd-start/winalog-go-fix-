//go:build !windows

package live

import (
	"context"
	"time"
)

type stubCollector struct{}

func (s *stubCollector) Name() string                            { return "stub" }
func (s *stubCollector) Start(ctx context.Context) error            { return nil }
func (s *stubCollector) Stop()                                   {}
func (s *stubCollector) IsRunning() bool                           { return false }
func (s *stubCollector) ChannelName() string                       { return "" }

func NewEventCollector(channel, query string) EventCollector {
	return nil
}

type stubPollCollector struct{}

func (s *stubPollCollector) Start(ctx context.Context) error { return nil }
func (s *stubPollCollector) Stop()                            {}
func (s *stubPollCollector) IsRunning() bool                   { return false }
func (s *stubPollCollector) GetLastRecordID() uint64          { return 0 }
func (s *stubPollCollector) SetChannels(channels []ChannelConfig) {}

func NewEvtPollCollector(channels []ChannelConfig, buffer *EventBuffer, pollInterval time.Duration) *stubPollCollector {
	return &stubPollCollector{}
}

func ListAvailableChannels() ([]string, error) {
	return []string{
		"Security",
		"System",
		"Application",
		"Setup",
		"ForwardedEvents",
	}, nil
}
