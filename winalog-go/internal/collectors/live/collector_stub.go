//go:build !windows

package live

import "context"

type stubCollector struct{}

func (s *stubCollector) Name() string                                { return "stub" }
func (s *stubCollector) Start(ctx context.Context) error            { return nil }
func (s *stubCollector) Stop()                                       {}
func (s *stubCollector) IsRunning() bool                            { return false }
func (s *stubCollector) ChannelName() string                        { return "" }

func NewEventCollector(channel, query string) EventCollector {
	return nil
}
