//go:build windows

package live

func NewEventCollector(channel, query string) EventCollector {
	return NewEvtLiveCollector(channel, query)
}
