package evtx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	evtxlib "github.com/0xrawsec/golang-evtx/evtx"
	"github.com/kkkdddd-start/winalog-go/internal/parsers"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

func init() {
	parsers.GetGlobalRegistry().Register(NewEvtxParser())
}

type EvtxParser struct{}

func NewEvtxParser() *EvtxParser {
	return &EvtxParser{}
}

func (p *EvtxParser) Priority() int {
	return 90
}

func (p *EvtxParser) CanParse(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".evtx"
}

func (p *EvtxParser) GetType() string {
	return "evtx"
}

func (p *EvtxParser) Parse(path string) <-chan *types.Event {
	return p.ParseWithError(path).Events
}

func (p *EvtxParser) ParseWithError(path string) parsers.ParseResult {
	events := make(chan *types.Event, 100)
	errChan := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errChan)

		evtxEvents, err := p.parseEvtxFile(path)
		if err != nil {
			errChan <- err
			return
		}

		for _, e := range evtxEvents {
			events <- e
		}
	}()

	return parsers.ParseResult{
		Events: events,
		ErrCh:  errChan,
	}
}

func (p *EvtxParser) ParseBatch(path string) ([]*types.Event, error) {
	return p.parseEvtxFile(path)
}

func (p *EvtxParser) parseEvtxFile(path string) ([]*types.Event, error) {
	evtxFile, err := evtxlib.Open(path)
	if err != nil {
		evtxFile, err = evtxlib.OpenDirty(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open EVTX file: %w", err)
		}
	}
	defer evtxFile.Close()

	fileInfo, err := os.Stat(path)
	estCount := 1000
	if err == nil && fileInfo.Size() > 0 {
		estCount = int(fileInfo.Size() / 512)
		if estCount < 1000 {
			estCount = 1000
		}
		if estCount > 100000 {
			estCount = 100000
		}
	}
	events := make([]*types.Event, 0, estCount)

	for eventMap := range evtxFile.FastEvents() {
		if eventMap == nil {
			continue
		}

		event := p.convertMapToEvent(eventMap)
		if event != nil {
			events = append(events, event)
		}
	}

	return events, nil
}

func (p *EvtxParser) convertMapToEvent(m *evtxlib.GoEvtxMap) *types.Event {
	if m == nil {
		return nil
	}

	event := &types.Event{
		Level:      types.EventLevelInfo,
		ImportTime: time.Now(),
	}

	event.EventID = int32(m.EventID())
	event.LogName = m.Channel()

	eventPath := evtxlib.Path("Event")
	elem, err := m.Get(&eventPath)
	if err == nil && elem != nil {
		if eventMap, ok := (*elem).(evtxlib.GoEvtxMap); ok {
			systemPath := evtxlib.Path("System")
			if sysElem, err := eventMap.Get(&systemPath); err == nil && sysElem != nil {
				if system, ok := (*sysElem).(evtxlib.GoEvtxMap); ok {
					computerPath := evtxlib.Path("Computer")
					event.Computer = system.GetStringStrict(&computerPath)
					levelPath := evtxlib.Path("Level")
					level := system.GetIntStrict(&levelPath)
					if level > 0 && level <= 5 {
						event.Level = types.EventLevelFromInt(int(level))
					}

					timePath := evtxlib.Path("TimeCreated/SystemTime")
					if t, err := system.GetTime(&timePath); err == nil {
						event.Timestamp = t
					}

					providerPath := evtxlib.Path("Provider")
					if provElem, err := system.Get(&providerPath); err == nil && provElem != nil {
						if provider, ok := (*provElem).(evtxlib.GoEvtxMap); ok {
							namePath := evtxlib.Path("Name")
							event.Source = provider.GetStringStrict(&namePath)
						}
					}
				}
			}

			edPath := evtxlib.Path("EventData")
			if edElem, err := eventMap.Get(&edPath); err == nil && edElem != nil {
				if ed, ok := (*edElem).(evtxlib.GoEvtxMap); ok {
					event.Message = p.extractEventData(&ed)
				}
			}
		}
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	return event
}

func (p *EvtxParser) extractEventData(m *evtxlib.GoEvtxMap) string {
	var parts []string
	for k, v := range *m {
		if v == nil {
			continue
		}
		switch val := v.(type) {
		case string:
			if val != "" {
				parts = append(parts, fmt.Sprintf("%s=%s", k, val))
			}
		case evtxlib.GoEvtxMap:
			if val != nil {
				parts = append(parts, p.extractEventData(&val))
			}
		default:
			parts = append(parts, fmt.Sprintf("%s=%v", k, val))
		}
	}
	return strings.Join(parts, "; ")
}
