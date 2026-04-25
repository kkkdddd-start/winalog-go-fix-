package correlation

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kkkdddd-start/winalog-go/internal/rules"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type ChainConfig struct {
	StartEventIDs map[int32]bool
	Transitions   map[int32][]int32
	TimeWindow    time.Duration
}

var DefaultChainConfig = &ChainConfig{
	StartEventIDs: map[int32]bool{
		4624: true,
		4625: true,
		4634: true,
		4648: true,
		4672: true,
		4688: true,
		4698: true,
		4697: true,
	},
	Transitions: map[int32][]int32{
		4624: {4634, 4672, 4688},
		4625: {4624},
		4648: {4624, 4672},
		4688: {4698, 4697},
	},
	TimeWindow: 1 * time.Hour,
}

type ChainBuilder struct {
	eventRepo *storage.EventRepo
	config    *ChainConfig
}

func NewChainBuilder() *ChainBuilder {
	return &ChainBuilder{config: DefaultChainConfig}
}

func NewChainBuilderWithConfig(cfg *ChainConfig) *ChainBuilder {
	return &ChainBuilder{config: cfg}
}

func NewChainBuilderWithEventRepo(eventRepo *storage.EventRepo) *ChainBuilder {
	return &ChainBuilder{
		eventRepo: eventRepo,
		config:    DefaultChainConfig,
	}
}

func (cb *ChainBuilder) SetEventRepo(eventRepo *storage.EventRepo) {
	cb.eventRepo = eventRepo
}

func (cb *ChainBuilder) Build(startEvent *types.Event, relatedEvents []*types.Event, rule *rules.CorrelationRule) *types.CorrelationResult {
	result := &types.CorrelationResult{
		ID:          generateResultID(),
		RuleName:    rule.Name,
		Description: rule.Description,
		Severity:    types.Severity(rule.Severity),
		Events:      []*types.Event{startEvent},
		StartTime:   startEvent.Timestamp,
		EndTime:     startEvent.Timestamp,
	}

	for _, evt := range relatedEvents {
		result.Events = append(result.Events, evt)
		if evt.Timestamp.After(result.EndTime) {
			result.EndTime = evt.Timestamp
		}
	}

	return result
}

func (cb *ChainBuilder) FindChains(startEvent *types.Event, maxDepth int) ([]*types.CorrelationResult, error) {
	chains := make([]*types.CorrelationResult, 0)

	if !cb.config.StartEventIDs[startEvent.EventID] {
		return chains, nil
	}

	depth := 0
	currentEvents := []*types.Event{startEvent}

	for depth < maxDepth {
		nextEvents, err := cb.findNextEvents(currentEvents)
		if err != nil {
			return chains, err
		}
		if len(nextEvents) == 0 {
			break
		}

		for _, nextEvent := range nextEvents {
			chain := &types.CorrelationResult{
				ID:        generateResultID(),
				StartTime: startEvent.Timestamp,
				EndTime:   nextEvent.Timestamp,
				Events:    append([]*types.Event{startEvent}, nextEvent),
				Severity:  types.SeverityHigh,
			}
			chains = append(chains, chain)
		}

		currentEvents = nextEvents
		depth++
	}

	return chains, nil
}

func (cb *ChainBuilder) findNextEvents(events []*types.Event) ([]*types.Event, error) {
	if len(events) == 0 {
		return nil, nil
	}

	if cb.eventRepo == nil {
		return cb.findNextEventsFallback(events)
	}

	nextEventIDs := make(map[int32]bool)
	for _, event := range events {
		if nextIDs, ok := cb.config.Transitions[event.EventID]; ok {
			for _, nextID := range nextIDs {
				nextEventIDs[nextID] = true
			}
		}
	}
	if len(nextEventIDs) == 0 {
		return nil, nil
	}

	maxTime := events[0].Timestamp
	for _, e := range events {
		if e.Timestamp.After(maxTime) {
			maxTime = e.Timestamp
		}
	}

	ids := make([]int32, 0, len(nextEventIDs))
	for id := range nextEventIDs {
		ids = append(ids, id)
	}

	endTime := maxTime.Add(cb.config.TimeWindow)
	req := &types.SearchRequest{
		EventIDs:  ids,
		StartTime: &maxTime,
		EndTime:   &endTime,
		PageSize:  1000,
	}
	results, _, err := cb.eventRepo.Search(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query subsequent events: %w", err)
	}
	return results, nil
}

func (cb *ChainBuilder) findNextEventsFallback(events []*types.Event) ([]*types.Event, error) {
	return []*types.Event{}, nil
}

func (cb *ChainBuilder) BuildFromRule(rule *rules.CorrelationRule, events []*types.Event) *types.CorrelationResult {
	if len(events) == 0 {
		return nil
	}

	result := &types.CorrelationResult{
		ID:          generateResultID(),
		RuleName:    rule.Name,
		Description: rule.Description,
		Severity:    types.Severity(rule.Severity),
		Events:      events,
		StartTime:   events[0].Timestamp,
		EndTime:     events[0].Timestamp,
	}

	for _, event := range events {
		if event.Timestamp.After(result.EndTime) {
			result.EndTime = event.Timestamp
		}
	}

	return result
}

func generateResultID() string {
	return uuid.New().String()
}
