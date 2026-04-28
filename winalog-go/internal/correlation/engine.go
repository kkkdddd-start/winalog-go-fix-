package correlation

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/rules"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type Engine struct {
	mu      sync.RWMutex
	index   *EventIndex
	matcher *Matcher
	chain   *ChainBuilder
	maxAge  time.Duration
}

type indexEntry struct {
	ID        int64
	Timestamp time.Time
}

type EventIndex struct {
	mu              sync.RWMutex
	eventRepo       *storage.EventRepo
	eventsCache     map[int64]*types.Event
	byID            map[int64]time.Time
	byTime          []indexEntry
	byEID           map[int32][]int64
	maxAge          time.Duration
	lastCleanup     time.Time
	cleanupInterval time.Duration
}

func NewEventIndex(maxAge time.Duration) *EventIndex {
	return &EventIndex{
		eventsCache:     make(map[int64]*types.Event),
		byID:            make(map[int64]time.Time),
		byEID:           make(map[int32][]int64),
		maxAge:          maxAge,
		lastCleanup:     time.Now(),
		cleanupInterval: 5 * time.Minute,
	}
}

func (idx *EventIndex) SetEventRepo(eventRepo *storage.EventRepo) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.eventRepo = eventRepo
}

func (idx *EventIndex) Add(event *types.Event) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	if time.Since(idx.lastCleanup) > idx.cleanupInterval {
		idx.lastCleanup = time.Now()
		go idx.Cleanup()
	}

	idx.eventsCache[event.ID] = event
	idx.byID[event.ID] = event.Timestamp
	idx.byTime = append(idx.byTime, indexEntry{ID: event.ID, Timestamp: event.Timestamp})
	idx.byEID[event.EventID] = append(idx.byEID[event.EventID], event.ID)
}

func (idx *EventIndex) Cleanup() {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	if idx.maxAge <= 0 {
		return
	}

	cutoff := time.Now().Add(-idx.maxAge)
	if len(idx.byTime) == 0 || idx.byTime[0].Timestamp.After(cutoff) {
		return
	}

	splitIdx := 0
	for i, entry := range idx.byTime {
		if entry.Timestamp.After(cutoff) {
			break
		}
		splitIdx = i + 1
	}

	oldEntries := idx.byTime[:splitIdx]
	idx.byTime = idx.byTime[splitIdx:]

	for _, entry := range oldEntries {
		delete(idx.byID, entry.ID)
		delete(idx.eventsCache, entry.ID)
	}

	for eid, ids := range idx.byEID {
		newIDs := make([]int64, 0)
		for _, id := range ids {
			if _, exists := idx.byID[id]; exists {
				newIDs = append(newIDs, id)
			}
		}
		if len(newIDs) == 0 {
			delete(idx.byEID, eid)
		} else {
			idx.byEID[eid] = newIDs
		}
	}
}

func (idx *EventIndex) GetByID(id int64) (*types.Event, bool) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	_, ok := idx.byID[id]
	if !ok {
		return nil, false
	}

	if event, ok := idx.eventsCache[id]; ok {
		return event, true
	}

	if idx.eventRepo != nil {
		event, err := idx.eventRepo.GetByID(id)
		if err == nil {
			return event, true
		}
	}

	return nil, false
}

func (idx *EventIndex) GetByEventID(eid int32) []*types.Event {
	idx.mu.RLock()
	candidateIDs := idx.byEID[eid]
	idx.mu.RUnlock()

	if len(candidateIDs) == 0 {
		return nil
	}

	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if idx.eventRepo != nil {
		events, err := idx.eventRepo.GetByIDs(candidateIDs)
		if err == nil {
			return events
		}
	}

	var events []*types.Event
	for _, id := range candidateIDs {
		if event, ok := idx.eventsCache[id]; ok {
			events = append(events, event)
		}
	}
	return events
}

func (idx *EventIndex) GetByTimeRange(start, end time.Time) []*types.Event {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	var validIDs []int64
	for _, entry := range idx.byTime {
		if entry.Timestamp.After(start) && entry.Timestamp.Before(end) {
			validIDs = append(validIDs, entry.ID)
		}
	}

	if len(validIDs) == 0 {
		return nil
	}

	if idx.eventRepo != nil {
		events, err := idx.eventRepo.GetByIDs(validIDs)
		if err == nil {
			return events
		}
	}

	var events []*types.Event
	for _, id := range validIDs {
		if event, ok := idx.eventsCache[id]; ok {
			events = append(events, event)
		}
	}
	return events
}

func (idx *EventIndex) GetAllEvents() []*types.Event {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	events := make([]*types.Event, 0, len(idx.eventsCache))
	for _, event := range idx.eventsCache {
		events = append(events, event)
	}
	return events
}

func NewEngine(maxAge time.Duration) *Engine {
	return &Engine{
		index:   NewEventIndex(maxAge),
		matcher: NewMatcher(),
		chain:   NewChainBuilder(),
		maxAge:  maxAge,
	}
}

func NewEngineWithEventRepo(eventRepo *storage.EventRepo, maxAge time.Duration) *Engine {
	return &Engine{
		index:   NewEventIndex(maxAge),
		matcher: NewMatcher(),
		chain:   NewChainBuilderWithEventRepo(eventRepo),
		maxAge:  maxAge,
	}
}

func (e *Engine) SetEventRepo(eventRepo *storage.EventRepo) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.chain.SetEventRepo(eventRepo)
	e.index.SetEventRepo(eventRepo)
}

func (e *Engine) LoadEvents(events []*types.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, event := range events {
		e.index.Add(event)
	}
}

func (e *Engine) Analyze(ctx context.Context, rules []*rules.CorrelationRule) ([]*types.CorrelationResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	results := make([]*types.CorrelationResult, 0)

	for _, rule := range rules {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		if !rule.Enabled {
			continue
		}

		ruleResults := e.analyzeRule(rule)
		results = append(results, ruleResults...)
	}

	return results, nil
}

func (e *Engine) analyzeRule(rule *rules.CorrelationRule) []*types.CorrelationResult {
	allResults := make([]*types.CorrelationResult, 0)
	patterns := rule.Patterns
	if len(patterns) < 2 {
		return allResults
	}

	seenChains := make(map[string]bool)

	initialEvents := e.index.GetByEventID(patterns[0].EventID)
	if initialEvents == nil {
		return allResults
	}

	initialEvents = e.matcher.FilterByPattern(initialEvents, patterns[0])
	if len(initialEvents) == 0 {
		return allResults
	}

	if patterns[0].TimeWindow > 0 {
		initialEvents = e.filterByTimeWindow(initialEvents, patterns[0].TimeWindow)
	}

	for _, startEvent := range initialEvents {
		e.findFullChain(startEvent, nil, patterns, 0, rule, seenChains, &allResults)
	}

	return allResults
}

func (e *Engine) findFullChain(baseEvent *types.Event, chainEvents []*types.Event, patterns []*rules.Pattern, patternIndex int, rule *rules.CorrelationRule, seenChains map[string]bool, results *[]*types.CorrelationResult) {
	if chainEvents == nil {
		chainEvents = []*types.Event{baseEvent}
	} else {
		chainEvents = append(chainEvents, baseEvent)
	}

	if patternIndex == len(patterns)-1 {
		chainKey := e.chainKey(chainEvents)
		if seenChains[chainKey] {
			return
		}
		seenChains[chainKey] = true

		chainEventsCopy := make([]*types.Event, len(chainEvents))
		copy(chainEventsCopy, chainEvents)
		result := e.chain.Build(baseEvent, chainEventsCopy[1:], rule)
		if result != nil {
			*results = append(*results, result)
		}
		return
	}

	nextPattern := patterns[patternIndex+1]
	nextEvents := e.findRelatedEventsWithRule(baseEvent, nextPattern, rule)
	if len(nextEvents) == 0 {
		return
	}

	nextEvents = e.matcher.FilterByPattern(nextEvents, nextPattern)
	if len(nextEvents) == 0 {
		return
	}

	timeWindow := nextPattern.TimeWindow
	if timeWindow <= 0 {
		timeWindow = rule.TimeWindow
	}
	if timeWindow > 0 {
		nextEvents = e.filterByTimeWindowWithBase(baseEvent.Timestamp, nextEvents, timeWindow)
	}

	for _, nextEvent := range nextEvents {
		if !e.matcher.CheckOrderedSequence(chainEvents, nextPattern) {
			continue
		}
		e.findFullChain(nextEvent, chainEvents, patterns, patternIndex+1, rule, seenChains, results)
	}
}

func (e *Engine) chainKey(events []*types.Event) string {
	key := ""
	for _, evt := range events {
		key += fmt.Sprintf("%d:", evt.ID)
	}
	return key
}

func (e *Engine) filterByTimeWindowWithBase(baseTime time.Time, events []*types.Event, window time.Duration) []*types.Event {
	if len(events) == 0 || window <= 0 {
		return events
	}

	cutoff := baseTime.Add(window)
	filtered := make([]*types.Event, 0)

	for _, event := range events {
		if event.Timestamp.After(baseTime) && event.Timestamp.Before(cutoff) {
			filtered = append(filtered, event)
		}
	}

	return filtered
}

func (e *Engine) filterByTimeWindow(events []*types.Event, window time.Duration) []*types.Event {
	if len(events) == 0 || window <= 0 {
		return events
	}

	baseTime := events[0].Timestamp
	for _, event := range events {
		if event.Timestamp.Before(baseTime) {
			baseTime = event.Timestamp
		}
	}
	cutoff := baseTime.Add(window)
	filtered := make([]*types.Event, 0)

	for _, event := range events {
		if event.Timestamp.After(baseTime) && event.Timestamp.Before(cutoff) {
			filtered = append(filtered, event)
		}
	}

	return filtered
}

func (e *Engine) findRelatedEventsWithRule(base *types.Event, pattern *rules.Pattern, rule *rules.CorrelationRule) []*types.Event {
	join := pattern.Join
	if join == "" {
		join = rule.Join
	}

	events := e.index.GetByEventID(pattern.EventID)
	if events == nil {
		return nil
	}

	switch join {
	case "user":
		filtered := make([]*types.Event, 0)
		for _, evt := range events {
			if !evt.Timestamp.After(base.Timestamp) {
				continue
			}
			userMatch := false
			if evt.User != nil && base.User != nil {
				userMatch = *evt.User == *base.User
			} else if evt.UserSID != nil && base.UserSID != nil {
				userMatch = *evt.UserSID == *base.UserSID
			}
			if userMatch {
				filtered = append(filtered, evt)
			}
		}
		return filtered

	case "computer":
		filtered := make([]*types.Event, 0)
		for _, evt := range events {
			if !evt.Timestamp.After(base.Timestamp) {
				continue
			}
			if evt.Computer == base.Computer {
				filtered = append(filtered, evt)
			}
		}
		return filtered

	case "ip":
		filtered := make([]*types.Event, 0)
		for _, evt := range events {
			if !evt.Timestamp.After(base.Timestamp) {
				continue
			}
			if evt.IPAddress != nil && base.IPAddress != nil && *evt.IPAddress == *base.IPAddress {
				filtered = append(filtered, evt)
			}
		}
		return filtered

	default:
		filtered := make([]*types.Event, 0)
		for _, evt := range events {
			if evt.Timestamp.After(base.Timestamp) {
				filtered = append(filtered, evt)
			}
		}
		return filtered
	}
}

func (e *Engine) FindChains(ctx context.Context, startEventID int64, maxDepth int) ([]*types.CorrelationResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	startEvent, ok := e.index.GetByID(startEventID)
	if !ok {
		return nil, nil
	}

	return e.chain.FindChains(startEvent, maxDepth)
}

func (e *Engine) GetEvents() []*types.Event {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.index.GetAllEvents()
}

func (e *Engine) Clear() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.index = NewEventIndex(e.maxAge)
}

// findRelatedEvents 是 findRelatedEventsWithRule 的简化版本，用于测试和简单场景
func (e *Engine) findRelatedEvents(base *types.Event, pattern *rules.Pattern) []*types.Event {
	// 创建一个默认规则，确保 rule 不为 nil
	rule := &rules.CorrelationRule{
		Join: "", // 空字符串，确保 findRelatedEventsWithRule 中的 rule.Join 不会 panic
	}
	return e.findRelatedEventsWithRule(base, pattern, rule)
}
