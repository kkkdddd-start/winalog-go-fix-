package correlation

import (
	"context"
	"testing"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/rules"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

func TestNewEngine(t *testing.T) {
	engine := NewEngine(0)
	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}

	if engine.index == nil {
		t.Error("Engine.index is nil")
	}
	if engine.matcher == nil {
		t.Error("Engine.matcher is nil")
	}
	if engine.chain == nil {
		t.Error("Engine.chain is nil")
	}
}

func TestNewEventIndex(t *testing.T) {
	idx := NewEventIndex(0)
	if idx == nil {
		t.Fatal("NewEventIndex returned nil")
	}

	if idx.byID == nil {
		t.Error("EventIndex.byID is nil")
	}
	if idx.byEID == nil {
		t.Error("EventIndex.byEID is nil")
	}
}

func TestEventIndexAdd(t *testing.T) {
	idx := NewEventIndex(0)

	event := &types.Event{
		ID:        1,
		EventID:   4624,
		Timestamp: time.Now(),
	}

	idx.Add(event)

	if len(idx.byID) != 1 {
		t.Errorf("len(byID) = %d, want 1", len(idx.byID))
	}
	if len(idx.byEID[4624]) != 1 {
		t.Errorf("len(byEID[4624]) = %d, want 1", len(idx.byEID[4624]))
	}
}

func TestEventIndexGetByID(t *testing.T) {
	idx := NewEventIndex(0)

	event := &types.Event{
		ID:        1,
		EventID:   4624,
		Timestamp: time.Now(),
	}

	idx.Add(event)

	found, ok := idx.GetByID(1)
	if !ok {
		t.Error("GetByID returned false, want true")
	}
	if found.ID != 1 {
		t.Errorf("found.ID = %d, want 1", found.ID)
	}

	_, ok = idx.GetByID(999)
	if ok {
		t.Error("GetByID returned true for non-existent ID")
	}
}

func TestEventIndexGetByEventID(t *testing.T) {
	idx := NewEventIndex(0)

	for i := int64(1); i <= 3; i++ {
		idx.Add(&types.Event{
			ID:        i,
			EventID:   4624,
			Timestamp: time.Now(),
		})
	}

	events := idx.GetByEventID(4624)
	if len(events) != 3 {
		t.Errorf("len(events) = %d, want 3", len(events))
	}

	events = idx.GetByEventID(9999)
	if events != nil {
		t.Error("GetByEventID should return nil for non-existent event ID")
	}
}

func TestEventIndexGetByTimeRange(t *testing.T) {
	idx := NewEventIndex(0)

	now := time.Now()
	idx.Add(&types.Event{
		ID:        1,
		EventID:   4624,
		Timestamp: now,
	})
	idx.Add(&types.Event{
		ID:        2,
		EventID:   4625,
		Timestamp: now.Add(-time.Hour),
	})
	idx.Add(&types.Event{
		ID:        3,
		EventID:   4626,
		Timestamp: now.Add(-2 * time.Hour),
	})

	start := now.Add(-30 * time.Minute)
	end := now.Add(30 * time.Minute)
	events := idx.GetByTimeRange(start, end)

	if len(events) != 1 {
		t.Errorf("len(events) = %d, want 1", len(events))
	}
}

func TestEngineLoadEvents(t *testing.T) {
	engine := NewEngine(0)

	events := []*types.Event{
		{ID: 1, EventID: 4624, Timestamp: time.Now()},
		{ID: 2, EventID: 4625, Timestamp: time.Now()},
	}

	engine.LoadEvents(events)

	retrieved := engine.GetEvents()
	if len(retrieved) != 2 {
		t.Errorf("len(GetEvents()) = %d, want 2", len(retrieved))
	}
}

func TestEngineAnalyzeNoRules(t *testing.T) {
	engine := NewEngine(0)

	ctx := context.Background()
	results, err := engine.Analyze(ctx, nil)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("len(results) = %d, want 0", len(results))
	}
}

func TestEngineAnalyzeDisabledRule(t *testing.T) {
	engine := NewEngine(0)

	events := []*types.Event{
		{ID: 1, EventID: 4624, Timestamp: time.Now()},
		{ID: 2, EventID: 4625, Timestamp: time.Now()},
	}
	engine.LoadEvents(events)

	rule := &rules.CorrelationRule{
		Name:     "Disabled Rule",
		Enabled:  false,
		Patterns: []*rules.Pattern{{EventID: 4624}, {EventID: 4625}},
	}

	ctx := context.Background()
	results, err := engine.Analyze(ctx, []*rules.CorrelationRule{rule})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("len(results) = %d, want 0", len(results))
	}
}

func TestEngineAnalyzeWithMatchingRule(t *testing.T) {
	engine := NewEngine(0)

	events := []*types.Event{
		{ID: 1, EventID: 4624, Timestamp: time.Now(), Computer: "WORKSTATION1"},
		{ID: 2, EventID: 4625, Timestamp: time.Now(), Computer: "WORKSTATION1"},
	}
	engine.LoadEvents(events)

	rule := &rules.CorrelationRule{
		Name:       "Login Correlation",
		Enabled:    true,
		Patterns:   []*rules.Pattern{{EventID: 4624}, {EventID: 4625}},
		TimeWindow: 15 * time.Minute,
	}

	ctx := context.Background()
	results, err := engine.Analyze(ctx, []*rules.CorrelationRule{rule})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(results) == 0 {
		t.Error("Analyze returned no results, want at least 1")
	}
}

func TestEngineAnalyzeWithSinglePattern(t *testing.T) {
	engine := NewEngine(0)

	events := []*types.Event{
		{ID: 1, EventID: 4624, Timestamp: time.Now()},
	}
	engine.LoadEvents(events)

	rule := &rules.CorrelationRule{
		Name:     "Single Pattern Rule",
		Enabled:  true,
		Patterns: []*rules.Pattern{{EventID: 4624}},
	}

	ctx := context.Background()
	results, err := engine.Analyze(ctx, []*rules.CorrelationRule{rule})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("len(results) = %d, want 0", len(results))
	}
}

func TestEngineFindChains(t *testing.T) {
	engine := NewEngine(0)

	events := []*types.Event{
		{ID: 1, EventID: 4624, Timestamp: time.Now()},
	}
	engine.LoadEvents(events)

	ctx := context.Background()
	chains, err := engine.FindChains(ctx, 1, 5)
	if err != nil {
		t.Fatalf("FindChains returned unexpected error: %v", err)
	}

	if chains == nil {
		t.Error("FindChains returned nil")
	}
}

func TestEngineFindChainsNonExistent(t *testing.T) {
	engine := NewEngine(0)

	ctx := context.Background()
	chains, err := engine.FindChains(ctx, 999, 5)
	if err != nil {
		t.Fatalf("FindChains failed: %v", err)
	}

	if chains != nil {
		t.Error("FindChains should return nil for non-existent event")
	}
}

func TestEngineGetEvents(t *testing.T) {
	engine := NewEngine(0)

	events := []*types.Event{
		{ID: 1, EventID: 4624, Timestamp: time.Now()},
		{ID: 2, EventID: 4625, Timestamp: time.Now()},
	}
	engine.LoadEvents(events)

	retrieved := engine.GetEvents()
	if len(retrieved) != 2 {
		t.Errorf("len(GetEvents()) = %d, want 2", len(retrieved))
	}
}

func TestEngineClear(t *testing.T) {
	engine := NewEngine(0)

	events := []*types.Event{
		{ID: 1, EventID: 4624, Timestamp: time.Now()},
	}
	engine.LoadEvents(events)

	engine.Clear()

	retrieved := engine.GetEvents()
	if len(retrieved) != 0 {
		t.Errorf("len(GetEvents()) after Clear = %d, want 0", len(retrieved))
	}
}

func TestEngineFindRelatedEventsByUser(t *testing.T) {
	engine := NewEngine(0)

	user1 := "user1"
	user2 := "user2"

	events := []*types.Event{
		{ID: 1, EventID: 4624, User: &user1, Computer: "WORKSTATION1", Timestamp: time.Now()},
		{ID: 2, EventID: 4625, User: &user1, Computer: "WORKSTATION1", Timestamp: time.Now()},
		{ID: 3, EventID: 4624, User: &user2, Computer: "WORKSTATION1", Timestamp: time.Now()},
	}
	engine.LoadEvents(events)

	baseEvent := events[0]
	pattern := &rules.Pattern{
		EventID: 4625,
		Join:    "user",
	}

	related := engine.findRelatedEvents(baseEvent, pattern)
	if len(related) != 1 {
		t.Errorf("len(related) = %d, want 1", len(related))
	}
}

func TestEngineFindRelatedEventsByComputer(t *testing.T) {
	engine := NewEngine(0)

	events := []*types.Event{
		{ID: 1, EventID: 4624, Computer: "WORKSTATION1", Timestamp: time.Now()},
		{ID: 2, EventID: 4625, Computer: "WORKSTATION1", Timestamp: time.Now()},
		{ID: 3, EventID: 4625, Computer: "WORKSTATION2", Timestamp: time.Now()},
	}
	engine.LoadEvents(events)

	baseEvent := events[0]
	pattern := &rules.Pattern{
		EventID: 4625,
		Join:    "computer",
	}

	related := engine.findRelatedEvents(baseEvent, pattern)
	if len(related) != 1 {
		t.Errorf("len(related) = %d, want 1", len(related))
	}
}

func TestEngineFindRelatedEventsByIP(t *testing.T) {
	engine := NewEngine(0)

	ip1 := "192.168.1.100"
	ip2 := "192.168.1.101"

	events := []*types.Event{
		{ID: 1, EventID: 4624, IPAddress: &ip1, Timestamp: time.Now()},
		{ID: 2, EventID: 4625, IPAddress: &ip1, Timestamp: time.Now()},
		{ID: 3, EventID: 4625, IPAddress: &ip2, Timestamp: time.Now()},
	}
	engine.LoadEvents(events)

	baseEvent := events[0]
	pattern := &rules.Pattern{
		EventID: 4625,
		Join:    "ip",
	}

	related := engine.findRelatedEvents(baseEvent, pattern)
	if len(related) != 1 {
		t.Errorf("len(related) = %d, want 1", len(related))
	}
}

func TestEngineFindRelatedEventsDefault(t *testing.T) {
	engine := NewEngine(0)

	events := []*types.Event{
		{ID: 1, EventID: 4624, Computer: "WORKSTATION1", Timestamp: time.Now()},
		{ID: 2, EventID: 4625, Computer: "WORKSTATION1", Timestamp: time.Now()},
	}
	engine.LoadEvents(events)

	baseEvent := events[0]
	pattern := &rules.Pattern{
		EventID: 4625,
		Join:    "",
	}

	related := engine.findRelatedEvents(baseEvent, pattern)
	if len(related) != 1 {
		t.Errorf("len(related) = %d, want 1", len(related))
	}
}
