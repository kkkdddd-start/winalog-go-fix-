package alerts

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/rules"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

func setupTestDB(t *testing.T) (*storage.DB, func()) {
	tmpFile, err := os.CreateTemp("", "test_alerts_db_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()

	db, err := storage.NewDB(tmpFile.Name())
	if err != nil {
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to create DB: %v", err)
	}

	cleanup := func() {
		db.Close()
		os.Remove(tmpFile.Name())
	}

	return db, cleanup
}

func TestNewEngine(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	cfg := EngineConfig{
		DedupWindow: 5 * time.Minute,
		StatsWindow: 24 * time.Hour,
	}

	engine := NewEngine(db, cfg)
	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}

	if engine.db != db {
		t.Error("Engine.db not set correctly")
	}
	if engine.dedup == nil {
		t.Error("Engine.dedup not initialized")
	}
	if engine.evaluator == nil {
		t.Error("Engine.evaluator not initialized")
	}
}

func TestNewEngineDefaultConfig(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	engine := NewEngine(db, EngineConfig{})
	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}
}

func TestEngineLoadRules(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	engine := NewEngine(db, EngineConfig{})

	rule := &rules.AlertRule{
		Name:     "Test Rule",
		Enabled:  true,
		Severity: types.SeverityHigh,
	}

	engine.LoadRules([]*rules.AlertRule{rule})

	rules := engine.GetRules()
	if len(rules) != 1 {
		t.Errorf("GetRules returned %d rules, want 1", len(rules))
	}
}

func TestEngineLoadRulesDisabled(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	engine := NewEngine(db, EngineConfig{})

	rule := &rules.AlertRule{
		Name:    "Disabled Rule",
		Enabled: false,
	}

	engine.LoadRules([]*rules.AlertRule{rule})

	rules := engine.GetRules()
	if len(rules) != 0 {
		t.Errorf("GetRules returned %d rules, want 0", len(rules))
	}
}

func TestEngineAddRule(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	engine := NewEngine(db, EngineConfig{})

	rule := &rules.AlertRule{
		Name:     "Added Rule",
		Enabled:  true,
		Severity: types.SeverityMedium,
	}

	engine.AddRule(rule)

	rules := engine.GetRules()
	if len(rules) != 1 {
		t.Errorf("GetRules returned %d rules, want 1", len(rules))
	}
}

func TestEngineRemoveRule(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	engine := NewEngine(db, EngineConfig{})

	rule := &rules.AlertRule{
		Name:     "To Be Removed",
		Enabled:  true,
		Severity: types.SeverityLow,
	}

	engine.AddRule(rule)
	engine.RemoveRule("To Be Removed")

	rules := engine.GetRules()
	if len(rules) != 0 {
		t.Errorf("GetRules returned %d rules, want 0", len(rules))
	}
}

func TestEngineEvaluateNoRules(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	engine := NewEngine(db, EngineConfig{})

	event := &types.Event{
		EventID: 4624,
		Level:   types.EventLevelInfo,
		Source:  "Security",
		LogName: "Security",
	}

	ctx := context.Background()
	alerts, err := engine.Evaluate(ctx, event)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if len(alerts) != 0 {
		t.Errorf("Evaluate returned %d alerts, want 0", len(alerts))
	}
}

func TestEngineEvaluateWithMatchingRule(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	engine := NewEngine(db, EngineConfig{})

	rule := &rules.AlertRule{
		Name:     "Login Rule",
		Enabled:  true,
		Severity: types.SeverityHigh,
		Filter: &rules.Filter{
			EventIDs: []int32{4624},
		},
		Message: "User login detected",
	}

	engine.LoadRules([]*rules.AlertRule{rule})

	event := &types.Event{
		EventID:  4624,
		Level:    types.EventLevelInfo,
		Source:   "Security",
		LogName:  "Security",
		Computer: "WORKSTATION1",
		Message:  "An account was successfully logged on",
	}

	ctx := context.Background()
	alerts, err := engine.Evaluate(ctx, event)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if len(alerts) != 1 {
		t.Errorf("Evaluate returned %d alerts, want 1", len(alerts))
	}

	if alerts[0].RuleName != "Login Rule" {
		t.Errorf("Alert RuleName = %s, want Login Rule", alerts[0].RuleName)
	}
}

func TestEngineEvaluateWithNonMatchingRule(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	engine := NewEngine(db, EngineConfig{})

	rule := &rules.AlertRule{
		Name:     "Specific Event Rule",
		Enabled:  true,
		Severity: types.SeverityHigh,
		Filter: &rules.Filter{
			EventIDs: []int32{9999},
		},
	}

	engine.LoadRules([]*rules.AlertRule{rule})

	event := &types.Event{
		EventID: 4624,
		Level:   types.EventLevelInfo,
		Source:  "Security",
		LogName: "Security",
	}

	ctx := context.Background()
	alerts, err := engine.Evaluate(ctx, event)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if len(alerts) != 0 {
		t.Errorf("Evaluate returned %d alerts, want 0", len(alerts))
	}
}

func TestDedupCacheIsDuplicate(t *testing.T) {
	cache := NewDedupCache(5 * time.Minute)

	event := &types.Event{
		EventID:  4624,
		Computer: "WORKSTATION1",
		Source:   "Security",
	}

	if cache.IsDuplicate("TestRule", event) {
		t.Error("IsDuplicate returned true for new event")
	}

	cache.Mark("TestRule", event)

	if !cache.IsDuplicate("TestRule", event) {
		t.Error("IsDuplicate returned false after Mark")
	}
}

func TestDedupCacheGetCount(t *testing.T) {
	cache := NewDedupCache(5 * time.Minute)

	event := &types.Event{
		EventID:  4624,
		Computer: "WORKSTATION1",
		Source:   "Security",
	}

	count := cache.GetCount("TestRule", event)
	if count != 0 {
		t.Errorf("GetCount = %d, want 0", count)
	}

	cache.Mark("TestRule", event)
	cache.Mark("TestRule", event)

	count = cache.GetCount("TestRule", event)
	if count != 2 {
		t.Errorf("GetCount = %d, want 2", count)
	}
}

func TestDedupCacheClear(t *testing.T) {
	cache := NewDedupCache(5 * time.Minute)

	event := &types.Event{
		EventID:  4624,
		Computer: "WORKSTATION1",
		Source:   "Security",
	}

	cache.Mark("TestRule", event)
	cache.Clear()

	count := cache.GetCount("TestRule", event)
	if count != 0 {
		t.Errorf("GetCount after Clear = %d, want 0", count)
	}
}

func TestDedupCacheSize(t *testing.T) {
	cache := NewDedupCache(5 * time.Minute)

	if cache.Size() != 0 {
		t.Errorf("Size = %d, want 0", cache.Size())
	}

	event1 := &types.Event{
		EventID:  4624,
		Computer: "WORKSTATION1",
		Source:   "Security",
	}

	event2 := &types.Event{
		EventID:  4625,
		Computer: "WORKSTATION1",
		Source:   "Security",
	}

	cache.Mark("Rule1", event1)
	cache.Mark("Rule2", event2)

	if cache.Size() != 2 {
		t.Errorf("Size = %d, want 2", cache.Size())
	}
}

func TestNewEvaluator(t *testing.T) {
	eval := NewEvaluator()
	if eval == nil {
		t.Fatal("NewEvaluator returned nil")
	}
}

func TestEvaluatorEvaluateNilFilter(t *testing.T) {
	eval := NewEvaluator()

	rule := &rules.AlertRule{
		Filter: nil,
	}

	event := &types.Event{
		EventID: 4624,
		Level:   types.EventLevelInfo,
	}

	matched, err := eval.Evaluate(rule, event)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if !matched {
		t.Error("Evaluate returned false for nil filter")
	}
}

func TestEvaluatorMatchFilterEventID(t *testing.T) {
	eval := NewEvaluator()

	rule := &rules.AlertRule{
		Filter: &rules.Filter{
			EventIDs: []int32{4624, 4625},
		},
	}

	event := &types.Event{EventID: 4624}
	if !eval.matchFilter(rule.Filter, event) {
		t.Error("matchFilter returned false for matching EventID")
	}

	event2 := &types.Event{EventID: 9999}
	if eval.matchFilter(rule.Filter, event2) {
		t.Error("matchFilter returned true for non-matching EventID")
	}
}

func TestEvaluatorMatchFilterLogName(t *testing.T) {
	eval := NewEvaluator()

	rule := &rules.AlertRule{
		Filter: &rules.Filter{
			LogNames: []string{"Security", "System"},
		},
	}

	event := &types.Event{LogName: "Security"}
	if !eval.matchFilter(rule.Filter, event) {
		t.Error("matchFilter returned false for matching LogName")
	}

	event2 := &types.Event{LogName: "Application"}
	if eval.matchFilter(rule.Filter, event2) {
		t.Error("matchFilter returned true for non-matching LogName")
	}
}

func TestEvaluatorMatchKeywords(t *testing.T) {
	eval := NewEvaluator()

	event := &types.Event{
		Message: "User login failed from IP 192.168.1.100",
	}

	words := "login,failed"
	mode := rules.OpAnd

	if !eval.matchKeywords(words, event, mode) {
		t.Error("matchKeywords returned false for matching keywords")
	}
}

func TestEvaluatorCompareInt(t *testing.T) {
	eval := NewEvaluator()

	tests := []struct {
		op     string
		a      int
		b      int
		expect bool
	}{
		{"==", 5, 5, true},
		{"==", 5, 6, false},
		{"!=", 5, 6, true},
		{"!=", 5, 5, false},
		{">", 6, 5, true},
		{">", 5, 6, false},
		{">=", 5, 5, true},
		{">=", 6, 5, true},
		{"<", 5, 6, true},
		{"<", 6, 5, false},
		{"<=", 5, 5, true},
	}

	for _, tt := range tests {
		result := eval.compareInt(tt.a, tt.op, tt.b)
		if result != tt.expect {
			t.Errorf("compareInt(%d, %s, %d) = %v, want %v", tt.a, tt.op, tt.b, result, tt.expect)
		}
	}
}

func TestEvaluatorCompareString(t *testing.T) {
	eval := NewEvaluator()

	if !eval.compareString("Hello World", "contains", "World", false) {
		t.Error("compareString contains failed")
	}

	if eval.compareString("Hello World", "not", "World", false) {
		t.Error("compareString not failed")
	}

	if !eval.compareString("Hello World", "startswith", "Hello", false) {
		t.Error("compareString startswith failed")
	}

	if !eval.compareString("Hello World", "endswith", "World", false) {
		t.Error("compareString endswith failed")
	}
}

func TestNewAlertStats(t *testing.T) {
	stats := NewAlertStats()
	if stats == nil {
		t.Fatal("NewAlertStats returned nil")
	}

	if stats.TotalCount != 0 {
		t.Errorf("TotalCount = %d, want 0", stats.TotalCount)
	}

	if stats.BySeverity == nil {
		t.Error("BySeverity is nil")
	}
}

func TestAlertStatsRecord(t *testing.T) {
	stats := NewAlertStats()

	alert := &types.Alert{
		Severity: types.SeverityHigh,
		RuleName: "Test Rule",
		Resolved: false,
	}

	stats.Record(alert)

	if stats.TotalCount != 1 {
		t.Errorf("TotalCount = %d, want 1", stats.TotalCount)
	}

	if stats.BySeverity["high"] != 1 {
		t.Errorf("BySeverity[high] = %d, want 1", stats.BySeverity["high"])
	}
}

func TestAlertStatsGetTopRules(t *testing.T) {
	stats := NewAlertStats()

	stats.ByRule["Rule1"] = 100
	stats.ByRule["Rule2"] = 50
	stats.ByRule["Rule3"] = 75

	top := stats.GetTopRules(2)
	if len(top) != 2 {
		t.Errorf("GetTopRules(2) returned %d rules, want 2", len(top))
	}

	if top[0].RuleName != "Rule1" {
		t.Errorf("top[0].RuleName = %s, want Rule1", top[0].RuleName)
	}
}

func TestAlertStatsReset(t *testing.T) {
	stats := NewAlertStats()

	stats.TotalCount = 100
	stats.BySeverity["high"] = 50

	stats.Reset()

	if stats.TotalCount != 0 {
		t.Errorf("TotalCount after Reset = %d, want 0", stats.TotalCount)
	}
}

func TestAlertStatsCopyFrom(t *testing.T) {
	stats := NewAlertStats()

	data := &types.AlertStatsData{
		TotalCount: 100,
		BySeverity: map[string]int64{"high": 50, "medium": 50},
		ByStatus:   map[string]int64{"active": 100},
	}

	stats.CopyFrom(data)

	if stats.TotalCount != 100 {
		t.Errorf("TotalCount = %d, want 100", stats.TotalCount)
	}
}

func TestAlertUpgradeCache(t *testing.T) {
	cache := NewAlertUpgradeCache()

	rule := &types.AlertUpgradeRule{
		ID:          1,
		Name:        "Test Rule",
		Condition:   "count > 10",
		Threshold:   10,
		NewSeverity: "",
	}

	cache.Add(rule)

	alert := &types.Alert{
		RuleName: "Test Rule",
		Severity: types.SeverityLow,
		Count:    15,
	}

	shouldUpgrade, upgradeRule := cache.Check(alert)
	if !shouldUpgrade {
		t.Error("Check returned false, want true")
	}

	if upgradeRule == nil {
		t.Error("upgradeRule is nil")
	}
}

func TestAlertUpgradeCacheNoMatch(t *testing.T) {
	cache := NewAlertUpgradeCache()

	rule := &types.AlertUpgradeRule{
		ID:          1,
		Name:        "Other Rule",
		Threshold:   10,
		NewSeverity: types.SeverityCritical,
	}

	cache.Add(rule)

	alert := &types.Alert{
		RuleName: "Test Rule",
		Count:    5,
	}

	shouldUpgrade, _ := cache.Check(alert)
	if shouldUpgrade {
		t.Error("Check returned true for non-matching alert")
	}
}

func TestSuppressCache(t *testing.T) {
	cache := NewSuppressCache()

	rule := &types.SuppressRule{
		ID:       1,
		Name:     "Suppress Test",
		Duration: 30 * time.Minute,
		Scope:    "global",
		Enabled:  true,
	}

	cache.Add(rule)

	alertRule := &rules.AlertRule{
		Name: "Test Rule",
	}

	event := &types.Event{
		EventID: 4624,
	}

	if cache.IsSuppressed(alertRule, event) {
		t.Error("IsSuppressed returned true for non-existent suppression")
	}

	cache.Clear()

	if cache.IsSuppressed(alertRule, event) {
		t.Error("IsSuppressed returned true after Clear")
	}
}
