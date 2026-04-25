package ueba

import (
	"testing"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

func TestNewEngine(t *testing.T) {
	t.Helper()
	cfg := EngineConfig{
		LearningWindow:       7 * 24 * time.Hour,
		AlertThreshold:       70,
		MinEventsForBaseline: 10,
	}
	e := NewEngine(cfg)

	if e == nil {
		t.Fatal("NewEngine() returned nil")
	}
	if e.config == nil {
		t.Error("NewEngine() config is nil")
	}
	if e.baseline == nil {
		t.Error("NewEngine() baseline is nil")
	}
}

func TestEngine_Learn(t *testing.T) {
	t.Helper()
	e := NewEngine(EngineConfig{
		LearningWindow:       7 * 24 * time.Hour,
		AlertThreshold:       70,
		MinEventsForBaseline: 10,
	})

	events := []*types.Event{
		makeTestEvent(4624, "user1", "192.168.1.1"),
		makeTestEvent(4624, "user1", "192.168.1.2"),
		makeTestEvent(4624, "user2", "192.168.1.1"),
	}

	err := e.Learn(events)
	if err != nil {
		t.Fatalf("Learn() error = %v", err)
	}

	profiles := e.GetUserActivity()
	if len(profiles) != 2 {
		t.Errorf("Learn() got %v profiles, want 2", len(profiles))
	}
}

func TestEngine_GetUserActivity(t *testing.T) {
	t.Helper()
	e := NewEngine(EngineConfig{
		LearningWindow:       7 * 24 * time.Hour,
		AlertThreshold:       70,
		MinEventsForBaseline: 10,
	})

	profiles := e.GetUserActivity()
	if profiles == nil {
		t.Error("GetUserActivity() returned nil")
	}
	if len(profiles) != 0 {
		t.Errorf("GetUserActivity() got %v profiles, want 0", len(profiles))
	}

	e.Learn([]*types.Event{
		makeTestEvent(4624, "user1", "192.168.1.1"),
	})

	profiles = e.GetUserActivity()
	if len(profiles) != 1 {
		t.Errorf("GetUserActivity() got %v profiles, want 1", len(profiles))
	}
}

func TestEngine_DetectAnomalies(t *testing.T) {
	t.Helper()
	tests := []struct {
		name        string
		events      []*types.Event
		wantAnomaly bool
	}{
		{
			name:        "no events",
			events:      []*types.Event{},
			wantAnomaly: false,
		},
		{
			name: "normal login",
			events: []*types.Event{
				makeTestEvent(4624, "user1", "192.168.1.1"),
			},
			wantAnomaly: false,
		},
		{
			name: "impossible travel",
			events: []*types.Event{
				makeTestEventAt(4624, "user1", "192.168.1.1", time.Now().Add(-1*time.Hour)),
				makeTestEventAt(4624, "user1", "8.8.8.8", time.Now()),
			},
			wantAnomaly: true,
		},
		{
			name: "abnormal behavior",
			events: []*types.Event{
				makeTestEvent(4624, "user1", "192.168.1.1"),
			},
			wantAnomaly: false,
		},
		{
			name: "privilege escalation",
			events: []*types.Event{
				makeTestEvent(4672, "user1", "192.168.1.1"),
				makeTestEvent(4672, "user1", "192.168.1.1"),
				makeTestEvent(4672, "user1", "192.168.1.1"),
				makeTestEvent(4672, "user1", "192.168.1.1"),
				makeTestEvent(4672, "user1", "192.168.1.1"),
				makeTestEvent(4672, "user1", "192.168.1.1"),
			},
			wantAnomaly: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEngine(EngineConfig{
				LearningWindow:       7 * 24 * time.Hour,
				AlertThreshold:       70,
				MinEventsForBaseline: 10,
			})
			e.Learn(tt.events)
			anomalies := e.DetectAnomalies(tt.events)

			hasHigh := false
			for _, a := range anomalies {
				if a.Severity == "high" || a.Severity == "critical" {
					hasHigh = true
					break
				}
			}

			if hasHigh != tt.wantAnomaly {
				t.Errorf("DetectAnomalies() high severity = %v, want %v", hasHigh, tt.wantAnomaly)
			}
		})
	}
}

func TestEngine_DetectImpossibleTravel(t *testing.T) {
	t.Helper()
	tests := []struct {
		name        string
		events      []*types.Event
		wantAnomaly bool
	}{
		{
			name:        "no events",
			events:      []*types.Event{},
			wantAnomaly: false,
		},
		{
			name: "single location",
			events: []*types.Event{
				makeTestEventAt(4624, "user1", "192.168.1.1", time.Now().Add(-1*time.Hour)),
				makeTestEventAt(4624, "user1", "192.168.1.1", time.Now()),
			},
			wantAnomaly: false,
		},
		{
			name: "different IPs within hour",
			events: []*types.Event{
				makeTestEventAt(4624, "user1", "192.168.1.1", time.Now().Add(-30*time.Minute)),
				makeTestEventAt(4624, "user1", "8.8.8.8", time.Now()),
			},
			wantAnomaly: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEngine(EngineConfig{})
			anomalies := e.detectImpossibleTravel(tt.events)

			if len(anomalies) > 0 != tt.wantAnomaly {
				t.Errorf("detectImpossibleTravel() = %v anomalies, want %v", len(anomalies), tt.wantAnomaly)
			}
		})
	}
}

func TestEngine_DetectAbnormalBehavior(t *testing.T) {
	t.Helper()
	e := NewEngine(EngineConfig{
		LearningWindow:       7 * 24 * time.Hour,
		AlertThreshold:       70,
		MinEventsForBaseline: 10,
	})

	baselineEvents := []*types.Event{
		makeTestEventAt(4624, "user1", "192.168.1.1", time.Now().Add(-48*time.Hour)),
		makeTestEventAt(4624, "user1", "192.168.1.1", time.Now().Add(-24*time.Hour)),
	}
	e.Learn(baselineEvents)

	testEvents := []*types.Event{
		makeTestEventAt(4624, "user1", "192.168.1.1", time.Now().Add(-1*time.Hour)),
	}

	anomalies := e.detectAbnormalBehavior(testEvents)
	if len(anomalies) != 1 {
		t.Errorf("detectAbnormalBehavior() = %v, want 1 (event at non-typical hour)", len(anomalies))
	}
}

func TestEngine_DetectUnusualHours(t *testing.T) {
	t.Helper()
	tests := []struct {
		name        string
		events      []*types.Event
		wantAnomaly bool
	}{
		{
			name: "normal hours",
			events: []*types.Event{
				makeTestEventAt(4624, "user1", "192.168.1.1", time.Now().Add(-10*time.Hour)),
				makeTestEventAt(4624, "user1", "192.168.1.1", time.Now().Add(-11*time.Hour)),
				makeTestEventAt(4624, "user1", "192.168.1.1", time.Now().Add(-12*time.Hour)),
				makeTestEventAt(4624, "user1", "192.168.1.1", time.Now().Add(-13*time.Hour)),
				makeTestEventAt(4624, "user1", "192.168.1.1", time.Now().Add(-14*time.Hour)),
			},
			wantAnomaly: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEngine(EngineConfig{})
			anomalies := e.detectUnusualHours(tt.events)

			if len(anomalies) > 0 != tt.wantAnomaly {
				t.Errorf("detectUnusualHours() = %v, want %v", len(anomalies), tt.wantAnomaly)
			}
		})
	}
}

func TestEngine_DetectPrivilegeEscalation(t *testing.T) {
	t.Helper()
	tests := []struct {
		name        string
		events      []*types.Event
		wantAnomaly bool
	}{
		{
			name:        "no events",
			events:      []*types.Event{},
			wantAnomaly: false,
		},
		{
			name: "few privilege events",
			events: []*types.Event{
				makeTestEvent(4672, "user1", "192.168.1.1"),
				makeTestEvent(4672, "user1", "192.168.1.1"),
			},
			wantAnomaly: false,
		},
		{
			name: "many privilege events",
			events: []*types.Event{
				makeTestEvent(4672, "user1", "192.168.1.1"),
				makeTestEvent(4672, "user1", "192.168.1.1"),
				makeTestEvent(4672, "user1", "192.168.1.1"),
				makeTestEvent(4672, "user1", "192.168.1.1"),
				makeTestEvent(4672, "user1", "192.168.1.1"),
				makeTestEvent(4672, "user1", "192.168.1.1"),
			},
			wantAnomaly: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEngine(EngineConfig{})
			anomalies := e.detectPrivilegeEscalation(tt.events)

			if len(anomalies) > 0 != tt.wantAnomaly {
				t.Errorf("detectPrivilegeEscalation() = %v, want %v", len(anomalies), tt.wantAnomaly)
			}
		})
	}
}

func TestBaselineManager_Update(t *testing.T) {
	t.Helper()
	m := NewBaselineManager()

	events := []*types.Event{
		makeTestEvent(4624, "user1", "192.168.1.1"),
		makeTestEvent(4624, "user1", "192.168.1.2"),
		makeTestEvent(4624, "user2", "192.168.1.1"),
	}

	err := m.Update(events)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	profiles := m.GetUserActivity()
	if len(profiles) != 2 {
		t.Errorf("Update() got %v profiles, want 2", len(profiles))
	}
}

func TestBaselineManager_GetUserBaseline(t *testing.T) {
	t.Helper()
	m := NewBaselineManager()

	m.Update([]*types.Event{
		makeTestEvent(4624, "user1", "192.168.1.1"),
	})

	baseline, exists := m.GetUserBaseline("user1")
	if !exists {
		t.Error("GetUserBaseline() exists = false, want true")
	}
	if baseline == nil {
		t.Error("GetUserBaseline() baseline = nil, want non-nil")
	}
	if baseline.LoginCount != 1 {
		t.Errorf("GetUserBaseline() LoginCount = %v, want 1", baseline.LoginCount)
	}

	_, exists = m.GetUserBaseline("nonexistent")
	if exists {
		t.Error("GetUserBaseline() exists = true for nonexistent user, want false")
	}
}

func TestBaselineManager_GetUserActivity(t *testing.T) {
	t.Helper()
	m := NewBaselineManager()

	activity := m.GetUserActivity()
	if activity == nil {
		t.Error("GetUserActivity() returned nil")
	}

	m.Update([]*types.Event{
		makeTestEvent(4624, "user1", "192.168.1.1"),
	})

	activity = m.GetUserActivity()
	if len(activity) != 1 {
		t.Errorf("GetUserActivity() len = %v, want 1", len(activity))
	}
}

func TestBaselineManager_GetEntityStats(t *testing.T) {
	t.Helper()
	m := NewBaselineManager()

	user := "user1"
	ip := "192.168.1.1"
	m.Update([]*types.Event{
		{
			ID:        1,
			EventID:   4624,
			Timestamp: time.Now(),
			User:      &user,
			IPAddress: &ip,
			Computer:  "WORKSTATION1",
			Source:    "Security",
			Message:   "Test event",
		},
	})

	stats, exists := m.GetEntityStats("WORKSTATION1:Security")
	if !exists {
		t.Error("GetEntityStats() exists = false, want true")
	}
	if stats.EventCount != 1 {
		t.Errorf("GetEntityStats() EventCount = %v, want 1", stats.EventCount)
	}
}

func TestBaselineManager_Clear(t *testing.T) {
	t.Helper()
	m := NewBaselineManager()

	m.Update([]*types.Event{
		makeTestEvent(4624, "user1", "192.168.1.1"),
	})

	m.Clear()

	profiles := m.GetUserActivity()
	if len(profiles) != 0 {
		t.Errorf("Clear() got %v profiles, want 0", len(profiles))
	}
}

func TestBaselineManager_SetWindow(t *testing.T) {
	t.Helper()
	m := NewBaselineManager()

	window := 30 * 24 * time.Hour
	m.SetWindow(window)

	if m.window != window {
		t.Errorf("SetWindow() window = %v, want %v", m.window, window)
	}
}

func TestNewBaselineManager(t *testing.T) {
	t.Helper()
	m := NewBaselineManager()

	if m == nil {
		t.Fatal("NewBaselineManager() returned nil")
	}
	if m.userActivity == nil {
		t.Error("NewBaselineManager() userActivity is nil")
	}
	if m.entityStats == nil {
		t.Error("NewBaselineManager() entityStats is nil")
	}
	if m.window != 7*24*time.Hour {
		t.Errorf("NewBaselineManager() window = %v, want %v", m.window, 7*24*time.Hour)
	}
}

func TestAnomalyResult_ToAlert(t *testing.T) {
	t.Helper()
	result := &AnomalyResult{
		Type:        AnomalyTypeImpossibleTravel,
		User:        "user1",
		Severity:    "high",
		Score:       90,
		Description: "Impossible travel detected",
		StartTime:   time.Now().Add(-1 * time.Hour),
		EndTime:     time.Now(),
	}

	alert := result.ToAlert()
	if alert == nil {
		t.Fatal("ToAlert() returned nil")
	}
	if alert.RuleName != string(AnomalyTypeImpossibleTravel) {
		t.Errorf("ToAlert() RuleName = %v, want %v", alert.RuleName, AnomalyTypeImpossibleTravel)
	}
	if alert.Severity != types.Severity("high") {
		t.Errorf("ToAlert() Severity = %v, want high", alert.Severity)
	}
}

func TestNewUEBAReport(t *testing.T) {
	t.Helper()
	r := NewUEBAReport()

	if r == nil {
		t.Fatal("NewUEBAReport() returned nil")
	}
	if r.GeneratedAt.IsZero() {
		t.Error("NewUEBAReport() GeneratedAt is zero")
	}
	if r.ProfilesAnalyzed != 0 {
		t.Errorf("NewUEBAReport() ProfilesAnalyzed = %v, want 0", r.ProfilesAnalyzed)
	}
	if r.AnomaliesDetected != 0 {
		t.Errorf("NewUEBAReport() AnomaliesDetected = %v, want 0", r.AnomaliesDetected)
	}
}

func TestUEBAReport_AddAnomaly(t *testing.T) {
	t.Helper()
	tests := []struct {
		name           string
		anomalies      []*AnomalyResult
		wantHighRisk   int
		wantMediumRisk int
	}{
		{
			name:           "no anomalies",
			anomalies:      []*AnomalyResult{},
			wantHighRisk:   0,
			wantMediumRisk: 0,
		},
		{
			name: "high severity",
			anomalies: []*AnomalyResult{
				{User: "user1", Severity: "high"},
				{User: "user2", Severity: "high"},
			},
			wantHighRisk:   2,
			wantMediumRisk: 0,
		},
		{
			name: "medium severity",
			anomalies: []*AnomalyResult{
				{User: "user1", Severity: "medium"},
				{User: "user2", Severity: "medium"},
			},
			wantHighRisk:   0,
			wantMediumRisk: 2,
		},
		{
			name: "mixed severity",
			anomalies: []*AnomalyResult{
				{User: "user1", Severity: "high"},
				{User: "user1", Severity: "medium"},
				{User: "user2", Severity: "medium"},
			},
			wantHighRisk:   1,
			wantMediumRisk: 2,
		},
		{
			name: "duplicate users",
			anomalies: []*AnomalyResult{
				{User: "user1", Severity: "high"},
				{User: "user1", Severity: "high"},
			},
			wantHighRisk:   1,
			wantMediumRisk: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewUEBAReport()
			for _, a := range tt.anomalies {
				r.AddAnomaly(a)
			}

			if len(r.HighRiskUsers) != tt.wantHighRisk {
				t.Errorf("AddAnomaly() HighRiskUsers = %v, want %v", len(r.HighRiskUsers), tt.wantHighRisk)
			}
			if len(r.MediumRiskUsers) != tt.wantMediumRisk {
				t.Errorf("AddAnomaly() MediumRiskUsers = %v, want %v", len(r.MediumRiskUsers), tt.wantMediumRisk)
			}
		})
	}
}

func TestContains(t *testing.T) {
	t.Helper()
	tests := []struct {
		name  string
		slice []string
		item  string
		want  bool
	}{
		{"empty slice", []string{}, "item", false},
		{"item exists", []string{"a", "b", "c"}, "b", true},
		{"item not found", []string{"a", "b", "c"}, "d", false},
		{"single match", []string{"item"}, "item", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := contains(tt.slice, tt.item); got != tt.want {
				t.Errorf("contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatAnomalyDetails(t *testing.T) {
	t.Helper()
	tests := []struct {
		name    string
		details map[string]interface{}
		wantLen int
	}{
		{
			name:    "nil details",
			details: nil,
			wantLen: 0,
		},
		{
			name:    "empty details",
			details: map[string]interface{}{},
			wantLen: 0,
		},
		{
			name: "with details",
			details: map[string]interface{}{
				"ip":    "192.168.1.1",
				"count": 5,
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatAnomalyDetails(tt.details)
			if tt.wantLen == 0 && result != "" {
				t.Errorf("formatAnomalyDetails() = %v, want empty", result)
			}
			if tt.wantLen > 0 && result == "" {
				t.Error("formatAnomalyDetails() = empty, want non-empty")
			}
		})
	}
}

func TestCalculateIPDistance(t *testing.T) {
	t.Helper()
	tests := []struct {
		name string
		ip1  string
		ip2  string
		want float64
	}{
		{"empty ip1", "", "192.168.1.1", 0},
		{"empty ip2", "192.168.1.1", "", 0},
		{"same ip", "192.168.1.1", "192.168.1.1", 0},
		{"different ips", "192.168.1.1", "8.8.8.8", 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := calculateIPDistance(tt.ip1, tt.ip2); got != tt.want {
				t.Errorf("calculateIPDistance() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkEngine_DetectAnomalies(b *testing.B) {
	b.Helper()
	e := NewEngine(EngineConfig{
		LearningWindow:       7 * 24 * time.Hour,
		AlertThreshold:       70,
		MinEventsForBaseline: 10,
	})

	events := make([]*types.Event, 100)
	for i := range events {
		events[i] = makeTestEvent(4624, "user", "192.168.1.1")
	}
	e.Learn(events)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.DetectAnomalies(events)
	}
}

func BenchmarkBaselineManager_Update(b *testing.B) {
	b.Helper()
	m := NewBaselineManager()

	events := make([]*types.Event, 100)
	for i := range events {
		events[i] = makeTestEvent(4624, "user", "192.168.1.1")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Update(events)
	}
}

func makeTestEvent(eventID int32, user, ip string) *types.Event {
	return makeTestEventAt(eventID, user, ip, time.Now())
}

func makeTestEventAt(eventID int32, user, ip string, timestamp time.Time) *types.Event {
	return &types.Event{
		ID:        1,
		EventID:   eventID,
		Timestamp: timestamp,
		User:      &user,
		IPAddress: &ip,
		Computer:  "WORKSTATION1",
		Message:   "Test event",
	}
}
