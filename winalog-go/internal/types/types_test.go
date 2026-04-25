package types

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEventLevelString(t *testing.T) {
	tests := []struct {
		level    EventLevel
		expected string
	}{
		{EventLevelCritical, "Critical"},
		{EventLevelError, "Error"},
		{EventLevelWarning, "Warning"},
		{EventLevelInfo, "Info"},
		{EventLevelVerbose, "Verbose"},
		{"Unknown", "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.level.String(); got != tt.expected {
			t.Errorf("EventLevel.String() = %v, want %v", got, tt.expected)
		}
	}
}

func TestEventLevelMarshalJSON(t *testing.T) {
	level := EventLevelWarning
	data, err := json.Marshal(level)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	expected := `"Warning"`
	if string(data) != expected {
		t.Errorf("EventLevel.MarshalJSON() = %v, want %v", string(data), expected)
	}
}

func TestEventLevelUnmarshalJSON(t *testing.T) {
	tests := []struct {
		input    string
		expected EventLevel
	}{
		{`"Critical"`, EventLevelCritical},
		{`"Error"`, EventLevelError},
		{`"Warning"`, EventLevelWarning},
		{`"Info"`, EventLevelInfo},
		{`"Verbose"`, EventLevelVerbose},
		{`"Unknown"`, "Unknown"},
	}

	for _, tt := range tests {
		var level EventLevel
		if err := json.Unmarshal([]byte(tt.input), &level); err != nil {
			t.Errorf("json.Unmarshal failed for %s: %v", tt.input, err)
			continue
		}
		if level != tt.expected {
			t.Errorf("EventLevel.UnmarshalJSON(%s) = %v, want %v", tt.input, level, tt.expected)
		}
	}
}

func TestSeverityString(t *testing.T) {
	s := SeverityHigh
	if got := s.String(); got != "high" {
		t.Errorf("Severity.String() = %v, want high", got)
	}
}

func TestSeverityLevel(t *testing.T) {
	tests := []struct {
		severity Severity
		expected EventLevel
	}{
		{SeverityCritical, EventLevelCritical},
		{SeverityHigh, EventLevelError},
		{SeverityMedium, EventLevelWarning},
		{SeverityLow, EventLevelInfo},
		{SeverityInfo, EventLevelVerbose},
	}

	for _, tt := range tests {
		if got := tt.severity.Level(); got != tt.expected {
			t.Errorf("Severity.Level() = %v, want %v", got, tt.expected)
		}
	}
}

func TestEventToMap(t *testing.T) {
	user := "testuser"
	event := &Event{
		ID:        1,
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		EventID:   4624,
		Level:     EventLevelInfo,
		Source:    "Security",
		LogName:   "Security",
		Computer:  "WORKSTATION1",
		User:      &user,
		Message:   "An account was successfully logged on",
	}

	m := event.ToMap()

	if m["event_id"] != int32(4624) {
		t.Errorf("ToMap()[event_id] = %v, want 4624", m["event_id"])
	}
	if m["source"] != "Security" {
		t.Errorf("ToMap()[source] = %v, want Security", m["source"])
	}
	if m["user"] != "testuser" {
		t.Errorf("ToMap()[user] = %v, want testuser", m["user"])
	}
}

func TestEventToSlice(t *testing.T) {
	event := &Event{
		ID:        1,
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		EventID:   4624,
		Level:     EventLevelInfo,
		Source:    "Security",
		LogName:   "Security",
		Computer:  "WORKSTATION1",
		Message:   "Test message",
	}

	slice := event.ToSlice()
	if len(slice) != 15 {
		t.Errorf("ToSlice() length = %d, want 15", len(slice))
	}
	if slice[0].(int64) != 1 {
		t.Errorf("ToSlice()[0] = %v, want 1", slice[0])
	}
}

func TestEventColumns(t *testing.T) {
	expected := []string{
		"id", "timestamp", "event_id", "level", "source", "log_name",
		"computer", "user", "user_sid", "message", "raw_xml", "session_id",
		"ip_address", "import_time", "import_id",
	}
	if len(EventColumns) != len(expected) {
		t.Fatalf("EventColumns length = %d, want %d", len(EventColumns), len(expected))
	}
	for i, col := range EventColumns {
		if col != expected[i] {
			t.Errorf("EventColumns[%d] = %v, want %v", i, col, expected[i])
		}
	}
}

func TestAlertToMap(t *testing.T) {
	alert := &Alert{
		ID:       1,
		RuleName: "Test Rule",
		Severity: SeverityHigh,
		Message:  "Test alert",
		EventIDs: []int32{4624, 4625},
		Count:    5,
	}

	m := alert.ToMap()
	if m["rule_name"] != "Test Rule" {
		t.Errorf("ToMap()[rule_name] = %v, want Test Rule", m["rule_name"])
	}
	if m["severity"] != SeverityHigh {
		t.Errorf("ToMap()[severity] = %v, want high", m["severity"])
	}
}

func TestFilterMatches(t *testing.T) {
	event := &Event{
		EventID: 4624,
		Level:   EventLevelInfo,
		Source:  "Security",
		Message: "User login success",
	}

	tests := []struct {
		filter   Filter
		expected bool
	}{
		{Filter{Field: "event_id", Operator: "equals", Value: int32(4624)}, true},
		{Filter{Field: "event_id", Operator: "equals", Value: int32(9999)}, false},
		{Filter{Field: "source", Operator: "contains", Value: "Sec"}, true},
		{Filter{Field: "source", Operator: "not_contains", Value: "XXX"}, true},
		{Filter{Field: "message", Operator: "regex", Value: "login.*success"}, true},
	}

	for _, tt := range tests {
		if got := tt.filter.Matches(event); got != tt.expected {
			t.Errorf("Filter{Matches} = %v, want %v", got, tt.expected)
		}
	}
}

func TestAlertRuleMatches(t *testing.T) {
	rule := &AlertRule{
		BaseRule: BaseRule{
			Name:     "Test Rule",
			Severity: SeverityHigh,
			Enabled:  true,
		},
		EventIDs:    []int32{4624, 4625},
		ConditionOp: OpAnd,
	}

	event := &Event{EventID: 4624, Level: EventLevelInfo, Source: "Security"}

	if !rule.Matches(event) {
		t.Error("AlertRule.Matches() = false, want true")
	}

	event2 := &Event{EventID: 9999, Level: EventLevelInfo, Source: "Security"}
	if rule.Matches(event2) {
		t.Error("AlertRule.Matches() = true, want false")
	}
}

func TestContainsInt32(t *testing.T) {
	slice := []int32{1, 2, 3, 4, 5}

	if !containsInt32(slice, 3) {
		t.Error("containsInt32(slice, 3) = false, want true")
	}

	if containsInt32(slice, 99) {
		t.Error("containsInt32(slice, 99) = true, want false")
	}
}

func TestContainsIgnoreCase(t *testing.T) {
	if !containsIgnoreCase("Hello World", "world") {
		t.Error("containsIgnoreCase() = false, want true")
	}

	if containsIgnoreCase("Hello", "xxx") {
		t.Error("containsIgnoreCase() = true, want false")
	}
}

func TestNormalizeString(t *testing.T) {
	if normalizeString("  Hello World  ") != "hello world" {
		t.Errorf("normalizeString() = %v, want hello world", normalizeString("  Hello World  "))
	}
}

func TestIsPrintable(t *testing.T) {
	if !isPrintable("Hello World\n") {
		t.Error("isPrintable() = false for printable string")
	}

	if isPrintable(string([]byte{0x00, 0x01})) {
		t.Error("isPrintable() = true for non-printable string")
	}
}

func TestTruncateString(t *testing.T) {
	if truncateString("Hello World", 20) != "Hello World" {
		t.Error("truncateString() should not truncate short strings")
	}

	if truncateString("Hello World", 8) != "Hello..." {
		t.Error("truncateString() incorrect truncation")
	}
}

func TestCompareValues(t *testing.T) {
	if compareValues(5, 3) != 1 {
		t.Error("compareValues(5, 3) should return 1")
	}
	if compareValues(3, 5) != -1 {
		t.Error("compareValues(3, 5) should return -1")
	}
	if compareValues(5, 5) != 0 {
		t.Error("compareValues(5, 5) should return 0")
	}
}

func TestAlertRuleGetMethods(t *testing.T) {
	rule := &AlertRule{
		BaseRule: BaseRule{
			Name:     "Test Rule",
			Severity: SeverityHigh,
			Enabled:  true,
		},
	}

	if rule.GetName() != "Test Rule" {
		t.Errorf("GetName() = %v, want Test Rule", rule.GetName())
	}
	if rule.GetSeverity() != SeverityHigh {
		t.Errorf("GetSeverity() = %v, want high", rule.GetSeverity())
	}
	if !rule.IsEnabled() {
		t.Error("IsEnabled() = false, want true")
	}
	if rule.GetRuleType() != "alert" {
		t.Errorf("GetRuleType() = %v, want alert", rule.GetRuleType())
	}
}

func TestCorrelationRuleGetMethods(t *testing.T) {
	rule := &CorrelationRule{
		BaseRule: BaseRule{
			Name:     "Correlation Rule",
			Severity: SeverityMedium,
			Enabled:  false,
		},
	}

	if rule.GetName() != "Correlation Rule" {
		t.Errorf("GetName() = %v, want Correlation Rule", rule.GetName())
	}
	if rule.GetSeverity() != SeverityMedium {
		t.Errorf("GetSeverity() = %v, want medium", rule.GetSeverity())
	}
	if rule.IsEnabled() {
		t.Error("IsEnabled() = true, want false")
	}
	if rule.GetRuleType() != "correlation" {
		t.Errorf("GetRuleType() = %v, want correlation", rule.GetRuleType())
	}
}

func TestCalculateRuleScore(t *testing.T) {
	rule := &AlertRule{
		BaseRule: BaseRule{
			Name:        "Test",
			Severity:    SeverityHigh,
			MITREAttack: []string{"T1078", "T1098"},
		},
	}

	stats := &AlertStats{}
	score := CalculateRuleScore(rule, stats)

	if score <= 0 {
		t.Error("CalculateRuleScore() should return positive value")
	}
}

func TestEventIDCountStruct(t *testing.T) {
	e := EventIDCount{EventID: 4624, Count: 100}
	if e.EventID != 4624 {
		t.Errorf("EventID = %d, want 4624", e.EventID)
	}
	if e.Count != 100 {
		t.Errorf("Count = %d, want 100", e.Count)
	}
}

func TestLevelDistributionStruct(t *testing.T) {
	d := LevelDistribution{Level: EventLevelWarning, Count: 50}
	if d.Level != EventLevelWarning {
		t.Errorf("Level = %v, want Warning", d.Level)
	}
	if d.Count != 50 {
		t.Errorf("Count = %d, want 50", d.Count)
	}
}

func TestLogNameDistributionStruct(t *testing.T) {
	d := LogNameDistribution{LogName: "Security", Count: 200}
	if d.LogName != "Security" {
		t.Errorf("LogName = %v, want Security", d.LogName)
	}
	if d.Count != 200 {
		t.Errorf("Count = %d, want 200", d.Count)
	}
}

func TestParseTimeFilter(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		input   string
		wantErr bool
		checkFn func(*TimeFilter) bool
	}{
		{
			name:    "empty string returns nil",
			input:   "",
			wantErr: false,
			checkFn: func(tf *TimeFilter) bool { return tf == nil },
		},
		{
			name:    "duration 24h",
			input:   "24h",
			wantErr: false,
			checkFn: func(tf *TimeFilter) bool {
				if tf == nil {
					return false
				}
				diff := tf.Duration() - 24*time.Hour
				return diff < time.Second && diff > -time.Second
			},
		},
		{
			name:    "duration 168h (7 days)",
			input:   "168h",
			wantErr: false,
			checkFn: func(tf *TimeFilter) bool {
				if tf == nil {
					return false
				}
				diff := tf.Duration() - 168*time.Hour
				return diff < time.Second && diff > -time.Second
			},
		},
		{
			name:    "RFC3339 format",
			input:   "2024-01-01T00:00:00Z",
			wantErr: false,
			checkFn: func(tf *TimeFilter) bool {
				return tf != nil && tf.Start.Year() == 2024 && tf.Start.Month() == 1 && tf.Start.Day() == 1
			},
		},
		{
			name:    "date only format",
			input:   "2024-01-01",
			wantErr: false,
			checkFn: func(tf *TimeFilter) bool {
				return tf != nil && tf.Start.Year() == 2024 && tf.Start.Month() == 1 && tf.Start.Day() == 1
			},
		},
		{
			name:    "custom range with comma",
			input:   "2024-01-01T00:00:00Z,2024-01-02T00:00:00Z",
			wantErr: false,
			checkFn: func(tf *TimeFilter) bool {
				return tf != nil && tf.Duration() == 24*time.Hour
			},
		},
		{
			name:    "custom range with date only",
			input:   "2024-01-01,2024-01-02",
			wantErr: false,
			checkFn: func(tf *TimeFilter) bool {
				return tf != nil && tf.Duration() == 24*time.Hour
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTimeFilter(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTimeFilter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.checkFn(got) {
				t.Errorf("ParseTimeFilter() = %v, check failed", got)
			}
			_ = now
		})
	}
}

func TestTimeFilterMethods(t *testing.T) {
	now := time.Now()
	start := now.Add(-24 * time.Hour)

	tf := &TimeFilter{
		Start: start,
		End:   now,
	}

	if !tf.IsValid() {
		t.Error("TimeFilter.IsValid() = false, want true")
	}

	if tf.Duration() != 24*time.Hour {
		t.Errorf("TimeFilter.Duration() = %v, want 24h", tf.Duration())
	}
}
