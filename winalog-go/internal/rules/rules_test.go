package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

func TestAlertRuleBuildMessage(t *testing.T) {
	rule := &AlertRule{
		Name:    "Test Rule",
		Message: "Login event {{.EventID}} from {{.Computer}}",
	}

	user := "testuser"
	event := &types.Event{
		EventID:  4624,
		Source:   "Security",
		Computer: "WORKSTATION1",
		User:     &user,
		Message:  "An account was logged on",
	}

	msg := rule.BuildMessage(event)
	expected := "Login event 4624 from WORKSTATION1"

	if msg != expected {
		t.Errorf("BuildMessage = %s, want %s", msg, expected)
	}
}

func TestAlertRuleBuildMessageEmpty(t *testing.T) {
	rule := &AlertRule{
		Name: "Test Rule",
	}

	event := &types.Event{
		EventID: 4624,
	}

	msg := rule.BuildMessage(event)
	expected := "Alert triggered by rule Test Rule"

	if msg != expected {
		t.Errorf("BuildMessage = %s, want %s", msg, expected)
	}
}

func TestAlertRuleValidate(t *testing.T) {
	tests := []struct {
		name    string
		rule    *AlertRule
		wantErr bool
	}{
		{
			name: "valid rule with filter",
			rule: &AlertRule{
				Name:     "Test Rule",
				Severity: types.SeverityHigh,
				Filter:   &Filter{EventIDs: []int32{4624}},
			},
			wantErr: false,
		},
		{
			name: "valid rule with conditions",
			rule: &AlertRule{
				Name:       "Test Rule",
				Severity:   types.SeverityHigh,
				Conditions: &Conditions{Any: []*Condition{{Field: "event_id", Operator: "==", Value: "4624"}}},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			rule: &AlertRule{
				Severity: types.SeverityHigh,
				Filter:   &Filter{EventIDs: []int32{4624}},
			},
			wantErr: true,
		},
		{
			name: "missing severity",
			rule: &AlertRule{
				Name:   "Test Rule",
				Filter: &Filter{EventIDs: []int32{4624}},
			},
			wantErr: true,
		},
		{
			name: "missing filter and conditions",
			rule: &AlertRule{
				Name:     "Test Rule",
				Severity: types.SeverityHigh,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCorrelationRuleValidate(t *testing.T) {
	tests := []struct {
		name    string
		rule    *CorrelationRule
		wantErr bool
	}{
		{
			name: "valid rule",
			rule: &CorrelationRule{
				Name:     "Test Rule",
				Patterns: []*Pattern{{EventID: 4624}, {EventID: 4625}},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			rule: &CorrelationRule{
				Patterns: []*Pattern{{EventID: 4624}, {EventID: 4625}},
			},
			wantErr: true,
		},
		{
			name: "only one pattern",
			rule: &CorrelationRule{
				Name:     "Test Rule",
				Patterns: []*Pattern{{EventID: 4624}},
			},
			wantErr: true,
		},
		{
			name: "zero event_id in pattern",
			rule: &CorrelationRule{
				Name:     "Test Rule",
				Patterns: []*Pattern{{EventID: 0}, {EventID: 4625}},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected types.Severity
		wantErr  bool
	}{
		{"critical", types.SeverityCritical, false},
		{"high", types.SeverityHigh, false},
		{"medium", types.SeverityMedium, false},
		{"low", types.SeverityLow, false},
		{"info", types.SeverityInfo, false},
		{"invalid", types.SeverityInfo, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			sev, err := ParseSeverity(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSeverity() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if sev != tt.expected {
				t.Errorf("ParseSeverity() = %v, want %v", sev, tt.expected)
			}
		})
	}
}

func TestSeverityScoreValue(t *testing.T) {
	tests := []struct {
		severity types.Severity
		expected float64
	}{
		{types.SeverityCritical, 100},
		{types.SeverityHigh, 75},
		{types.SeverityMedium, 50},
		{types.SeverityLow, 25},
		{types.SeverityInfo, 10},
		{types.Severity("unknown"), 10},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			if score := ScoreValue(tt.severity); score != tt.expected {
				t.Errorf("ScoreValue() = %v, want %v", score, tt.expected)
			}
		})
	}
}

func TestFilterStruct(t *testing.T) {
	filter := &Filter{
		EventIDs:    []int32{4624, 4625},
		Levels:      []string{"Critical", "Error"},
		LogNames:    []string{"Security", "System"},
		Sources:     []string{"Microsoft-Windows-Security-Auditing"},
		Computers:   []string{"WORKSTATION1"},
		Keywords:    "login,failed",
		KeywordMode: OpAnd,
	}

	if len(filter.EventIDs) != 2 {
		t.Errorf("len(EventIDs) = %d, want 2", len(filter.EventIDs))
	}
	if len(filter.LogNames) != 2 {
		t.Errorf("len(LogNames) = %d, want 2", len(filter.LogNames))
	}
}

func TestConditionsStruct(t *testing.T) {
	conditions := &Conditions{
		Any: []*Condition{
			{Field: "event_id", Operator: "==", Value: "4624"},
		},
		All: []*Condition{
			{Field: "level", Operator: ">=", Value: "2"},
		},
		None: []*Condition{
			{Field: "source", Operator: "contains", Value: "Test"},
		},
	}

	if len(conditions.Any) != 1 {
		t.Errorf("len(Any) = %d, want 1", len(conditions.Any))
	}
	if len(conditions.All) != 1 {
		t.Errorf("len(All) = %d, want 1", len(conditions.All))
	}
	if len(conditions.None) != 1 {
		t.Errorf("len(None) = %d, want 1", len(conditions.None))
	}
}

func TestConditionStruct(t *testing.T) {
	cond := &Condition{
		Field:    "event_id",
		Operator: "==",
		Value:    "4624",
		Regex:    false,
	}

	if cond.Field != "event_id" {
		t.Errorf("Field = %s, want event_id", cond.Field)
	}
	if cond.Operator != "==" {
		t.Errorf("Operator = %s, want ==", cond.Operator)
	}
}

func TestPatternStruct(t *testing.T) {
	pattern := &Pattern{
		EventID:    4624,
		Conditions: []*Condition{{Field: "level", Operator: ">=", Value: "2"}},
		Join:       "AND",
		TimeWindow: 5 * time.Minute,
	}

	if pattern.EventID != 4624 {
		t.Errorf("EventID = %d, want 4624", pattern.EventID)
	}
	if pattern.TimeWindow != 5*time.Minute {
		t.Errorf("TimeWindow = %v, want 5m", pattern.TimeWindow)
	}
}

func TestAlertRuleStruct(t *testing.T) {
	rule := &AlertRule{
		Name:           "Test Rule",
		Description:    "Test description",
		Enabled:        true,
		Severity:       types.SeverityHigh,
		Score:          85.0,
		MitreAttack:    "T1078",
		Filter:         &Filter{EventIDs: []int32{4624}},
		Conditions:     nil,
		Threshold:      5,
		TimeWindow:     10 * time.Minute,
		AggregationKey: "user",
		Message:        "Alert message",
		Tags:           []string{"authentication", "windows"},
	}

	if rule.Name != "Test Rule" {
		t.Errorf("Name = %s, want Test Rule", rule.Name)
	}
	if rule.Score != 85.0 {
		t.Errorf("Score = %f, want 85.0", rule.Score)
	}
	if len(rule.Tags) != 2 {
		t.Errorf("len(Tags) = %d, want 2", len(rule.Tags))
	}
}

func TestCorrelationRuleStruct(t *testing.T) {
	rule := &CorrelationRule{
		Name:        "Correlation Rule",
		Description: "Test correlation rule",
		Enabled:     true,
		Severity:    types.SeverityMedium,
		Patterns:    []*Pattern{{EventID: 4624}, {EventID: 4625}},
		TimeWindow:  15 * time.Minute,
		Join:        "AND",
		MitreAttack: "T1078.004",
		Tags:        []string{"lateral_movement"},
	}

	if rule.Name != "Correlation Rule" {
		t.Errorf("Name = %s, want Correlation Rule", rule.Name)
	}
	if len(rule.Patterns) != 2 {
		t.Errorf("len(Patterns) = %d, want 2", len(rule.Patterns))
	}
}

func TestBaseRuleStruct(t *testing.T) {
	rule := &BaseRule{
		Name:        "Base Rule",
		Description: "Base rule description",
		Enabled:     true,
		Tags:        []string{"test", "base"},
	}

	if rule.Name != "Base Rule" {
		t.Errorf("Name = %s, want Base Rule", rule.Name)
	}
	if !rule.Enabled {
		t.Error("Enabled should be true")
	}
}

func TestReplace(t *testing.T) {
	tests := []struct {
		s      string
		old    string
		new    string
		expect string
	}{
		{"Hello World", "World", "Go", "Hello Go"},
		{"Hello {{.Name}}", "{{.Name}}", "World", "Hello World"},
		{"No replacement", "X", "Y", "No replacement"},
	}

	for _, tt := range tests {
		result := strings.ReplaceAll(tt.s, tt.old, tt.new)
		if result != tt.expect {
			t.Errorf("ReplaceAll(%q, %q, %q) = %q, want %q", tt.s, tt.old, tt.new, result, tt.expect)
		}
	}
}

func TestLogicalOpConstants(t *testing.T) {
	if OpAnd != "AND" {
		t.Errorf("OpAnd = %s, want AND", OpAnd)
	}
	if OpOr != "OR" {
		t.Errorf("OpOr = %s, want OR", OpOr)
	}
}

func TestSeverityConstants(t *testing.T) {
	if types.SeverityCritical != "critical" {
		t.Errorf("SeverityCritical = %s, want critical", types.SeverityCritical)
	}
	if types.SeverityHigh != "high" {
		t.Errorf("SeverityHigh = %s, want high", types.SeverityHigh)
	}
	if types.SeverityMedium != "medium" {
		t.Errorf("SeverityMedium = %s, want medium", types.SeverityMedium)
	}
	if types.SeverityLow != "low" {
		t.Errorf("SeverityLow = %s, want low", types.SeverityLow)
	}
	if types.SeverityInfo != "info" {
		t.Errorf("SeverityInfo = %s, want info", types.SeverityInfo)
	}
}
