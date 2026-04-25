package types

import (
	"encoding/json"
	"time"
)

type LogicalOp string

const (
	OpAnd LogicalOp = "AND"
	OpOr  LogicalOp = "OR"
)

type BaseRule struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	MITREAttack []string `json:"mitre_attack,omitempty"`
	Enabled     bool     `json:"enabled"`
	Tags        []string `json:"tags,omitempty"`
}

type Filter struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

func (f *Filter) Matches(event *Event) bool {
	switch f.Operator {
	case "equals":
		return f.getFieldValue(event) == f.Value
	case "not_equals":
		return f.getFieldValue(event) != f.Value
	case "contains":
		if str, ok := f.getFieldValue(event).(string); ok {
			if v, ok := f.Value.(string); ok {
				return containsIgnoreCase(str, v)
			}
		}
	case "not_contains":
		if str, ok := f.getFieldValue(event).(string); ok {
			if v, ok := f.Value.(string); ok {
				return !containsIgnoreCase(str, v)
			}
		}
	case "regex":
		return matchesRegex(f.getFieldValue(event), f.Value.(string))
	case "gt":
		return compareValues(f.getFieldValue(event), f.Value) > 0
	case "gte":
		return compareValues(f.getFieldValue(event), f.Value) >= 0
	case "lt":
		return compareValues(f.getFieldValue(event), f.Value) < 0
	case "lte":
		return compareValues(f.getFieldValue(event), f.Value) <= 0
	}
	return false
}

func (f *Filter) getFieldValue(event *Event) interface{} {
	switch f.Field {
	case "event_id":
		return event.EventID
	case "level":
		return event.Level
	case "source":
		return event.Source
	case "log_name":
		return event.LogName
	case "computer":
		return event.Computer
	case "user":
		if event.User != nil {
			return *event.User
		}
	case "message":
		return event.Message
	case "ip_address":
		if event.IPAddress != nil {
			return *event.IPAddress
		}
	}
	return nil
}

type AlertRule struct {
	BaseRule
	EventIDs        []int32       `json:"event_ids"`
	Filters         []Filter      `json:"filters,omitempty"`
	ConditionOp     LogicalOp     `json:"condition_op"`
	GroupBy         string        `json:"group_by,omitempty"`
	Threshold       int           `json:"threshold"`
	TimeWindow      time.Duration `json:"time_window"`
	RuleScore       float64       `json:"rule_score"`
	Recommendations []string      `json:"recommendations,omitempty"`
}

func (r *AlertRule) GetRuleType() string {
	return "alert"
}

func (r *AlertRule) Matches(event *Event) bool {
	if !containsInt32(r.EventIDs, event.EventID) {
		return false
	}

	if len(r.Filters) == 0 {
		return true
	}

	for _, filter := range r.Filters {
		matches := filter.Matches(event)
		if r.ConditionOp == OpAnd && !matches {
			return false
		}
		if r.ConditionOp == OpOr && matches {
			return true
		}
	}
	return r.ConditionOp == OpAnd
}

type Condition struct {
	EventIDs    []int32  `json:"event_ids"`
	LogSource   string   `json:"log_source,omitempty"`
	Filters     []Filter `json:"filters,omitempty"`
	Aggregation string   `json:"aggregation,omitempty"`
}

type CorrelationRule struct {
	BaseRule
	TimeWindow  time.Duration `json:"time_window"`
	Conditions  []Condition   `json:"conditions"`
	JoinField   string        `json:"join_field,omitempty"`
	CrossBucket bool          `json:"cross_bucket"`
}

func (r *CorrelationRule) GetRuleType() string {
	return "correlation"
}

type Rule interface {
	GetName() string
	GetSeverity() Severity
	GetRuleType() string
	IsEnabled() bool
}

func (r *AlertRule) GetName() string       { return r.Name }
func (r *AlertRule) GetSeverity() Severity { return r.Severity }
func (r *AlertRule) IsEnabled() bool       { return r.Enabled }

func (r *CorrelationRule) GetName() string       { return r.Name }
func (r *CorrelationRule) GetSeverity() Severity { return r.Severity }
func (r *CorrelationRule) IsEnabled() bool       { return r.Enabled }

type RuleScore struct {
	Name   string  `json:"name"`
	Score  float64 `json:"score"`
	Weight float64 `json:"weight"`
}

var DefaultRuleWeights = map[string]float64{
	"mitre_coverage": 0.3,
	"false_positive": 0.2,
	"severity":       0.2,
	"hit_rate":       0.15,
	"recency":        0.15,
}

func eventLevelToScore(level EventLevel) float64 {
	switch level {
	case EventLevelCritical:
		return 5.0
	case EventLevelError:
		return 4.0
	case EventLevelWarning:
		return 3.0
	case EventLevelInfo:
		return 2.0
	case EventLevelVerbose:
		return 1.0
	default:
		return 0.0
	}
}

func CalculateRuleScore(rule *AlertRule, stats *AlertStats) float64 {
	var score float64

	score += eventLevelToScore(rule.Severity.Level()) * DefaultRuleWeights["severity"] * 100

	if len(rule.MITREAttack) > 0 {
		score += float64(len(rule.MITREAttack)) * DefaultRuleWeights["mitre_coverage"] * 10
	}

	return score
}

type RuleMetadata struct {
	Author     string    `json:"author,omitempty"`
	Version    string    `json:"version,omitempty"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
	Category   string    `json:"category,omitempty"`
	Industry   string    `json:"industry,omitempty"`
	References []string  `json:"references,omitempty"`
}

func (r *AlertRule) MarshalJSON() ([]byte, error) {
	type Alias AlertRule
	return json.Marshal(&struct {
		*Alias
		RuleType string `json:"rule_type"`
	}{
		Alias:    (*Alias)(r),
		RuleType: "alert",
	})
}

func (r *CorrelationRule) MarshalJSON() ([]byte, error) {
	type Alias CorrelationRule
	return json.Marshal(&struct {
		*Alias
		RuleType string `json:"rule_type"`
	}{
		Alias:    (*Alias)(r),
		RuleType: "correlation",
	})
}
