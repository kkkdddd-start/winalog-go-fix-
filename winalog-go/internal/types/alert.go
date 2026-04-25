package types

import (
	"database/sql"
	"encoding/json"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

func (s Severity) String() string {
	return string(s)
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	*s = Severity(str)
	return nil
}

func (s Severity) Level() EventLevel {
	switch s {
	case SeverityCritical:
		return EventLevelCritical
	case SeverityHigh:
		return EventLevelError
	case SeverityMedium:
		return EventLevelWarning
	case SeverityLow:
		return EventLevelInfo
	case SeverityInfo:
		return EventLevelVerbose
	default:
		return EventLevelInfo
	}
}

type Alert struct {
	ID            int64      `json:"id" db:"id"`
	RuleName      string     `json:"rule_name" db:"rule_name"`
	Severity      Severity   `json:"severity" db:"severity"`
	Message       string     `json:"message" db:"message"`
	EventIDs      []int32    `json:"event_ids" db:"event_ids"`
	EventDBIDs    []int64    `json:"event_db_ids" db:"event_db_ids"`
	FirstSeen     time.Time  `json:"first_seen" db:"first_seen"`
	LastSeen      time.Time  `json:"last_seen" db:"last_seen"`
	Count         int        `json:"count" db:"count"`
	MITREAttack   []string   `json:"mitre_attack,omitempty" db:"mitre_attack"`
	Resolved      bool       `json:"resolved" db:"resolved"`
	ResolvedTime  *time.Time `json:"resolved_time,omitempty" db:"resolved_time"`
	Notes         string     `json:"notes,omitempty" db:"notes"`
	FalsePositive bool       `json:"false_positive" db:"false_positive"`
	LogName       string     `json:"log_name" db:"log_name"`
	RuleScore     float64    `json:"rule_score" db:"rule_score"`
}

func (a *Alert) ToMap() map[string]interface{} {
	eventIDsJSON, _ := json.Marshal(a.EventIDs)
	eventDBIDsJSON, _ := json.Marshal(a.EventDBIDs)
	mitreJSON, _ := json.Marshal(a.MITREAttack)

	m := map[string]interface{}{
		"rule_name":      a.RuleName,
		"severity":       a.Severity,
		"message":        a.Message,
		"event_ids":      string(eventIDsJSON),
		"event_db_ids":   string(eventDBIDsJSON),
		"first_seen":     a.FirstSeen,
		"last_seen":      a.LastSeen,
		"count":          a.Count,
		"mitre_attack":   string(mitreJSON),
		"resolved":       a.Resolved,
		"notes":          a.Notes,
		"false_positive": a.FalsePositive,
		"log_name":       a.LogName,
		"rule_score":     a.RuleScore,
	}
	if a.ResolvedTime != nil {
		m["resolved_time"] = *a.ResolvedTime
	}
	return m
}

func ScanAlert(row interface{ Scan(...interface{}) error }) (*Alert, error) {
	var a Alert
	var eventIDsJSON, mitreJSON sql.NullString
	var resolvedTime sql.NullInt64
	var notes sql.NullString

	err := row.Scan(
		&a.ID,
		&a.RuleName,
		&a.Severity,
		&a.Message,
		&eventIDsJSON,
		&a.FirstSeen,
		&a.LastSeen,
		&a.Count,
		&mitreJSON,
		&a.Resolved,
		&resolvedTime,
		&notes,
		&a.FalsePositive,
		&a.LogName,
		&a.RuleScore,
	)
	if err != nil {
		return nil, err
	}

	if eventIDsJSON.Valid {
		json.Unmarshal([]byte(eventIDsJSON.String), &a.EventIDs)
	}
	if mitreJSON.Valid {
		json.Unmarshal([]byte(mitreJSON.String), &a.MITREAttack)
	}
	if resolvedTime.Valid {
		t := time.Unix(resolvedTime.Int64, 0)
		a.ResolvedTime = &t
	}
	if notes.Valid {
		a.Notes = notes.String
	}

	return &a, nil
}

type AlertStats struct {
	Total        int64            `json:"total"`
	BySeverity   map[string]int64 `json:"by_severity"`
	ByStatus     map[string]int64 `json:"by_status"`
	ByRule       []*RuleCount     `json:"by_rule"`
	Trend        []*TrendPoint    `json:"trend"`
	AvgPerDay    float64          `json:"avg_per_day"`
	RuleScoreAvg float64          `json:"rule_score_avg"`
}

type RuleCount struct {
	RuleName   string  `json:"rule_name"`
	Count      int64   `json:"count"`
	Percentage float64 `json:"percentage"`
}

type TrendPoint struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

type AlertTrend struct {
	Daily       []*TrendPoint `json:"daily"`
	Weekly      []*TrendPoint `json:"weekly"`
	ByHour      []*TrendPoint `json:"by_hour"`
	ByDayOfWeek []*TrendPoint `json:"by_day_of_week"`
}

type AlertUpgradeRule struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Condition   string   `json:"condition"`
	Threshold   int      `json:"threshold"`
	NewSeverity Severity `json:"new_severity"`
	Notify      bool     `json:"notify"`
	Enabled     bool     `json:"enabled"`
}

type SuppressRule struct {
	ID         int64               `json:"id"`
	Name       string              `json:"name"`
	Conditions []SuppressCondition `json:"conditions"`
	Duration   time.Duration       `json:"duration"`
	Scope      string              `json:"scope"`
	Enabled    bool                `json:"enabled"`
	ExpiresAt  time.Time           `json:"expires_at,omitempty"`
	CreatedAt  time.Time           `json:"created_at"`
}

type SuppressCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

type CorrelationResult struct {
	ID          string    `json:"id"`
	RuleName    string    `json:"rule_name"`
	Description string    `json:"description"`
	Severity    Severity  `json:"severity"`
	Events      []*Event  `json:"events"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	MITREAttack []string  `json:"mitre_attack,omitempty"`
}

type AlertStatsData struct {
	TotalCount   int64
	BySeverity   map[string]int64
	ByStatus     map[string]int64
	ByRule       map[string]int64
	TopRules     []*RuleCount
	AvgPerDay    float64
	RuleScoreAvg float64
}

type AttackChain struct {
	ID          string    `json:"id"`
	EventIDs    []int64   `json:"event_ids"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Severity    Severity  `json:"severity"`
	Description string    `json:"description"`
	Technique   string    `json:"technique"`
	Events      []*Event  `json:"events"`
}
