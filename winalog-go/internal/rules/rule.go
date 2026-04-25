package rules

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type LogicalOp string

const (
	OpAnd LogicalOp = "AND"
	OpOr  LogicalOp = "OR"
)

type AlertRule struct {
	Name           string         `yaml:"name"`
	Description    string         `yaml:"description"`
	Enabled        bool           `yaml:"enabled"`
	Severity       types.Severity `yaml:"severity"`
	Score          float64        `yaml:"score"`
	MitreAttack    string         `yaml:"mitre_attack,omitempty"`
	Priority       int            `yaml:"priority"` // 1-100，默认 50
	Weight         float64        `yaml:"weight"`   // 告警权重，默认 1.0
	Filter         *Filter        `yaml:"filter"`
	Conditions     *Conditions    `yaml:"conditions,omitempty"`
	Threshold      int            `yaml:"threshold,omitempty"`
	TimeWindow     time.Duration  `yaml:"time_window,omitempty"`
	AggregationKey string         `yaml:"aggregation_key,omitempty"`
	Message        string         `yaml:"message"`
	Tags           []string       `yaml:"tags,omitempty"`
	Status         string         `yaml:"status,omitempty"`
	Product        string         `yaml:"logsource,omitempty"`
	LogSource      *LogSource     `yaml:"logsource,omitempty"`
	FalsePositives []string       `yaml:"falsepositives,omitempty"`
	Level          string         `yaml:"level,omitempty"`
	References     []string       `yaml:"references,omitempty"`
}

func (r *AlertRule) BuildMessage(event *types.Event) string {
	if r.Message == "" {
		return fmt.Sprintf("Alert triggered by rule %s", r.Name)
	}

	msg := r.Message
	msg = strings.ReplaceAll(msg, "{{.EventID}}", fmt.Sprintf("%d", event.EventID))
	msg = strings.ReplaceAll(msg, "{{.Source}}", event.Source)
	msg = strings.ReplaceAll(msg, "{{.Computer}}", event.Computer)
	var userStr string
	if event.User != nil {
		userStr = *event.User
	} else if event.UserSID != nil {
		userStr = *event.UserSID
	}
	msg = strings.ReplaceAll(msg, "{{.User}}", userStr)
	msg = strings.ReplaceAll(msg, "{{.Message}}", event.Message)

	return msg
}

type CorrelationRule struct {
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	Enabled     bool           `yaml:"enabled"`
	Severity    types.Severity `yaml:"severity"`
	Patterns    []*Pattern     `yaml:"patterns"`
	TimeWindow  time.Duration  `yaml:"time_window"`
	Join        string         `yaml:"join"`
	MitreAttack string         `yaml:"mitre_attack,omitempty"`
	Tags        []string       `yaml:"tags,omitempty"`
}

type Pattern struct {
	EventID    int32         `yaml:"event_id"`
	Conditions []*Condition  `yaml:"conditions,omitempty"`
	Join       string        `yaml:"join,omitempty"`
	TimeWindow time.Duration `yaml:"time_window,omitempty"`
	MinCount   int           `yaml:"min_count,omitempty"`
	MaxCount   int           `yaml:"max_count,omitempty"`
	Ordered    bool          `yaml:"ordered,omitempty"`
	Negate     bool          `yaml:"negate,omitempty"`
}

type Filter struct {
	EventIDs         []int32          `yaml:"event_ids,omitempty"`
	Levels           []string         `yaml:"levels,omitempty"`
	LogNames         []string         `yaml:"log_names,omitempty"`
	Sources          []string         `yaml:"sources,omitempty"`
	Computers        []string         `yaml:"computers,omitempty"`
	Keywords         string           `yaml:"keywords,omitempty"`
	KeywordMode      LogicalOp        `yaml:"keyword_mode,omitempty"`
	TimeRange        *types.TimeRange `yaml:"time_range,omitempty"`
	LogonTypes       []int            `yaml:"logon_types,omitempty"`
	ExcludeUsers     []string         `yaml:"exclude_users,omitempty"`
	ExcludeComputers []string         `yaml:"exclude_computers,omitempty"`
	ExcludeDomains   []string         `yaml:"exclude_domains,omitempty"`
	MinFailureCount  int              `yaml:"min_failure_count,omitempty"`
	IpAddress        []string         `yaml:"ip_address,omitempty"`
	ProcessNames     []string         `yaml:"process_names,omitempty"`
}

type Conditions struct {
	Any  []*Condition `yaml:"any,omitempty"`
	All  []*Condition `yaml:"all,omitempty"`
	None []*Condition `yaml:"none,omitempty"`
}

type Condition struct {
	Field    string `yaml:"field"`
	Operator string `yaml:"operator"`
	Value    string `yaml:"value"`
	Regex    bool   `yaml:"regex,omitempty"`
}

type LogSource struct {
	Product    string `yaml:"product,omitempty"`
	Service    string `yaml:"service,omitempty"`
	Category   string `yaml:"category,omitempty"`
	Definition string `yaml:"definition,omitempty"`
}

type BaseRule struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Enabled     bool     `yaml:"enabled"`
	Tags        []string `yaml:"tags,omitempty"`
}

var validConditionFields = map[string]bool{
	"event_id":        true,
	"level":           true,
	"source":          true,
	"log_name":        true,
	"computer":        true,
	"user":            true,
	"message":         true,
	"ip_address":      true,
	"process_name":    true,
	"command_line":    true,
	"service_name":    true,
	"logon_type":      true,
	"status":          true,
	"provider_name":   true,
	"workstation":     true,
	"domain":          true,
	"target_username": true,
	"task_name":       true,
}

var validOperators = map[string]bool{
	"==":         true,
	"=":          true,
	"!=":         true,
	">":          true,
	">=":         true,
	"<":          true,
	"<=":         true,
	"contains":   true,
	"startswith": true,
	"endswith":   true,
	"not":        true,
	"regex":      true,
}

func (r *AlertRule) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if r.Severity == "" {
		return fmt.Errorf("severity is required")
	}
	if r.Filter == nil && r.Conditions == nil {
		return fmt.Errorf("either filter or conditions is required")
	}

	if r.Threshold > 0 && r.TimeWindow == 0 {
		return fmt.Errorf("threshold requires time_window to be set")
	}

	validSeverities := map[types.Severity]bool{
		types.SeverityCritical: true,
		types.SeverityHigh:     true,
		types.SeverityMedium:   true,
		types.SeverityLow:      true,
		types.SeverityInfo:     true,
	}
	if !validSeverities[r.Severity] {
		return fmt.Errorf("invalid severity: %s", r.Severity)
	}

	if r.MitreAttack != "" {
		if err := validateMitreIDFormat(r.MitreAttack); err != nil {
			return err
		}
	}

	if r.Filter != nil {
		if err := r.validateFilter(r.Filter); err != nil {
			return fmt.Errorf("filter validation failed: %w", err)
		}
	}

	if r.Conditions != nil {
		if err := r.validateConditions(r.Conditions); err != nil {
			return fmt.Errorf("conditions validation failed: %w", err)
		}
	}

	return nil
}

func (r *AlertRule) validateFilter(f *Filter) error {
	for _, eid := range f.EventIDs {
		if eid < 0 || eid > 65535 {
			return fmt.Errorf("invalid event_id: %d (must be 0-65535)", eid)
		}
	}

	for _, lvl := range f.Levels {
		if !types.EventLevel(lvl).IsValid() {
			return fmt.Errorf("invalid level: %s (must be Critical, Error, Warning, Info, Verbose)", lvl)
		}
	}

	if f.Keywords != "" && f.KeywordMode == "" {
		return fmt.Errorf("keywords requires keyword_mode to be set")
	}

	if f.TimeRange != nil {
		if f.TimeRange.End.Before(f.TimeRange.Start) {
			return fmt.Errorf("time_range end must be after start")
		}
	}

	return nil
}

func (r *AlertRule) validateConditions(c *Conditions) error {
	validateCondition := func(cond *Condition) error {
		if cond.Field == "" {
			return fmt.Errorf("condition field is required")
		}
		if !validConditionFields[cond.Field] {
			return fmt.Errorf("invalid condition field: %s", cond.Field)
		}

		if !validOperators[cond.Operator] {
			return fmt.Errorf("invalid operator: %s", cond.Operator)
		}

		if cond.Regex {
			if _, err := regexp.Compile(cond.Value); err != nil {
				return fmt.Errorf("invalid regex pattern: %w", err)
			}
		}

		return nil
	}

	for _, anyCond := range c.Any {
		if err := validateCondition(anyCond); err != nil {
			return err
		}
	}
	for _, allCond := range c.All {
		if err := validateCondition(allCond); err != nil {
			return err
		}
	}
	for _, noneCond := range c.None {
		if err := validateCondition(noneCond); err != nil {
			return err
		}
	}

	return nil
}

func (r *CorrelationRule) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if len(r.Patterns) < 2 {
		return fmt.Errorf("correlation rule requires at least 2 patterns")
	}
	for i, pattern := range r.Patterns {
		if pattern.EventID == 0 {
			return fmt.Errorf("pattern %d has invalid event_id", i)
		}
	}
	return nil
}

func ParseSeverity(s string) (types.Severity, error) {
	switch s {
	case "critical":
		return types.SeverityCritical, nil
	case "high":
		return types.SeverityHigh, nil
	case "medium":
		return types.SeverityMedium, nil
	case "low":
		return types.SeverityLow, nil
	case "info":
		return types.SeverityInfo, nil
	default:
		return types.SeverityInfo, fmt.Errorf("unknown severity: %s", s)
	}
}

func ScoreValue(s types.Severity) float64 {
	switch s {
	case types.SeverityCritical:
		return 100
	case types.SeverityHigh:
		return 75
	case types.SeverityMedium:
		return 50
	case types.SeverityLow:
		return 25
	default:
		return 10
	}
}

var mitreIDRegex = regexp.MustCompile(`^(T\d{4}(?:\.\d{3})?)$`)

func validateMitreIDFormat(id string) error {
	if id == "" {
		return nil
	}

	if !mitreIDRegex.MatchString(id) {
		return fmt.Errorf("invalid mitre_attack format: %s (expected T#### or T####.###)", id)
	}

	tacticStr := strings.TrimPrefix(id, "T")
	if strings.Contains(tacticStr, ".") {
		tacticStr = strings.Split(tacticStr, ".")[0]
	}

	tacticNum, err := strconv.Atoi(tacticStr)
	if err != nil {
		return fmt.Errorf("invalid mitre_attack: %s", id)
	}

	tacticType := tacticNum / 1000
	if tacticType < 1 || tacticType > 3 {
		return fmt.Errorf("invalid mitre_attack: %s (tactic type must be 1-3)", id)
	}

	return nil
}

func (r *AlertRule) GetPriority() int {
	if r.Priority <= 0 {
		return 50
	}
	if r.Priority > 100 {
		return 100
	}
	return r.Priority
}

func (r *AlertRule) GetWeight() float64 {
	if r.Weight <= 0 {
		return 1.0
	}
	return r.Weight
}

func (r *AlertRule) GetEffectiveScore() float64 {
	return r.Score * r.GetWeight()
}

type RuleSorter struct {
	rules []*AlertRule
}

func (s *RuleSorter) Len() int {
	return len(s.rules)
}

func (s *RuleSorter) Less(i, j int) bool {
	pi := s.rules[i].GetPriority()
	pj := s.rules[j].GetPriority()
	if pi != pj {
		return pi > pj
	}
	return s.rules[i].GetWeight() > s.rules[j].GetWeight()
}

func (s *RuleSorter) Swap(i, j int) {
	s.rules[i], s.rules[j] = s.rules[j], s.rules[i]
}

func SortRules(rules []*AlertRule) {
	sorter := &RuleSorter{rules: rules}
	sort.Sort(sorter)
}
