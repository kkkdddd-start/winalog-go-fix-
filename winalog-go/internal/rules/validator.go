package rules

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type ValidationResult struct {
	Valid    bool
	Errors   []string
	Warnings []string
}

func (v *ValidationResult) AddError(msg string) {
	v.Valid = false
	v.Errors = append(v.Errors, msg)
}

func (v *ValidationResult) AddWarning(msg string) {
	v.Warnings = append(v.Warnings, msg)
}

func ValidateRule(rule interface{}) *ValidationResult {
	result := &ValidationResult{Valid: true}

	switch r := rule.(type) {
	case *AlertRule:
		v := NewValidator()
		if err := v.ValidateAlertRule(r); err != nil {
			result.AddError(err.Error())
		}
		result.validateAlertRuleFields(r)
	case *CorrelationRule:
		v := NewValidator()
		if err := v.ValidateCorrelationRule(r); err != nil {
			result.AddError(err.Error())
		}
		result.validateCorrelationRuleFields(r)
	default:
		result.AddError("unknown rule type")
	}

	return result
}

func (v *ValidationResult) validateAlertRuleFields(rule *AlertRule) {
	if len(rule.Name) > 100 {
		v.AddWarning("rule name exceeds 100 characters")
	}

	if rule.Filter != nil {
		v.validateFilterFields(rule.Filter)
	}

	if rule.Conditions != nil {
		v.validateConditionsFields(rule.Conditions)
	}

	if rule.MitreAttack != "" {
		validator := NewValidator()
		if !validator.ValidateMITREID(rule.MitreAttack) {
			v.AddWarning("invalid MITRE ATT&CK ID format")
		}
	}

	if rule.Score < 0 || rule.Score > 100 {
		v.AddWarning("score should be between 0 and 100")
	}

	if rule.Threshold > 0 && rule.TimeWindow == 0 {
		v.AddWarning("threshold set but time_window is zero")
	}
}

func (v *ValidationResult) validateCorrelationRuleFields(rule *CorrelationRule) {
	if len(rule.Patterns) > 10 {
		v.AddWarning("correlation rule has more than 10 patterns")
	}

	for i, pattern := range rule.Patterns {
		if pattern.EventID == 0 {
			v.AddError(fmt.Sprintf("pattern %d has event_id 0", i))
		}

		if len(pattern.Conditions) > 5 {
			v.AddWarning(fmt.Sprintf("pattern %d has more than 5 conditions", i))
		}
	}

	if rule.TimeWindow == 0 {
		v.AddWarning("time_window is zero, may match events at same timestamp")
	}
}

func (v *ValidationResult) validateFilterFields(filter *Filter) {
	if len(filter.EventIDs) > 100 {
		v.AddWarning("filter has more than 100 event IDs")
	}

	eventIDPattern := regexp.MustCompile(`^\d+$`)
	for _, eid := range filter.EventIDs {
		if !eventIDPattern.MatchString(fmt.Sprintf("%d", eid)) {
			v.AddWarning(fmt.Sprintf("invalid event ID: %d", eid))
		}
	}

	levelValues := map[string]bool{
		"Critical": true,
		"Error":    true,
		"Warning":  true,
		"Info":     true,
		"Verbose":  true,
	}
	for _, level := range filter.Levels {
		if !levelValues[level] {
			v.AddWarning(fmt.Sprintf("invalid level: %s", level))
		}
	}
}

func (v *ValidationResult) validateConditionsFields(conditions *Conditions) {
	totalConditions := len(conditions.Any) + len(conditions.All) + len(conditions.None)

	if totalConditions == 0 {
		v.AddWarning("conditions has no actual conditions")
	}

	if totalConditions > 50 {
		v.AddWarning("conditions has more than 50 conditions")
	}

	for _, cond := range conditions.Any {
		v.validateConditionFields(cond)
	}

	for _, cond := range conditions.All {
		v.validateConditionFields(cond)
	}

	for _, cond := range conditions.None {
		v.validateConditionFields(cond)
	}
}

func (v *ValidationResult) validateConditionFields(cond *Condition) {
	validFields := map[string]bool{
		"event_id":        true,
		"level":           true,
		"source":          true,
		"log_name":        true,
		"computer":        true,
		"user":            true,
		"user_sid":        true,
		"ip_address":      true,
		"message":         true,
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

	field := strings.ToLower(cond.Field)
	if !validFields[field] {
		v.AddWarning(fmt.Sprintf("unknown field: %s", cond.Field))
	}

	validOperators := map[string]bool{
		"==":         true,
		"=":          true,
		"!=":         true,
		">":          true,
		"<":          true,
		">=":         true,
		"<=":         true,
		"contains":   true,
		"not":        true,
		"startswith": true,
		"endswith":   true,
		"regex":      true,
	}

	if !validOperators[cond.Operator] {
		v.AddWarning(fmt.Sprintf("unknown operator: %s", cond.Operator))
	}

	if cond.Value == "" && !cond.Regex {
		v.AddWarning("condition value is empty")
	}
}

func ValidateRuleSyntax(ruleYAML string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	var doc YAMLDocument
	if err := unmarshalYAML(ruleYAML, &doc); err != nil {
		result.AddError(fmt.Sprintf("YAML parse error: %v", err))
		return result
	}

	for _, rule := range doc.AlertRules {
		if err := NewValidator().ValidateAlertRule(rule); err != nil {
			result.AddError(err.Error())
		}
	}

	for _, rule := range doc.CorrelationRules {
		if err := NewValidator().ValidateCorrelationRule(rule); err != nil {
			result.AddError(err.Error())
		}
	}

	return result
}

func unmarshalYAML(data string, v interface{}) error {
	if data == "" {
		return fmt.Errorf("empty YAML data")
	}

	err := yaml.Unmarshal([]byte(data), v)
	if err != nil {
		return fmt.Errorf("YAML parse error: %w", err)
	}

	return nil
}
