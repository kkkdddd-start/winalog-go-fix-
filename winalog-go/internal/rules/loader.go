package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Loader struct {
	rulePaths []string
	validator *Validator
}

func NewLoader(paths []string) *Loader {
	return &Loader{
		rulePaths: paths,
		validator: NewValidator(),
	}
}

func (l *Loader) Load() ([]*AlertRule, []*CorrelationRule, error) {
	alertRules := make([]*AlertRule, 0)
	correlationRules := make([]*CorrelationRule, 0)
	var errs []string

	for _, path := range l.rulePaths {
		rules, corrRules, err := l.loadFromPath(path)
		if err != nil {
			errs = append(errs, fmt.Sprintf("path %s: %v", path, err))
			continue
		}
		alertRules = append(alertRules, rules...)
		correlationRules = append(correlationRules, corrRules...)
	}

	if len(errs) > 0 {
		return alertRules, correlationRules, fmt.Errorf("loading errors: %s", strings.Join(errs, "; "))
	}
	return alertRules, correlationRules, nil
}

func (l *Loader) loadFromPath(path string) ([]*AlertRule, []*CorrelationRule, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}

	if info.IsDir() {
		return l.loadFromDir(path)
	}

	return l.loadFromFile(path)
}

func (l *Loader) loadFromDir(dir string) ([]*AlertRule, []*CorrelationRule, error) {
	alertRules := make([]*AlertRule, 0)
	correlationRules := make([]*CorrelationRule, 0)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		filePath := filepath.Join(dir, entry.Name())
		rules, corrRules, err := l.loadFromFile(filePath)
		if err != nil {
			continue
		}

		alertRules = append(alertRules, rules...)
		correlationRules = append(correlationRules, corrRules...)
	}

	return alertRules, correlationRules, nil
}

func (l *Loader) loadFromFile(filePath string) ([]*AlertRule, []*CorrelationRule, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}

	var doc YAMLDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}

	alertRules := make([]*AlertRule, 0)
	correlationRules := make([]*CorrelationRule, 0)
	var errs []string

	for _, rule := range doc.AlertRules {
		if err := l.validator.ValidateAlertRule(rule); err != nil {
			errs = append(errs, fmt.Sprintf("alert rule %s: %v", rule.Name, err))
			continue
		}
		alertRules = append(alertRules, rule)
	}

	for _, rule := range doc.CorrelationRules {
		if err := l.validator.ValidateCorrelationRule(rule); err != nil {
			errs = append(errs, fmt.Sprintf("correlation rule %s: %v", rule.Name, err))
			continue
		}
		correlationRules = append(correlationRules, rule)
	}

	if len(errs) > 0 {
		return alertRules, correlationRules, fmt.Errorf("validation errors in %s: %s", filePath, strings.Join(errs, "; "))
	}
	return alertRules, correlationRules, nil
}

type YAMLDocument struct {
	AlertRules       []*AlertRule       `yaml:"alert_rules,omitempty"`
	CorrelationRules []*CorrelationRule `yaml:"correlation_rules,omitempty"`
}

type Validator struct{}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) ValidateAlertRule(rule *AlertRule) error {
	return rule.Validate()
}

func (v *Validator) ValidateCorrelationRule(rule *CorrelationRule) error {
	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}

	if len(rule.Patterns) < 2 {
		return fmt.Errorf("correlation rule requires at least 2 patterns")
	}

	for i, pattern := range rule.Patterns {
		if pattern.EventID == 0 {
			return fmt.Errorf("pattern %d has invalid event_id", i)
		}
	}

	return nil
}

func (v *Validator) ValidateMITREID(id string) bool {
	return validateMitreIDFormat(id) == nil
}

func (v *Validator) ValidateThreshold(threshold int) error {
	if threshold < 0 {
		return fmt.Errorf("threshold must be non-negative")
	}
	return nil
}

func (v *Validator) ValidateTimeWindow(tw time.Duration) error {
	if tw < 0 {
		return fmt.Errorf("time_window must be non-negative")
	}
	return nil
}

func LoadRulesFromFile(filePath string) ([]*AlertRule, error) {
	loader := NewLoader([]string{filePath})
	alertRules, _, err := loader.Load()
	return alertRules, err
}

func LoadCorrelationRulesFromFile(filePath string) ([]*CorrelationRule, error) {
	loader := NewLoader([]string{filePath})
	_, corrRules, err := loader.Load()
	return corrRules, err
}
