package builtin

import (
	"github.com/kkkdddd-start/winalog-go/internal/rules"
)

type Registry struct {
	alertRules       []*rules.AlertRule
	correlationRules []*rules.CorrelationRule
}

func NewRegistry() *Registry {
	return &Registry{
		alertRules:       make([]*rules.AlertRule, 0),
		correlationRules: make([]*rules.CorrelationRule, 0),
	}
}

func (r *Registry) RegisterAlertRule(rule *rules.AlertRule) {
	r.alertRules = append(r.alertRules, rule)
}

func (r *Registry) RegisterCorrelationRule(rule *rules.CorrelationRule) {
	r.correlationRules = append(r.correlationRules, rule)
}

func (r *Registry) GetAlertRules() []*rules.AlertRule {
	return r.alertRules
}

func (r *Registry) GetCorrelationRules() []*rules.CorrelationRule {
	return r.correlationRules
}

func (r *Registry) GetAlertRuleByName(name string) *rules.AlertRule {
	for _, rule := range r.alertRules {
		if rule.Name == name {
			return rule
		}
	}
	return nil
}

func (r *Registry) GetCorrelationRuleByName(name string) *rules.CorrelationRule {
	for _, rule := range r.correlationRules {
		if rule.Name == name {
			return rule
		}
	}
	return nil
}

func LoadDefaultRules() *Registry {
	registry := NewRegistry()

	for _, rule := range GetAlertRules() {
		registry.RegisterAlertRule(rule)
	}

	for _, rule := range GetCorrelationRules() {
		registry.RegisterCorrelationRule(rule)
	}

	return registry
}
