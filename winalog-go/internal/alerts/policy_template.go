package alerts

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type PolicyTemplate struct {
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	PolicyType   PolicyType        `json:"policy_type"`
	Parameters   []PolicyParam     `json:"parameters,omitempty"`
	Conditions   []PolicyCondition `json:"conditions"`
	Actions      []PolicyAction    `json:"actions"`
	TimeWindow   time.Duration     `json:"time_window"`
	Enabled      bool              `json:"enabled"`
	Priority     int               `json:"priority"`
	MITREMapping []string          `json:"mitre_mapping,omitempty"`
	BuiltIn      bool              `json:"built_in"`
}

type PolicyType string

const (
	PolicyTypeUpgrade   PolicyType = "upgrade"
	PolicyTypeSuppress  PolicyType = "suppress"
	PolicyTypeComposite PolicyType = "composite"
)

type PolicyParam struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Default     string   `json:"default,omitempty"`
	Required    bool     `json:"required"`
	Type        string   `json:"type"`
	Options     []string `json:"options,omitempty"`
}

type PolicyCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

type PolicyAction struct {
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

type PolicyManager struct {
	mu        sync.RWMutex
	templates map[string]*PolicyTemplate
	instances map[string]*PolicyInstance
}

type PolicyInstance struct {
	TemplateName string
	RuleName     string
	Parameters   map[string]string
	CreatedAt    time.Time
	ExpiresAt    *time.Time
	Enabled      bool
}

var (
	defaultPolicyManager *PolicyManager
	once                 sync.Once
)

func GetPolicyManager() *PolicyManager {
	once.Do(func() {
		defaultPolicyManager = &PolicyManager{
			templates: make(map[string]*PolicyTemplate),
			instances: make(map[string]*PolicyInstance),
		}
		defaultPolicyManager.registerBuiltInTemplates()
	})
	return defaultPolicyManager
}

func (m *PolicyManager) registerBuiltInTemplates() {
	m.templates["brute_force_protection"] = &PolicyTemplate{
		Name:        "brute_force_protection",
		Description: "Automatic alert upgrade for brute force attack detection",
		PolicyType:  PolicyTypeUpgrade,
		Parameters: []PolicyParam{
			{Name: "threshold", Description: "Failed login threshold", Default: "10", Required: true, Type: "int"},
			{Name: "window", Description: "Time window in minutes", Default: "5", Required: true, Type: "int"},
			{Name: "new_severity", Description: "Severity to upgrade to", Default: "high", Required: false, Type: "select", Options: []string{"critical", "high", "medium"}},
		},
		Conditions: []PolicyCondition{
			{Field: "event_id", Operator: "equals", Value: 4625},
			{Field: "level", Operator: "gte", Value: 2},
		},
		Actions: []PolicyAction{
			{Type: "upgrade_severity", Parameters: map[string]interface{}{"severity": "{{new_severity}}"}},
			{Type: "increment_threshold", Parameters: map[string]interface{}{"count": 1}},
		},
		TimeWindow:   5 * time.Minute,
		Enabled:      true,
		Priority:     10,
		MITREMapping: []string{"T1110"},
		BuiltIn:      true,
	}

	m.templates["lateral_movement_suppress"] = &PolicyTemplate{
		Name:        "lateral_movement_suppress",
		Description: "Suppress alerts from known trusted source computers",
		PolicyType:  PolicyTypeSuppress,
		Parameters: []PolicyParam{
			{Name: "source_computer", Description: "Trusted source computer name", Default: "", Required: true, Type: "string"},
			{Name: "duration", Description: "Suppression duration in hours", Default: "24", Required: false, Type: "int"},
		},
		Conditions: []PolicyCondition{
			{Field: "source", Operator: "equals", Value: "Microsoft-Windows-Security-Auditing"},
			{Field: "event_id", Operator: "in", Value: []int{4624, 4625, 4672}},
		},
		Actions: []PolicyAction{
			{Type: "suppress", Parameters: map[string]interface{}{"scope": "{{source_computer}}"}},
		},
		TimeWindow: 24 * time.Hour,
		Enabled:    true,
		Priority:   5,
		BuiltIn:    true,
	}

	m.templates["credential_theft_alert"] = &PolicyTemplate{
		Name:        "credential_theft_alert",
		Description: "Enhanced alerting for credential theft indicators",
		PolicyType:  PolicyTypeUpgrade,
		Parameters: []PolicyParam{
			{Name: "min_event_count", Description: "Minimum suspicious events", Default: "3", Required: true, Type: "int"},
			{Name: "escalate_to", Description: "Severity to escalate to", Default: "critical", Required: false, Type: "select", Options: []string{"critical", "high"}},
		},
		Conditions: []PolicyCondition{
			{Field: "event_id", Operator: "in", Value: []int{4624, 4625, 4648, 4672}},
			{Field: "logon_type", Operator: "in", Value: []int{3, 10}},
		},
		Actions: []PolicyAction{
			{Type: "upgrade_severity", Parameters: map[string]interface{}{"severity": "{{escalate_to}}"}},
			{Type: "tag", Parameters: map[string]interface{}{"label": "credential_theft"}},
		},
		TimeWindow:   10 * time.Minute,
		Enabled:      true,
		Priority:     20,
		MITREMapping: []string{"T1003", "T1078", "T1110"},
		BuiltIn:      true,
	}

	m.templates["malware_activity_detect"] = &PolicyTemplate{
		Name:        "malware_activity_detect",
		Description: "Detect and upgrade malware-related activity",
		PolicyType:  PolicyTypeUpgrade,
		Parameters: []PolicyParam{
			{Name: "sensitivity", Description: "Detection sensitivity", Default: "medium", Required: false, Type: "select", Options: []string{"low", "medium", "high"}},
		},
		Conditions: []PolicyCondition{
			{Field: "source", Operator: "contains", Value: "Microsoft-Windows-Windows Defender"},
			{Field: "event_id", Operator: "in", Value: []int{1006, 1007, 1008, 1116, 1117}},
		},
		Actions: []PolicyAction{
			{Type: "upgrade_severity", Parameters: map[string]interface{}{"severity": "high"}},
			{Type: "notify", Parameters: map[string]interface{}{"channel": "security"}},
		},
		TimeWindow:   1 * time.Minute,
		Enabled:      true,
		Priority:     15,
		MITREMapping: []string{"T1566", "T1006", "T1059"},
		BuiltIn:      true,
	}
}

func (m *PolicyManager) ListTemplates() []*PolicyTemplate {
	m.mu.RLock()
	defer m.mu.RUnlock()

	templates := make([]*PolicyTemplate, 0, len(m.templates))
	for _, t := range m.templates {
		templates = append(templates, t)
	}
	return templates
}

func (m *PolicyManager) GetTemplate(name string) (*PolicyTemplate, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	t, ok := m.templates[name]
	return t, ok
}

func (m *PolicyManager) InstantiateTemplate(templateName string, ruleName string, params map[string]string) (*PolicyInstance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	template, ok := m.templates[templateName]
	if !ok {
		return nil, fmt.Errorf("template '%s' not found", templateName)
	}

	for _, p := range template.Parameters {
		if p.Required {
			if val, ok := params[p.Name]; !ok || val == "" {
				if p.Default == "" {
					return nil, fmt.Errorf("required parameter '%s' is missing", p.Name)
				}
			}
		}
	}

	instance := &PolicyInstance{
		TemplateName: templateName,
		RuleName:     ruleName,
		Parameters:   params,
		CreatedAt:    time.Now(),
		Enabled:      true,
	}

	key := fmt.Sprintf("%s_%s_%s", templateName, ruleName, uuid.New().String())
	m.instances[key] = instance

	return instance, nil
}

func (m *PolicyManager) ListInstances() []*PolicyInstance {
	m.mu.RLock()
	defer m.mu.RUnlock()

	instances := make([]*PolicyInstance, 0, len(m.instances))
	for _, inst := range m.instances {
		instances = append(instances, inst)
	}
	return instances
}

func (m *PolicyManager) DeleteInstance(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.instances[key]; ok {
		delete(m.instances, key)
		return true
	}
	return false
}

func (m *PolicyManager) ApplyToEngine(e *Engine) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, inst := range m.instances {
		if !inst.Enabled {
			continue
		}

		template, ok := m.templates[inst.TemplateName]
		if !ok {
			continue
		}

		switch template.PolicyType {
		case PolicyTypeUpgrade:
			m.applyUpgradePolicy(e, template, inst)
		case PolicyTypeSuppress:
			m.applySuppressPolicy(e, template, inst)
		}
	}
	return nil
}

func (m *PolicyManager) applyUpgradePolicy(e *Engine, template *PolicyTemplate, inst *PolicyInstance) {
	for _, action := range template.Actions {
		if action.Type == "upgrade_severity" {
			severityStr := inst.Parameters["new_severity"]
			if severityStr == "" {
				severityStr = "high"
			}

			threshold := 5
			if t, ok := inst.Parameters["threshold"]; ok {
				_, _ = fmt.Sscanf(t, "%d", &threshold)
			}

			upgradeRule := &types.AlertUpgradeRule{
				ID:          0,
				Name:        inst.RuleName,
				Condition:   template.Name,
				Threshold:   threshold,
				NewSeverity: types.Severity(severityStr),
				Notify:      true,
				Enabled:     true,
			}
			e.AddUpgradeRule(upgradeRule)
		}
	}
}

func (m *PolicyManager) applySuppressPolicy(e *Engine, template *PolicyTemplate, inst *PolicyInstance) {
	for _, action := range template.Actions {
		if action.Type == "suppress" {
			duration := 24 * time.Hour
			if d, ok := inst.Parameters["duration"]; ok {
				var hours int
				_, _ = fmt.Sscanf(d, "%d", &hours)
				duration = time.Duration(hours) * time.Hour
			}

			sourceComputer := inst.Parameters["source_computer"]
			if sourceComputer == "" {
				sourceComputer = "*"
			}

			suppressRule := &types.SuppressRule{
				ID:       0,
				Name:     inst.RuleName,
				Scope:    sourceComputer,
				Duration: duration,
				Enabled:  true,
			}

			for _, cond := range template.Conditions {
				suppressRule.Conditions = append(suppressRule.Conditions, types.SuppressCondition{
					Field:    cond.Field,
					Operator: cond.Operator,
					Value:    cond.Value,
				})
			}

			e.AddSuppressRule(suppressRule)
		}
	}
}

func (m *PolicyManager) CreateCustomTemplate(template *PolicyTemplate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if template.Name == "" {
		return fmt.Errorf("template name is required")
	}

	if existing, ok := m.templates[template.Name]; ok {
		if existing.BuiltIn {
			return fmt.Errorf("cannot override built-in template '%s'", template.Name)
		}
	}

	template.BuiltIn = false
	m.templates[template.Name] = template
	return nil
}

func (m *PolicyManager) DeleteTemplate(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.templates[name]; ok {
		if existing.BuiltIn {
			return false
		}
	}

	if _, ok := m.templates[name]; ok {
		delete(m.templates, name)
		return true
	}
	return false
}

func (m *PolicyManager) EvaluatePolicy(event *types.Event, template *PolicyTemplate) (bool, []PolicyAction) {
	if !template.Enabled {
		return false, nil
	}

	allMatch := true
	for _, cond := range template.Conditions {
		if !m.matchCondition(event, cond) {
			allMatch = false
			break
		}
	}

	if allMatch {
		return true, template.Actions
	}
	return false, nil
}

func (m *PolicyManager) matchCondition(event *types.Event, cond PolicyCondition) bool {
	switch cond.Field {
	case "event_id":
		return m.compareValue(event.EventID, cond.Operator, cond.Value)
	case "source":
		return m.compareValue(event.Source, cond.Operator, cond.Value)
	case "computer":
		return m.compareValue(event.Computer, cond.Operator, cond.Value)
	case "level":
		return m.compareValue(string(event.Level), cond.Operator, cond.Value)
	case "log_name":
		return m.compareValue(event.LogName, cond.Operator, cond.Value)
	}
	return false
}

func (m *PolicyManager) compareValue(fieldValue interface{}, operator string, condValue interface{}) bool {
	switch operator {
	case "equals":
		return fmt.Sprintf("%v", fieldValue) == fmt.Sprintf("%v", condValue)
	case "not_equals":
		return fmt.Sprintf("%v", fieldValue) != fmt.Sprintf("%v", condValue)
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", fieldValue), fmt.Sprintf("%v", condValue))
	case "in":
		// 支持 []int, []interface{} (JSON 反序列化), []float64 等
		condStr := fmt.Sprintf("%v", fieldValue)
		switch arr := condValue.(type) {
		case []int:
			if intVal, ok := fieldValue.(int); ok {
				for _, v := range arr {
					if intVal == v {
						return true
					}
				}
			}
		case []interface{}:
			for _, v := range arr {
				if fmt.Sprintf("%v", v) == condStr {
					return true
				}
			}
		}
		return false
	case "gte":
		return m.compareNumeric(fieldValue, condValue) >= 0
	case "lte":
		return m.compareNumeric(fieldValue, condValue) <= 0
	case "gt":
		return m.compareNumeric(fieldValue, condValue) > 0
	case "lt":
		return m.compareNumeric(fieldValue, condValue) < 0
	}
	return false
}

func (m *PolicyManager) compareNumeric(a, b interface{}) int {
	var aVal, bVal float64

	switch v := a.(type) {
	case int:
		aVal = float64(v)
	case int32:
		aVal = float64(v)
	case int64:
		aVal = float64(v)
	case float64:
		aVal = v
	}

	switch v := b.(type) {
	case int:
		bVal = float64(v)
	case int32:
		bVal = float64(v)
	case int64:
		bVal = float64(v)
	case float64:
		bVal = v
	}

	if aVal < bVal {
		return -1
	} else if aVal > bVal {
		return 1
	}
	return 0
}
