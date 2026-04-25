package correlation

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/rules"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type Matcher struct{}

func NewMatcher() *Matcher {
	return &Matcher{}
}

func (m *Matcher) Match(rule *rules.CorrelationRule, events []*types.Event) bool {
	if len(rule.Patterns) != len(events) {
		return false
	}

	for i, pattern := range rule.Patterns {
		event := events[i]
		if !m.matchPattern(pattern, event) {
			return false
		}
	}

	return true
}

func (m *Matcher) matchPattern(pattern *rules.Pattern, event *types.Event) bool {
	if pattern.EventID != 0 && event.EventID != pattern.EventID {
		return false
	}

	if len(pattern.Conditions) > 0 {
		if !m.matchConditions(pattern.Conditions, event) {
			return false
		}
	}

	return true
}

func (m *Matcher) matchConditions(conditions []*rules.Condition, event *types.Event) bool {
	for _, cond := range conditions {
		if !m.matchCondition(cond, event) {
			return false
		}
	}
	return true
}

func (m *Matcher) matchCondition(cond *rules.Condition, event *types.Event) bool {
	field := cond.Field
	value := cond.Value
	op := cond.Operator
	if op == "" {
		op = "=="
	}

	getUserStr := func() string {
		if event.User != nil {
			return *event.User
		}
		return ""
	}

	switch field {
	case "source":
		return m.compareString(event.Source, value, op)
	case "log_name":
		return m.compareString(event.LogName, value, op)
	case "computer":
		return m.compareString(event.Computer, value, op)
	case "user":
		return m.compareString(getUserStr(), value, op)
	case "message":
		return m.compareString(event.Message, value, op)
	case "ip_address":
		if event.IPAddress == nil {
			return false
		}
		return m.compareString(*event.IPAddress, value, op)
	case "destination_port":
		port := m.getExtendedDataInt(event, "DestinationPort")
		return m.compareInt(port, value, op)
	case "logon_type":
		lt := m.getExtendedDataInt(event, "LogonType")
		return m.compareInt(lt, value, op)
	case "status":
		return m.compareString(event.Message, value, op)
	case "process_name":
		return m.compareString(m.getExtendedDataStr(event, "NewProcessName"), value, op)
	case "command_line":
		return m.compareString(m.getExtendedDataStr(event, "CommandLine"), value, op)
	case "service_name":
		return m.compareString(m.getExtendedDataStr(event, "ServiceName"), value, op)
	case "provider_name":
		return m.compareString(event.Source, value, op)
	case "workstation":
		return m.compareString(m.getExtendedDataStr(event, "WorkstationName"), value, op)
	case "domain":
		return m.compareString(m.getExtendedDataStr(event, "TargetDomainName"), value, op)
	case "target_username":
		return m.compareString(m.getExtendedDataStr(event, "TargetUserName"), value, op)
	case "task_name":
		return m.compareString(m.getExtendedDataStr(event, "TaskName"), value, op)
	default:
		return false
	}
}

func (m *Matcher) compareString(fieldValue, condValue, op string) bool {
	switch op {
	case "==", "=", "equals":
		return strings.EqualFold(fieldValue, condValue)
	case "!=", "not_equals":
		return !strings.EqualFold(fieldValue, condValue)
	case "contains":
		return contains(strings.ToLower(fieldValue), strings.ToLower(condValue))
	case "not_contains":
		return !contains(strings.ToLower(fieldValue), strings.ToLower(condValue))
	case "startswith":
		return strings.HasPrefix(strings.ToLower(fieldValue), strings.ToLower(condValue))
	case "endswith":
		return strings.HasSuffix(strings.ToLower(fieldValue), strings.ToLower(condValue))
	case "regex":
		matched, err := regexp.MatchString(condValue, fieldValue)
		return err == nil && matched
	default:
		return strings.EqualFold(fieldValue, condValue)
	}
}

func (m *Matcher) compareInt(fieldValue int, condValue string, op string) bool {
	condInt, err := strconv.Atoi(condValue)
	if err != nil {
		return false
	}
	switch op {
	case "==", "=", "equals":
		return fieldValue == condInt
	case "!=", "not_equals":
		return fieldValue != condInt
	case ">":
		return fieldValue > condInt
	case ">=":
		return fieldValue >= condInt
	case "<":
		return fieldValue < condInt
	case "<=":
		return fieldValue <= condInt
	default:
		return fieldValue == condInt
	}
}

func (m *Matcher) getExtendedDataStr(event *types.Event, key string) string {
	if event.ExtractedFields == nil {
		return ""
	}
	if v, ok := event.ExtractedFields[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (m *Matcher) getExtendedDataInt(event *types.Event, key string) int {
	if event.ExtractedFields == nil {
		return 0
	}
	if v, ok := event.ExtractedFields[key]; ok {
		switch val := v.(type) {
		case int:
			return val
		case int32:
			return int(val)
		case int64:
			return int(val)
		case float64:
			return int(val)
		case string:
			if i, err := strconv.Atoi(val); err == nil {
				return i
			}
		}
	}
	return 0
}

func (m *Matcher) FilterByTimeRange(events []*types.Event, start, end time.Time) []*types.Event {
	filtered := make([]*types.Event, 0)

	for _, event := range events {
		if event.Timestamp.After(start) && event.Timestamp.Before(end) {
			filtered = append(filtered, event)
		}
	}

	return filtered
}

func (m *Matcher) FilterByPattern(events []*types.Event, pattern *rules.Pattern) []*types.Event {
	filtered := make([]*types.Event, 0)

	for _, event := range events {
		if m.matchPattern(pattern, event) {
			filtered = append(filtered, event)
		}
	}

	if pattern.MinCount > 0 && len(filtered) < pattern.MinCount {
		return []*types.Event{}
	}

	if pattern.MaxCount > 0 && len(filtered) > pattern.MaxCount {
		return filtered[:pattern.MaxCount]
	}

	return filtered
}

func (m *Matcher) CountMatches(events []*types.Event, pattern *rules.Pattern) int {
	count := 0
	for _, event := range events {
		if m.matchPattern(pattern, event) {
			count++
		}
	}
	return count
}

func (m *Matcher) CheckOrderedSequence(events []*types.Event, pattern *rules.Pattern) bool {
	if !pattern.Ordered || len(events) < 2 {
		return true
	}

	for i := 0; i < len(events)-1; i++ {
		if events[i].Timestamp.After(events[i+1].Timestamp) {
			return false
		}
	}
	return true
}

func contains(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
