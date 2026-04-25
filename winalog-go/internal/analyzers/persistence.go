package analyzers

import (
	"fmt"
	"strings"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type PersistenceAnalyzer struct {
	BaseAnalyzer
	config *AnalyzerConfig
}

func NewPersistenceAnalyzer() *PersistenceAnalyzer {
	return &PersistenceAnalyzer{
		BaseAnalyzer: BaseAnalyzer{name: "persistence"},
		config: &AnalyzerConfig{
			EventIDs:  []int32{4697, 4698, 4702, 4720, 4722, 4724, 4728, 4729, 4732, 4733, 4756, 4757, 7045, 4690},
			Patterns:  []string{},
			Whitelist: []string{},
		},
	}
}

func (a *PersistenceAnalyzer) SetConfig(config *AnalyzerConfig) {
	if config != nil {
		a.config = config
	}
}

func (a *PersistenceAnalyzer) GetConfig() *AnalyzerConfig {
	return a.config
}

type PersistenceInfo struct {
	User        string
	Computer    string
	EventID     int32
	Timestamp   string
	Message     string
	Technique   string
	Category    string
	Severity    string
	Score       float64
	MITREAttack []string
}

func (a *PersistenceAnalyzer) Analyze(events []*types.Event) (*Result, error) {
	result := NewResult("persistence", nil, "", "medium", 50)

	persistenceEvents := a.filterPersistenceEvents(events)
	findings := a.analyzePersistence(persistenceEvents)

	for _, finding := range findings {
		result.AddFinding(finding)
	}

	result.Summary = a.generateSummary(findings)
	result.Score = result.CalculateOverallScore()

	if len(findings) > 0 {
		highSeverity := false
		for _, f := range findings {
			if f.Severity == "critical" || f.Severity == "high" {
				highSeverity = true
				break
			}
		}
		if highSeverity {
			result.Severity = "high"
		}
	}

	return result, nil
}

func (a *PersistenceAnalyzer) filterPersistenceEvents(events []*types.Event) []*types.Event {
	var persistence []*types.Event
	persistenceEventIDs := map[int32]bool{
		4697: true, // Windows service installed
		4698: true, // Scheduled task created
		4702: true, // Scheduled task updated
		4720: true, // User account created
		4722: true, // User account enabled
		4724: true, // Password reset attempted
		4728: true, // Member added to security-global group
		4729: true, // Member removed from security-global group
		4732: true, // Member added to security-local group
		4733: true, // Member removed from security-local group
		4756: true, // Member added to security-universal group
		4757: true, // Member removed from security-universal group
		7045: true, // New service installed (Sysmon)
		4690: true, // Attempt to create duplicate SPN
	}

	for _, e := range events {
		if persistenceEventIDs[e.EventID] {
			persistence = append(persistence, e)
		}
	}
	return persistence
}

func (a *PersistenceAnalyzer) analyzePersistence(events []*types.Event) []Finding {
	findings := make([]Finding, 0)

	userCreations := make(map[string][]*types.Event)
	serviceInstalls := make([]*types.Event, 0)
	taskCreations := make([]*types.Event, 0)
	groupModifications := make([]*types.Event, 0)

	for _, e := range events {
		switch e.EventID {
		case 4720:
			user := getEventUser(e)
			userCreations[user] = append(userCreations[user], e)
		case 4697, 7045:
			serviceInstalls = append(serviceInstalls, e)
		case 4698:
			taskCreations = append(taskCreations, e)
		case 4728, 4729, 4732, 4733, 4756, 4757:
			groupModifications = append(groupModifications, e)
		}
	}

	for user, creations := range userCreations {
		if len(creations) > 2 {
			findings = append(findings, Finding{
				Description: "Multiple user accounts created in short period - possible account creation attack",
				RuleName:    "Persistence - Suspicious Account Creation",
				Severity:    "high",
				Score:       80,
				Metadata: map[string]interface{}{
					"user":      user,
					"count":     len(creations),
					"event_ids": []int32{4720},
				},
			})
		}
	}

	for _, e := range serviceInstalls {
		serviceName := extractServiceName(e.Message)
		if serviceName != "" && isSuspiciousService(serviceName) {
			findings = append(findings, Finding{
				Description: "Suspicious service installed: " + serviceName,
				RuleName:    "Persistence - Suspicious Service",
				Severity:    "critical",
				Score:       90,
				MitreAttack: "T1543",
				Metadata: map[string]interface{}{
					"service_name": serviceName,
					"computer":     e.Computer,
					"event_id":     e.EventID,
				},
			})
		} else if serviceName != "" {
			findings = append(findings, Finding{
				Description: "New service installed: " + serviceName,
				RuleName:    "Persistence - Service Installation",
				Severity:    "medium",
				Score:       50,
				MitreAttack: "T1543",
				Metadata: map[string]interface{}{
					"service_name": serviceName,
					"computer":     e.Computer,
					"event_id":     e.EventID,
				},
			})
		}
	}

	for _, e := range taskCreations {
		taskName := extractTaskName(e.Message)
		if taskName != "" {
			severity := "medium"
			score := float64(50)
			if isSuspiciousTask(taskName) {
				severity = "high"
				score = 75
			}
			findings = append(findings, Finding{
				Description: "Scheduled task created: " + taskName,
				RuleName:    "Persistence - Scheduled Task",
				Severity:    severity,
				Score:       score,
				MitreAttack: "T1053",
				Metadata: map[string]interface{}{
					"task_name": taskName,
					"computer":  e.Computer,
					"event_id":  e.EventID,
				},
			})
		}
	}

	for _, e := range groupModifications {
		groupName := extractGroupName(e.Message)
		user := getEventUser(e)
		action := "added to"
		if e.EventID == 4729 || e.EventID == 4733 || e.EventID == 4757 {
			action = "removed from"
		}
		if isPrivilegedGroup(groupName) {
			findings = append(findings, Finding{
				Description: "User " + user + " " + action + " privileged group: " + groupName,
				RuleName:    "Persistence - Privileged Group Modification",
				Severity:    "high",
				Score:       85,
				MitreAttack: "T1098",
				Metadata: map[string]interface{}{
					"user":     user,
					"group":    groupName,
					"action":   action,
					"event_id": e.EventID,
				},
			})
		}
	}

	return findings
}

func (a *PersistenceAnalyzer) generateSummary(findings []Finding) string {
	if len(findings) == 0 {
		return "No significant persistence mechanisms detected."
	}

	criticalCount := 0
	highCount := 0
	for _, f := range findings {
		if f.Severity == "critical" {
			criticalCount++
		} else if f.Severity == "high" {
			highCount++
		}
	}

	return fmt.Sprintf("Found %d persistence mechanisms (%d critical, %d high severity)", len(findings), criticalCount, highCount)
}

func extractServiceName(message string) string {
	keywords := []string{"service name:", "service:", "service name"}
	lowerMsg := strings.ToLower(message)

	for _, keyword := range keywords {
		if idx := strings.Index(lowerMsg, keyword); idx != -1 {
			start := idx + len(keyword)
			end := start
			for end < len(message) && message[end] != '\n' && message[end] != '\r' {
				end++
			}
			name := strings.TrimSpace(message[start:end])
			name = strings.Trim(name, " \t:")
			return name
		}
	}
	return ""
}

func extractTaskName(message string) string {
	keywords := []string{"task name:", "task:", "task name"}
	lowerMsg := strings.ToLower(message)

	for _, keyword := range keywords {
		if idx := strings.Index(lowerMsg, keyword); idx != -1 {
			start := idx + len(keyword)
			end := start
			for end < len(message) && message[end] != '\n' && message[end] != '\r' {
				end++
			}
			name := strings.TrimSpace(message[start:end])
			name = strings.Trim(name, " \t:")
			return name
		}
	}
	return ""
}

func extractGroupName(message string) string {
	keywords := []string{"group:", "group name:", "target group"}
	lowerMsg := strings.ToLower(message)

	for _, keyword := range keywords {
		if idx := strings.Index(lowerMsg, keyword); idx != -1 {
			start := idx + len(keyword)
			end := start
			for end < len(message) && message[end] != '\n' && message[end] != '\r' {
				end++
			}
			name := strings.TrimSpace(message[start:end])
			name = strings.Trim(name, " \t")
			return name
		}
	}
	return ""
}

func isSuspiciousService(name string) bool {
	suspicious := []string{
		"remote", "vnc", "teamviewer", "anydesk", "chrome",
		"svchost", " Rundll", "PowerShell", "cmd.exe", "wscript",
		"cscript", "mshta", "regsvr32", "certutil", "bitsadmin",
	}
	lowerName := strings.ToLower(name)
	for _, s := range suspicious {
		if strings.Contains(lowerName, s) {
			return true
		}
	}
	return false
}

func isSuspiciousTask(name string) bool {
	suspicious := []string{
		"powershell", "cmd", "wscript", "cscript", "mshta",
		"rundll32", "certutil", "bitsadmin", "remote", "update",
	}
	lowerName := strings.ToLower(name)
	for _, s := range suspicious {
		if strings.Contains(lowerName, s) {
			return true
		}
	}
	return false
}

func isPrivilegedGroup(name string) bool {
	privileged := []string{
		"administrators", "domain admins", "enterprise admins",
		"schema admins", "backup operators", "domain controllers",
		"group policy creator", "read-only domain controllers",
		"account operators", "server operators", "print operators",
	}
	lowerName := strings.ToLower(name)
	for _, g := range privileged {
		if strings.Contains(lowerName, g) {
			return true
		}
	}
	return false
}
