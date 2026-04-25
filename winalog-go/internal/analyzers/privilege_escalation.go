package analyzers

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type PrivilegeEscalationAnalyzer struct {
	BaseAnalyzer
	config *AnalyzerConfig
}

func NewPrivilegeEscalationAnalyzer() *PrivilegeEscalationAnalyzer {
	return &PrivilegeEscalationAnalyzer{
		BaseAnalyzer: BaseAnalyzer{name: "privilege_escalation"},
		config: &AnalyzerConfig{
			EventIDs:  []int32{4672, 4673, 4674, 4688, 4689, 4656, 4657, 4659},
			Patterns:  []string{},
			Whitelist: []string{},
		},
	}
}

func (a *PrivilegeEscalationAnalyzer) SetConfig(config *AnalyzerConfig) {
	if config != nil {
		a.config = config
	}
}

func (a *PrivilegeEscalationAnalyzer) GetConfig() *AnalyzerConfig {
	return a.config
}

type PrivilegeEvent struct {
	User      string
	Privilege string
	Timestamp time.Time
	Computer  string
	Message   string
	Severity  string
}

func (a *PrivilegeEscalationAnalyzer) Analyze(events []*types.Event) (*Result, error) {
	result := NewResult("privilege_escalation", nil, "", "medium", 50)

	privilegeEvents := a.filterPrivilegeEvents(events)
	findings := a.analyzePrivilegeEscalation(privilegeEvents)

	for _, finding := range findings {
		result.AddFinding(finding)
	}

	result.Summary = a.generateSummary(findings)
	result.Score = result.CalculateOverallScore()

	if len(findings) > 0 {
		result.Severity = a.determineOverallSeverity(findings)
	}

	return result, nil
}

func (a *PrivilegeEscalationAnalyzer) filterPrivilegeEvents(events []*types.Event) []*types.Event {
	var privilege []*types.Event
	privilegeEventIDs := map[int32]bool{
		4672: true, // Special privileges assigned to new logon
		4673: true, // Sensitive privilege use
		4674: true, // Privileged service called
		4688: true, // Process creation
		4689: true, // Process termination
		4656: true, // Handle to object opened
		4657: true, // Registry key modified
		4659: true, // Registry key deleted
	}

	for _, e := range events {
		if privilegeEventIDs[e.EventID] {
			privilege = append(privilege, e)
		}
	}
	return privilege
}

func (a *PrivilegeEscalationAnalyzer) analyzePrivilegeEscalation(events []*types.Event) []Finding {
	findings := make([]Finding, 0)

	sensitivePrivileges := a.analyzeSpecialPrivileges(events)
	findings = append(findings, sensitivePrivileges...)

	processAnomalies := a.analyzeProcessCreation(events)
	findings = append(findings, processAnomalies...)

	suspiciousCommands := a.analyzeSuspiciousCommands(events)
	findings = append(findings, suspiciousCommands...)

	return findings
}

func (a *PrivilegeEscalationAnalyzer) analyzeSpecialPrivileges(events []*types.Event) []Finding {
	findings := make([]Finding, 0)

	adminLogins := make(map[string][]*PrivilegeEvent)
	privilegeUse := make(map[string][]*PrivilegeEvent)

	for _, e := range events {
		if e.EventID == 4672 {
			privs := extractPrivileges(e.Message)
			user := getEventUser(e)
			for _, priv := range privs {
				if isSensitivePrivilege(priv) {
					adminLogins[user] = append(adminLogins[user], &PrivilegeEvent{
						User:      user,
						Privilege: priv,
						Timestamp: e.Timestamp,
						Computer:  e.Computer,
						Message:   e.Message,
						Severity:  "high",
					})
				}
			}
		} else if e.EventID == 4673 || e.EventID == 4674 {
			priv := extractSinglePrivilege(e.Message)
			user := getEventUser(e)
			if priv != "" && isSensitivePrivilege(priv) {
				privilegeUse[user] = append(privilegeUse[user], &PrivilegeEvent{
					User:      user,
					Privilege: priv,
					Timestamp: e.Timestamp,
					Computer:  e.Computer,
					Message:   e.Message,
					Severity:  "medium",
				})
			}
		}
	}

	for user, logins := range adminLogins {
		if len(logins) > 5 {
			findings = append(findings, Finding{
				Description: "User assigned multiple sensitive privileges - potential privilege escalation",
				RuleName:    "Privilege Escalation - Excessive Privileges",
				Severity:    "critical",
				Score:       90,
				MitreAttack: "T1068",
				Metadata: map[string]interface{}{
					"user":            user,
					"privilege_count": len(logins),
					"privileges":      extractPrivilegeNames(logins),
				},
			})
		}
	}

	for user, uses := range privilegeUse {
		if len(uses) > 10 {
			privs := make([]string, 0)
			privCount := make(map[string]int)
			for _, u := range uses {
				privCount[u.Privilege]++
			}
			for p, c := range privCount {
				if c > 3 {
					privs = append(privs, p)
				}
			}
			if len(privs) > 0 {
				findings = append(findings, Finding{
					Description: "User heavily using sensitive privileges: " + strings.Join(privs, ", "),
					RuleName:    "Privilege Escalation - Excessive Privilege Use",
					Severity:    "high",
					Score:       80,
					MitreAttack: "T1068",
					Metadata: map[string]interface{}{
						"user":       user,
						"use_count":  len(uses),
						"privileges": privs,
					},
				})
			}
		}
	}

	return findings
}

func (a *PrivilegeEscalationAnalyzer) analyzeProcessCreation(events []*types.Event) []Finding {
	findings := make([]Finding, 0)

	suspiciousProcesses := make(map[string][]*types.Event)
	cmdProcesses := make(map[string][]*types.Event)

	for _, e := range events {
		if e.EventID == 4688 {
			processName := extractProcessName(e.Message)
			if processName != "" {
				if isSuspiciousProcess(processName) {
					suspiciousProcesses[processName] = append(suspiciousProcesses[processName], e)
				}
				if isCmdProcess(processName) {
					cmdProcesses[processName] = append(cmdProcesses[processName], e)
				}
			}
		}
	}

	for proc, events := range suspiciousProcesses {
		if len(events) >= 3 {
			findings = append(findings, Finding{
				Description: "Suspicious process executed multiple times: " + proc,
				RuleName:    "Privilege Escalation - Suspicious Process",
				Severity:    "high",
				Score:       75,
				MitreAttack: "T1059",
				Metadata: map[string]interface{}{
					"process": proc,
					"count":   len(events),
				},
			})
		}
	}

	for proc, events := range cmdProcesses {
		if len(events) >= 5 {
			findings = append(findings, Finding{
				Description: "Multiple cmd.exe processes spawned - possible command execution attack",
				RuleName:    "Privilege Escalation - Suspicious CMD Usage",
				Severity:    "medium",
				Score:       55,
				MitreAttack: "T1059",
				Metadata: map[string]interface{}{
					"process": proc,
					"count":   len(events),
				},
			})
		}
	}

	return findings
}

func (a *PrivilegeEscalationAnalyzer) analyzeSuspiciousCommands(events []*types.Event) []Finding {
	findings := make([]Finding, 0)

	suspiciousPatterns := []struct {
		Pattern  string
		Name     string
		MITRE    string
		Severity string
		Score    float64
	}{
		{
			Pattern:  "whoami",
			Name:     "Privilege Escalation - Whoami Execution",
			MITRE:    "T1087",
			Severity: "low",
			Score:    30,
		},
		{
			Pattern:  "net user",
			Name:     "Privilege Escalation - Account Enumeration",
			MITRE:    "T1087",
			Severity: "low",
			Score:    30,
		},
		{
			Pattern:  "net localgroup administrators",
			Name:     "Privilege Escalation - Admin Group Enumeration",
			MITRE:    "T1069",
			Severity: "medium",
			Score:    50,
		},
		{
			Pattern:  "reg save",
			Name:     "Privilege Escalation - Registry Backup",
			MITRE:    "T1003",
			Severity: "high",
			Score:    80,
		},
		{
			Pattern:  "mimikatz",
			Name:     "Privilege Escalation - Credential Theft Tool",
			MITRE:    "T1003",
			Severity: "critical",
			Score:    95,
		},
		{
			Pattern:  "pwdump",
			Name:     "Privilege Escalation - Password Dump",
			MITRE:    "T1003",
			Severity: "critical",
			Score:    95,
		},
		{
			Pattern:  "wmic",
			Name:     "Privilege Escalation - WMI Abuse",
			MITRE:    "T1047",
			Severity: "medium",
			Score:    50,
		},
		{
			Pattern:  "psexec",
			Name:     "Privilege Escalation - PsExec Usage",
			MITRE:    "T1569",
			Severity: "high",
			Score:    75,
		},
	}

	patternMatches := make(map[string]int)

	for _, e := range events {
		if e.Message != "" {
			lowerMsg := strings.ToLower(e.Message)
			for _, p := range suspiciousPatterns {
				if strings.Contains(lowerMsg, p.Pattern) {
					patternMatches[p.Name]++
				}
			}
		}
	}

	for _, p := range suspiciousPatterns {
		if count, ok := patternMatches[p.Name]; ok && count >= 1 {
			severity := p.Severity
			score := p.Score
			if count > 3 {
				severity = "high"
				score = float64(int(p.Score) + 10)
				if score > 100 {
					score = 100
				}
			}
			findings = append(findings, Finding{
				Description: p.Name + " (detected " + strconv.Itoa(count) + " times)",
				RuleName:    p.Name,
				Severity:    severity,
				Score:       score,
				MitreAttack: p.MITRE,
				Metadata: map[string]interface{}{
					"pattern": p.Pattern,
					"count":   count,
				},
			})
		}
	}

	return findings
}

func (a *PrivilegeEscalationAnalyzer) generateSummary(findings []Finding) string {
	if len(findings) == 0 {
		return "No significant privilege escalation activity detected."
	}

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	for _, f := range findings {
		if f.Severity == "critical" {
			criticalCount++
		} else if f.Severity == "high" {
			highCount++
		} else if f.Severity == "medium" {
			mediumCount++
		}
	}

	return fmt.Sprintf("Found %d privilege escalation indicators (%d critical, %d high, %d medium)",
		len(findings), criticalCount, highCount, mediumCount)
}

func (a *PrivilegeEscalationAnalyzer) determineOverallSeverity(findings []Finding) string {
	for _, f := range findings {
		if f.Severity == "critical" {
			return "critical"
		}
	}
	for _, f := range findings {
		if f.Severity == "high" {
			return "high"
		}
	}
	return "medium"
}

func extractPrivileges(message string) []string {
	privileges := make([]string, 0)
	keywords := []string{"SeSecurity", "SeBackup", "SeRestore", "SeShutdown", "SeSystemProfile",
		"SeProcessTrace", "SeDebug", "SeAudit", "SeSystemEnvironment", "SeLoadDriver",
		"SeCreatePagefile", "SeCreateToken", "SeCreatePermanent", "SeIncreaseBasePriority",
		"SeCreateGlobal", "SeCreateSymbolicLink", "SeLoadDriver", "SeTcb", "SeMachineAccount",
		"SeBackup", "SeRestore", "SeTakeOwnership", "SeDebug"}

	lowerMsg := strings.ToLower(message)
	for _, priv := range keywords {
		if strings.Contains(lowerMsg, strings.ToLower(priv)) {
			privileges = append(privileges, priv)
		}
	}
	return privileges
}

func extractSinglePrivilege(message string) string {
	keywords := []string{"SeSecurity", "SeBackup", "SeRestore", "SeShutdown", "SeDebug", "SeTcb"}
	lowerMsg := strings.ToLower(message)
	for _, priv := range keywords {
		if strings.Contains(lowerMsg, strings.ToLower(priv)) {
			return priv
		}
	}
	return ""
}

func isSensitivePrivilege(priv string) bool {
	sensitive := []string{
		"SeSecurity", "SeBackup", "SeRestore", "SeShutdown", "SeDebug",
		"SeSystemProfile", "SeSystemEnvironment", "SeLoadDriver", "SeTcb",
		"SeCreateToken", "SeCreateGlobal", "SeCreatePagefile", "SeIncreaseBasePriority",
	}
	for _, s := range sensitive {
		if s == priv {
			return true
		}
	}
	return false
}

func extractPrivilegeNames(events []*PrivilegeEvent) []string {
	names := make([]string, 0)
	seen := make(map[string]bool)
	for _, e := range events {
		if !seen[e.Privilege] {
			names = append(names, e.Privilege)
			seen[e.Privilege] = true
		}
	}
	return names
}

func extractProcessName(message string) string {
	keywords := []string{"new process name:", "process name:", "process"}
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

func isSuspiciousProcess(name string) bool {
	suspicious := []string{
		"powershell", "cmd.exe", "wscript", "cscript", "mshta",
		"rundll32", "regsvr32", "certutil", "bitsadmin", "vbscript",
		"jscript", "msbuild", "installutil", "regasm", "regsvcs",
	}
	lowerName := strings.ToLower(name)
	for _, s := range suspicious {
		if strings.Contains(lowerName, s) {
			return true
		}
	}
	return false
}

func isCmdProcess(name string) bool {
	lowerName := strings.ToLower(name)
	return strings.Contains(lowerName, "cmd") || strings.Contains(lowerName, "command")
}

func getEventUser(e *types.Event) string {
	if e.User != nil && *e.User != "" {
		return *e.User
	}
	if e.UserSID != nil {
		return *e.UserSID
	}
	return "unknown"
}
