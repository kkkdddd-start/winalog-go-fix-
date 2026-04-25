package analyzers

import (
	"strconv"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type LoginAnalyzer struct {
	BaseAnalyzer
	config *AnalyzerConfig
}

func NewLoginAnalyzer() *LoginAnalyzer {
	return &LoginAnalyzer{
		BaseAnalyzer: BaseAnalyzer{name: "login"},
		config: &AnalyzerConfig{
			EventIDs:  []int32{4624, 4625},
			Patterns:  []string{},
			Whitelist: []string{},
		},
	}
}

func (a *LoginAnalyzer) SetConfig(config *AnalyzerConfig) {
	if config != nil {
		a.config = config
	}
}

func (a *LoginAnalyzer) GetConfig() *AnalyzerConfig {
	return a.config
}

func (a *LoginAnalyzer) shouldProcessEvent(e *types.Event) bool {
	eventIDs := a.config.EventIDs
	if len(eventIDs) == 0 {
		eventIDs = []int32{4624, 4625}
	}

	for _, id := range eventIDs {
		if e.EventID == id {
			goto checkWhitelist
		}
	}
	return false

checkWhitelist:
	whitelist := a.config.Whitelist
	if len(whitelist) > 0 {
		for _, w := range whitelist {
			w = strings.TrimSpace(w)
			if w == "" {
				continue
			}
			user := a.getTargetUser(e)
			ip := a.getSourceIP(e)
			if (user != "" && strings.Contains(user, w)) || (ip != "" && strings.Contains(ip, w)) {
				return false
			}
		}
	}
	return true
}

func (a *LoginAnalyzer) matchesPattern(e *types.Event) bool {
	patterns := a.config.Patterns
	if len(patterns) == 0 {
		return true
	}

	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if strings.Contains(strings.ToLower(e.Message), strings.ToLower(pattern)) {
			return true
		}
	}
	return len(patterns) == 0
}

type LoginAnalysis struct {
	TotalLogins       int
	SuccessfulLogins  int
	FailedLogins      int
	SuccessRate       float64
	ByLogonType       map[int]int
	ByTimeOfDay       map[int]int
	SuspiciousLogins  []*SuspiciousLogin
	RDPConnections    int
	NetworkLogins     int
	InteractiveLogins int
}

type SuspiciousLogin struct {
	User      string
	Time      time.Time
	SourceIP  string
	Reason    string
	Severity  string
	LogonType int
}

func (a *LoginAnalyzer) Analyze(events []*types.Event) (*Result, error) {
	result := NewResult("login", nil, "", "medium", 50)

	analysis := a.performAnalysis(events)

	findings := a.detectSuspiciousLogins(analysis)

	for _, finding := range findings {
		result.AddFinding(finding)
	}

	result.Summary = a.generateSummary(analysis)
	result.Score = result.CalculateOverallScore()

	return result, nil
}

func (a *LoginAnalyzer) performAnalysis(events []*types.Event) *LoginAnalysis {
	analysis := &LoginAnalysis{
		ByLogonType:      make(map[int]int),
		ByTimeOfDay:      make(map[int]int),
		SuspiciousLogins: make([]*SuspiciousLogin, 0),
	}

	for _, e := range events {
		if !a.shouldProcessEvent(e) {
			continue
		}

		if !a.matchesPattern(e) {
			continue
		}

		switch e.EventID {
		case 4624:
			analysis.SuccessfulLogins++
			logonType := a.getLogonType(e)
			analysis.ByLogonType[logonType]++
			analysis.ByTimeOfDay[e.Timestamp.Hour()]++

			if logonType == 10 {
				analysis.RDPConnections++
			}
			if logonType == 3 {
				analysis.NetworkLogins++
			}
			if logonType == 2 {
				analysis.InteractiveLogins++
			}

			if a.isSuspiciousLogin(e, logonType) {
				analysis.SuspiciousLogins = append(analysis.SuspiciousLogins, &SuspiciousLogin{
					User:      a.getTargetUser(e),
					Time:      e.Timestamp,
					SourceIP:  a.getSourceIP(e),
					Reason:    "Successful login from unusual source or time",
					Severity:  "medium",
					LogonType: logonType,
				})
			}

		case 4625:
			analysis.FailedLogins++
			logonType := a.getLogonType(e)

			if a.isSuspiciousFailedLogin(e, logonType) {
				analysis.SuspiciousLogins = append(analysis.SuspiciousLogins, &SuspiciousLogin{
					User:      a.getTargetUser(e),
					Time:      e.Timestamp,
					SourceIP:  a.getSourceIP(e),
					Reason:    "Failed login attempt - possible brute force",
					Severity:  "high",
					LogonType: logonType,
				})
			}
		}
	}

	analysis.TotalLogins = analysis.SuccessfulLogins + analysis.FailedLogins
	if analysis.TotalLogins > 0 {
		analysis.SuccessRate = float64(analysis.SuccessfulLogins) / float64(analysis.TotalLogins)
	}

	return analysis
}

func (a *LoginAnalyzer) getLogonType(e *types.Event) int {
	logonTypeStr := a.extractFromMessage(e.Message, "LogonType:", "Logon Type:")
	if logonTypeStr != "" {
		if logonType, err := strconv.Atoi(logonTypeStr); err == nil {
			return logonType
		}
	}

	return 0
}

func (a *LoginAnalyzer) getTargetUser(e *types.Event) string {
	if e.User != nil && *e.User != "" {
		return *e.User
	}

	return a.extractFromMessage(e.Message, "TargetUserName:", "Account Name:")
}

func (a *LoginAnalyzer) getSourceIP(e *types.Event) string {
	if e.IPAddress != nil && *e.IPAddress != "" && *e.IPAddress != "-" {
		return *e.IPAddress
	}

	return a.extractFromMessage(e.Message, "IpAddress:", "Source Address:")
}

func (a *LoginAnalyzer) extractFromMessage(message, pattern1, pattern2 string) string {
	patterns := []string{pattern1, pattern2}
	for _, pattern := range patterns {
		idx := strings.Index(message, pattern)
		if idx >= 0 {
			valuePart := message[idx+len(pattern):]
			endIdx := strings.IndexAny(valuePart, "\r\n\t,")
			if endIdx > 0 {
				return strings.TrimSpace(valuePart[:endIdx])
			}
			return strings.TrimSpace(valuePart)
		}
	}
	return ""
}

func (a *LoginAnalyzer) isSuspiciousLogin(e *types.Event, logonType int) bool {
	sourceIP := a.getSourceIP(e)

	if sourceIP == "" || sourceIP == "-" || sourceIP == "127.0.0.1" || sourceIP == "::1" {
		return false
	}

	if logonType == 10 && types.IsExternalIP(sourceIP) {
		hour := e.Timestamp.Hour()
		if hour < 6 || hour > 22 {
			return true
		}
	}

	return false
}

func (a *LoginAnalyzer) isSuspiciousFailedLogin(e *types.Event, logonType int) bool {
	sourceIP := a.getSourceIP(e)

	if sourceIP == "" || sourceIP == "-" {
		return false
	}

	return types.IsExternalIP(sourceIP)
}

func (a *LoginAnalyzer) detectSuspiciousLogins(analysis *LoginAnalysis) []Finding {
	findings := make([]Finding, 0)

	if analysis.TotalLogins == 0 {
		return findings
	}

	if analysis.SuccessRate < 0.5 && analysis.TotalLogins > 10 {
		findings = append(findings, Finding{
			Description: "Low login success rate indicates potential attack",
			RuleName:    "Login - Low Success Rate",
			Severity:    "high",
			Score:       70,
		})
	}

	failedRatio := float64(analysis.FailedLogins) / float64(analysis.TotalLogins)
	if failedRatio > 0.8 && analysis.FailedLogins > 50 {
		findings = append(findings, Finding{
			Description: "High number of failed login attempts - possible brute force",
			RuleName:    "Login - Potential Brute Force",
			Severity:    "critical",
			Score:       90,
		})
	}

	if analysis.RDPConnections > 10 {
		findings = append(findings, Finding{
			Description: "Multiple RDP connections detected",
			RuleName:    "Login - Multiple RDP",
			Severity:    "medium",
			Score:       50,
			Metadata: map[string]interface{}{
				"rdp_count": analysis.RDPConnections,
			},
		})
	}

	for _, sl := range analysis.SuspiciousLogins {
		findings = append(findings, Finding{
			Description: sl.Reason,
			RuleName:    "Login - Suspicious Activity",
			Severity:    sl.Severity,
			Score:       60,
			Metadata: map[string]interface{}{
				"user":       sl.User,
				"source_ip":  sl.SourceIP,
				"logon_type": sl.LogonType,
				"time":       sl.Time.Format(time.RFC3339),
			},
		})
	}

	return findings
}

func (a *LoginAnalyzer) generateSummary(analysis *LoginAnalysis) string {
	var sb strings.Builder
	sb.WriteString("Login Analysis Summary:\n")
	sb.WriteString("  Total Logins: ")
	sb.WriteString(strconv.Itoa(analysis.TotalLogins))
	sb.WriteString("\n  Successful: ")
	sb.WriteString(strconv.Itoa(analysis.SuccessfulLogins))
	sb.WriteString(" (")
	sb.WriteString(strconv.Itoa(int(analysis.SuccessRate * 100)))
	sb.WriteString("%)\n  Failed: ")
	sb.WriteString(strconv.Itoa(analysis.FailedLogins))
	sb.WriteString("\n\nBy Logon Type:\n")

	for logonType, count := range analysis.ByLogonType {
		sb.WriteString("  Type ")
		sb.WriteString(strconv.Itoa(logonType))
		sb.WriteString(": ")
		sb.WriteString(strconv.Itoa(count))
		sb.WriteString("\n")
	}

	if analysis.RDPConnections > 0 {
		sb.WriteString("\nRDP Connections: ")
		sb.WriteString(strconv.Itoa(analysis.RDPConnections))
		sb.WriteString("\n")
	}

	if analysis.NetworkLogins > 0 {
		sb.WriteString("Network Logins: ")
		sb.WriteString(strconv.Itoa(analysis.NetworkLogins))
		sb.WriteString("\n")
	}

	if analysis.InteractiveLogins > 0 {
		sb.WriteString("Interactive Logins: ")
		sb.WriteString(strconv.Itoa(analysis.InteractiveLogins))
		sb.WriteString("\n")
	}

	return sb.String()
}
