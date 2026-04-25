package analyzers

import (
	"strconv"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type KerberosAnalyzer struct {
	BaseAnalyzer
	config *AnalyzerConfig
}

func NewKerberosAnalyzer() *KerberosAnalyzer {
	return &KerberosAnalyzer{
		BaseAnalyzer: BaseAnalyzer{name: "kerberos"},
		config: &AnalyzerConfig{
			EventIDs:  []int32{4768, 4769, 4771, 4770},
			Patterns:  []string{},
			Whitelist: []string{"krbtgt", "*$"},
		},
	}
}

func (a *KerberosAnalyzer) SetConfig(config *AnalyzerConfig) {
	if config != nil {
		a.config = config
	}
}

func (a *KerberosAnalyzer) GetConfig() *AnalyzerConfig {
	return a.config
}

func (a *KerberosAnalyzer) shouldProcessEvent(e *types.Event) bool {
	eventIDs := a.config.EventIDs
	if len(eventIDs) == 0 {
		eventIDs = []int32{4768, 4769, 4771, 4770}
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
		user := a.getTargetUser(e)
		userLower := strings.ToLower(user)
		for _, w := range whitelist {
			w = strings.TrimSpace(w)
			if w == "" {
				continue
			}
			if user != "" {
				if strings.HasSuffix(userLower, "$") && strings.HasSuffix(w, "$") {
					continue
				}
				if strings.Contains(userLower, strings.ToLower(w)) {
					return false
				}
			}
		}
	}
	return true
}

type KerberosAnalysis struct {
	TGTRequests    int
	TGSRequests    int
	GoldenTickets  int
	SilverTickets  int
	TicketWarnings int
	Kerberoasting  int
	FailedPreauth  int
	Anomalies      []*KerberosAnomaly
}

type KerberosAnomaly struct {
	Type        string
	User        string
	Time        time.Time
	SourceIP    string
	Severity    string
	Description string
	TicketType  string
	Lifetime    int
}

func (a *KerberosAnalyzer) Analyze(events []*types.Event) (*Result, error) {
	result := NewResult("kerberos", nil, "", "medium", 50)

	analysis := a.performAnalysis(events)

	findings := a.detectAnomalies(analysis)

	for _, finding := range findings {
		result.AddFinding(finding)
	}

	result.Summary = a.generateSummary(analysis)
	result.Score = result.CalculateOverallScore()

	return result, nil
}

func (a *KerberosAnalyzer) performAnalysis(events []*types.Event) *KerberosAnalysis {
	analysis := &KerberosAnalysis{
		Anomalies: make([]*KerberosAnomaly, 0),
	}

	for _, e := range events {
		switch e.EventID {
		case 4768:
			analysis.TGTRequests++
			if a.isGoldenTicket(e) {
				analysis.GoldenTickets++
				analysis.Anomalies = append(analysis.Anomalies, &KerberosAnomaly{
					Type:        "Golden Ticket",
					User:        a.getTargetUser(e),
					Time:        e.Timestamp,
					SourceIP:    a.getSourceIP(e),
					Severity:    "critical",
					Description: "TGT with suspicious lifetime or encryption detected",
					TicketType:  "TGT",
					Lifetime:    a.getTicketLifetime(e),
				})
			}

		case 4769:
			analysis.TGSRequests++
			if a.isKerberoasting(e) {
				analysis.Kerberoasting++
				analysis.Anomalies = append(analysis.Anomalies, &KerberosAnomaly{
					Type:        "Kerberoasting",
					User:        a.getTargetUser(e),
					Time:        e.Timestamp,
					SourceIP:    a.getSourceIP(e),
					Severity:    "high",
					Description: "TGS request for user account - possible Kerberoasting attack",
					TicketType:  "TGS",
				})
			}
			if a.isSilverTicket(e) {
				analysis.SilverTickets++
				analysis.Anomalies = append(analysis.Anomalies, &KerberosAnomaly{
					Type:        "Silver Ticket",
					User:        a.getTargetUser(e),
					Time:        e.Timestamp,
					SourceIP:    a.getSourceIP(e),
					Severity:    "high",
					Description: "TGS request with suspicious service - possible Silver Ticket",
					TicketType:  "TGS",
				})
			}

		case 4771:
			analysis.FailedPreauth++
			if a.isSuspiciousPreauth(e) {
				analysis.TicketWarnings++
				analysis.Anomalies = append(analysis.Anomalies, &KerberosAnomaly{
					Type:        "Failed Preauthentication",
					User:        a.getTargetUser(e),
					Time:        e.Timestamp,
					SourceIP:    a.getSourceIP(e),
					Severity:    "medium",
					Description: "Failed Kerberos preauthentication - possible brute force or AS-REP Roasting",
					TicketType:  "AS-REQ",
				})
			}

		case 4770:
			analysis.TicketWarnings++
			analysis.Anomalies = append(analysis.Anomalies, &KerberosAnomaly{
				Type:        "AS-REP Ticket Modification",
				User:        a.getTargetUser(e),
				Time:        e.Timestamp,
				SourceIP:    a.getSourceIP(e),
				Severity:    "high",
				Description: "AS-REP ticket modification detected - possible AS-REP Roasting",
				TicketType:  "AS-REP",
			})
		}
	}

	return analysis
}

func (a *KerberosAnalyzer) getTargetUser(e *types.Event) string {
	if e.User != nil && *e.User != "" {
		return *e.User
	}

	user := a.extractFromMessage(e.Message, "Target User:", "TargetUserName:")
	if user != "" {
		return user
	}

	return a.extractFromMessage(e.Message, "Account Name:", "AccountName:")
}

func (a *KerberosAnalyzer) getSourceIP(e *types.Event) string {
	if e.IPAddress != nil && *e.IPAddress != "" && *e.IPAddress != "-" {
		return *e.IPAddress
	}

	return a.extractFromMessage(e.Message, "IpAddress:", "Client Address:")
}

func (a *KerberosAnalyzer) getTicketLifetime(e *types.Event) int {
	lifetimeStr := a.extractFromMessage(e.Message, "TicketLifetime:", "Lifetime:")
	if lifetimeStr != "" {
		if lifetime, err := strconv.Atoi(lifetimeStr); err == nil {
			return lifetime
		}
	}
	return 0
}

func (a *KerberosAnalyzer) extractFromMessage(message, pattern1, pattern2 string) string {
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

func (a *KerberosAnalyzer) isGoldenTicket(e *types.Event) bool {
	lifetime := a.getTicketLifetime(e)

	if lifetime > 24*60*60*1000 {
		return true
	}

	return false
}

func (a *KerberosAnalyzer) isSilverTicket(e *types.Event) bool {
	serviceName := a.extractServiceName(e)

	if serviceName == "" {
		return false
	}

	suspiciousServices := []string{
		"cifs", "smb", "ldap", "http", "host",
		"rpcss", "mssql", "mysql", "postgres",
	}

	serviceLower := strings.ToLower(serviceName)
	for _, suspicious := range suspiciousServices {
		if strings.Contains(serviceLower, suspicious) {
			return true
		}
	}

	return false
}

func (a *KerberosAnalyzer) extractServiceName(e *types.Event) string {
	serviceName := a.extractFromMessage(e.Message, "ServiceName:", "Service Short Name:")
	if serviceName != "" {
		return serviceName
	}

	return a.extractFromMessage(e.Message, "Service:", "Service Name:")
}

func (a *KerberosAnalyzer) isKerberoasting(e *types.Event) bool {
	serviceName := a.extractServiceName(e)
	if serviceName == "" {
		return false
	}

	if !strings.Contains(serviceName, "$") {
		return true
	}

	return false
}

func (a *KerberosAnalyzer) isSuspiciousPreauth(e *types.Event) bool {
	sourceIP := a.getSourceIP(e)
	if sourceIP == "" || sourceIP == "-" || sourceIP == "::1" || sourceIP == "127.0.0.1" {
		return true
	}

	if strings.HasPrefix(sourceIP, "192.168.") ||
		strings.HasPrefix(sourceIP, "10.") ||
		strings.HasPrefix(sourceIP, "172.") {
		return false
	}

	return true
}

func (a *KerberosAnalyzer) detectAnomalies(analysis *KerberosAnalysis) []Finding {
	findings := make([]Finding, 0)

	if analysis.GoldenTickets > 0 {
		findings = append(findings, Finding{
			Description: "Possible Golden Ticket attack detected - TGT with suspicious lifetime",
			RuleName:    "Kerberos - Golden Ticket",
			MitreAttack: "T1558.001",
			Severity:    "critical",
			Score:       95,
			Metadata: map[string]interface{}{
				"count": analysis.GoldenTickets,
			},
		})
	}

	if analysis.SilverTickets > 0 {
		findings = append(findings, Finding{
			Description: "Possible Silver Ticket attack detected",
			RuleName:    "Kerberos - Silver Ticket",
			MitreAttack: "T1558.002",
			Severity:    "high",
			Score:       85,
			Metadata: map[string]interface{}{
				"count": analysis.SilverTickets,
			},
		})
	}

	if analysis.Kerberoasting > 0 {
		findings = append(findings, Finding{
			Description: "Kerberoasting attack detected - TGS requests for service accounts",
			RuleName:    "Kerberos - Kerberoasting",
			MitreAttack: "T1558.003",
			Severity:    "high",
			Score:       80,
			Metadata: map[string]interface{}{
				"count": analysis.Kerberoasting,
			},
		})
	}

	if analysis.FailedPreauth > 10 {
		findings = append(findings, Finding{
			Description: "High number of failed Kerberos preauthentication attempts",
			RuleName:    "Kerberos - Failed Preauth Flood",
			MitreAttack: "T1558.004",
			Severity:    "medium",
			Score:       60,
			Metadata: map[string]interface{}{
				"count": analysis.FailedPreauth,
			},
		})
	}

	return findings
}

func (a *KerberosAnalyzer) generateSummary(analysis *KerberosAnalysis) string {
	var sb strings.Builder
	sb.WriteString("Kerberos Analysis Summary:\n")
	sb.WriteString("  TGT Requests: ")
	sb.WriteString(strconv.Itoa(analysis.TGTRequests))
	sb.WriteString("\n  TGS Requests: ")
	sb.WriteString(strconv.Itoa(analysis.TGSRequests))
	sb.WriteString("\n  Failed Preauth: ")
	sb.WriteString(strconv.Itoa(analysis.FailedPreauth))
	sb.WriteString("\n  Golden Tickets: ")
	sb.WriteString(strconv.Itoa(analysis.GoldenTickets))
	sb.WriteString("\n  Silver Tickets: ")
	sb.WriteString(strconv.Itoa(analysis.SilverTickets))
	sb.WriteString("\n  Kerberoasting: ")
	sb.WriteString(strconv.Itoa(analysis.Kerberoasting))
	sb.WriteString("\n  Ticket Warnings: ")
	sb.WriteString(strconv.Itoa(analysis.TicketWarnings))
	return sb.String()
}
