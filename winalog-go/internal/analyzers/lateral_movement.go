package analyzers

import (
	"strconv"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type LateralMovementAnalyzer struct {
	BaseAnalyzer
	config *AnalyzerConfig
}

func NewLateralMovementAnalyzer() *LateralMovementAnalyzer {
	return &LateralMovementAnalyzer{
		BaseAnalyzer: BaseAnalyzer{name: "lateral_movement"},
		config: &AnalyzerConfig{
			EventIDs:  []int32{4624, 4688, 4648},
			Patterns:  []string{},
			Whitelist: []string{},
		},
	}
}

func (a *LateralMovementAnalyzer) SetConfig(config *AnalyzerConfig) {
	if config != nil {
		a.config = config
	}
}

func (a *LateralMovementAnalyzer) GetConfig() *AnalyzerConfig {
	return a.config
}

func (a *LateralMovementAnalyzer) shouldProcessEvent(e *types.Event) bool {
	eventIDs := a.config.EventIDs
	if len(eventIDs) == 0 {
		eventIDs = []int32{4624, 4688, 4648}
	}

	for _, id := range eventIDs {
		if e.EventID == id {
			return true
		}
	}
	return false
}

type LateralMovementAnalysis struct {
	TotalEvents    int
	RDPConnections int
	PSExecEvents   int
	WMIEvents      int
	PassTheHash    int
	AdminShares    int
	RemoteFX       int
	Findings       []*LateralMovementFinding
}

type LateralMovementFinding struct {
	Type        string
	Time        time.Time
	SourceIP    string
	SourceHost  string
	TargetHost  string
	User        string
	Description string
	Severity    string
	MitreAttack string
}

func (a *LateralMovementAnalyzer) Analyze(events []*types.Event) (*Result, error) {
	result := NewResult("lateral_movement", nil, "", "medium", 50)

	analysis := a.performAnalysis(events)
	findings := a.detectLateralMovement(analysis)

	for _, finding := range findings {
		result.AddFinding(Finding{
			Description: finding.Description,
			RuleName:    "Lateral Movement - " + finding.Type,
			MitreAttack: finding.MitreAttack,
			Severity:    finding.Severity,
			Score:       a.calculateScore(finding.Severity),
			Metadata: map[string]interface{}{
				"source_ip":   finding.SourceIP,
				"source_host": finding.SourceHost,
				"target_host": finding.TargetHost,
				"user":        finding.User,
				"time":        finding.Time.Format(time.RFC3339),
			},
		})
	}

	result.Summary = a.generateSummary(analysis)
	result.Score = result.CalculateOverallScore()

	if len(findings) > 0 {
		result.Severity = "high"
	}

	return result, nil
}

func (a *LateralMovementAnalyzer) performAnalysis(events []*types.Event) *LateralMovementAnalysis {
	analysis := &LateralMovementAnalysis{
		Findings: make([]*LateralMovementFinding, 0),
	}

	for _, e := range events {
		if !a.shouldProcessEvent(e) {
			continue
		}

		switch e.EventID {
		case 4624:
			analysis.TotalEvents++
			logonType := a.getLogonType(e)
			if logonType == 3 || logonType == 10 || logonType == 12 {
				analysis.RDPConnections++
				if a.isSuspiciousLogin(e) {
					analysis.Findings = append(analysis.Findings, &LateralMovementFinding{
						Type:        "Suspicious RDP",
						Time:        e.Timestamp,
						SourceIP:    a.getSourceIP(e),
						SourceHost:  a.getSourceHost(e),
						TargetHost:  e.Computer,
						User:        a.getTargetUser(e),
						Description: "Suspicious RDP login from external IP",
						Severity:    "high",
						MitreAttack: "T1021.001",
					})
				}
			}

		case 4688:
			analysis.TotalEvents++
			command := strings.ToLower(e.Message)
			if strings.Contains(command, "psexec") || strings.Contains(command, "psexec") {
				analysis.PSExecEvents++
				analysis.Findings = append(analysis.Findings, &LateralMovementFinding{
					Type:        "PSExec Usage",
					Time:        e.Timestamp,
					SourceHost:  e.Computer,
					TargetHost:  a.extractTargetFromCommand(e.Message),
					User:        a.getTargetUser(e),
					Description: "PSExec-like process execution detected",
					Severity:    "critical",
					MitreAttack: "T1021.002",
				})
			}
			if strings.Contains(command, "wmic") || strings.Contains(command, "wmiexec") {
				analysis.WMIEvents++
				analysis.Findings = append(analysis.Findings, &LateralMovementFinding{
					Type:        "WMI Execution",
					Time:        e.Timestamp,
					SourceHost:  e.Computer,
					User:        a.getTargetUser(e),
					Description: "WMI remote execution detected",
					Severity:    "high",
					MitreAttack: "T1047",
				})
			}

		case 4648:
			analysis.TotalEvents++
			if a.isExplicitCredentials(e) {
				analysis.Findings = append(analysis.Findings, &LateralMovementFinding{
					Type:        "Explicit Credentials",
					Time:        e.Timestamp,
					SourceHost:  a.getSourceHost(e),
					TargetHost:  e.Computer,
					User:        a.getTargetUser(e),
					Description: "Logon with explicit credentials - possible lateral movement",
					Severity:    "medium",
					MitreAttack: "T1078.004",
				})
			}
		}
	}

	return analysis
}

func (a *LateralMovementAnalyzer) getLogonType(e *types.Event) int {
	return e.GetLogonType()
}

func (a *LateralMovementAnalyzer) getSourceIP(e *types.Event) string {
	if e.IPAddress != nil && *e.IPAddress != "" && *e.IPAddress != "-" {
		return *e.IPAddress
	}
	return ""
}

func (a *LateralMovementAnalyzer) getSourceIPFromEvent(e *types.Event) string {
	return a.getSourceIP(e)
}

func (a *LateralMovementAnalyzer) getSourceHost(e *types.Event) string {
	if v := e.GetExtractedField("WorkstationName"); v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	if e.IPAddress != nil && *e.IPAddress != "" && *e.IPAddress != "-" {
		return *e.IPAddress
	}
	return ""
}

func (a *LateralMovementAnalyzer) getTargetUser(e *types.Event) string {
	if e.User != nil && *e.User != "" {
		return *e.User
	}
	return ""
}

func (a *LateralMovementAnalyzer) isSuspiciousLogin(e *types.Event) bool {
	sourceIP := a.getSourceIP(e)
	if sourceIP == "" || sourceIP == "-" || sourceIP == "127.0.0.1" {
		return false
	}
	return types.IsExternalIP(sourceIP)
}

func (a *LateralMovementAnalyzer) isExplicitCredentials(e *types.Event) bool {
	return strings.Contains(strings.ToLower(e.Message), "explicit")
}

func (a *LateralMovementAnalyzer) extractTargetFromCommand(message string) string {
	return ""
}

func (a *LateralMovementAnalyzer) detectLateralMovement(analysis *LateralMovementAnalysis) []*LateralMovementFinding {
	return analysis.Findings
}

func (a *LateralMovementAnalyzer) calculateScore(severity string) float64 {
	switch severity {
	case "critical":
		return 90
	case "high":
		return 75
	case "medium":
		return 50
	case "low":
		return 25
	default:
		return 50
	}
}

func (a *LateralMovementAnalyzer) generateSummary(analysis *LateralMovementAnalysis) string {
	return "Lateral Movement Analysis: " +
		" RDP=" + strconv.Itoa(analysis.RDPConnections) +
		" PSExec=" + strconv.Itoa(analysis.PSExecEvents) +
		" WMI=" + strconv.Itoa(analysis.WMIEvents) +
		" Total=" + strconv.Itoa(analysis.TotalEvents)
}
