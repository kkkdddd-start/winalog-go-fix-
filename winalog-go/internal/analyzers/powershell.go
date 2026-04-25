package analyzers

import (
	"strconv"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type PowerShellAnalyzer struct {
	BaseAnalyzer
	config *AnalyzerConfig
}

func NewPowerShellAnalyzer() *PowerShellAnalyzer {
	return &PowerShellAnalyzer{
		BaseAnalyzer: BaseAnalyzer{name: "powershell"},
		config: &AnalyzerConfig{
			EventIDs:  []int32{4103, 4104},
			Patterns:  []string{"powershell", "Invoke-", "cmd.exe", "-enc", "-EncodedCommand", "-w hidden", "IEX", "Invoke-Expression", "Invoke-WebRequest", "downloadstring", "downloadfile", "mimikatz"},
			Whitelist: []string{},
		},
	}
}

func (a *PowerShellAnalyzer) SetConfig(config *AnalyzerConfig) {
	if config != nil {
		a.config = config
	}
}

func (a *PowerShellAnalyzer) GetConfig() *AnalyzerConfig {
	return a.config
}

func (a *PowerShellAnalyzer) shouldProcessEvent(e *types.Event) bool {
	eventIDs := a.config.EventIDs
	if len(eventIDs) == 0 {
		eventIDs = []int32{4103, 4104}
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
			if strings.Contains(e.Message, w) {
				return false
			}
		}
	}
	return true
}

func (a *PowerShellAnalyzer) isWhitelistedPath(e *types.Event) bool {
	whitelist := []string{
		`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`,
		`%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`,
		`%SystemRoot%\System32\wbem\wmiadap.exe`,
		`%ProgramFiles%\Microsoft Monitoring Agent\Agent\MonitoringHost.exe`,
	}
	path := getProcessPath(e)
	for _, w := range whitelist {
		if strings.Contains(path, strings.ReplaceAll(w, `%SystemRoot%\System32`, `C:\Windows\System32`)) ||
			strings.Contains(path, strings.ReplaceAll(w, `%SystemRoot%\SysWOW64`, `C:\Windows\SysWOW64`)) ||
			strings.Contains(path, strings.ReplaceAll(w, `%ProgramFiles%`, `C:\Program Files`)) {
			return true
		}
	}
	return false
}

func getProcessPath(e *types.Event) string {
	if e.Message != "" {
		parts := strings.Split(e.Message, "Process Name:")
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

type PowerShellAnalysis struct {
	EncodedCommands   int
	SuspiciousScripts int
	InvokeCommands    int
	RiskScore         float64
	Anomalies         []*PowerShellAnomaly
}

type PowerShellAnomaly struct {
	Type        string
	Time        time.Time
	Source      string
	Command     string
	Severity    string
	Description string
}

func (a *PowerShellAnalyzer) Analyze(events []*types.Event) (*Result, error) {
	result := NewResult("powershell", nil, "", "medium", 50)

	analysis := a.performAnalysis(events)

	findings := a.detectAnomalies(analysis)

	for _, finding := range findings {
		result.AddFinding(finding)
	}

	result.Summary = a.generateSummary(analysis)
	result.Score = result.CalculateOverallScore()

	return result, nil
}

func (a *PowerShellAnalyzer) performAnalysis(events []*types.Event) *PowerShellAnalysis {
	analysis := &PowerShellAnalysis{
		Anomalies: make([]*PowerShellAnomaly, 0),
	}

	patterns := a.config.Patterns
	if len(patterns) == 0 {
		patterns = []string{
			"mimikatz", "pwdump", "hashdump",
			"invoke-mimikatz", "sekurlsa",
			"empire", "meterpreter",
			"net user", "net localgroup",
			"reg save", "lsass",
			"extract", "dcsync",
		}
	}

	for _, e := range events {
		if !a.shouldProcessEvent(e) {
			continue
		}

		if a.isWhitelistedPath(e) {
			continue
		}

		command := a.extractCommand(e)
		if command == "" {
			continue
		}

		commandLower := strings.ToLower(command)

		if strings.Contains(commandLower, "-encodedcommand") ||
			strings.Contains(commandLower, "-enc ") {
			analysis.EncodedCommands++
			analysis.Anomalies = append(analysis.Anomalies, &PowerShellAnomaly{
				Type:        "Encoded Command",
				Time:        e.Timestamp,
				Command:     command,
				Severity:    "high",
				Description: "PowerShell encoded command detected",
			})
		}

		if strings.Contains(commandLower, "invoke-") ||
			strings.Contains(commandLower, "iex ") {
			analysis.InvokeCommands++
		}

		for _, pattern := range patterns {
			patternLower := strings.ToLower(pattern)
			if strings.Contains(commandLower, patternLower) {
				analysis.SuspiciousScripts++
				analysis.Anomalies = append(analysis.Anomalies, &PowerShellAnomaly{
					Type:        "Suspicious Script",
					Time:        e.Timestamp,
					Command:     command,
					Severity:    "critical",
					Description: "Suspicious PowerShell script detected: " + pattern,
				})
				break
			}
		}
	}

	analysis.RiskScore = a.calculateRiskScore(analysis)

	return analysis
}

func (a *PowerShellAnalyzer) matchesPattern(e *types.Event) bool {
	patterns := a.config.Patterns
	if len(patterns) == 0 {
		return false
	}

	command := strings.ToLower(e.Message)
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(strings.ToLower(pattern))
		if pattern == "" {
			continue
		}
		if strings.Contains(command, pattern) {
			return true
		}
	}
	return false
}

func (a *PowerShellAnalyzer) extractCommand(e *types.Event) string {
	if e.Message != "" {
		return e.Message
	}

	return ""
}

func (a *PowerShellAnalyzer) calculateRiskScore(analysis *PowerShellAnalysis) float64 {
	score := 0.0

	if analysis.EncodedCommands > 0 {
		score += 30
	}
	if analysis.SuspiciousScripts > 0 {
		score += 50
	}
	if analysis.InvokeCommands > 5 {
		score += 20
	}

	if score > 100 {
		score = 100
	}

	return score
}

func (a *PowerShellAnalyzer) detectAnomalies(analysis *PowerShellAnalysis) []Finding {
	findings := make([]Finding, 0)

	if analysis.EncodedCommands > 0 {
		findings = append(findings, Finding{
			Description: "PowerShell encoded command detected - common in attacks",
			RuleName:    "PowerShell - Encoded Command",
			MitreAttack: "T1059.001",
			Severity:    "high",
			Score:       75,
			Metadata: map[string]interface{}{
				"count": analysis.EncodedCommands,
			},
		})
	}

	if analysis.SuspiciousScripts > 0 {
		findings = append(findings, Finding{
			Description: "Suspicious PowerShell script detected - possible attacker tool",
			RuleName:    "PowerShell - Suspicious Script",
			MitreAttack: "T1059.001",
			Severity:    "critical",
			Score:       90,
			Metadata: map[string]interface{}{
				"count": analysis.SuspiciousScripts,
			},
		})
	}

	return findings
}

func (a *PowerShellAnalyzer) generateSummary(analysis *PowerShellAnalysis) string {
	var sb strings.Builder
	sb.WriteString("PowerShell Analysis Summary:\n")
	sb.WriteString("  Encoded Commands: ")
	sb.WriteString(strconv.Itoa(analysis.EncodedCommands))
	sb.WriteString("\n  Invoke Commands: ")
	sb.WriteString(strconv.Itoa(analysis.InvokeCommands))
	sb.WriteString("\n  Suspicious Scripts: ")
	sb.WriteString(strconv.Itoa(analysis.SuspiciousScripts))
	sb.WriteString("\n  Risk Score: ")
	sb.WriteString(strconv.Itoa(int(analysis.RiskScore)))
	return sb.String()
}
