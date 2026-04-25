package analyzers

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type DataExfiltrationAnalyzer struct {
	BaseAnalyzer
	config *AnalyzerConfig
}

func NewDataExfiltrationAnalyzer() *DataExfiltrationAnalyzer {
	return &DataExfiltrationAnalyzer{
		BaseAnalyzer: BaseAnalyzer{name: "data_exfiltration"},
		config: &AnalyzerConfig{
			EventIDs:  []int32{4624, 4688, 4663},
			Patterns:  []string{},
			Whitelist: []string{},
		},
	}
}

func (a *DataExfiltrationAnalyzer) SetConfig(config *AnalyzerConfig) {
	if config != nil {
		a.config = config
	}
}

func (a *DataExfiltrationAnalyzer) GetConfig() *AnalyzerConfig {
	return a.config
}

func (a *DataExfiltrationAnalyzer) shouldProcessEvent(e *types.Event) bool {
	eventIDs := a.config.EventIDs
	if len(eventIDs) == 0 {
		eventIDs = []int32{4624, 4688, 4663}
	}

	for _, id := range eventIDs {
		if e.EventID == id {
			return true
		}
	}
	return false
}

type DataExfiltrationAnalysis struct {
	TotalEvents     int
	LargeOutbound   int
	CloudUploads    int
	USBTransfers    int
	SuspiciousExfil int
	UnusualHours    int
	MassFileAccess  int
	Findings        []*ExfilFinding
}

type ExfilFinding struct {
	Type        string
	Time        time.Time
	User        string
	Computer    string
	SourceIP    string
	Destination string
	FileCount   int
	Volume      string
	Description string
	Severity    string
	MitreAttack string
}

func (a *DataExfiltrationAnalyzer) Analyze(events []*types.Event) (*Result, error) {
	result := NewResult("data_exfiltration", nil, "", "low", 30)

	analysis := a.performAnalysis(events)
	findings := a.detectExfiltration(analysis)

	for _, finding := range findings {
		result.AddFinding(Finding{
			Description: finding.Description,
			RuleName:    "Data Exfiltration - " + finding.Type,
			MitreAttack: finding.MitreAttack,
			Severity:    finding.Severity,
			Score:       a.calculateScore(finding.Severity),
			Metadata: map[string]interface{}{
				"user":        finding.User,
				"computer":    finding.Computer,
				"source_ip":   finding.SourceIP,
				"destination": finding.Destination,
				"file_count":  finding.FileCount,
				"volume":      finding.Volume,
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

func (a *DataExfiltrationAnalyzer) performAnalysis(events []*types.Event) *DataExfiltrationAnalysis {
	analysis := &DataExfiltrationAnalysis{
		Findings: make([]*ExfilFinding, 0),
	}

	suspiciousExtensions := []string{
		".docx", ".xlsx", ".pdf", ".zip", ".rar",
		".7z", ".tar", ".gz", ".bak", ".backup",
		".pst", ".ost", ".mbox",
	}

	suspiciousKeywords := []string{
		"upload", "exfil", "steal", "extract",
		"credential", "password", "shadow",
		"backup", "archive", "dump",
	}

	for _, e := range events {
		if !a.shouldProcessEvent(e) {
			continue
		}

		switch e.EventID {
		case 4624:
			analysis.TotalEvents++
			if a.isUnusualHours(e.Timestamp) {
				analysis.UnusualHours++
				analysis.Findings = append(analysis.Findings, &ExfilFinding{
					Type:        "Off-Hours Login",
					Time:        e.Timestamp,
					User:        a.getUser(e),
					Computer:    e.Computer,
					SourceIP:    a.getSourceIP(e),
					Description: "Login detected during unusual hours",
					Severity:    "low",
					MitreAttack: "T1074",
				})
			}

		case 4688:
			analysis.TotalEvents++
			command := strings.ToLower(e.Message)
			for _, ext := range suspiciousExtensions {
				if strings.Contains(command, ext) {
					analysis.MassFileAccess++
					analysis.Findings = append(analysis.Findings, &ExfilFinding{
						Type:        "Sensitive File Access",
						Time:        e.Timestamp,
						User:        a.getUser(e),
						Computer:    e.Computer,
						Description: "Process accessing sensitive file extension: " + ext,
						Severity:    "medium",
						MitreAttack: "T1005",
					})
					break
				}
			}
			for _, kw := range suspiciousKeywords {
				if strings.Contains(command, kw) {
					analysis.SuspiciousExfil++
					analysis.Findings = append(analysis.Findings, &ExfilFinding{
						Type:        "Suspicious Keyword",
						Time:        e.Timestamp,
						User:        a.getUser(e),
						Computer:    e.Computer,
						Description: "Suspicious keyword detected: " + kw,
						Severity:    "high",
						MitreAttack: "T1041",
					})
					break
				}
			}

		case 4663:
			analysis.TotalEvents++
			if a.isCopyToRemovable(e.Message) {
				analysis.USBTransfers++
				analysis.Findings = append(analysis.Findings, &ExfilFinding{
					Type:        "USB Transfer",
					Time:        e.Timestamp,
					User:        a.getUser(e),
					Computer:    e.Computer,
					Description: "File copy to removable media detected",
					Severity:    "high",
					MitreAttack: "T1025",
				})
			}
		}
	}

	return analysis
}

func (a *DataExfiltrationAnalyzer) getUser(e *types.Event) string {
	if e.User != nil && *e.User != "" {
		return *e.User
	}
	return ""
}

func (a *DataExfiltrationAnalyzer) getSourceIP(e *types.Event) string {
	if e.IPAddress != nil && *e.IPAddress != "" && *e.IPAddress != "-" {
		return *e.IPAddress
	}
	return ""
}

func (a *DataExfiltrationAnalyzer) getDestIP(e *types.Event) string {
	return a.getSourceIP(e)
}

func (a *DataExfiltrationAnalyzer) isUnusualHours(t time.Time) bool {
	hour := t.Hour()
	return hour < 6 || hour > 22
}

func (a *DataExfiltrationAnalyzer) isCloudService(ip string) bool {
	if ip == "" {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	cloudCIDRs := []string{
		"162.125.0.0/16",   // Dropbox
		"108.160.160.0/19", // Dropbox
		"34.64.0.0/10",     // Google Cloud
		"35.190.0.0/17",    // Google Cloud
		"13.64.0.0/11",     // Azure
		"13.104.0.0/14",    // Azure
		"52.96.0.0/14",     // Azure
		"104.40.0.0/13",    // Azure
		"54.240.0.0/16",    // Amazon AWS
		"99.77.0.0/16",     // Amazon CloudFront
		"185.60.216.0/22",  // iCloud
		"17.0.0.0/8",       // Apple iCloud
		"130.211.0.0/16",   // Google
		"199.16.156.0/22",  // Dropbox
	}

	for _, cidr := range cloudCIDRs {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			if ipNet.Contains(parsedIP) {
				return true
			}
		}
	}

	return false
}

func (a *DataExfiltrationAnalyzer) isCopyToRemovable(message string) bool {
	removableKeywords := []string{
		"removable", "usb", "flash", "mass storage",
		"\\device\\harddiskvolume", "d:", "e:", "f:",
	}
	msgLower := strings.ToLower(message)
	for _, keyword := range removableKeywords {
		if strings.Contains(msgLower, keyword) {
			return true
		}
	}
	return false
}

func (a *DataExfiltrationAnalyzer) detectExfiltration(analysis *DataExfiltrationAnalysis) []*ExfilFinding {
	return analysis.Findings
}

func (a *DataExfiltrationAnalyzer) calculateScore(severity string) float64 {
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

func (a *DataExfiltrationAnalyzer) generateSummary(analysis *DataExfiltrationAnalysis) string {
	return "Data Exfiltration Analysis: " +
		" LargeOutbound=" + strconv.Itoa(analysis.LargeOutbound) +
		" CloudUploads=" + strconv.Itoa(analysis.CloudUploads) +
		" USBTransfers=" + strconv.Itoa(analysis.USBTransfers) +
		" UnusualHours=" + strconv.Itoa(analysis.UnusualHours)
}
