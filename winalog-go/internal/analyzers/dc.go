package analyzers

import (
	"fmt"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type DCAnalyzer struct {
	BaseAnalyzer
	config *AnalyzerConfig
}

func NewDCAnalyzer() *DCAnalyzer {
	return &DCAnalyzer{
		BaseAnalyzer: BaseAnalyzer{name: "domain_controller"},
		config: &AnalyzerConfig{
			EventIDs:  []int32{4720, 4726, 4728, 4729, 4732, 4733, 4746, 4747, 4756, 4757, 5136, 4662, 5139, 5140, 4670, 4741},
			Patterns:  []string{},
			Whitelist: []string{},
		},
	}
}

func (a *DCAnalyzer) SetConfig(config *AnalyzerConfig) {
	if config != nil {
		a.config = config
	}
}

func (a *DCAnalyzer) GetConfig() *AnalyzerConfig {
	return a.config
}

type DCAnalysis struct {
	UserCreations     int
	UserDeletions     int
	UserModifications int
	GroupAdds         int
	GroupRemoves      int
	PrivilegeAdds     int
	DCReplicationOps  int
	DCSyncAttempts    int
	PolicyChanges     int
	AccountLockouts   int
	LogonFailures     int
	SensitiveGroupOps int
	Anomalies         []*DCAnomaly
}

type DCAnomaly struct {
	Type        string
	User        string
	Target      string
	Time        time.Time
	SourceIP    string
	Severity    string
	Description string
	EventID     int32
	Metadata    map[string]interface{}
}

var sensitiveGroups = []string{
	"enterprise admins",
	"domain admins",
	"schema admins",
	"administrators",
	"backup operators",
	"domain controllers",
	"group policy creator owners",
	"read-only domain controllers",
	"account operators",
	"server operators",
	"network configuration operators",
}

var privilegedAccounts = []string{
	"administrator",
	"krbtgt",
	"domain admin",
	"enterprise admin",
	"schema admin",
}

func (a *DCAnalyzer) Analyze(events []*types.Event) (*Result, error) {
	result := NewResult("domain_controller", nil, "", "medium", 50)

	analysis := a.performAnalysis(events)

	findings := a.detectAnomalies(analysis)

	for _, finding := range findings {
		result.AddFinding(finding)
	}

	result.Summary = a.generateSummary(analysis)
	result.Score = result.CalculateOverallScore()

	return result, nil
}

func (a *DCAnalyzer) performAnalysis(events []*types.Event) *DCAnalysis {
	analysis := &DCAnalysis{
		Anomalies: make([]*DCAnomaly, 0),
	}

	for _, e := range events {
		switch e.EventID {
		case 4720:
			analysis.UserCreations++
			if a.isPrivilegedUser(e) {
				analysis.PrivilegeAdds++
				analysis.Anomalies = append(analysis.Anomalies, &DCAnomaly{
					Type:        "Privileged User Creation",
					User:        a.getSubjectUser(e),
					Target:      a.getTargetUser(e),
					Time:        e.Timestamp,
					SourceIP:    a.getSourceIP(e),
					Severity:    "high",
					Description: "Privileged user account created",
					EventID:     4720,
				})
			}

		case 4726:
			analysis.UserDeletions++
			if a.isPrivilegedUser(e) {
				analysis.PrivilegeAdds++
				analysis.Anomalies = append(analysis.Anomalies, &DCAnomaly{
					Type:        "Privileged User Deletion",
					User:        a.getSubjectUser(e),
					Target:      a.getTargetUser(e),
					Time:        e.Timestamp,
					SourceIP:    a.getSourceIP(e),
					Severity:    "critical",
					Description: "Privileged user account deleted",
					EventID:     4726,
				})
			}

		case 4728, 4732, 4746, 4756:
			analysis.GroupAdds++
			if a.isSensitiveGroupMember(e) {
				analysis.SensitiveGroupOps++
				analysis.Anomalies = append(analysis.Anomalies, &DCAnomaly{
					Type:        "Sensitive Group Addition",
					User:        a.getSubjectUser(e),
					Target:      a.getTargetUser(e),
					Time:        e.Timestamp,
					SourceIP:    a.getSourceIP(e),
					Severity:    "critical",
					Description: fmt.Sprintf("User added to sensitive group: %s", a.getTargetGroup(e)),
					EventID:     e.EventID,
					Metadata: map[string]interface{}{
						"group": a.getTargetGroup(e),
					},
				})
			}

		case 4729, 4733, 4747, 4757:
			analysis.GroupRemoves++
			if a.isSensitiveGroupMember(e) {
				analysis.SensitiveGroupOps++
				analysis.Anomalies = append(analysis.Anomalies, &DCAnomaly{
					Type:        "Sensitive Group Removal",
					User:        a.getSubjectUser(e),
					Target:      a.getTargetUser(e),
					Time:        e.Timestamp,
					SourceIP:    a.getSourceIP(e),
					Severity:    "high",
					Description: fmt.Sprintf("User removed from sensitive group: %s", a.getTargetGroup(e)),
					EventID:     e.EventID,
					Metadata: map[string]interface{}{
						"group": a.getTargetGroup(e),
					},
				})
			}

		case 5136:
			analysis.DCReplicationOps++
			if a.isSensitiveAttributeChange(e) {
				analysis.DCSyncAttempts++
				analysis.Anomalies = append(analysis.Anomalies, &DCAnomaly{
					Type:        "Sensitive Attribute Modification",
					User:        a.getSubjectUser(e),
					Target:      a.getObjectName(e),
					Time:        e.Timestamp,
					SourceIP:    a.getSourceIP(e),
					Severity:    "high",
					Description: fmt.Sprintf("Modification of sensitive attribute: %s", a.getAttributeName(e)),
					EventID:     5136,
					Metadata: map[string]interface{}{
						"attribute": a.getAttributeName(e),
						"object":    a.getObjectName(e),
					},
				})
			}

		case 4662:
			analysis.DCReplicationOps++
			if a.isReplicationOperation(e) {
				analysis.DCSyncAttempts++
				analysis.Anomalies = append(analysis.Anomalies, &DCAnomaly{
					Type:        "Replication Operation",
					User:        a.getSubjectUser(e),
					Target:      a.getObjectName(e),
					Time:        e.Timestamp,
					SourceIP:    a.getSourceIP(e),
					Severity:    "medium",
					Description: "Directory object access related to replication",
					EventID:     4662,
				})
			}

		case 5139:
			analysis.DCReplicationOps++
			analysis.Anomalies = append(analysis.Anomalies, &DCAnomaly{
				Type:        "Directory Object Moved",
				User:        a.getSubjectUser(e),
				Target:      a.getObjectName(e),
				Time:        e.Timestamp,
				SourceIP:    a.getSourceIP(e),
				Severity:    "medium",
				Description: "AD object moved in directory",
				EventID:     5139,
			})

		case 5140:
			analysis.DCReplicationOps++
			if a.isSensitiveShareAccess(e) {
				analysis.Anomalies = append(analysis.Anomalies, &DCAnomaly{
					Type:        "Sensitive Share Access",
					User:        a.getSubjectUser(e),
					Target:      a.getShareName(e),
					Time:        e.Timestamp,
					SourceIP:    a.getSourceIP(e),
					Severity:    "medium",
					Description: "Access to sensitive network share",
					EventID:     5140,
				})
			}

		case 4670:
			analysis.DCReplicationOps++
			if a.isSensitivePrivilege(e) {
				analysis.Anomalies = append(analysis.Anomalies, &DCAnomaly{
					Type:        "Sensitive Privilege Assignment",
					User:        a.getSubjectUser(e),
					Target:      a.getTargetUser(e),
					Time:        e.Timestamp,
					SourceIP:    a.getSourceIP(e),
					Severity:    "critical",
					Description: fmt.Sprintf("Sensitive privilege assigned: %s", a.getPrivilegeName(e)),
					EventID:     4670,
					Metadata: map[string]interface{}{
						"privilege": a.getPrivilegeName(e),
					},
				})
			}

		case 4741:
			analysis.UserModifications++
			if a.isKrbtgtPasswordChange(e) {
				analysis.Anomalies = append(analysis.Anomalies, &DCAnomaly{
					Type:        "Krbtgt Password Change",
					User:        a.getSubjectUser(e),
					Target:      a.getTargetUser(e),
					Time:        e.Timestamp,
					SourceIP:    a.getSourceIP(e),
					Severity:    "info",
					Description: "Krbtgt account password changed - verify if authorized",
					EventID:     4741,
				})
			}

		case 5138:
			analysis.PolicyChanges++
			analysis.Anomalies = append(analysis.Anomalies, &DCAnomaly{
				Type:        "Directory Service Policy Changed",
				User:        a.getSubjectUser(e),
				Target:      a.getObjectName(e),
				Time:        e.Timestamp,
				SourceIP:    a.getSourceIP(e),
				Severity:    "high",
				Description: "Directory service policy was modified",
				EventID:     5138,
			})

		case 5141:
			analysis.DCReplicationOps++
			analysis.Anomalies = append(analysis.Anomalies, &DCAnomaly{
				Type:        "Directory Service Object Accessed",
				User:        a.getSubjectUser(e),
				Target:      a.getObjectName(e),
				Time:        e.Timestamp,
				SourceIP:    a.getSourceIP(e),
				Severity:    "low",
				Description: "Directory object was accessed",
				EventID:     5141,
			})

		case 4625:
			analysis.LogonFailures++
			if a.isAdminLogonFailure(e) {
				analysis.Anomalies = append(analysis.Anomalies, &DCAnomaly{
					Type:        "Admin Logon Failure",
					User:        a.getTargetUser(e),
					Time:        e.Timestamp,
					SourceIP:    a.getSourceIP(e),
					Severity:    "high",
					Description: "Failed logon attempt to privileged account",
					EventID:     4625,
				})
			}

		case 4624:
			if a.isNetworkLogonToDC(e) {
				if a.isPrivilegedLogon(e) {
					analysis.Anomalies = append(analysis.Anomalies, &DCAnomaly{
						Type:        "Privileged Network Logon to DC",
						User:        a.getTargetUser(e),
						Time:        e.Timestamp,
						SourceIP:    a.getSourceIP(e),
						Severity:    "medium",
						Description: "Privileged account logged in via network to DC",
						EventID:     4624,
					})
				}
			}

		case 4768:
			if a.isKrbtgtTGT(e) {
				analysis.Anomalies = append(analysis.Anomalies, &DCAnomaly{
					Type:        "Krbtgt TGT Request",
					User:        a.getTargetUser(e),
					Time:        e.Timestamp,
					SourceIP:    a.getSourceIP(e),
					Severity:    "info",
					Description: "TGT requested for krbtgt account",
					EventID:     4768,
				})
			}
		}
	}

	return analysis
}

func (a *DCAnalyzer) isPrivilegedUser(e *types.Event) bool {
	user := strings.ToLower(a.getTargetUser(e))
	for _, priv := range privilegedAccounts {
		if strings.Contains(user, priv) {
			return true
		}
	}
	return false
}

func (a *DCAnalyzer) isSensitiveGroupMember(e *types.Event) bool {
	group := strings.ToLower(a.getTargetGroup(e))
	for _, sensitive := range sensitiveGroups {
		if strings.Contains(group, sensitive) {
			return true
		}
	}
	return false
}

func (a *DCAnalyzer) isSensitiveAttributeChange(e *types.Event) bool {
	attr := strings.ToLower(a.getAttributeName(e))
	sensitiveAttrs := []string{
		"pwdlastset", "logoncount", "samaccountname",
		"useraccountcontrol", "supplementalcredentials",
		"ntsecuritydescriptor", "lmhistory",
	}
	for _, sensitive := range sensitiveAttrs {
		if strings.Contains(attr, sensitive) {
			return true
		}
	}
	return false
}

func (a *DCAnalyzer) isReplicationOperation(e *types.Event) bool {
	msg := strings.ToLower(e.Message)
	replicationAttrs := []string{
		"replication", "dsreplication", "drs",
	}
	for _, attr := range replicationAttrs {
		if strings.Contains(msg, attr) {
			return true
		}
	}
	return false
}

func (a *DCAnalyzer) isSensitiveShareAccess(e *types.Event) bool {
	share := strings.ToLower(a.getShareName(e))
	sensitiveShares := []string{
		"sysvol", "netlogon", "admin$",
		"c$", "ipc$", "scripts",
	}
	for _, s := range sensitiveShares {
		if strings.Contains(share, s) {
			return true
		}
	}
	return false
}

func (a *DCAnalyzer) isSensitivePrivilege(e *types.Event) bool {
	priv := strings.ToLower(a.getPrivilegeName(e))
	sensitivePrivs := []string{
		"sesecurityprivilege", "setakeyprivilege",
		"restore privilege", "backup privilege",
		"debug", "impersonate",
	}
	for _, sp := range sensitivePrivs {
		if strings.Contains(priv, sp) {
			return true
		}
	}
	return false
}

func (a *DCAnalyzer) isKrbtgtPasswordChange(e *types.Event) bool {
	return strings.Contains(strings.ToLower(a.getTargetUser(e)), "krbtgt")
}

func (a *DCAnalyzer) isNetworkLogonToDC(e *types.Event) bool {
	logonType := a.extractField(e.Message, "LogonType:", "Logon Type:")
	return strings.Contains(logonType, "3")
}

func (a *DCAnalyzer) isPrivilegedLogon(e *types.Event) bool {
	user := strings.ToLower(a.getTargetUser(e))
	for _, priv := range privilegedAccounts {
		if strings.Contains(user, priv) {
			return true
		}
	}
	return false
}

func (a *DCAnalyzer) isKrbtgtTGT(e *types.Event) bool {
	return strings.Contains(strings.ToLower(a.getTargetUser(e)), "krbtgt")
}

func (a *DCAnalyzer) isAdminLogonFailure(e *types.Event) bool {
	user := strings.ToLower(a.getTargetUser(e))
	for _, priv := range privilegedAccounts {
		if strings.Contains(user, priv) {
			return true
		}
	}
	return false
}

func (a *DCAnalyzer) getSubjectUser(e *types.Event) string {
	if e.User != nil && *e.User != "" {
		return *e.User
	}
	return a.extractField(e.Message, "Subject:", "SubjectUserName:", "Caller User Name:")
}

func (a *DCAnalyzer) getTargetUser(e *types.Event) string {
	return a.extractField(e.Message, "Target:", "TargetUserName:", "Account Name:")
}

func (a *DCAnalyzer) getTargetGroup(e *types.Event) string {
	return a.extractField(e.Message, "Target Group:", "Group Name:", "Member:")
}

func (a *DCAnalyzer) getSourceIP(e *types.Event) string {
	if e.IPAddress != nil && *e.IPAddress != "" && *e.IPAddress != "-" {
		return *e.IPAddress
	}
	return a.extractField(e.Message, "IpAddress:", "Client Address:", "Source Address:")
}

func (a *DCAnalyzer) getObjectName(e *types.Event) string {
	return a.extractField(e.Message, "Object:", "Object Name:", "Object DN:")
}

func (a *DCAnalyzer) getAttributeName(e *types.Event) string {
	return a.extractField(e.Message, "Attribute:", "Attribute Name:")
}

func (a *DCAnalyzer) getShareName(e *types.Event) string {
	return a.extractField(e.Message, "Share Name:", "Share:")
}

func (a *DCAnalyzer) getPrivilegeName(e *types.Event) string {
	return a.extractField(e.Message, "Privilege:", "Privilege Name:")
}

func (a *DCAnalyzer) extractField(message string, patterns ...string) string {
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

func (a *DCAnalyzer) detectAnomalies(analysis *DCAnalysis) []Finding {
	findings := make([]Finding, 0)

	if analysis.DCSyncAttempts > 0 {
		findings = append(findings, Finding{
			Description: "Possible DCSync attack detected - replication of sensitive AD data",
			RuleName:    "DC - DCSync Attack",
			MitreAttack: "T1003.006",
			Severity:    "critical",
			Score:       95,
			Metadata: map[string]interface{}{
				"count": analysis.DCSyncAttempts,
			},
		})
	}

	if analysis.SensitiveGroupOps > 0 {
		findings = append(findings, Finding{
			Description: "Sensitive group membership changes detected",
			RuleName:    "DC - Sensitive Group Modification",
			MitreAttack: "T1078.004",
			Severity:    "critical",
			Score:       90,
			Metadata: map[string]interface{}{
				"count": analysis.SensitiveGroupOps,
			},
		})
	}

	if analysis.PrivilegeAdds > 0 {
		findings = append(findings, Finding{
			Description: "Privileged account created or deleted",
			RuleName:    "DC - Privileged Account Change",
			MitreAttack: "T1078.004",
			Severity:    "high",
			Score:       80,
			Metadata: map[string]interface{}{
				"count": analysis.PrivilegeAdds,
			},
		})
	}

	if analysis.PolicyChanges > 0 {
		findings = append(findings, Finding{
			Description: "Directory service policy changes detected",
			RuleName:    "DC - Policy Change",
			MitreAttack: "T1484.001",
			Severity:    "medium",
			Score:       60,
			Metadata: map[string]interface{}{
				"count": analysis.PolicyChanges,
			},
		})
	}

	if analysis.DCReplicationOps > 10 {
		findings = append(findings, Finding{
			Description: "High number of directory replication operations",
			RuleName:    "DC - Replication Flood",
			MitreAttack: "T1003.006",
			Severity:    "medium",
			Score:       50,
			Metadata: map[string]interface{}{
				"count": analysis.DCReplicationOps,
			},
		})
	}

	return findings
}

func (a *DCAnalyzer) generateSummary(analysis *DCAnalysis) string {
	var sb strings.Builder
	sb.WriteString("Domain Controller Analysis Summary:\n")
	sb.WriteString("  User Creations: ")
	sb.WriteString(fmt.Sprintf("%d", analysis.UserCreations))
	sb.WriteString("\n  User Deletions: ")
	sb.WriteString(fmt.Sprintf("%d", analysis.UserDeletions))
	sb.WriteString("\n  Group Additions: ")
	sb.WriteString(fmt.Sprintf("%d", analysis.GroupAdds))
	sb.WriteString("\n  Group Removals: ")
	sb.WriteString(fmt.Sprintf("%d", analysis.GroupRemoves))
	sb.WriteString("\n  Privileged Operations: ")
	sb.WriteString(fmt.Sprintf("%d", analysis.PrivilegeAdds))
	sb.WriteString("\n  DC Replication Ops: ")
	sb.WriteString(fmt.Sprintf("%d", analysis.DCReplicationOps))
	sb.WriteString("\n  DCSync Attempts: ")
	sb.WriteString(fmt.Sprintf("%d", analysis.DCSyncAttempts))
	sb.WriteString("\n  Policy Changes: ")
	sb.WriteString(fmt.Sprintf("%d", analysis.PolicyChanges))
	sb.WriteString("\n  Anomalies Detected: ")
	sb.WriteString(fmt.Sprintf("%d", len(analysis.Anomalies)))
	return sb.String()
}
