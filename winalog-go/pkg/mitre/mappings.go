package mitre

import (
	"fmt"
	"strings"
)

type ATTACKTechnique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Tactic      string   `json:"tactic"`
	Description string   `json:"description"`
	Platforms   []string `json:"platforms,omitempty"`
	DataSources []string `json:"data_sources,omitempty"`
}

type ATTACKTactic struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Techniques  []string `json:"techniques,omitempty"`
}

var (
	Techniques = map[string]*ATTACKTechnique{
		"T1003": {
			ID:          "T1003",
			Name:        "OS Credential Dumping",
			Tactic:      "Credential Access",
			Description: "Adversaries may dump credentials to obtain account login and credential material",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Windows Event Logs", "LSASS"},
		},
		"T1005": {
			ID:          "T1005",
			Name:        "Data from Local System",
			Tactic:      "Collection",
			Description: "Adversaries may collect data from local system",
			Platforms:   []string{"Windows"},
			DataSources: []string{"File System", "Registry"},
		},
		"T1018": {
			ID:          "T1018",
			Name:        "Remote System Discovery",
			Tactic:      "Discovery",
			Description: "Adversaries may discover remote systems",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Network Traffic", "Windows Event Logs"},
		},
		"T1021": {
			ID:          "T1021",
			Name:        "Remote Services",
			Tactic:      "Lateral Movement",
			Description: "Adversaries may use remote services to move laterally",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Windows Event Logs", "Network Traffic"},
		},
		"T1037": {
			ID:          "T1037",
			Name:        "Boot or Logon Initialization Scripts",
			Tactic:      "Persistence",
			Description: "Adversaries may use boot or logon scripts",
			Platforms:   []string{"Windows"},
			DataSources: []string{"File System", "Windows Event Logs"},
		},
		"T1047": {
			ID:          "T1047",
			Name:        "Windows Management Instrumentation",
			Tactic:      "Execution",
			Description: "Adversaries may use WMI for execution",
			Platforms:   []string{"Windows"},
			DataSources: []string{"WMI", "Windows Event Logs"},
		},
		"T1053": {
			ID:          "T1053",
			Name:        "Scheduled Task/Job",
			Tactic:      "Persistence",
			Description: "Adversaries may create scheduled tasks for persistence",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Windows Task Scheduler", "Windows Event Logs"},
		},
		"T1055": {
			ID:          "T1055",
			Name:        "Process Injection",
			Tactic:      "Defense Evasion",
			Description: "Adversaries may inject code into processes",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Process Monitoring", "DLL Monitoring"},
		},
		"T1057": {
			ID:          "T1057",
			Name:        "Process Discovery",
			Tactic:      "Discovery",
			Description: "Adversaries may discover running processes",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Process Monitoring", "Windows Event Logs"},
		},
		"T1059": {
			ID:          "T1059",
			Name:        "Command and Scripting Interpreter",
			Tactic:      "Execution",
			Description: "Adversaries may use command and scripting interpreters",
			Platforms:   []string{"Windows"},
			DataSources: []string{"PowerShell Logs", "Windows Event Logs"},
		},
		"T1070": {
			ID:          "T1070",
			Name:        "Indicator Removal",
			Tactic:      "Defense Evasion",
			Description: "Adversaries may remove indicators",
			Platforms:   []string{"Windows"},
			DataSources: []string{"File System", "Windows Event Logs"},
		},
		"T1071": {
			ID:          "T1071",
			Name:        "Application Layer Protocol",
			Tactic:      "Command and Control",
			Description: "Adversaries may use application layer protocols",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Network Traffic", "DNS"},
		},
		"T1072": {
			ID:          "T1072",
			Name:        "Software Deployment Tools",
			Tactic:      "Lateral Movement",
			Description: "Adversaries may use software deployment tools",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Windows Event Logs", "Process Monitoring"},
		},
		"T1078": {
			ID:          "T1078",
			Name:        "Valid Accounts",
			Tactic:      "Defense Evasion",
			Description: "Adversaries may use valid accounts",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Windows Event Logs", "Authentication Logs"},
		},
		"T1082": {
			ID:          "T1082",
			Name:        "System Information Discovery",
			Tactic:      "Discovery",
			Description: "Adversaries may discover system information",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Windows Event Logs", "Registry"},
		},
		"T1086": {
			ID:          "T1086",
			Name:        "PowerShell",
			Tactic:      "Execution",
			Description: "Adversaries may use PowerShell",
			Platforms:   []string{"Windows"},
			DataSources: []string{"PowerShell Logs", "Windows Event Logs"},
		},
		"T1095": {
			ID:          "T1095",
			Name:        "Non-Application Layer Protocol",
			Tactic:      "Command and Control",
			Description: "Adversaries may use non-application layer protocols",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Network Traffic"},
		},
		"T1097": {
			ID:          "T1097",
			Name:        "Pass the Ticket",
			Tactic:      "Lateral Movement",
			Description: "Adversaries may pass tickets for lateral movement",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Kerberos Logs", "Windows Event Logs"},
		},
		"T1098": {
			ID:          "T1098",
			Name:        "Account Manipulation",
			Tactic:      "Persistence",
			Description: "Adversaries may manipulate accounts",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Windows Event Logs", "Active Directory"},
		},
		"T1106": {
			ID:          "T1106",
			Name:        "Native API",
			Tactic:      "Execution",
			Description: "Adversaries may use native APIs",
			Platforms:   []string{"Windows"},
			DataSources: []string{"API Monitoring", "Windows Event Logs"},
		},
		"T1110": {
			ID:          "T1110",
			Name:        "Brute Force",
			Tactic:      "Credential Access",
			Description: "Adversaries may use brute force to obtain credentials",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Windows Event Logs", "Authentication Logs"},
		},
		"T1112": {
			ID:          "T1112",
			Name:        "Modify Registry",
			Tactic:      "Defense Evasion",
			Description: "Adversaries may modify registry",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Registry Monitoring", "Windows Event Logs"},
		},
		"T1113": {
			ID:          "T1113",
			Name:        "Screen Capture",
			Tactic:      "Collection",
			Description: "Adversaries may capture screen",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Process Monitoring", "Windows Event Logs"},
		},
		"T1114": {
			ID:          "T1114",
			Name:        "Email Collection",
			Tactic:      "Collection",
			Description: "Adversaries may collect email",
			Platforms:   []string{"Windows"},
			DataSources: []string{"File System", "Email Logs"},
		},
		"T1124": {
			ID:          "T1124",
			Name:        "System Time Discovery",
			Tactic:      "Discovery",
			Description: "Adversaries may discover system time",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Windows Event Logs"},
		},
		"T1127": {
			ID:          "T1127",
			Name:        "Trusted Developer Utilities",
			Tactic:      "Defense Evasion",
			Description: "Adversaries may use trusted developer utilities",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Process Monitoring", "DLL Monitoring"},
		},
		"T1189": {
			ID:          "T1189",
			Name:        "Drive-by Compromise",
			Tactic:      "Initial Access",
			Description: "Adversaries may compromise systems via drive-by",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Network Traffic", "Web Proxy"},
		},
		"T1190": {
			ID:          "T1190",
			Name:        "Exploit Public-Facing Application",
			Tactic:      "Initial Access",
			Description: "Adversaries may exploit public-facing applications",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Web Logs", "Network Traffic"},
		},
		"T1197": {
			ID:          "T1197",
			Name:        "BITS Jobs",
			Tactic:      "Defense Evasion",
			Description: "Adversaries may use BITS jobs",
			Platforms:   []string{"Windows"},
			DataSources: []string{"BITS Logs", "Windows Event Logs"},
		},
		"T1203": {
			ID:          "T1203",
			Name:        "Exploitation for Client Execution",
			Tactic:      "Execution",
			Description: "Adversaries may exploit for client execution",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Exploit Detection", "Windows Event Logs"},
		},
		"T1204": {
			ID:          "T1204",
			Name:        "User Execution",
			Tactic:      "Execution",
			Description: "Adversaries may rely on user execution",
			Platforms:   []string{"Windows"},
			DataSources: []string{"File System", "Windows Event Logs"},
		},
		"T1218": {
			ID:          "T1218",
			Name:        "System Binary Proxy Execution",
			Tactic:      "Defense Evasion",
			Description: "Adversaries may use system binary proxy execution",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Process Monitoring", "Windows Event Logs"},
		},
		"T1219": {
			ID:          "T1219",
			Name:        "Remote Access Software",
			Tactic:      "Command and Control",
			Description: "Adversaries may use remote access software",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Network Traffic", "Windows Event Logs"},
		},
		"T1543": {
			ID:          "T1543",
			Name:        "Create/Modify System Process",
			Tactic:      "Persistence",
			Description: "Adversaries may create or modify system processes",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Windows Event Logs", "Process Monitoring"},
		},
		"T1547": {
			ID:          "T1547",
			Name:        "Boot or Logon Autostart Execution",
			Tactic:      "Persistence",
			Description: "Adversaries may configure autostart execution",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Registry", "Windows Event Logs"},
		},
		"T1550": {
			ID:          "T1550",
			Name:        "Use Alternate Authentication Material",
			Tactic:      "Defense Evasion",
			Description: "Adversaries may use alternate authentication material",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Windows Event Logs", "Authentication Logs"},
		},
		"T1552": {
			ID:          "T1552",
			Name:        "Unsecured Credentials",
			Tactic:      "Credential Access",
			Description: "Adversaries may obtain unsecured credentials",
			Platforms:   []string{"Windows"},
			DataSources: []string{"File System", "Registry"},
		},
		"T1553": {
			ID:          "T1553",
			Name:        "Subvert Trust Controls",
			Tactic:      "Defense Evasion",
			Description: "Adversaries may subvert trust controls",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Code Signing", "Windows Event Logs"},
		},
		"T1556": {
			ID:          "T1556",
			Name:        "Modify Authentication Process",
			Tactic:      "Credential Access",
			Description: "Adversaries may modify authentication process",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Authentication Logs", "Windows Event Logs"},
		},
		"T1558": {
			ID:          "T1558",
			Name:        "Steal or Forge Kerberos Tickets",
			Tactic:      "Credential Access",
			Description: "Adversaries may steal or forge Kerberos tickets",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Kerberos Logs", "Windows Event Logs"},
		},
		"T1560": {
			ID:          "T1560",
			Name:        "Archive Collected Data",
			Tactic:      "Collection",
			Description: "Adversaries may archive collected data",
			Platforms:   []string{"Windows"},
			DataSources: []string{"File System", "Windows Event Logs"},
		},
		"T1562": {
			ID:          "T1562",
			Name:        "Impair Defenses",
			Tactic:      "Defense Evasion",
			Description: "Adversaries may impair defenses",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Security Logs", "Windows Event Logs"},
		},
		"T1565": {
			ID:          "T1565",
			Name:        "Data Manipulation",
			Tactic:      "Impact",
			Description: "Adversaries may manipulate data",
			Platforms:   []string{"Windows"},
			DataSources: []string{"File System", "Database Logs"},
		},
		"T1569": {
			ID:          "T1569",
			Name:        "System Services",
			Tactic:      "Execution",
			Description: "Adversaries may use system services for execution",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Windows Event Logs", "Process Monitoring"},
		},
		"T1570": {
			ID:          "T1570",
			Name:        "Lateral Tool Transfer",
			Tactic:      "Lateral Movement",
			Description: "Adversaries may transfer tools between systems",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Network Traffic", "File System"},
		},
		"T1571": {
			ID:          "T1571",
			Name:        "Non-Standard Port",
			Tactic:      "Command and Control",
			Description: "Adversaries may use non-standard ports",
			Platforms:   []string{"Windows"},
			DataSources: []string{"Network Traffic", "Firewall Logs"},
		},
		"T1574": {
			ID:          "T1574",
			Name:        "Hijack Execution Flow",
			Tactic:      "Defense Evasion",
			Description: "Adversaries may hijack execution flow",
			Platforms:   []string{"Windows"},
			DataSources: []string{"DLL Monitoring", "Windows Event Logs"},
		},
	}

	Tactics = map[string]*ATTACKTactic{
		"TA0001": {
			ID:          "TA0001",
			Name:        "Initial Access",
			Description: "The adversary is trying to get into your network",
		},
		"TA0002": {
			ID:          "TA0002",
			Name:        "Execution",
			Description: "The adversary is trying to run their code",
		},
		"TA0003": {
			ID:          "TA0003",
			Name:        "Persistence",
			Description: "The adversary is trying to maintain their foothold",
		},
		"TA0004": {
			ID:          "TA0004",
			Name:        "Privilege Escalation",
			Description: "The adversary is trying to gain higher-level permissions",
		},
		"TA0005": {
			ID:          "TA0005",
			Name:        "Defense Evasion",
			Description: "The adversary is trying to avoid being detected",
		},
		"TA0006": {
			ID:          "TA0006",
			Name:        "Credential Access",
			Description: "The adversary is trying to steal credentials",
		},
		"TA0007": {
			ID:          "TA0007",
			Name:        "Discovery",
			Description: "The adversary is trying to figure out your environment",
		},
		"TA0008": {
			ID:          "TA0008",
			Name:        "Lateral Movement",
			Description: "The adversary is trying to move through your environment",
		},
		"TA0009": {
			ID:          "TA0009",
			Name:        "Collection",
			Description: "The adversary is trying to gather data",
		},
		"TA0010": {
			ID:          "TA0010",
			Name:        "Command and Control",
			Description: "The adversary is trying to communicate with compromised systems",
		},
		"TA0011": {
			ID:          "TA0011",
			Name:        "Exfiltration",
			Description: "The adversary is trying to steal data",
		},
		"TA0012": {
			ID:          "TA0012",
			Name:        "Impact",
			Description: "The adversary is trying to manipulate, interrupt, or destroy systems and data",
		},
	}

	EventToTechnique = map[int32][]string{
		4624: {"T1078", "T1550"},
		4625: {"T1110", "T1078"},
		4634: {"T1078"},
		4647: {"T1078"},
		4648: {"T1078", "T1021"},
		4670: {"T1222"},
		4672: {"T1098"},
		4673: {"T1222"},
		4674: {"T1222"},
		4688: {"T1053", "T1055", "T1106"},
		4689: {"T1053", "T1055"},
		4696: {"T1053"},
		4697: {"T1543"},
		4698: {"T1053"},
		4699: {"T1053"},
		4700: {"T1053"},
		4701: {"T1053"},
		4702: {"T1053"},
		4720: {"T1136"},
		4721: {"T1136"},
		4722: {"T1098"},
		4723: {"T1110"},
		4724: {"T1098"},
		4725: {"T1136"},
		4726: {"T1136"},
		4738: {"T1098"},
		4740: {"T1098"},
		4767: {"T1098"},
		4768: {"T1558"},
		4769: {"T1558", "T1097"},
		4776: {"T1110"},
	}
)

func GetTechnique(id string) (*ATTACKTechnique, error) {
	technique, ok := Techniques[id]
	if !ok {
		return nil, fmt.Errorf("technique %s not found", id)
	}
	return technique, nil
}

func GetTactic(id string) (*ATTACKTactic, error) {
	tactic, ok := Tactics[id]
	if !ok {
		return nil, fmt.Errorf("tactic %s not found", id)
	}
	return tactic, nil
}

func GetTechniquesByTactic(tacticName string) []*ATTACKTechnique {
	var result []*ATTACKTechnique
	for _, technique := range Techniques {
		if strings.EqualFold(technique.Tactic, tacticName) {
			result = append(result, technique)
		}
	}
	return result
}

func GetTechniqueByEventID(eventID int32) []*ATTACKTechnique {
	var result []*ATTACKTechnique
	techniqueIDs, ok := EventToTechnique[eventID]
	if !ok {
		return result
	}
	for _, id := range techniqueIDs {
		if tech, err := GetTechnique(id); err == nil {
			result = append(result, tech)
		}
	}
	return result
}

func GetTacticByTechnique(techniqueID string) string {
	if tech, ok := Techniques[techniqueID]; ok {
		return tech.Tactic
	}
	return "Unknown"
}

type MITREMapping struct {
	EventID     int32    `json:"event_id"`
	Techniques  []string `json:"techniques"`
	Tactics     []string `json:"tactics"`
	Description string   `json:"description"`
}

func GetMITREMappingsForEvent(eventID int32) *MITREMapping {
	mapping := &MITREMapping{
		EventID:    eventID,
		Techniques: []string{},
		Tactics:    []string{},
	}

	techIDs, ok := EventToTechnique[eventID]
	if !ok {
		return mapping
	}

	tacticSet := make(map[string]bool)
	for _, techID := range techIDs {
		mapping.Techniques = append(mapping.Techniques, techID)
		if tech, ok := Techniques[techID]; ok {
			tacticSet[tech.Tactic] = true
			mapping.Description = tech.Description
		}
	}

	for tactic := range tacticSet {
		mapping.Tactics = append(mapping.Tactics, tactic)
	}

	return mapping
}

type MITREReport struct {
	TechniqueCounts map[string]int   `json:"technique_counts"`
	TacticCounts    map[string]int   `json:"tactic_counts"`
	TopTechniques   []TechniqueCount `json:"top_techniques"`
	TopTactics      []TacticCount    `json:"top_tactics"`
}

type TechniqueCount struct {
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
	Count         int    `json:"count"`
}

type TacticCount struct {
	TacticID   string `json:"tactic_id"`
	TacticName string `json:"tactic_name"`
	Count      int    `json:"count"`
}

func GenerateMITREReport(eventMappings map[int32]int) *MITREReport {
	report := &MITREReport{
		TechniqueCounts: make(map[string]int),
		TacticCounts:    make(map[string]int),
		TopTechniques:   make([]TechniqueCount, 0),
		TopTactics:      make([]TacticCount, 0),
	}

	for eventID, count := range eventMappings {
		techIDs, ok := EventToTechnique[int32(eventID)]
		if !ok {
			continue
		}

		for _, techID := range techIDs {
			report.TechniqueCounts[techID] += count
			if tech, ok := Techniques[techID]; ok {
				report.TacticCounts[tech.Tactic] += count
			}
		}
	}

	for techID, count := range report.TechniqueCounts {
		if tech, ok := Techniques[techID]; ok {
			report.TopTechniques = append(report.TopTechniques, TechniqueCount{
				TechniqueID:   techID,
				TechniqueName: tech.Name,
				Count:         count,
			})
		}
	}

	for tacticName, count := range report.TacticCounts {
		report.TopTactics = append(report.TopTactics, TacticCount{
			TacticID:   GetTacticIDByName(tacticName),
			TacticName: tacticName,
			Count:      count,
		})
	}

	return report
}

func GetTacticIDByName(name string) string {
	for id, tactic := range Tactics {
		if strings.EqualFold(tactic.Name, name) {
			return id
		}
	}
	return "TA0000"
}

func ValidateTechniqueID(id string) bool {
	_, ok := Techniques[id]
	return ok
}

func ValidateTacticID(id string) bool {
	_, ok := Tactics[id]
	return ok
}
