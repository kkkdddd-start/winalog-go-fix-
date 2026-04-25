package persistence

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/rules/builtin"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Technique string

const (
	TechniqueT1546001 Technique = "T1546.001"
	TechniqueT1546002 Technique = "T1546.002"
	TechniqueT1546003 Technique = "T1546.003"
	TechniqueT1546007 Technique = "T1546.007"
	TechniqueT1546008 Technique = "T1546.008"
	TechniqueT1546010 Technique = "T1546.010"
	TechniqueT1546012 Technique = "T1546.012"
	TechniqueT1546015 Technique = "T1546.015"
	TechniqueT1546016 Technique = "T1546.016"
	TechniqueT1546006 Technique = "T1546.006"
	TechniqueT1053    Technique = "T1053"
	TechniqueT1053020 Technique = "T1053.020"
	TechniqueT1543003 Technique = "T1543.003"
	TechniqueT1197    Technique = "T1197"
	TechniqueT1098    Technique = "T1098"
)

type EvidenceType string

const (
	EvidenceTypeRegistry EvidenceType = "registry"
	EvidenceTypeFile     EvidenceType = "file"
	EvidenceTypeWMI      EvidenceType = "wmi"
	EvidenceTypeService  EvidenceType = "service"
	EvidenceTypeTask     EvidenceType = "task"
	EvidenceTypeCOM      EvidenceType = "com"
	EvidenceTypeETW      EvidenceType = "etw"
)

type Detection struct {
	ID                string                 `json:"id"`
	Time              time.Time              `json:"time"`
	Technique         Technique              `json:"technique"`
	Category          string                 `json:"category"`
	Severity          Severity               `json:"severity"`
	Title             string                 `json:"title"`
	Description       string                 `json:"description"`
	Evidence          Evidence               `json:"evidence"`
	MITRERef          []string               `json:"mitre_ref"`
	RecommendedAction string                 `json:"recommended_action"`
	FalsePositiveRisk string                 `json:"false_positive_risk"`
	RawData           map[string]interface{} `json:"raw_data,omitempty"`
}

type Evidence struct {
	Type     EvidenceType `json:"type"`
	Path     string       `json:"path,omitempty"`
	Key      string       `json:"key,omitempty"`
	Value    string       `json:"value,omitempty"`
	Expected string       `json:"expected,omitempty"`
	Process  string       `json:"process,omitempty"`
	FilePath string       `json:"file_path,omitempty"`
	Command  string       `json:"command,omitempty"`
	RawData  interface{}  `json:"raw_data,omitempty"`
}

type DetectionResult struct {
	Detections []*Detection  `json:"detections"`
	StartTime  time.Time     `json:"start_time"`
	EndTime    time.Time     `json:"end_time"`
	Duration   time.Duration `json:"duration"`
	TotalCount int           `json:"total_count"`
	ErrorCount int           `json:"error_count"`
	Errors     []string      `json:"errors,omitempty"`
}

func NewDetectionResult() *DetectionResult {
	return &DetectionResult{
		Detections: make([]*Detection, 0),
		StartTime:  time.Now(),
	}
}

func (r *DetectionResult) Add(d *Detection) {
	r.Detections = append(r.Detections, d)
	r.TotalCount++
}

func (r *DetectionResult) ToJSON() ([]byte, error) {
	r.EndTime = time.Now()
	r.Duration = r.EndTime.Sub(r.StartTime)
	return json.MarshalIndent(r, "", "  ")
}

func (r *DetectionResult) Summary() map[string]interface{} {
	summary := map[string]interface{}{
		"total_detections": r.TotalCount,
		"duration_ms":      r.Duration.Milliseconds(),
		"error_count":      r.ErrorCount,
	}

	byTechnique := make(map[string]int)
	bySeverity := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	byCategory := make(map[string]int)

	for _, d := range r.Detections {
		technique := string(d.Technique)
		byTechnique[technique]++
		bySeverity[string(d.Severity)]++
		byCategory[d.Category]++
	}

	summary["by_technique"] = byTechnique
	summary["by_severity"] = bySeverity
	summary["by_category"] = byCategory

	return summary
}

type PersistenceCategory struct {
	Name        string
	Description string
	Techniques  []Technique
}

var PersistenceCategories = []PersistenceCategory{
	{
		Name:        "Registry",
		Description: "Registry-based persistence mechanisms",
		Techniques:  []Technique{TechniqueT1546001, TechniqueT1546010, TechniqueT1546012, TechniqueT1546015},
	},
	{
		Name:        "ScheduledTask",
		Description: "Scheduled task/Job persistence",
		Techniques:  []Technique{TechniqueT1053, TechniqueT1053020},
	},
	{
		Name:        "Service",
		Description: "Windows service persistence",
		Techniques:  []Technique{TechniqueT1543003},
	},
	{
		Name:        "WMI",
		Description: "WMI event subscription persistence",
		Techniques:  []Technique{TechniqueT1546003},
	},
	{
		Name:        "COM",
		Description: "COM object hijacking persistence",
		Techniques:  []Technique{TechniqueT1546015},
	},
	{
		Name:        "BITS",
		Description: "BITS persistence",
		Techniques:  []Technique{TechniqueT1197},
	},
	{
		Name:        "ETW",
		Description: "ETW (Event Tracing for Windows) manipulation",
		Techniques:  []Technique{TechniqueT1546006},
	},
}

func GetTechniqueInfo(t Technique) (name, description string) {
	switch t {
	case TechniqueT1546001:
		return "Accessibility Features", "Gain persistence or execute code with elevated privileges by modifying accessibility programs"
	case TechniqueT1546002:
		return "SCM", "Modify Service Control Manager configuration"
	case TechniqueT1546003:
		return "WMI Event Subscription", "Use WMI permanent event subscriptions for persistence"
	case TechniqueT1546007:
		return " Netsh Helper DLL", "Modify Netsh Helper DLL for persistence"
	case TechniqueT1546008:
		return "LSASS", "Create LSASS.exe for credential access"
	case TechniqueT1546010:
		return "AppInit_DLLs", "Modify AppInit_DLLs registry value for DLL injection"
	case TechniqueT1546012:
		return "IFEO", "Modify Image File Execution Options for debugger injection"
	case TechniqueT1546015:
		return "COM Hijacking", "Hijack COM object references for persistence"
	case TechniqueT1546016:
		return "Startup Items", "Modify startup folder or registry for persistence"
	case TechniqueT1053:
		return "Scheduled Task/Job", "Create or modify scheduled tasks for persistence"
	case TechniqueT1053020:
		return "Cron", "Unix-specific scheduled task (not applicable on Windows)"
	case TechniqueT1543003:
		return "Create/Modify System Process", "Create or modify Windows service for persistence"
	case TechniqueT1197:
		return "BITS Jobs", "Use BITS jobs for persistence or download"
	case TechniqueT1098:
		return "Account Manipulation", "Modify account settings or SID history"
	case TechniqueT1546006:
		return "ETW Hook", "Modify Event Tracing for Windows to hide malicious behavior"
	default:
		return "Unknown", "Unknown technique"
	}
}

func (s Severity) ToAlertSeverity() types.Severity {
	switch s {
	case SeverityCritical:
		return types.SeverityCritical
	case SeverityHigh:
		return types.SeverityHigh
	case SeverityMedium:
		return types.SeverityMedium
	case SeverityLow:
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

var techniqueToRuleName = map[Technique]string{
	TechniqueT1546001: "registry-run-key-modification",
	TechniqueT1546002: "registry-services-modification",
	TechniqueT1546003: "wmi-event-subscription",
	TechniqueT1546007: "netsh-helper-dll-persistence",
	TechniqueT1546008: "lsass-memory-dump",
	TechniqueT1546010: "appinit-dll-persistence",
	TechniqueT1546012: "ifeo-injection",
	TechniqueT1546015: "com-object-hijacking",
	TechniqueT1546016: "startup-folder-write",
	TechniqueT1053:    "scheduled-task-creation",
	TechniqueT1053020: "scheduled-task-creation",
	TechniqueT1543003: "registry-service-persistence",
	TechniqueT1197:    "bits-persistence",
	TechniqueT1098:    "account-manipulation",
}

func (t Technique) ToRuleName() string {
	if ruleName, ok := techniqueToRuleName[t]; ok {
		return ruleName
	}
	return string(t)
}

func (d *Detection) ToRuleName() string {
	return d.Technique.ToRuleName()
}

func (d *Detection) GetExplanation() string {
	ruleName := d.ToRuleName()
	if ruleName == string(d.Technique) {
		techniqueName, techniqueDesc := GetTechniqueInfo(d.Technique)
		return fmt.Sprintf("[%s] %s - %s", d.Technique, techniqueName, techniqueDesc)
	}
	explanation, _, _ := builtin.GetRuleDetails(ruleName)
	if explanation == "暂无详细规则解读" {
		techniqueName, techniqueDesc := GetTechniqueInfo(d.Technique)
		return fmt.Sprintf("[%s] %s - %s", d.Technique, techniqueName, techniqueDesc)
	}
	return explanation
}

func (d *Detection) GetRecommendation() string {
	ruleName := d.ToRuleName()
	_, recommendation, _ := builtin.GetRuleDetails(ruleName)
	if recommendation == "暂无处置建议" {
		return d.RecommendedAction
	}
	return recommendation
}

func (d *Detection) GetRealCase() string {
	ruleName := d.ToRuleName()
	_, _, realCase := builtin.GetRuleDetails(ruleName)
	return realCase
}

func (d *Detection) GetRuleDetails() (explanation, recommendation, realCase string) {
	ruleName := d.ToRuleName()
	explanation, recommendation, realCase = builtin.GetRuleDetails(ruleName)
	if explanation == "暂无详细规则解读" {
		techniqueName, techniqueDesc := GetTechniqueInfo(d.Technique)
		explanation = fmt.Sprintf("[%s] %s - %s", d.Technique, techniqueName, techniqueDesc)
	}
	if recommendation == "暂无处置建议" {
		recommendation = d.RecommendedAction
	}
	return
}

func (d *Detection) ToAlert() *types.Alert {
	explanation, recommendation, realCase := d.GetRuleDetails()

	message := fmt.Sprintf("[%s] %s", d.Technique, d.Title)
	if d.Description != "" {
		message = fmt.Sprintf("[%s] %s - %s", d.Technique, d.Title, d.Description)
	}

	mitreRef := make([]string, len(d.MITRERef))
	copy(mitreRef, d.MITRERef)
	if len(mitreRef) == 0 && d.Technique != "" {
		mitreRef = []string{string(d.Technique)}
	}

	return &types.Alert{
		RuleName:    d.ToRuleName(),
		Severity:    d.Severity.ToAlertSeverity(),
		Message:     message,
		EventIDs:    []int32{},
		FirstSeen:   d.Time,
		LastSeen:    d.Time,
		Count:       1,
		MITREAttack: mitreRef,
		Resolved:    false,
		Notes: fmt.Sprintf("=== 规则解读 ===\n%s\n\n=== 处置建议 ===\n%s\n\n=== 真实案例 ===\n%s\n\n=== 原始描述 ===\n%s",
			explanation, recommendation, realCase, d.Description),
		RuleScore: d.SeverityToScore(),
	}
}

func (d *Detection) SeverityToScore() float64 {
	switch d.Severity {
	case SeverityCritical:
		return 100
	case SeverityHigh:
		return 80
	case SeverityMedium:
		return 60
	case SeverityLow:
		return 40
	default:
		return 20
	}
}

func (d *Detection) ToAlertWithEvidence() *types.Alert {
	alert := d.ToAlert()
	if d.Evidence.RawData != nil {
		evidenceJSON, _ := json.Marshal(d.Evidence.RawData)
		alert.Notes += fmt.Sprintf("\n\n=== 证据数据 ===\n%s", string(evidenceJSON))
	}
	return alert
}
