//go:build windows

package persistence

import (
	"context"
	"fmt"
	"strings"
)

type PrintMonitorDetector struct {
	config *DetectorConfig
}

func NewPrintMonitorDetector() *PrintMonitorDetector {
	return &PrintMonitorDetector{
		config: &DetectorConfig{
			Enabled:  true,
			EventIDs: []int32{4697},
		},
	}
}

func (d *PrintMonitorDetector) Name() string {
	return "print_monitor_detector"
}

func (d *PrintMonitorDetector) GetTechnique() Technique {
	return TechniqueT1543003
}

func (d *PrintMonitorDetector) RequiresAdmin() bool {
	return true
}

func (d *PrintMonitorDetector) SetConfig(config *DetectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	d.config = config
	return nil
}

func (d *PrintMonitorDetector) GetConfig() *DetectorConfig {
	return d.config
}

var PrintMonitorRegistryPaths = []string{
	`HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors`,
	`HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\Microsoft Document Imaging Writer Port`,
	`HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\Standard TCP/IP Port`,
	`HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\USB001`,
}

var SuspiciousPrintMonitorIndicators = []string{
	"%TEMP%", "%APPDATA%", "%LOCALAPPDATA%",
	"\\temp\\", "\\tmp\\",
	"\\\\UNC\\", "\\\\127\\",
	"mimikatz", "credential", "pwdump",
	"metasploit", "cobaltstrike",
	"powershell", "wscript", "cscript",
	"hook", "inject", "keylog",
}

func (d *PrintMonitorDetector) Detect(ctx context.Context) ([]*Detection, error) {
	if d.config != nil && !d.config.Enabled {
		return nil, nil
	}

	detections := make([]*Detection, 0)

	for _, keyPath := range PrintMonitorRegistryPaths {
		entries, err := d.enumeratePrintMonitorKey(keyPath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if d.isSuspicious(entry) {
				det := &Detection{
					Technique:   d.GetTechnique(),
					Category:    "Service",
					Severity:    d.calculateSeverity(entry),
					Title:       "Suspicious Print Monitor",
					Description: "A suspicious print monitor DLL was found",
					Evidence: Evidence{
						Type:     EvidenceTypeService,
						Key:      keyPath,
						Value:    entry.Name + " = " + entry.Value,
						FilePath: entry.Value,
					},
					MITRERef:          []string{"T1543.003"},
					RecommendedAction: "Investigate this print monitor. Malicious print monitors can execute code during printing operations.",
					FalsePositiveRisk: d.calculateFPRisk(entry),
				}
				detections = append(detections, det)
			}
		}
	}

	return detections, nil
}

type PrintMonitorEntry struct {
	Name  string
	Value string
	Path  string
}

func (d *PrintMonitorDetector) enumeratePrintMonitorKey(keyPath string) ([]PrintMonitorEntry, error) {
	entries := make([]PrintMonitorEntry, 0)

	subkeys, err := listRegistrySubkeys(keyPath)
	if err != nil {
		return entries, nil
	}

	for _, subkey := range subkeys {
		if subkey == "Microsoft Document Imaging Writer Port" ||
			subkey == "Standard TCP/IP Port" ||
			subkey == "USB001" {
			continue
		}

		fullPath := keyPath + "\\" + subkey
		value, err := getRegistryValue(fullPath, "Driver")
		if err != nil {
			value, err = getRegistryValue(fullPath, "")
			if err != nil {
				continue
			}
		}

		if value != "" {
			entries = append(entries, PrintMonitorEntry{
				Name:  subkey,
				Value: value,
				Path:  fullPath,
			})
		}
	}

	return entries, nil
}

func (d *PrintMonitorDetector) isSuspicious(entry PrintMonitorEntry) bool {
	if entry.Value == "" {
		return false
	}

	if GlobalWhitelist.IsAllowed(entry.Name) {
		return false
	}

	valueUpper := strings.ToUpper(entry.Value)
	for _, indicator := range SuspiciousPrintMonitorIndicators {
		if strings.Contains(valueUpper, strings.ToUpper(indicator)) {
			return true
		}
	}

	if strings.Contains(valueUpper, ".DLL") && !strings.Contains(valueUpper, "SYSTEM32") && !strings.Contains(valueUpper, "SYSWOW64") {
		return true
	}

	return false
}

func (d *PrintMonitorDetector) calculateSeverity(entry PrintMonitorEntry) Severity {
	valueUpper := strings.ToUpper(entry.Value)

	highRiskIndicators := []string{
		"MIMIKATZ", "PWDUMP", "CREDENTIAL",
		"METASPLOIT", "COBALTSTRIKE",
	}

	for _, indicator := range highRiskIndicators {
		if strings.Contains(valueUpper, indicator) {
			return SeverityCritical
		}
	}

	if !strings.Contains(valueUpper, "SYSTEM32") && !strings.Contains(valueUpper, "SYSWOW64") {
		return SeverityHigh
	}

	return SeverityMedium
}

func (d *PrintMonitorDetector) calculateFPRisk(entry PrintMonitorEntry) string {
	if strings.Contains(strings.ToUpper(entry.Value), "SYSTEM32") {
		return "Low"
	}
	if strings.Contains(strings.ToUpper(entry.Value), "SYSWOW64") {
		return "Low"
	}
	return "Medium"
}
