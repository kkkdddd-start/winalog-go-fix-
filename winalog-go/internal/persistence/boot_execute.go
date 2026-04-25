//go:build windows

package persistence

import (
	"context"
	"fmt"
	"strings"

	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type BootExecuteDetector struct {
	config *DetectorConfig
}

func NewBootExecuteDetector() *BootExecuteDetector {
	return &BootExecuteDetector{
		config: &DetectorConfig{
			Enabled:  true,
			EventIDs: []int32{4697},
		},
	}
}

func (d *BootExecuteDetector) Name() string {
	return "boot_execute_detector"
}

func (d *BootExecuteDetector) GetTechnique() Technique {
	return TechniqueT1546016
}

func (d *BootExecuteDetector) RequiresAdmin() bool {
	return true
}

func (d *BootExecuteDetector) SetConfig(config *DetectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	d.config = config
	return nil
}

func (d *BootExecuteDetector) GetConfig() *DetectorConfig {
	return d.config
}

var BootExecuteRegistryPaths = []string{
	`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute`,
	`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive`,
	`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`,
	`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDlls`,
}

var SuspiciousBootExecuteIndicators = []string{
	"%TEMP%", "%APPDATA%", "%LOCALAPPDATA%",
	"\\temp\\", "\\tmp\\",
	"\\\\UNC\\", "\\\\127\\",
	".exe", ".dll", ".sys",
	"mimikatz", "credential", "pwdump",
	"metasploit", "cobaltstrike", "empire",
	"powershell", "wscript", "cscript",
	"cmd.exe", "wscript.exe", "cscript.exe",
	"base64", "-enc", "-encodedcommand",
	"sethc", "utilman", "osk", "magnify", "narrator", "displayswitch",
}

func (d *BootExecuteDetector) Detect(ctx context.Context) ([]*Detection, error) {
	if d.config != nil && !d.config.Enabled {
		return nil, nil
	}

	detections := make([]*Detection, 0)

	for _, keyPath := range BootExecuteRegistryPaths {
		entries, err := d.enumerateBootExecuteKey(keyPath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if d.isSuspicious(entry) {
				det := &Detection{
					Technique:   d.GetTechnique(),
					Category:    "Registry",
					Severity:    d.calculateSeverity(entry),
					Title:       "Suspicious Boot Execute Configuration",
					Description: "A suspicious value was found in a boot execution registry key",
					Evidence: Evidence{
						Type:  EvidenceTypeRegistry,
						Key:   keyPath,
						Value: entry.Name + " = " + entry.Value,
					},
					MITRERef:          []string{"T1546.016", "T1547.001"},
					RecommendedAction: "Investigate this boot execute configuration. Adversaries may use boot execute for persistence.",
					FalsePositiveRisk: d.calculateFPRisk(entry),
				}
				detections = append(detections, det)
			}
		}
	}

	return detections, nil
}

type BootExecuteEntry struct {
	Name  string
	Value string
	Path  string
	Type  string
}

func (d *BootExecuteDetector) enumerateBootExecuteKey(keyPath string) ([]BootExecuteEntry, error) {
	entries := make([]BootExecuteEntry, 0)

	value, err := utils.GetRegistryValue(keyPath, "")
	if err == nil && value != "" {
		entries = append(entries, BootExecuteEntry{
			Name:  "(Default)",
			Value: value,
			Path:  keyPath,
			Type:  "REG_MULTI_SZ",
		})
	}

	multiValues, err := utils.GetRegistryMultiStringValue(keyPath, "")
	if err == nil && len(multiValues) > 0 {
		for i, v := range multiValues {
			if v != "" && !GlobalWhitelist.IsAllowed(v) {
				entries = append(entries, BootExecuteEntry{
					Name:  "(Value " + string(rune('0'+i)) + ")",
					Value: v,
					Path:  keyPath,
					Type:  "REG_MULTI_SZ",
				})
			}
		}
	}

	subkeys, err := utils.ListRegistrySubkeys(keyPath)
	if err == nil {
		for _, subkey := range subkeys {
			fullPath := keyPath + "\\" + subkey
			subValue, err := utils.GetRegistryValue(fullPath, "")
			if err == nil && subValue != "" {
				entries = append(entries, BootExecuteEntry{
					Name:  subkey,
					Value: subValue,
					Path:  fullPath,
					Type:  "REG_SZ",
				})
			}
		}
	}

	return entries, nil
}

func (d *BootExecuteDetector) isSuspicious(entry BootExecuteEntry) bool {
	if entry.Value == "" {
		return false
	}

	if GlobalWhitelist.IsAllowed(entry.Value) {
		return false
	}

	valueUpper := strings.ToUpper(entry.Value)

	for _, indicator := range SuspiciousBootExecuteIndicators {
		if strings.Contains(valueUpper, strings.ToUpper(indicator)) {
			return true
		}
	}

	accessibilityTerms := []string{"SETHC", "UTILMAN", "OSK", "MAGNIFY", "NARRATOR", "DISPLAYSWITCH"}
	for _, term := range accessibilityTerms {
		if strings.Contains(valueUpper, term) && !strings.Contains(valueUpper, "SYSTEM32") {
			return true
		}
	}

	return false
}

func (d *BootExecuteDetector) calculateSeverity(entry BootExecuteEntry) Severity {
	valueUpper := strings.ToUpper(entry.Value)

	highRiskIndicators := []string{
		"MIMIKATZ", "PWDUMP", "CREDENTIAL",
		"METASPLOIT", "COBALTSTRIKE", "EMPIRE",
		"BASE64", "-ENC", "-ENCODEDCOMMAND",
	}

	for _, indicator := range highRiskIndicators {
		if strings.Contains(valueUpper, indicator) {
			return SeverityCritical
		}
	}

	mediumRiskIndicators := []string{
		"%TEMP%", "%APPDATA%", "%LOCALAPPDATA%",
		"POWERSHELL", "WSCRIPT", "CSCRIPT",
		"CMD.EXE",
	}

	for _, indicator := range mediumRiskIndicators {
		if strings.Contains(valueUpper, indicator) {
			return SeverityHigh
		}
	}

	accessibilityTerms := []string{"SETHC", "UTILMAN", "OSK", "MAGNIFY", "NARRATOR", "DISPLAYSWITCH"}
	for _, term := range accessibilityTerms {
		if strings.Contains(valueUpper, term) && !strings.Contains(valueUpper, "SYSTEM32") {
			return SeverityHigh
		}
	}

	if !strings.Contains(valueUpper, "SYSTEM32") && !strings.Contains(valueUpper, "WINDOWS") {
		return SeverityMedium
	}

	return SeverityLow
}

func (d *BootExecuteDetector) calculateFPRisk(entry BootExecuteEntry) string {
	valueUpper := strings.ToUpper(entry.Value)

	if strings.Contains(valueUpper, "SYSTEM32") || strings.Contains(valueUpper, "WINDOWS") {
		return "Low"
	}
	if strings.Contains(valueUpper, "MICROSOFT") {
		return "Low"
	}
	return "Medium"
}
