//go:build windows

package persistence

import (
	"context"
	"fmt"
	"strings"
)

type BHODetector struct {
	config *DetectorConfig
}

func NewBHODetector() *BHODetector {
	return &BHODetector{
		config: &DetectorConfig{
			Enabled:  true,
			EventIDs: []int32{4697},
		},
	}
}

func (d *BHODetector) Name() string {
	return "bho_detector"
}

func (d *BHODetector) GetTechnique() Technique {
	return TechniqueT1546015
}

func (d *BHODetector) RequiresAdmin() bool {
	return true
}

func (d *BHODetector) SetConfig(config *DetectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	d.config = config
	return nil
}

func (d *BHODetector) GetConfig() *DetectorConfig {
	return d.config
}

var BHORegistryPaths = []string{
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`,
	`HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`,
	`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`,
	`HKCU\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`,
}

var SuspiciousBHOIndicators = []string{
	"%TEMP%", "%APPDATA%", "%LOCALAPPDATA%",
	"\\temp\\", "\\tmp\\",
	"\\\\UNC\\", "\\\\127\\",
	"keylog", "keystroke", "password",
	"mimikatz", " credential", "pwdump",
	"metasploit", "cobaltstrike", "empire",
	"powershell", "wscript", "cscript",
	"hook", "inject", "spy",
}

var KnownBenignBHONames = []string{
	"Google Toolbar",
	"Microsoft Bing Bar",
	"Alexa Toolbar",
	"Java(tm) Plug-In",
}

func (d *BHODetector) Detect(ctx context.Context) ([]*Detection, error) {
	if d.config != nil && !d.config.Enabled {
		return nil, nil
	}

	detections := make([]*Detection, 0)

	for _, keyPath := range BHORegistryPaths {
		entries, err := d.enumerateBHOKey(keyPath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if d.isSuspicious(entry) {
				det := &Detection{
					Technique:   d.GetTechnique(),
					Category:    "BHO",
					Severity:    d.calculateSeverity(entry),
					Title:       "Suspicious Browser Helper Object (BHO)",
					Description: "A suspicious BHO was found that may be used for browser hooking or data theft",
					Evidence: Evidence{
						Type:     EvidenceTypeRegistry,
						Key:      keyPath,
						Value:    entry.Name + " = " + entry.Value,
						FilePath: entry.Value,
					},
					MITRERef:          []string{"T1546.015"},
					RecommendedAction: "Investigate this BHO. BHOs can intercept all browser traffic and steal sensitive data.",
					FalsePositiveRisk: d.calculateFPRisk(entry),
				}
				detections = append(detections, det)
			}
		}
	}

	return detections, nil
}

type BHOEntry struct {
	Name  string
	Value string
	Path  string
}

func (d *BHODetector) enumerateBHOKey(keyPath string) ([]BHOEntry, error) {
	entries := make([]BHOEntry, 0)

	subkeys, err := listRegistrySubkeys(keyPath)
	if err != nil {
		return entries, nil
	}

	for _, subkey := range subkeys {
		fullPath := keyPath + "\\" + subkey
		value, err := getRegistryValue(fullPath, "")
		if err != nil {
			continue
		}

		if value != "" {
			entries = append(entries, BHOEntry{
				Name:  subkey,
				Value: value,
				Path:  fullPath,
			})
		}

		subSubkeys, err := listRegistrySubkeys(fullPath)
		if err != nil {
			continue
		}

		for _, subSubkey := range subSubkeys {
			subSubPath := fullPath + "\\" + subSubkey
			subValue, err := getRegistryValue(subSubPath, "")
			if err != nil {
				continue
			}

			if subValue != "" {
				entries = append(entries, BHOEntry{
					Name:  subkey + "\\" + subSubkey,
					Value: subValue,
					Path:  subSubPath,
				})
			}
		}
	}

	return entries, nil
}

func getRegistryValue(keyPath, valueName string) (string, error) {
	return "", nil
}

func (d *BHODetector) isSuspicious(entry BHOEntry) bool {
	if entry.Value == "" {
		return false
	}

	if GlobalWhitelist.IsAllowed(entry.Name) {
		return false
	}

	for _, known := range KnownBenignBHONames {
		if strings.Contains(strings.ToUpper(entry.Value), strings.ToUpper(known)) {
			return false
		}
	}

	valueUpper := strings.ToUpper(entry.Value)
	for _, indicator := range SuspiciousBHOIndicators {
		if strings.Contains(valueUpper, strings.ToUpper(indicator)) {
			return true
		}
	}

	if strings.Contains(valueUpper, ".DLL") && !strings.Contains(valueUpper, "PROGRAM FILES") && !strings.Contains(valueUpper, "WINDOWS\\SYSTEM") {
		return true
	}

	return false
}

func (d *BHODetector) calculateSeverity(entry BHOEntry) Severity {
	valueUpper := strings.ToUpper(entry.Value)

	highRiskIndicators := []string{
		"MIMIKATZ", "PWDUMP", "CREDENTIAL",
		"METASPLOIT", "COBALTSTRIKE", "EMPIRE",
		"KEYLOG", "KEYSTROKE", "PASSWORD",
	}

	for _, indicator := range highRiskIndicators {
		if strings.Contains(valueUpper, indicator) {
			return SeverityCritical
		}
	}

	mediumRiskIndicators := []string{
		"%TEMP%", "%APPDATA%", "%LOCALAPPDATA%",
		"POWERSHELL", "WSCRIPT", "CSCRIPT",
		"HOOK", "INJECT", "SPY",
	}

	for _, indicator := range mediumRiskIndicators {
		if strings.Contains(valueUpper, indicator) {
			return SeverityHigh
		}
	}

	if !strings.Contains(valueUpper, "PROGRAM FILES") && !strings.Contains(valueUpper, "WINDOWS\\SYSTEM") {
		return SeverityMedium
	}

	return SeverityLow
}

func (d *BHODetector) calculateFPRisk(entry BHOEntry) string {
	if strings.Contains(strings.ToUpper(entry.Value), "PROGRAM FILES") {
		return "Low"
	}
	if strings.Contains(strings.ToUpper(entry.Value), "WINDOWS\\SYSTEM") {
		return "Low"
	}
	if strings.Contains(strings.ToUpper(entry.Value), "WINDOWS\\SYSWOW64") {
		return "Low"
	}
	return "Medium"
}
