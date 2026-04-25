//go:build windows

package persistence

import (
	"context"
	"fmt"
	"strings"

	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type LSAPersistenceDetector struct {
	config *DetectorConfig
}

func NewLSAPersistenceDetector() *LSAPersistenceDetector {
	return &LSAPersistenceDetector{
		config: &DetectorConfig{
			Enabled:  true,
			EventIDs: []int32{4670},
		},
	}
}

func (d *LSAPersistenceDetector) Name() string {
	return "lsa_persistence_detector"
}

func (d *LSAPersistenceDetector) GetTechnique() Technique {
	return TechniqueT1546008
}

func (d *LSAPersistenceDetector) RequiresAdmin() bool {
	return true
}

func (d *LSAPersistenceDetector) SetConfig(config *DetectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	d.config = config
	return nil
}

func (d *LSAPersistenceDetector) GetConfig() *DetectorConfig {
	return d.config
}

var LSARegistryPaths = []string{
	`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notify`,
	`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`,
	`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Msv1_0`,
	`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages`,
	`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\BootVerifier`,
}

var SuspiciousLSAIndicators = []string{
	".dll",
	"%TEMP%", "%APPDATA%", "%LOCALAPPDATA%",
	"\\temp\\", "\\tmp\\",
	"\\\\UNC\\", "\\\\127\\",
	"mimikatz", "logonpasswords",
	"powershell", "wscript", "cscript",
	"metasploit", "cobaltstrike",
}

func (d *LSAPersistenceDetector) Detect(ctx context.Context) ([]*Detection, error) {
	if d.config != nil && !d.config.Enabled {
		return nil, nil
	}

	detections := make([]*Detection, 0)

	for _, keyPath := range LSARegistryPaths {
		entries, err := d.enumerateLSAKey(keyPath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if d.isSuspicious(entry) {
				det := &Detection{
					Technique:   d.GetTechnique(),
					Category:    "Registry",
					Severity:    d.calculateSeverity(entry),
					Title:       "Suspicious LSA Provider Modification",
					Description: "A suspicious value was found in an LSA security-related registry key",
					Evidence: Evidence{
						Type:  EvidenceTypeRegistry,
						Key:   keyPath,
						Value: entry.Name + " = " + entry.Value,
					},
					MITRERef:          []string{"T1546.008"},
					RecommendedAction: "Investigate this LSA modification. Adversaries may use LSA modules for credential access.",
					FalsePositiveRisk: d.calculateFPRisk(keyPath, entry),
				}
				detections = append(detections, det)
			}
		}
	}

	return detections, nil
}

type LSAEntry struct {
	Name  string
	Value string
	Type  string
}

func (d *LSAPersistenceDetector) enumerateLSAKey(keyPath string) ([]LSAEntry, error) {
	entries := make([]LSAEntry, 0)

	subkeys, err := utils.ListRegistrySubkeys(keyPath)
	if err != nil {
		multiValues, err := d.getLSAValues(keyPath)
		if err != nil {
			return entries, nil
		}
		return multiValues, nil
	}

	for _, subkey := range subkeys {
		fullPath := keyPath + "\\" + subkey
		value, err := utils.GetRegistryValue(fullPath, "")
		if err != nil {
			continue
		}
		entries = append(entries, LSAEntry{
			Name:  subkey,
			Value: value,
			Type:  "REG_SZ",
		})
	}

	return entries, nil
}

func (d *LSAPersistenceDetector) getLSAValues(keyPath string) ([]LSAEntry, error) {
	entries := make([]LSAEntry, 0)

	subkeys, err := utils.ListRegistrySubkeys(keyPath)
	if err != nil {
		return entries, err
	}

	for _, subkey := range subkeys {
		fullPath := keyPath + "\\" + subkey
		values, err := utils.GetRegistryMultiStringValue(fullPath, "")
		if err != nil {
			value, err := utils.GetRegistryValue(fullPath, "")
			if err == nil && value != "" {
				entries = append(entries, LSAEntry{
					Name:  subkey,
					Value: value,
					Type:  "REG_MULTI_SZ",
				})
			}
			continue
		}
		for _, v := range values {
			if v != "" {
				entries = append(entries, LSAEntry{
					Name:  subkey,
					Value: v,
					Type:  "REG_MULTI_SZ",
				})
			}
		}
	}

	return entries, nil
}

func (d *LSAPersistenceDetector) isSuspicious(entry LSAEntry) bool {
	if entry.Value == "" {
		return false
	}

	valueUpper := strings.ToUpper(entry.Value)

	if GlobalWhitelist.IsAllowed(entry.Name) {
		return false
	}

	for _, indicator := range SuspiciousLSAIndicators {
		if strings.Contains(valueUpper, strings.ToUpper(indicator)) {
			return true
		}
	}

	if strings.Contains(valueUpper, ".DLL") && !strings.Contains(valueUpper, "SYSTEM32") && !strings.Contains(valueUpper, "SYSWOW64") {
		return true
	}

	return false
}

func (d *LSAPersistenceDetector) calculateSeverity(entry LSAEntry) Severity {
	valueUpper := strings.ToUpper(entry.Value)

	highRiskIndicators := []string{
		"MIMIKATZ", "LOGONPASSWORDS", "PWDUMP",
		"METASPLOIT", "COBALTSTRIKE",
	}

	for _, indicator := range highRiskIndicators {
		if strings.Contains(valueUpper, indicator) {
			return SeverityCritical
		}
	}

	mediumRiskIndicators := []string{
		"%TEMP%", "%APPDATA%", "%LOCALAPPDATA%",
		"POWERSHELL", "WSCRIPT", "CSCRIPT",
	}

	for _, indicator := range mediumRiskIndicators {
		if strings.Contains(valueUpper, indicator) {
			return SeverityHigh
		}
	}

	if !strings.Contains(valueUpper, "SYSTEM32") && !strings.Contains(valueUpper, "SYSWOW64") {
		return SeverityMedium
	}

	return SeverityLow
}

func (d *LSAPersistenceDetector) calculateFPRisk(keyPath string, entry LSAEntry) string {
	if strings.Contains(strings.ToUpper(entry.Value), "SYSTEM32") {
		return "Low"
	}
	if strings.Contains(strings.ToUpper(entry.Value), "SYSWOW64") {
		return "Low"
	}
	return "Medium"
}
