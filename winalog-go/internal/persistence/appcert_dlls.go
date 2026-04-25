//go:build windows

package persistence

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type AppCertDllsDetector struct {
	config *DetectorConfig
}

func NewAppCertDllsDetector() *AppCertDllsDetector {
	return &AppCertDllsDetector{
		config: &DetectorConfig{
			Enabled:  true,
			EventIDs: []int32{4697},
		},
	}
}

func (d *AppCertDllsDetector) Name() string {
	return "appcert_detector"
}

func (d *AppCertDllsDetector) GetTechnique() Technique {
	return TechniqueT1546001
}

func (d *AppCertDllsDetector) RequiresAdmin() bool {
	return true
}

func (d *AppCertDllsDetector) SetConfig(config *DetectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	d.config = config
	return nil
}

func (d *AppCertDllsDetector) GetConfig() *DetectorConfig {
	return d.config
}

type AppCertEntry struct {
	Name  string
	Value string
	Path  string
}

var SuspiciousAppCertIndicators = []string{
	".dll", ".exe", ".sys",
	"\\temp\\", "\\tmp\\", "%temp%",
	"\\downloads\\", "\\desktop\\",
	"mimikatz", "pwdump", "nc.exe",
}

func (d *AppCertDllsDetector) Detect(ctx context.Context) ([]*Detection, error) {
	if d.config != nil && !d.config.Enabled {
		return nil, nil
	}

	detections := make([]*Detection, 0)

	entries, err := d.enumerateAppCertDlls()
	if err != nil {
		return detections, err
	}

	for _, entry := range entries {
		if d.isSuspicious(entry) {
			det := &Detection{
				Technique:   TechniqueT1546001,
				Category:    "Registry",
				Severity:    d.calculateSeverity(entry),
				Time:        time.Now(),
				Title:       "Suspicious AppCertDlls Entry",
				Description: fmt.Sprintf("A suspicious value was found in AppCertDlls: %s", entry.Name),
				Evidence: Evidence{
					Type:  EvidenceTypeRegistry,
					Key:   entry.Path,
					Value: entry.Name + "=" + entry.Value,
				},
				MITRERef:          []string{"T1546.001"},
				RecommendedAction: "Investigate the AppCertDlls entry and verify if it is legitimate",
				FalsePositiveRisk: d.calculateFPRisk(entry),
			}
			detections = append(detections, det)
		}
	}

	return detections, nil
}

func (d *AppCertDllsDetector) enumerateAppCertDlls() ([]AppCertEntry, error) {
	entries := make([]AppCertEntry, 0)

	paths := []string{
		`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`,
		`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls32`,
	}

	for _, keyPath := range paths {
		if !utils.RegistryKeyExists(keyPath) {
			continue
		}

		values, err := utils.ListRegistryValues(keyPath)
		if err != nil {
			continue
		}

		for _, valueName := range values {
			value, err := utils.GetRegistryValue(keyPath, valueName)
			if err != nil || value == "" {
				continue
			}

			entries = append(entries, AppCertEntry{
				Name:  valueName,
				Value: value,
				Path:  keyPath,
			})
		}
	}

	return entries, nil
}

func (d *AppCertDllsDetector) isSuspicious(entry AppCertEntry) bool {
	if GlobalWhitelist.IsAllowed(entry.Path + "\\" + entry.Name) {
		return false
	}

	valueLower := strings.ToLower(entry.Value)
	for _, indicator := range SuspiciousAppCertIndicators {
		if strings.Contains(valueLower, strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

func (d *AppCertDllsDetector) calculateSeverity(entry AppCertEntry) Severity {
	valueLower := strings.ToLower(entry.Value)

	highRisk := []string{"mimikatz", "pwdump", "nc.exe", "netcat"}
	for _, risk := range highRisk {
		if strings.Contains(valueLower, risk) {
			return SeverityHigh
		}
	}

	mediumRisk := []string{".dll", "\\temp\\", "\\downloads\\", "\\desktop\\"}
	for _, risk := range mediumRisk {
		if strings.Contains(valueLower, risk) {
			return SeverityMedium
		}
	}

	return SeverityLow
}

func (d *AppCertDllsDetector) calculateFPRisk(entry AppCertEntry) string {
	if GlobalWhitelist.IsAllowed(entry.Path + "\\" + entry.Name) {
		return "Low (Whitelisted)"
	}

	if strings.Contains(strings.ToLower(entry.Value), "system32") ||
		strings.Contains(strings.ToLower(entry.Value), "syswow64") {
		return "Low"
	}

	return "Medium"
}
