//go:build windows

package persistence

import (
	"context"
	"fmt"
	"strings"

	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type WinsockDetector struct {
	config *DetectorConfig
}

func NewWinsockDetector() *WinsockDetector {
	return &WinsockDetector{
		config: &DetectorConfig{
			Enabled:  true,
			EventIDs: []int32{4697},
		},
	}
}

func (d *WinsockDetector) Name() string {
	return "winsock_detector"
}

func (d *WinsockDetector) GetTechnique() Technique {
	return TechniqueT1546007
}

func (d *WinsockDetector) RequiresAdmin() bool {
	return true
}

func (d *WinsockDetector) SetConfig(config *DetectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	d.config = config
	return nil
}

func (d *WinsockDetector) GetConfig() *DetectorConfig {
	return d.config
}

var WinsockRegistryPaths = []string{
	`HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Name_Space_Catalog\Catalog_Entries`,
	`HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Name_Space_Catalog\Catalog_Entries64`,
	`HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog\Catalog_Entries`,
	`HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog\Catalog_Entries64`,
}

var SuspiciousWinsockIndicators = []string{
	"%TEMP%", "%APPDATA%", "%LOCALAPPDATA%",
	"\\temp\\", "\\tmp\\",
	"\\\\UNC\\", "\\\\127\\",
	".dll",
	"mimikatz", "metasploit", "cobaltstrike",
	"powershell", "wscript", "cscript",
	"revshell", "bindshell", "netcat",
}

func (d *WinsockDetector) Detect(ctx context.Context) ([]*Detection, error) {
	if d.config != nil && !d.config.Enabled {
		return nil, nil
	}

	detections := make([]*Detection, 0)

	for _, keyPath := range WinsockRegistryPaths {
		entries, err := d.enumerateWinsockKey(keyPath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if d.isSuspicious(entry) {
				det := &Detection{
					Technique:   d.GetTechnique(),
					Category:    "Registry",
					Severity:    d.calculateSeverity(entry),
					Title:       "Suspicious Winsock Provider Modification",
					Description: "A suspicious value was found in a Winsock namespace catalog entry",
					Evidence: Evidence{
						Type:  EvidenceTypeRegistry,
						Key:   keyPath,
						Value: entry.Name + " = " + entry.Value,
					},
					MITRERef:          []string{"T1546.007"},
					RecommendedAction: "Investigate this Winsock provider. Malicious LSPs can intercept all network traffic.",
					FalsePositiveRisk: d.calculateFPRisk(entry),
				}
				detections = append(detections, det)
			}
		}
	}

	return detections, nil
}

type WinsockEntry struct {
	Name  string
	Value string
	Path  string
}

func (d *WinsockDetector) enumerateWinsockKey(keyPath string) ([]WinsockEntry, error) {
	entries := make([]WinsockEntry, 0)

	subkeys, err := listRegistrySubkeysWithPrefix(keyPath)
	if err != nil {
		return entries, nil
	}

	for _, subkey := range subkeys {
		providerPath := subkey.Path
		value, err := getRegistryValueByPath(providerPath, "ProviderPath")
		if err != nil {
			continue
		}
		if value != "" {
			entries = append(entries, WinsockEntry{
				Name:  subkey.Name,
				Value: value,
				Path:  providerPath,
			})
		}
	}

	return entries, nil
}

func listRegistrySubkeysWithPrefix(keyPath string) ([]struct {
	Name string
	Path string
}, error) {
	result := make([]struct {
		Name string
		Path string
	}, 0)

	subkeys, err := listRegistrySubkeys(keyPath)
	if err != nil {
		return result, err
	}

	for _, subkey := range subkeys {
		fullPath := keyPath + "\\" + subkey
		result = append(result, struct {
			Name string
			Path string
		}{
			Name: subkey,
			Path: fullPath,
		})
	}

	return result, nil
}

func listRegistrySubkeys(keyPath string) ([]string, error) {
	result := make([]string, 0)

	paths := strings.Split(keyPath, "\\")
	root := paths[0]
	remaining := ""
	if len(paths) > 1 {
		remaining = strings.Join(paths[1:], "\\")
	}

	subkeys, err := listRegistrySubkeysRecursive(root, remaining)
	if err != nil {
		return result, err
	}

	return subkeys, nil
}

func listRegistrySubkeysRecursive(root, remaining string) ([]string, error) {
	result := make([]string, 0)

	if remaining == "" {
		subkeys, err := listImmediateSubkeys(root)
		if err != nil {
			return result, err
		}
		return subkeys, nil
	}

	parts := strings.SplitN(remaining, "\\", 2)
	current := parts[0]
	next := ""
	if len(parts) > 1 {
		next = parts[1]
	}

	subkeys, err := listImmediateSubkeys(root + "\\" + current)
	if err != nil {
		return result, err
	}

	for _, subkey := range subkeys {
		fullCurrent := root + "\\" + current + "\\" + subkey
		if next == "" {
			result = append(result, current+"\\"+subkey)
		} else {
			subSubkeys, err := listRegistrySubkeysRecursive(fullCurrent, next)
			if err != nil {
				continue
			}
			for _, ss := range subSubkeys {
				result = append(result, current+"\\"+subkey+"\\"+ss)
			}
		}
	}

	return result, nil
}

func listImmediateSubkeys(keyPath string) ([]string, error) {
	return utils.ListRegistrySubkeys(keyPath)
}

func (d *WinsockDetector) isSuspicious(entry WinsockEntry) bool {
	if entry.Value == "" {
		return false
	}

	if strings.HasPrefix(entry.Name, "0000000000") {
		return false
	}

	valueUpper := strings.ToUpper(entry.Value)

	for _, indicator := range SuspiciousWinsockIndicators {
		if strings.Contains(valueUpper, strings.ToUpper(indicator)) {
			return true
		}
	}

	if strings.Contains(valueUpper, ".DLL") && !strings.Contains(valueUpper, "SYSTEM32") && !strings.Contains(valueUpper, "SYSWOW64") {
		return true
	}

	return false
}

func (d *WinsockDetector) calculateSeverity(entry WinsockEntry) Severity {
	valueUpper := strings.ToUpper(entry.Value)

	highRiskIndicators := []string{
		"MIMIKATZ", "METASPLOIT", "COBALTSTRIKE",
		"REVSELL", "BINDSHELL", "NETCAT",
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

func (d *WinsockDetector) calculateFPRisk(entry WinsockEntry) string {
	if strings.Contains(strings.ToUpper(entry.Value), "SYSTEM32") {
		return "Low"
	}
	if strings.Contains(strings.ToUpper(entry.Value), "SYSWOW64") {
		return "Low"
	}
	return "Medium"
}

func getRegistryValueByPath(keyPath, valueName string) (string, error) {
	return "", nil
}
