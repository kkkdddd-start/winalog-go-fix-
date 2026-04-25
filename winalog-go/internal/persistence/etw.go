//go:build windows

package persistence

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type ETWDetector struct {
	config *DetectorConfig
}

func NewETWDetector() *ETWDetector {
	return &ETWDetector{
		config: &DetectorConfig{
			Enabled:  true,
			EventIDs: []int32{4670},
		},
	}
}

func (d *ETWDetector) Name() string {
	return "etw_persistence_detector"
}

func (d *ETWDetector) GetTechnique() Technique {
	return TechniqueT1546006
}

func (d *ETWDetector) RequiresAdmin() bool {
	return true
}

func (d *ETWDetector) SetConfig(config *DetectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	d.config = config
	return nil
}

func (d *ETWDetector) GetConfig() *DetectorConfig {
	return d.config
}

type ETWProvider struct {
	Name       string
	ID         string
	Enabled    bool
	ProcessIDs []uint32
}

type ETWConsumerBinding struct {
	ProviderName string
	ConsumerPath string
}

func (d *ETWDetector) Detect(ctx context.Context) ([]*Detection, error) {
	if d.config != nil && !d.config.Enabled {
		return nil, nil
	}

	detections := make([]*Detection, 0)

	providers, err := d.enumerateProviders()
	if err == nil {
		for _, provider := range providers {
			det := d.analyzeProvider(provider)
			if det != nil {
				detections = append(detections, det)
			}
		}
	}

	bindings, err := d.enumerateConsumerBindings()
	if err == nil {
		for _, binding := range bindings {
			det := d.analyzeConsumerBinding(binding)
			if det != nil {
				detections = append(detections, det)
			}
		}
	}

	return detections, nil
}

func (d *ETWDetector) enumerateProviders() ([]ETWProvider, error) {
	providers := make([]ETWProvider, 0)

	cmd := `Get-WinEvent -ListProvider * -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike 'Microsoft-Windows-*' } | ForEach-Object { $provider = $_; $_.Events | Select-Object -First 1 -ErrorAction SilentlyContinue | ForEach-Object { [PSCustomObject]@{ Name = $provider.Name; ID = $provider.Id; LogName = $_.LogName } } } | Select-Object -First 100 -Property Name, ID, LogName | ConvertTo-Json -Compress`

	result := utils.RunPowerShell(cmd)
	if !result.Success() {
		return providers, result.Error
	}

	output := strings.TrimSpace(result.Output)
	if output == "" || output == "null" {
		return providers, nil
	}

	var providerList []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &providerList); err != nil {
		if singleProvider, err := parseSingleProvider(output); err == nil {
			providers = append(providers, singleProvider)
		}
		return providers, nil
	}

	for _, p := range providerList {
		providers = append(providers, ETWProvider{
			Name: getStringValue(p, "Name"),
			ID:   getStringValue(p, "Id"),
		})
	}

	return providers, nil
}

func parseSingleProvider(output string) (ETWProvider, error) {
	var p map[string]interface{}
	if err := json.Unmarshal([]byte(output), &p); err != nil {
		return ETWProvider{}, err
	}
	return ETWProvider{
		Name: getStringValue(p, "Name"),
		ID:   getStringValue(p, "Id"),
	}, nil
}

func (d *ETWDetector) enumerateConsumerBindings() ([]ETWConsumerBinding, error) {
	bindings := make([]ETWConsumerBinding, 0)

	cmd := `Get-WinEvent -FilterHashtable @{ProviderName='Microsoft-Windows-Sysmon'} -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object { $_.Message -like '*EtwEventWrite*' } | ForEach-Object { $_.Message -match '(\S+)\s+EtwEventWrite'; if($Matches) { [PSCustomObject]@{ ProviderName = $Matches[1] } } } | Select-Object -First 20 -Property ProviderName | ConvertTo-Json -Compress`

	result := utils.RunPowerShell(cmd)
	if !result.Success() || result.Output == "" {
		return bindings, nil
	}

	output := strings.TrimSpace(result.Output)
	if output == "" || output == "null" {
		return bindings, nil
	}

	var bindingList []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &bindingList); err != nil {
		if singleBinding, err := parseSingleBinding(output); err == nil {
			bindings = append(bindings, singleBinding)
		}
		return bindings, nil
	}

	for _, b := range bindingList {
		bindings = append(bindings, ETWConsumerBinding{
			ProviderName: getStringValue(b, "ProviderName"),
		})
	}

	return bindings, nil
}

func parseSingleBinding(output string) (ETWConsumerBinding, error) {
	var b map[string]interface{}
	if err := json.Unmarshal([]byte(output), &b); err != nil {
		return ETWConsumerBinding{}, err
	}
	return ETWConsumerBinding{
		ProviderName: getStringValue(b, "ProviderName"),
	}, nil
}

func (d *ETWDetector) analyzeProvider(provider ETWProvider) *Detection {
	if provider.Name == "" {
		return nil
	}

	if d.isSuspiciousProvider(provider.Name) {
		return &Detection{
			Technique:   TechniqueT1546006,
			Category:    "ETW",
			Severity:    SeverityHigh,
			Time:        time.Now(),
			Title:       "Suspicious ETW Provider Registered",
			Description: "A potentially malicious ETW provider has been registered: " + provider.Name,
			Evidence: Evidence{
				Type:  EvidenceTypeETW,
				Key:   "Provider",
				Value: provider.Name,
			},
			MITRERef:          []string{"T1546.006"},
			RecommendedAction: "Investigate this ETW provider. ETW providers can be used for defense evasion and persistence.",
			FalsePositiveRisk: "Medium",
		}
	}

	return nil
}

func (d *ETWDetector) analyzeConsumerBinding(binding ETWConsumerBinding) *Detection {
	if binding.ProviderName == "" {
		return nil
	}

	if d.isSuspiciousProvider(binding.ProviderName) {
		return &Detection{
			Technique:   TechniqueT1546006,
			Category:    "ETW",
			Severity:    SeverityHigh,
			Time:        time.Now(),
			Title:       "Suspicious ETW Consumer Binding",
			Description: "A suspicious ETW provider is writing events: " + binding.ProviderName,
			Evidence: Evidence{
				Type:  EvidenceTypeETW,
				Key:   "ConsumerBinding",
				Value: binding.ProviderName,
			},
			MITRERef:          []string{"T1546.006"},
			RecommendedAction: "Investigate this ETW consumer binding. Malicious ETW consumers can intercept and modify events.",
			FalsePositiveRisk: "Medium",
		}
	}

	return nil
}

func (d *ETWDetector) isSuspiciousProvider(name string) bool {
	nameLower := strings.ToLower(name)

	suspiciousProviders := []string{
		"mimikatz", "pwdump", "hashdump",
		"metasploit", "cobalt", "empire",
		"bloodhound", "sharphound",
		"credential", "password",
		"keylog", "keystroke",
		"socket", "network",
		"shellcode", "inject",
		"malware", "trojan",
		"backdoor", "rat",
	}

	for _, suspicious := range suspiciousProviders {
		if strings.Contains(nameLower, suspicious) {
			return true
		}
	}

	return false
}

func CheckETWPersistence() []*Detection {
	detections := make([]*Detection, 0)
	detector := NewETWDetector()

	results, _ := detector.Detect(context.Background())
	detections = append(detections, results...)

	return detections
}

func getStringValue(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
