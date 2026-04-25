//go:build windows

package persistence

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type AppInitDetector struct {
	config *DetectorConfig
}

func NewAppInitDetector() *AppInitDetector {
	return &AppInitDetector{
		config: &DetectorConfig{
			Enabled:  true,
			EventIDs: []int32{4697},
		},
	}
}

func (d *AppInitDetector) Name() string {
	return "appinit_detector"
}

func (d *AppInitDetector) GetTechnique() Technique {
	return TechniqueT1546010
}

func (d *AppInitDetector) RequiresAdmin() bool {
	return true
}

func (d *AppInitDetector) SetConfig(config *DetectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	d.config = config
	return nil
}

func (d *AppInitDetector) GetConfig() *DetectorConfig {
	return d.config
}

var AppInitPaths = []string{
	`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
	`HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows`,
}

var SuspiciousAppInitDLLs = []string{
	"%TEMP%", "%APPDATA%", "%LOCALAPPDATA%",
	"\\temp\\", "\\tmp\\",
	"\\\\UNC\\", "\\\\127\\", "\\\\localhost\\",
	".ps1", ".vbs", ".js", ".bat", ".cmd",
}

func (d *AppInitDetector) Detect(ctx context.Context) ([]*Detection, error) {
	if d.config != nil && !d.config.Enabled {
		return nil, nil
	}

	detections := make([]*Detection, 0)

	for _, basePath := range AppInitPaths {
		det := d.checkAppInit(basePath)
		if det != nil {
			detections = append(detections, det)
		}
	}

	return detections, nil
}

func (d *AppInitDetector) checkAppInit(basePath string) *Detection {
	appInitDLLs, _ := utils.GetRegistryValue(basePath, "AppInit_DLLs")
	loadAppInit, _ := utils.GetRegistryValue(basePath, "LoadAppInit_DLLs")
	requireSigned, _ := utils.GetRegistryValue(basePath, "RequireSignedAppInit_DLLs")

	if appInitDLLs == "" && loadAppInit != "1" {
		return nil
	}

	if loadAppInit == "1" && appInitDLLs == "" {
		return &Detection{
			Technique:   TechniqueT1546010,
			Category:    "Registry",
			Severity:    SeverityMedium,
			Time:        time.Now(),
			Title:       "AppInit_DLLs Enabled with No DLLs",
			Description: "AppInit_DLLs registry key is enabled but no DLLs are configured. This may indicate partial persistence setup.",
			Evidence: Evidence{
				Type:  EvidenceTypeRegistry,
				Key:   basePath,
				Value: "LoadAppInit_DLLs=1, AppInit_DLLs=(empty)",
			},
			MITRERef:          []string{"T1546.010"},
			RecommendedAction: "Verify if AppInit_DLLs functionality is intentionally used",
			FalsePositiveRisk: "Low",
		}
	}

	if appInitDLLs != "" {
		dlls := strings.Split(appInitDLLs, " ")
		for _, dll := range dlls {
			dll = strings.TrimSpace(dll)
			if dll == "" {
				continue
			}

			if d.isSuspiciousDLL(dll) {
				return &Detection{
					Technique:   TechniqueT1546010,
					Category:    "Registry",
					Severity:    SeverityHigh,
					Time:        time.Now(),
					Title:       "Suspicious AppInit_DLLs Configuration",
					Description: "A suspicious DLL is configured in AppInit_DLLs: " + dll + ". AppInit_DLLs is a common DLL injection technique used by malware.",
					Evidence: Evidence{
						Type:     EvidenceTypeRegistry,
						Key:      basePath,
						Value:    "AppInit_DLLs = " + appInitDLLs,
						Expected: "Empty or System DLLs only",
					},
					MITRERef:          []string{"T1546.010"},
					RecommendedAction: "Investigate the DLL and verify if it is legitimate. Malicious DLLs loaded via AppInit can provide persistent code execution.",
					FalsePositiveRisk: "Medium",
				}
			}

			if !isSystemPath(dll) {
				return &Detection{
					Technique:   TechniqueT1546010,
					Category:    "Registry",
					Severity:    SeverityMedium,
					Time:        time.Now(),
					Title:       "AppInit_DLLs Outside System Directory",
					Description: "A DLL outside the Windows system directory is configured in AppInit_DLLs",
					Evidence: Evidence{
						Type:  EvidenceTypeRegistry,
						Key:   basePath,
						Value: "AppInit_DLLs = " + dll,
					},
					MITRERef:          []string{"T1546.010"},
					RecommendedAction: "Verify the DLL is legitimate",
					FalsePositiveRisk: "Medium",
				}
			}
		}
	}

	if requireSigned == "0" {
		return &Detection{
			Technique:   TechniqueT1546010,
			Category:    "Registry",
			Severity:    SeverityMedium,
			Time:        time.Now(),
			Title:       "AppInit_DLLs Signature Verification Disabled",
			Description: "RequireSignedAppInit_DLLs is set to 0, meaning DLL signature verification is disabled",
			Evidence: Evidence{
				Type:     EvidenceTypeRegistry,
				Key:      basePath,
				Value:    "RequireSignedAppInit_DLLs = 0",
				Expected: "1 (enabled)",
			},
			MITRERef:          []string{"T1546.010"},
			RecommendedAction: "Enable DLL signature verification if AppInit_DLLs is not intentionally used",
			FalsePositiveRisk: "Low",
		}
	}

	return nil
}

func (d *AppInitDetector) isSuspiciousDLL(dll string) bool {
	dllLower := strings.ToLower(dll)

	for _, suspicious := range SuspiciousAppInitDLLs {
		if strings.Contains(dllLower, strings.ToLower(suspicious)) {
			return true
		}
	}

	return false
}

func CheckAppInitDLLs() []*Detection {
	detections := make([]*Detection, 0)
	detector := NewAppInitDetector()

	results, _ := detector.Detect(context.Background())
	detections = append(detections, results...)

	return detections
}
