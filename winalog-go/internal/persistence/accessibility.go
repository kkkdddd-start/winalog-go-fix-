//go:build windows

package persistence

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type AccessibilityDetector struct {
	config *DetectorConfig
}

func NewAccessibilityDetector() *AccessibilityDetector {
	return &AccessibilityDetector{
		config: &DetectorConfig{
			Enabled:  true,
			EventIDs: []int32{4697},
		},
	}
}

func (d *AccessibilityDetector) Name() string {
	return "accessibility_detector"
}

func (d *AccessibilityDetector) GetTechnique() Technique {
	return TechniqueT1546001
}

func (d *AccessibilityDetector) RequiresAdmin() bool {
	return true
}

func (d *AccessibilityDetector) SetConfig(config *DetectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	d.config = config
	return nil
}

func (d *AccessibilityDetector) GetConfig() *DetectorConfig {
	return d.config
}

var AccessibilityBinaries = map[string]string{
	"sethc.exe":         "Sticky Keys",
	"utilman.exe":       "Utility Manager",
	"osk.exe":           "On-Screen Keyboard",
	"magnify.exe":       "Magnifier",
	"narrator.exe":      "Narrator",
	"displayswitch.exe": "Display Switch",
	"magnifyhost.exe":   "Magnifier Host",
	"tabtip.exe":        "Touch Keyboard and Handwriting Panel",
}

var AccessibilityPaths = []string{
	`C:\Windows\System32`,
	`C:\Windows\SysWOW64`,
	`C:\Windows\System32\Accessibility`,
}

func (d *AccessibilityDetector) Detect(ctx context.Context) ([]*Detection, error) {
	if d.config != nil && !d.config.Enabled {
		return nil, nil
	}

	detections := make([]*Detection, 0)

	for binary, description := range AccessibilityBinaries {
		det := d.checkAccessibilityBinary(binary, description)
		if det != nil {
			detections = append(detections, det)
		}
	}

	return detections, nil
}

func (d *AccessibilityDetector) checkAccessibilityBinary(binary, description string) *Detection {
	system32Path := `C:\Windows\System32\` + binary

	_, exists, _ := utils.FileExists(system32Path)
	if !exists {
		return nil
	}

	currentHash, _ := utils.GetFileHash(system32Path)

	expectedHash := KnownAccessibilityHashes[binary]
	if expectedHash != "" && currentHash != "" && currentHash != expectedHash {
		return &Detection{
			Technique:   TechniqueT1546001,
			Category:    "Accessibility",
			Severity:    SeverityCritical,
			Time:        time.Now(),
			Title:       description + " Backdoor Detected",
			Description: "The " + description + " (" + binary + ") binary has been modified or replaced. This is a common persistence technique used by attackers to gain elevated access.",
			Evidence: Evidence{
				Type:     EvidenceTypeFile,
				FilePath: system32Path,
				Process:  binary,
			},
			MITRERef:          []string{"T1546.001"},
			RecommendedAction: "Immediately investigate this host. Check for unauthorized remote access and review recent administrator logins.",
			FalsePositiveRisk: "Low (Replacing system accessibility programs is almost always malicious)",
		}
	}

	modifiedTime, _ := utils.GetFileModTime(system32Path)
	if time.Since(modifiedTime) < 24*time.Hour {
		return &Detection{
			Technique:   TechniqueT1546001,
			Category:    "Accessibility",
			Severity:    SeverityMedium,
			Time:        time.Now(),
			Title:       description + " Recently Modified",
			Description: "The " + description + " binary was modified within the last 24 hours.",
			Evidence: Evidence{
				Type:     EvidenceTypeFile,
				FilePath: system32Path,
				Process:  binary,
			},
			MITRERef:          []string{"T1546.001"},
			RecommendedAction: "Verify if this modification was authorized",
			FalsePositiveRisk: "Medium",
		}
	}

	return nil
}

var KnownAccessibilityHashes = map[string]string{}

func (d *AccessibilityDetector) DetectViaEventLog(ctx context.Context, taskName, taskCommand string) *Detection {
	taskNameLower := strings.ToLower(taskName)

	for accessibilityBinary, description := range AccessibilityBinaries {
		if strings.Contains(taskNameLower, accessibilityBinary) || strings.Contains(taskNameLower, strings.ToLower(description)) {
			if d.isSuspiciousTaskCommand(taskCommand) {
				return &Detection{
					Technique:   TechniqueT1546001,
					Category:    "ScheduledTask",
					Severity:    SeverityHigh,
					Time:        time.Now(),
					Title:       "Suspicious Accessibility Task Created",
					Description: "A scheduled task was created with a name similar to accessibility programs and contains suspicious commands",
					Evidence: Evidence{
						Type:    EvidenceTypeTask,
						Command: taskCommand,
						Process: taskName,
					},
					MITRERef:          []string{"T1546.001", "T1053"},
					RecommendedAction: "Investigate the task author and command to determine if this is legitimate",
					FalsePositiveRisk: "Medium",
				}
			}
		}
	}

	return nil
}

func (d *AccessibilityDetector) isSuspiciousTaskCommand(command string) bool {
	commandLower := strings.ToLower(command)

	suspicious := []string{
		"cmd.exe /c", "cmd /c", "powershell", "wscript", "cscript",
		"rundll32", "regsvr32", "mshta",
		".ps1", ".vbs", ".js",
		"\\\\unc\\", "\\\\127\\", "\\\\localhost\\",
		"%temp%", "%appdata%",
		"net user", "net localgroup",
	}

	for _, indicator := range suspicious {
		if strings.Contains(commandLower, indicator) {
			return true
		}
	}

	return false
}

func CheckAccessibilityBackdoor() []*Detection {
	detections := make([]*Detection, 0)
	detector := NewAccessibilityDetector()

	results, _ := detector.Detect(context.Background())
	detections = append(detections, results...)

	return detections
}
