//go:build windows

package persistence

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type IFEODetector struct {
	config *DetectorConfig
}

func NewIFEODetector() *IFEODetector {
	return &IFEODetector{
		config: &DetectorConfig{
			Enabled:  true,
			EventIDs: []int32{4697},
		},
	}
}

func (d *IFEODetector) Name() string {
	return "ifeo_detector"
}

func (d *IFEODetector) GetTechnique() Technique {
	return TechniqueT1546012
}

func (d *IFEODetector) RequiresAdmin() bool {
	return true
}

func (d *IFEODetector) SetConfig(config *DetectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	d.config = config
	return nil
}

func (d *IFEODetector) GetConfig() *DetectorConfig {
	return d.config
}

var IFEOPath = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

var CommonTargetProcesses = []string{
	"notepad.exe",
	"calc.exe",
	"cmd.exe",
	"powershell.exe",
	"regedit.exe",
	"msconfig.exe",
	"taskmgr.exe",
	"eventvwr.exe",
	"gpedit.msc",
	"mmc.exe",
	"explorer.exe",
	"svchost.exe",
	"lsass.exe",
	"csrss.exe",
	"smss.exe",
	"winlogon.exe",
}

var SuspiciousIFEODebuggers = []string{
	"cmd.exe", "powershell.exe", "pwsh.exe",
	"wscript.exe", "cscript.exe",
	"rundll32.exe", "regsvr32.exe",
	"mshta.exe", "wsreset.exe",
	"\\\\UNC\\", "\\\\127\\",
	"%TEMP%", "%APPDATA%",
	"certutil.exe", "bitsadmin.exe",
	"cmstp.exe", "msiexec.exe",
	"reg.exe", "schtasks.exe",
	"at.exe", "sc.exe",
	"wmic.exe", "winrm.exe",
	"psExec.exe", "psexec.exe",
	"hamachi.exe", "teamviewer.exe",
	"anydesk.exe", "chrome-remote-desktop.exe",
	"vnc.exe", "tightvnc.exe",
	"realvnc.exe", "ultravnc.exe",
	"ammyy.exe", "screenconnect.exe",
}

var RemoteAccessTools = map[string]string{
	"teamviewer.exe":            "TeamViewer",
	"anydesk.exe":               "AnyDesk",
	"ammyy.exe":                 "Ammy Admin",
	"chrome-remote-desktop.exe": "Chrome Remote Desktop",
	"vnc.exe":                   "VNC",
	"tightvnc.exe":              "TightVNC",
	"realvnc.exe":               "RealVNC",
	"ultravnc.exe":              "UltraVNC",
	"screenconnect.exe":         "ScreenConnect",
	"logmein.exe":               "LogMeIn",
	"bomgar.exe":                "Bomgar",
	"centosast.exe":             "CentraStage",
	"psp.exe":                   "pStrm",
}

func (d *IFEODetector) Detect(ctx context.Context) ([]*Detection, error) {
	if d.config != nil && !d.config.Enabled {
		return nil, nil
	}

	detections := make([]*Detection, 0)

	targetProcesses, err := d.enumerateIFEOTargets()
	if err != nil {
		return detections, nil
	}

	for _, target := range targetProcesses {
		det := d.analyzeIFEOTarget(target)
		if det != nil {
			detections = append(detections, det)
		}
	}

	return detections, nil
}

type IFEOTarget struct {
	ProcessName   string
	Debugger      string
	GlobalFlag    string
	ShutdownFlags int
}

func (d *IFEODetector) enumerateIFEOTargets() ([]IFEOTarget, error) {
	targets := make([]IFEOTarget, 0)

	subkeys, err := utils.ListRegistrySubkeys(IFEOPath)
	if err != nil {
		return targets, nil
	}

	for _, processName := range subkeys {
		if processName == "" {
			continue
		}

		processPath := IFEOPath + `\` + processName

		debugger, _ := utils.GetRegistryValue(processPath, "Debugger")
		globalFlag, _ := utils.GetRegistryValue(processPath, "GlobalFlag")

		targets = append(targets, IFEOTarget{
			ProcessName: processName,
			Debugger:    debugger,
			GlobalFlag:  globalFlag,
		})
	}

	return targets, nil
}

func (d *IFEODetector) analyzeIFEOTarget(target IFEOTarget) *Detection {
	if target.Debugger == "" {
		return nil
	}

	debuggerLower := strings.ToLower(target.Debugger)

	for _, suspicious := range SuspiciousIFEODebuggers {
		if strings.Contains(debuggerLower, strings.ToLower(suspicious)) {
			if toolName, isRemoteAccess := RemoteAccessTools[strings.ToLower(target.Debugger)]; isRemoteAccess {
				return &Detection{
					Technique:   TechniqueT1546012,
					Category:    "IFEO",
					Severity:    SeverityCritical,
					Time:        time.Now(),
					Title:       "IFEO Remote Access Tool Detected",
					Description: "A remote access tool (" + toolName + ") has been configured as IFEO debugger for: " + target.ProcessName + ". This is a common technique used by attackers for persistence and remote control.",
					Evidence: Evidence{
						Type:  EvidenceTypeRegistry,
						Key:   IFEOPath + `\` + target.ProcessName,
						Value: "Debugger = " + target.Debugger,
					},
					MITRERef:          []string{"T1546.012", "T1219"},
					RecommendedAction: "Immediately investigate this system for remote access. Consider isolating from network.",
					FalsePositiveRisk: "Low",
				}
			}
			return &Detection{
				Technique:   TechniqueT1546012,
				Category:    "IFEO",
				Severity:    SeverityHigh,
				Time:        time.Now(),
				Title:       "IFEO Debugger Hijacking Detected",
				Description: "A suspicious debugger was found set for process: " + target.ProcessName + ". This technique is used to intercept process execution.",
				Evidence: Evidence{
					Type:  EvidenceTypeRegistry,
					Key:   IFEOPath + `\` + target.ProcessName,
					Value: "Debugger = " + target.Debugger,
				},
				MITRERef:          []string{"T1546.012"},
				RecommendedAction: "Investigate the debugger and verify if this modification is authorized. Debugger hijacking is commonly used by malware and attacker tools.",
				FalsePositiveRisk: "Medium",
			}
		}
	}

	if target.GlobalFlag != "" {
		return &Detection{
			Technique:   TechniqueT1546012,
			Category:    "IFEO",
			Severity:    SeverityMedium,
			Time:        time.Now(),
			Title:       "IFEO GlobalFlag Set",
			Description: "A GlobalFlag has been configured for: " + target.ProcessName + ". This can be used to enable debugging flags.",
			Evidence: Evidence{
				Type:  EvidenceTypeRegistry,
				Key:   IFEOPath + `\` + target.ProcessName,
				Value: "GlobalFlag = " + target.GlobalFlag,
			},
			MITRERef:          []string{"T1546.012"},
			RecommendedAction: "Verify if this GlobalFlag is authorized",
			FalsePositiveRisk: "Medium",
		}
	}

	for _, commonProc := range CommonTargetProcesses {
		if strings.ToLower(target.ProcessName) == strings.ToLower(commonProc) && target.Debugger != "" {
			return &Detection{
				Technique:   TechniqueT1546012,
				Category:    "IFEO",
				Severity:    SeverityMedium,
				Time:        time.Now(),
				Title:       "IFEO Debugger Set for Common Process",
				Description: "A debugger has been set for a commonly targeted process: " + target.ProcessName,
				Evidence: Evidence{
					Type:  EvidenceTypeRegistry,
					Key:   IFEOPath + `\` + target.ProcessName,
					Value: "Debugger = " + target.Debugger,
				},
				MITRERef:          []string{"T1546.012"},
				RecommendedAction: "Verify if this debugger is legitimate",
				FalsePositiveRisk: "Medium",
			}
		}
	}

	return nil
}

func CheckIFEOHijacking() []*Detection {
	detections := make([]*Detection, 0)
	detector := NewIFEODetector()

	results, _ := detector.Detect(context.Background())
	detections = append(detections, results...)

	return detections
}
