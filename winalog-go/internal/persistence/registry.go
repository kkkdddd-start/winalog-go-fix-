//go:build windows

package persistence

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type RunKeyDetector struct {
	config           *DetectorConfig
	configPaths      []string
	configIndicators []string
	configWhitelist  []string
}

func NewRunKeyDetector() *RunKeyDetector {
	return &RunKeyDetector{
		config: &DetectorConfig{
			Enabled:  true,
			EventIDs: []int32{4657},
		},
		configPaths:      nil,
		configIndicators: nil,
		configWhitelist:  nil,
	}
}

func (d *RunKeyDetector) Name() string {
	return "run_key_detector"
}

func (d *RunKeyDetector) GetTechnique() Technique {
	return TechniqueT1546016
}

func (d *RunKeyDetector) RequiresAdmin() bool {
	return true
}

func (d *RunKeyDetector) SetConfig(config *DetectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	d.config = config
	if len(config.Paths) > 0 {
		d.configPaths = config.Paths
	}
	if len(config.Patterns) > 0 {
		d.configIndicators = config.Patterns
	}
	if len(config.Whitelist) > 0 {
		d.configWhitelist = config.Whitelist
	}
	return nil
}

func (d *RunKeyDetector) GetConfig() *DetectorConfig {
	return d.config
}

func (d *RunKeyDetector) getPaths() []string {
	if d.configPaths != nil {
		return d.configPaths
	}
	return []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx`,
		`HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`,
	}
}

func (d *RunKeyDetector) getIndicators() []string {
	if d.configIndicators != nil {
		return d.configIndicators
	}
	return []string{
		"%TEMP%", "%TMP%", "%APPDATA%", "%LOCALAPPDATA%",
		"\\temp\\", "\\tmp\\",
		"\\\\UNC\\", "\\\\127\\", "\\\\localhost\\",
		".ps1", ".vbs", ".js", ".wsf", ".bat", ".cmd",
		"powershell", "wscript", "cscript",
		"regsvr32", "rundll32",
		"base64", "-enc", "-encodedcommand",
		"mimikatz", "pwdump", "net user",
	}
}

func (d *RunKeyDetector) getWhitelist() []string {
	if d.configWhitelist != nil {
		return d.configWhitelist
	}
	return []string{}
}

func (d *RunKeyDetector) Detect(ctx context.Context) ([]*Detection, error) {
	if d.config != nil && !d.config.Enabled {
		return nil, nil
	}

	detections := make([]*Detection, 0)

	paths := d.getPaths()
	for _, keyPath := range paths {
		entries, err := d.enumerateRunKey(keyPath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if d.isSuspicious(entry.Value) {
				det := &Detection{
					Technique:   TechniqueT1546016,
					Category:    "Registry",
					Severity:    d.calculateSeverity(entry.Value),
					Title:       "Suspicious Run Key Persistence",
					Description: "A suspicious value was found in a Run key that may indicate persistence",
					Evidence: Evidence{
						Type:  EvidenceTypeRegistry,
						Key:   keyPath,
						Value: entry.Name + " = " + entry.Value,
					},
					MITRERef:          []string{"T1547.001", "T1547.016"},
					RecommendedAction: "Investigate the executable path and verify if it is legitimate",
					FalsePositiveRisk: d.calculateFPRisk(keyPath, entry.Name, entry.Value),
				}
				detections = append(detections, det)
			}
		}
	}

	return detections, nil
}

type RunKeyEntry struct {
	Name  string
	Value string
	Type  string
}

func (d *RunKeyDetector) enumerateRunKey(keyPath string) ([]RunKeyEntry, error) {
	entries := make([]RunKeyEntry, 0)

	values, err := utils.ListRegistryValues(keyPath)
	if err != nil {
		log.Printf("[DEBUG] [RunKeyDetector] ListRegistryValues(%s) failed: %v", keyPath, err)
		return entries, nil
	}

	log.Printf("[DEBUG] [RunKeyDetector] Found %d values under %s", len(values), keyPath)

	for _, valueName := range values {
		value, err := utils.GetRegistryValue(keyPath, valueName)
		if err != nil {
			log.Printf("[DEBUG] [RunKeyDetector] GetRegistryValue(%s, %s) failed: %v", keyPath, valueName, err)
			continue
		}
		if value != "" {
			log.Printf("[DEBUG] [RunKeyDetector] Found entry: %s = %s", valueName, value)
			entries = append(entries, RunKeyEntry{
				Name:  valueName,
				Value: value,
				Type:  "REG_SZ",
			})
		}
	}

	return entries, nil
}

func (d *RunKeyDetector) isSuspicious(value string) bool {
	valueLower := strings.ToLower(value)

	indicators := d.getIndicators()
	for _, indicator := range indicators {
		if strings.Contains(valueLower, strings.ToLower(indicator)) {
			return true
		}
	}

	if strings.Contains(value, "%") && !isSystemVariable(value) {
		return true
	}

	if filepath.IsAbs(value) && !isSystemPath(value) {
		return true
	}

	return false
}

func isSystemVariable(value string) bool {
	systemVars := []string{"%SYSTEMROOT%", "%WINDOWS%", "%PROGRAMFILES%", "%PROGRAMDATA%", "%SYSTEM32%", "%SYSWOW64%"}
	valueLower := strings.ToLower(value)
	for _, v := range systemVars {
		if strings.Contains(valueLower, strings.ToLower(v)) {
			return true
		}
	}
	return false
}

func isSystemPath(value string) bool {
	valueExpanded := os.ExpandEnv(value)
	valueLower := strings.ToLower(valueExpanded)
	systemPaths := []string{
		`c:\windows\system32`, `c:\windows\syswow64`,
		`c:\program files`, `c:\programdata`,
		`c:\windows`,
	}
	for _, path := range systemPaths {
		if strings.Contains(valueLower, path) {
			return true
		}
	}
	return false
}

func (d *RunKeyDetector) calculateSeverity(value string) Severity {
	valueLower := strings.ToLower(value)

	highRisk := []string{"mimikatz", "pwdump", "net user", "base64", "-enc", "powershell"}
	for _, indicator := range highRisk {
		if strings.Contains(valueLower, indicator) {
			return SeverityHigh
		}
	}

	mediumRisk := []string{"%temp%", "%appdata%", "\\\\unc\\", ".ps1", ".vbs"}
	for _, indicator := range mediumRisk {
		if strings.Contains(valueLower, indicator) {
			return SeverityMedium
		}
	}

	return SeverityLow
}

func (d *RunKeyDetector) calculateFPRisk(keyPath, name, value string) string {
	fullKey := keyPath + "\\" + name
	if GlobalWhitelist.IsAllowed(fullKey) {
		return "Low (Whitelisted)"
	}

	if strings.Contains(strings.ToLower(value), "microsoft") {
		return "Low"
	}

	return "Medium"
}

type UserInitDetector struct {
	config *DetectorConfig
}

func NewUserInitDetector() *UserInitDetector {
	return &UserInitDetector{
		config: &DetectorConfig{
			Enabled:  true,
			EventIDs: []int32{4688},
		},
	}
}

func (d *UserInitDetector) Name() string {
	return "user_init_detector"
}

func (d *UserInitDetector) GetTechnique() Technique {
	return TechniqueT1546001
}

func (d *UserInitDetector) RequiresAdmin() bool {
	return true
}

func (d *UserInitDetector) SetConfig(config *DetectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	d.config = config
	return nil
}

func (d *UserInitDetector) GetConfig() *DetectorConfig {
	return d.config
}

func (d *UserInitDetector) Detect(ctx context.Context) ([]*Detection, error) {
	if d.config != nil && !d.config.Enabled {
		return nil, nil
	}
	detections := make([]*Detection, 0)

	userInitPath := `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`
	expectedValue := `C:\Windows\system32\userinit.exe`

	value, err := utils.GetRegistryValue(userInitPath, "")
	if err != nil {
		return detections, nil
	}

	if value == "" {
		return detections, nil
	}

	values := strings.Split(value, ",")
	for _, v := range values {
		v = strings.TrimSpace(v)
		if !strings.EqualFold(filepath.Base(v), "userinit.exe") && !strings.Contains(strings.ToLower(v), "userinit.exe") {
			det := &Detection{
				Technique:   TechniqueT1546001,
				Category:    "Registry",
				Severity:    SeverityHigh,
				Time:        time.Now(),
				Title:       "Userinit Registry Modification",
				Description: "Userinit registry value has been modified, indicating possible persistence",
				Evidence: Evidence{
					Type:     EvidenceTypeRegistry,
					Key:      userInitPath,
					Value:    value,
					Expected: expectedValue,
				},
				MITRERef:          []string{"T1546.001"},
				RecommendedAction: "Verify if the modification is legitimate. Malicious scripts often add after userinit.exe",
				FalsePositiveRisk: "Low",
			}
			detections = append(detections, det)
		}
	}

	shellPath := `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`
	shellValue, _ := utils.GetRegistryValue(shellPath, "")
	if shellValue != "" && !strings.Contains(strings.ToLower(shellValue), "explorer.exe") {
		det := &Detection{
			Technique:   TechniqueT1546001,
			Category:    "Registry",
			Severity:    SeverityMedium,
			Time:        time.Now(),
			Title:       "Shell Registry Modification",
			Description: "Shell registry value has been modified from default explorer.exe",
			Evidence: Evidence{
				Type:     EvidenceTypeRegistry,
				Key:      shellPath,
				Value:    shellValue,
				Expected: "explorer.exe",
			},
			MITRERef:          []string{"T1546.001"},
			RecommendedAction: "Verify if the modification is legitimate",
			FalsePositiveRisk: "Medium",
		}
		detections = append(detections, det)
	}

	return detections, nil
}

type StartupFolderDetector struct {
	config      *DetectorConfig
	configPaths []string
	configExts  []string
}

func NewStartupFolderDetector() *StartupFolderDetector {
	return &StartupFolderDetector{
		config: &DetectorConfig{
			Enabled:  true,
			EventIDs: []int32{4657},
		},
		configPaths: nil,
		configExts:  nil,
	}
}

func (d *StartupFolderDetector) Name() string {
	return "startup_folder_detector"
}

func (d *StartupFolderDetector) GetTechnique() Technique {
	return TechniqueT1546016
}

func (d *StartupFolderDetector) RequiresAdmin() bool {
	return false
}

func (d *StartupFolderDetector) SetConfig(config *DetectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	d.config = config
	if len(config.Paths) > 0 {
		d.configPaths = config.Paths
	}
	if len(config.Patterns) > 0 {
		d.configExts = config.Patterns
	}
	return nil
}

func (d *StartupFolderDetector) GetConfig() *DetectorConfig {
	return d.config
}

func (d *StartupFolderDetector) getPaths() []string {
	if d.configPaths != nil {
		return d.configPaths
	}
	return []string{
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`,
		`C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`,
	}
}

func (d *StartupFolderDetector) getExtensions() []string {
	if d.configExts != nil {
		return d.configExts
	}
	return []string{".lnk", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".exe", ".dll"}
}

func (d *StartupFolderDetector) Detect(ctx context.Context) ([]*Detection, error) {
	if d.config != nil && !d.config.Enabled {
		return nil, nil
	}
	detections := make([]*Detection, 0)

	for _, basePath := range d.getPaths() {
		if strings.Contains(basePath, "*") {
			users, err := listUserDirectories()
			if err != nil {
				continue
			}
			for _, user := range users {
				path := strings.Replace(basePath, "*", user, 1)
				detects, err := d.detectInFolder(path)
				if err == nil {
					detections = append(detections, detects...)
				}
			}
		} else {
			detects, err := d.detectInFolder(basePath)
			if err == nil {
				detections = append(detections, detects...)
			}
		}
	}

	return detections, nil
}

func listUserDirectories() ([]string, error) {
	var users []string
	usersPath := `C:\Users`

	entries, err := os.ReadDir(usersPath)
	if err != nil {
		return users, err
	}

	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			users = append(users, entry.Name())
		}
	}

	return users, nil
}

func (d *StartupFolderDetector) detectInFolder(folderPath string) ([]*Detection, error) {
	detections := make([]*Detection, 0)

	entries, err := os.ReadDir(folderPath)
	if err != nil {
		return detections, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			subDetects, _ := d.detectInFolder(folderPath + string(os.PathSeparator) + entry.Name())
			detections = append(detections, subDetects...)
			continue
		}

		filePath := folderPath + string(os.PathSeparator) + entry.Name()
		ext := strings.ToLower(filepath.Ext(filePath))

		if !d.isSuspiciousStartupExtension(ext) {
			continue
		}

		det := d.analyzeStartupFile(filePath, entry.Name(), ext)
		if det != nil {
			detections = append(detections, det)
		}
	}

	return detections, nil
}

func (d *StartupFolderDetector) isSuspiciousStartupExtension(ext string) bool {
	for _, suspicious := range d.getExtensions() {
		if ext == suspicious {
			return true
		}
	}
	return false
}

func (d *StartupFolderDetector) analyzeStartupFile(filePath, fileName, ext string) *Detection {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil
	}

	detection := &Detection{
		Technique:   TechniqueT1546016,
		Category:    "Startup",
		Severity:    SeverityMedium,
		Time:        info.ModTime(),
		Title:       "Startup Folder Item Detected",
		Description: fmt.Sprintf("A file in the startup folder was detected: %s", fileName),
		Evidence: Evidence{
			Type:     EvidenceTypeFile,
			FilePath: filePath,
		},
		MITRERef:          []string{"T1547.001"},
		RecommendedAction: "Verify this startup item is legitimate",
		FalsePositiveRisk: "Low",
	}

	if ext == ".lnk" {
		targetPath := parseShortcut(filePath)
		if targetPath != "" {
			detection.Description = fmt.Sprintf("A shortcut in the startup folder points to: %s", targetPath)
			detection.Evidence.FilePath = targetPath

			if isSuspiciousPath(targetPath) {
				detection.Severity = SeverityHigh
				detection.Description = fmt.Sprintf("Suspicious startup shortcut detected, target: %s", targetPath)
			}
		}
	} else if isKnownSuspiciousStartup(fileName) {
		detection.Severity = SeverityHigh
		detection.Description = fmt.Sprintf("Known suspicious startup item detected: %s", fileName)
	} else if isSuspiciousPath(filePath) {
		detection.Severity = SeverityHigh
		detection.Description = fmt.Sprintf("Suspicious path in startup folder: %s", filePath)
	}

	return detection
}

func isSuspiciousPath(path string) bool {
	pathLower := strings.ToLower(path)
	suspiciousIndicators := []string{
		"%temp%", "%appdata%", "%localappdata%",
		"temp\\", "tmp\\",
		"\\\\unc\\", "\\\\127\\",
		"download", "temp", "cache",
	}

	for _, indicator := range suspiciousIndicators {
		if strings.Contains(pathLower, indicator) {
			return true
		}
	}

	return false
}

func isKnownSuspiciousStartup(fileName string) bool {
	fileLower := strings.ToLower(fileName)
	suspicious := []string{
		"mimikatz", "pwdump", "procdump",
		"nc.exe", "netcat", "psexec",
		"powershell", "psexec", "wce.exe",
	}

	for _, s := range suspicious {
		if strings.Contains(fileLower, s) {
			return true
		}
	}

	return false
}

func parseShortcut(filePath string) string {
	cmd := fmt.Sprintf(`(New-Object -ComObject WScript.Shell).CreateShortcut('%s').TargetPath`, filePath)

	result := utils.RunPowerShell(cmd)
	if result.Success() {
		return strings.TrimSpace(result.Output)
	}
	return ""
}
