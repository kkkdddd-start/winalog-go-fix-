//go:build windows

package persistence

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type ServicePersistenceDetector struct {
	config           *DetectorConfig
	configSuspicious []string
	configNames      []string
	configWhitelist  []string
}

func NewServicePersistenceDetector() *ServicePersistenceDetector {
	return &ServicePersistenceDetector{
		config: &DetectorConfig{
			Enabled:  true,
			EventIDs: []int32{4697, 7045},
		},
		configSuspicious: nil,
		configNames:      nil,
		configWhitelist:  nil,
	}
}

func (d *ServicePersistenceDetector) Name() string {
	return "service_persistence_detector"
}

func (d *ServicePersistenceDetector) GetTechnique() Technique {
	return TechniqueT1543003
}

func (d *ServicePersistenceDetector) RequiresAdmin() bool {
	return true
}

func (d *ServicePersistenceDetector) SetConfig(config *DetectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	d.config = config
	if len(config.Paths) > 0 {
		d.configSuspicious = config.Paths
	}
	if len(config.Patterns) > 0 {
		d.configNames = config.Patterns
	}
	if len(config.Whitelist) > 0 {
		d.configWhitelist = config.Whitelist
	}
	return nil
}

func (d *ServicePersistenceDetector) getWhitelist() []string {
	if d.configWhitelist != nil {
		return d.configWhitelist
	}
	return []string{}
}

func (d *ServicePersistenceDetector) GetConfig() *DetectorConfig {
	return d.config
}

type ServiceInfo struct {
	Name        string
	DisplayName string
	Path        string
	State       string
	StartType   string
}

var SuspiciousServicePaths = []string{
	"%TEMP%", "%APPDATA%", "%LOCALAPPDATA%",
	"\\temp\\", "\\tmp\\",
	"\\\\UNC\\", "\\\\127\\", "\\\\localhost\\",
	"\\downloads\\", "\\desktop\\",
	".ps1", ".vbs", ".js", ".bat", ".cmd",
}

// SuspiciousServiceNames 只包含伪装系统进程名的精确匹配，不再用 Contains 匹配厂商名
var SuspiciousServiceNames = []string{
	"svchost", "csrss", "lsass", "smss", "winlogon",
	"spoolsv", "taskhost", "rundll32", "regsvr32",
	"services", "lsm", "conhost",
}

// LegitimateServicePrefixes 白名单前缀，匹配到的服务直接跳过检测
var LegitimateServicePrefixes = []string{
	"Microsoft", "Windows", "Google", "Adobe",
	"Intel", "NVIDIA", "Realtek", "VMware",
	"Symantec", "McAfee", "Kaspersky", "CrowdStrike",
}

func (d *ServicePersistenceDetector) Detect(ctx context.Context) ([]*Detection, error) {
	if d.config != nil && !d.config.Enabled {
		return nil, nil
	}

	detections := make([]*Detection, 0)

	services, err := d.enumerateServices()
	if err != nil {
		return detections, err
	}

	for _, svc := range services {
		if d.isSuspiciousService(svc.Name, svc.Path) {
			det := &Detection{
				Technique:   TechniqueT1543003,
				Category:    "Service",
				Severity:    d.calculateServiceSeverity(svc.Name, svc.Path),
				Time:        time.Now(),
				Title:       "Suspicious Service Detected",
				Description: fmt.Sprintf("Service '%s' has suspicious characteristics", svc.Name),
				Evidence: Evidence{
					Type:     EvidenceTypeService,
					Key:      svc.Name,
					FilePath: svc.Path,
					Process:  svc.Name,
				},
				MITRERef:          []string{"T1543.003"},
				RecommendedAction: "Investigate the service and verify if it is legitimate",
				FalsePositiveRisk: d.calculateServiceFPRisk(svc.Name, svc.Path),
			}
			detections = append(detections, det)
		}
	}

	return detections, nil
}

func (d *ServicePersistenceDetector) enumerateServices() ([]ServiceInfo, error) {
	services := make([]ServiceInfo, 0)

	cmd := `Get-Service | Select-Object Name,DisplayName,Status,StartType | ForEach-Object { $_ | ConvertTo-Json -Compress }`

	result := utils.RunPowerShell(cmd)
	if !result.Success() {
		return services, result.Error
	}

	output := strings.TrimSpace(result.Output)
	if output == "" {
		return services, nil
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "null" {
			continue
		}

		var svc struct {
			Name        string `json:"Name"`
			DisplayName string `json:"DisplayName"`
			Status      string `json:"Status"`
			StartType   string `json:"StartType"`
		}

		if err := json.Unmarshal([]byte(line), &svc); err != nil {
			continue
		}

		services = append(services, ServiceInfo{
			Name:        svc.Name,
			DisplayName: svc.DisplayName,
			State:       string(svc.Status),
			StartType:   string(svc.StartType),
			Path:        d.getServicePath(svc.Name),
		})
	}

	return services, nil
}

func (d *ServicePersistenceDetector) getServicePath(serviceName string) string {
	cmd := fmt.Sprintf(`(Get-WmiObject -Class Win32_Service -Filter "Name='%s'" -ErrorAction SilentlyContinue).PathName`, serviceName)

	result := utils.RunPowerShell(cmd)
	if result.Success() {
		return strings.TrimSpace(result.Output)
	}
	return ""
}

func (d *ServicePersistenceDetector) AnalyzeServiceCreation(event *types.Event) *Detection {
	if d.config != nil && !d.config.Enabled {
		return nil
	}

	eventIDs := d.getEventIDs()
	isAllowedEventID := false
	for _, id := range eventIDs {
		if event.EventID == id {
			isAllowedEventID = true
			break
		}
	}
	if !isAllowedEventID && len(eventIDs) > 0 {
		return nil
	}

	message := strings.ToLower(event.Message)
	if !strings.Contains(message, "service") {
		return nil
	}

	serviceName := d.extractServiceName(event.Message)
	if serviceName == "" {
		return nil
	}

	servicePath := d.extractServicePath(event.Message)
	if servicePath == "" {
		return nil
	}

	if d.isSuspiciousService(serviceName, servicePath) {
		return &Detection{
			Technique:   TechniqueT1543003,
			Category:    "Service",
			Severity:    d.calculateServiceSeverity(serviceName, servicePath),
			Time:        event.Timestamp,
			Title:       "Suspicious Service Created",
			Description: "A service with suspicious characteristics was created: " + serviceName,
			Evidence: Evidence{
				Type:     EvidenceTypeService,
				Key:      serviceName,
				FilePath: servicePath,
				Process:  serviceName,
			},
			MITRERef:          []string{"T1543.003"},
			RecommendedAction: "Investigate the service and verify if it is legitimate. Malicious services are commonly used for persistence and privilege escalation.",
			FalsePositiveRisk: d.calculateServiceFPRisk(serviceName, servicePath),
		}
	}

	return nil
}

func (d *ServicePersistenceDetector) extractServiceName(message string) string {
	patterns := []string{
		"service name:", "service name :",
		"service:",
	}

	messageUpper := strings.ToUpper(message)
	for _, pattern := range patterns {
		idx := strings.Index(messageUpper, strings.ToUpper(pattern))
		if idx >= 0 {
			namePart := message[idx+len(pattern):]
			namePart = strings.TrimSpace(namePart)
			parts := strings.Fields(namePart)
			if len(parts) > 0 {
				return parts[0]
			}
		}
	}

	return ""
}

func (d *ServicePersistenceDetector) extractServicePath(message string) string {
	patterns := []string{
		"imagepath:", "imagepath :",
		"command line:", "command line :",
	}

	messageLower := strings.ToLower(message)
	for _, pattern := range patterns {
		idx := strings.Index(messageLower, pattern)
		if idx >= 0 {
			pathPart := message[idx+len(pattern):]
			pathPart = strings.TrimSpace(pathPart)
			pathPart = strings.Trim(pathPart, "\"")
			return pathPart
		}
	}

	return ""
}

func (d *ServicePersistenceDetector) isSuspiciousService(name, path string) bool {
	nameLower := strings.ToLower(name)
	pathLower := strings.ToLower(path)

	if GlobalWhitelist.IsAllowed(name) {
		return false
	}

	if d.isWhitelisted(nameLower) {
		return false
	}

	// 白名单前缀：合法厂商的服务直接跳过
	for _, prefix := range LegitimateServicePrefixes {
		if strings.HasPrefix(name, prefix) || strings.HasPrefix(nameLower, strings.ToLower(prefix)) {
			return false
		}
	}

	suspiciousPaths := d.getSuspiciousPaths()
	for _, suspicious := range suspiciousPaths {
		if strings.Contains(pathLower, strings.ToLower(suspicious)) {
			return true
		}
	}

	// 精确匹配伪装进程名，避免 Contains 导致的误报
	for _, suspicious := range SuspiciousServiceNames {
		if strings.EqualFold(name, suspicious) {
			return true
		}
	}

	return false
}

func (d *ServicePersistenceDetector) isWhitelisted(name string) bool {
	whitelist := d.getWhitelist()
	if len(whitelist) == 0 {
		return false
	}
	for _, entry := range whitelist {
		entryLower := strings.ToLower(entry)
		if strings.Contains(entryLower, "*") {
			prefix := strings.TrimSuffix(entryLower, "*")
			if strings.HasPrefix(name, prefix) {
				return true
			}
		} else if name == entryLower {
			return true
		}
	}
	return false
}

func (d *ServicePersistenceDetector) getSuspiciousPaths() []string {
	if d.configSuspicious != nil {
		return d.configSuspicious
	}
	return []string{
		"%TEMP%", "%APPDATA%", "%LOCALAPPDATA%",
		"\\temp\\", "\\tmp\\",
		"\\\\UNC\\", "\\\\127\\", "\\\\localhost\\",
		"\\downloads\\", "\\desktop\\",
		".ps1", ".vbs", ".js", ".bat", ".cmd",
	}
}

func (d *ServicePersistenceDetector) getSuspiciousNames() []string {
	if d.configNames != nil {
		return d.configNames
	}
	return []string{
		"update", "updates", "updatecheck",
		"security", "defender", "antivirus",
		"system", "windows",
		"microsoft", "google", "adobe",
	}
}

func (d *ServicePersistenceDetector) getEventIDs() []int32 {
	if d.config != nil && len(d.config.EventIDs) > 0 {
		return d.config.EventIDs
	}
	return []int32{4697, 7045}
}

func (d *ServicePersistenceDetector) isKnownLegitimate(name string) bool {
	knownLegitimate := []string{
		"security center", "security health",
		"windows defender", "windows update",
		"windows management",
	}

	for _, known := range knownLegitimate {
		if strings.Contains(name, known) {
			return true
		}
	}

	return false
}

func (d *ServicePersistenceDetector) calculateServiceSeverity(name, path string) Severity {
	pathLower := strings.ToLower(path)
	nameLower := strings.ToLower(name)

	highRisk := []string{"%temp%", "%appdata%", "\\\\unc\\", "mimikatz", "pwdump"}
	for _, risk := range highRisk {
		if strings.Contains(pathLower, risk) {
			return SeverityHigh
		}
	}

	mediumRisk := []string{"\\downloads\\", "\\desktop\\", "update", "security"}
	for _, risk := range mediumRisk {
		if strings.Contains(pathLower, risk) || strings.Contains(nameLower, risk) {
			return SeverityMedium
		}
	}

	return SeverityLow
}

func (d *ServicePersistenceDetector) calculateServiceFPRisk(name, path string) string {
	nameLower := strings.ToLower(name)

	if GlobalWhitelist.IsAllowed(name) {
		return "Low (Whitelisted service)"
	}

	if strings.Contains(nameLower, "microsoft") || strings.Contains(nameLower, "windows") {
		return "Low"
	}

	if strings.Contains(nameLower, "update") || strings.Contains(nameLower, "security") {
		return "Medium (Third-party update/security services may use this pattern)"
	}

	return "Medium"
}

func AnalyzeServiceEvents(events []*types.Event) []*Detection {
	detections := make([]*Detection, 0)
	detector := NewServicePersistenceDetector()

	for _, event := range events {
		det := detector.AnalyzeServiceCreation(event)
		if det != nil {
			detections = append(detections, det)
		}
	}

	return detections
}
