//go:build windows

package persistence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type ScheduledTaskDetector struct {
	config      *DetectorConfig
	configPaths []string
}

func NewScheduledTaskDetector() *ScheduledTaskDetector {
	return &ScheduledTaskDetector{
		config: &DetectorConfig{
			Enabled:  true,
			EventIDs: []int32{4698, 4699, 4700, 4701, 4702},
		},
		configPaths: nil,
	}
}

func (d *ScheduledTaskDetector) Name() string {
	return "scheduled_task_detector"
}

func (d *ScheduledTaskDetector) GetTechnique() Technique {
	return TechniqueT1053
}

func (d *ScheduledTaskDetector) RequiresAdmin() bool {
	return true
}

func (d *ScheduledTaskDetector) SetConfig(config *DetectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	d.config = config
	if len(config.Paths) > 0 {
		d.configPaths = config.Paths
	}
	return nil
}

func (d *ScheduledTaskDetector) GetConfig() *DetectorConfig {
	return d.config
}

type ScheduledTaskInfo struct {
	Name        string
	State       string
	Author      string
	Description string
	Path        string
	Actions     []string
	Triggers    []string
}

var SuspiciousScheduledTaskIndicators = []string{
	"powershell", "wscript", "cscript",
	"cmd.exe", "rundll32", "regsvr32",
	"mimikatz", "pwdump", "nc.exe", "netcat",
	"base64", "-enc", "-encodedcommand",
	"\\temp\\", "\\tmp\\", "%temp%",
	"\\downloads\\", "\\desktop\\",
}

func (d *ScheduledTaskDetector) Detect(ctx context.Context) ([]*Detection, error) {
	if d.config != nil && !d.config.Enabled {
		return nil, nil
	}

	detections := make([]*Detection, 0)

	tasks, err := d.enumerateScheduledTasks()
	if err != nil {
		return detections, err
	}

	for _, task := range tasks {
		if d.isSuspiciousTask(task) {
			det := &Detection{
				Technique:   TechniqueT1053,
				Category:    "ScheduledTask",
				Severity:    d.calculateTaskSeverity(task),
				Time:        time.Now(),
				Title:       "Suspicious Scheduled Task Detected",
				Description: fmt.Sprintf("Scheduled task '%s' has suspicious characteristics", task.Name),
				Evidence: Evidence{
					Type:     EvidenceTypeTask,
					Key:      task.Name,
					Path:     task.Path,
					Command:  strings.Join(task.Actions, "; "),
				},
				MITRERef:          []string{"T1053", "T1053.002"},
				RecommendedAction: "Investigate the scheduled task and verify if it is legitimate",
				FalsePositiveRisk: d.calculateTaskFPRisk(task),
			}
			detections = append(detections, det)
		}
	}

	return detections, nil
}

func (d *ScheduledTaskDetector) enumerateScheduledTasks() ([]ScheduledTaskInfo, error) {
	tasks := make([]ScheduledTaskInfo, 0)

	cmd := `Get-ScheduledTask | ForEach-Object {
		$task = $_
		$info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
		$result = @{
			Name = $task.TaskName
			Path = $task.TaskPath
			State = $task.State.ToString()
			Author = $task.Author
			Description = $task.Description
			Actions = @()
			Triggers = @()
		}
		if ($task.Actions) {
			$task.Actions | ForEach-Object { $result.Actions += $_.Execute }
		}
		if ($task.Triggers) {
			$task.Triggers | ForEach-Object { $result.Triggers += $_.ToString() }
		}
		$result | ConvertTo-Json -Compress -Depth 3
	}`

	result := utils.RunPowerShell(cmd)
	if !result.Success() {
		return tasks, result.Error
	}

	output := strings.TrimSpace(result.Output)
	if output == "" {
		return tasks, nil
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "null" || line == "{}" {
			continue
		}

		var task struct {
			Name        string   `json:"Name"`
			Path        string   `json:"Path"`
			State       string   `json:"State"`
			Author      string   `json:"Author"`
			Description string   `json:"Description"`
			Actions     []string `json:"Actions"`
			Triggers    []string `json:"Triggers"`
		}

		if err := json.Unmarshal([]byte(line), &task); err != nil {
			continue
		}

		tasks = append(tasks, ScheduledTaskInfo{
			Name:        task.Name,
			Path:        task.Path,
			State:       task.State,
			Author:      task.Author,
			Description: task.Description,
			Actions:     task.Actions,
			Triggers:    task.Triggers,
		})
	}

	return tasks, nil
}

func (d *ScheduledTaskDetector) isSuspiciousTask(task ScheduledTaskInfo) bool {
	if GlobalWhitelist.IsAllowed(task.Name) {
		return false
	}

	taskAuthorLower := strings.ToLower(task.Author)
	isMicrosoftTask := strings.Contains(taskAuthorLower, "microsoft") ||
		strings.Contains(taskAuthorLower, "system") ||
		taskAuthorLower == "" || taskAuthorLower == "author"

	for _, action := range task.Actions {
		actionLower := strings.ToLower(action)
		actionExpanded := os.ExpandEnv(action)

		for _, indicator := range SuspiciousScheduledTaskIndicators {
			if strings.Contains(actionLower, strings.ToLower(indicator)) {
				if isMicrosoftTask && isSystemPath(actionExpanded) {
					continue
				}
				return true
			}
		}
	}

	if strings.Contains(taskAuthorLower, "unknown") && len(task.Actions) > 0 {
		for _, action := range task.Actions {
			if !isSystemPath(action) {
				return true
			}
		}
	}

	return false
}

func (d *ScheduledTaskDetector) calculateTaskSeverity(task ScheduledTaskInfo) Severity {
	for _, action := range task.Actions {
		actionLower := strings.ToLower(action)
		highRisk := []string{"mimikatz", "pwdump", "base64", "-enc", "powershell", "nc.exe", "netcat"}
		for _, risk := range highRisk {
			if strings.Contains(actionLower, risk) {
				return SeverityHigh
			}
		}
	}

	mediumRisk := []string{"cmd.exe", "rundll32", "\\temp\\", "\\downloads\\", "\\desktop\\"}
	for _, action := range task.Actions {
		actionLower := strings.ToLower(action)
		for _, risk := range mediumRisk {
			if strings.Contains(actionLower, risk) {
				return SeverityMedium
			}
		}
	}

	return SeverityLow
}

func (d *ScheduledTaskDetector) calculateTaskFPRisk(task ScheduledTaskInfo) string {
	if GlobalWhitelist.IsAllowed(task.Name) {
		return "Low (Whitelisted)"
	}

	if strings.Contains(strings.ToLower(task.Author), "microsoft") ||
		strings.Contains(strings.ToLower(task.Author), "system") {
		return "Low"
	}

	return "Medium"
}
