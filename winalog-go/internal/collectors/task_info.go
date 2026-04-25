//go:build windows

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type TaskInfoCollector struct {
	BaseCollector
}

type ScheduledTaskInfo struct {
	TaskName        string
	TaskPath        string
	State          string
	Description    string
	Author         string
	NextRunTime    string
	LastRunTime    string
	LastResult     int
	RunAsUser      string
	Action         string
	TriggerType    string
}

func NewTaskInfoCollector() *TaskInfoCollector {
	return &TaskInfoCollector{
		BaseCollector: BaseCollector{
			info: CollectorInfo{
				Name:          "task_info",
				Description:   "Collect scheduled task information",
				RequiresAdmin: true,
				Version:       "1.0.0",
			},
		},
	}
}

func (c *TaskInfoCollector) Collect(ctx context.Context) ([]interface{}, error) {
	tasks, err := c.collectTaskInfo()
	if err != nil {
		return nil, err
	}
	interfaces := make([]interface{}, len(tasks))
	for i, t := range tasks {
		interfaces[i] = t
	}
	return interfaces, nil
}

func (c *TaskInfoCollector) collectTaskInfo() ([]*types.ScheduledTask, error) {
	tasks := make([]*types.ScheduledTask, 0)

	cmd := `Get-ScheduledTask | Select-Object TaskName,TaskPath,State,Description,Author | ConvertTo-Json -Compress`

	result := utils.RunPowerShell(cmd)
	if !result.Success() || result.Output == "" {
		log.Printf("[WARN] Get-ScheduledTask failed or returned empty: %v, trying alternative method", result.Error)
		return c.collectTaskInfoAlternative()
	}

	output := strings.TrimSpace(result.Output)
	if output == "" || output == "null" || output == "[]" {
		log.Printf("[WARN] Get-ScheduledTask returned empty result, trying alternative method")
		return c.collectTaskInfoAlternative()
	}

	var taskRawList []struct {
		TaskName    string      `json:"TaskName"`
		TaskPath    string      `json:"TaskPath"`
		State       interface{} `json:"State"`
		Description string      `json:"Description"`
		Author      string      `json:"Author"`
	}

	if err := json.Unmarshal([]byte(output), &taskRawList); err != nil {
		var single struct {
			TaskName    string      `json:"TaskName"`
			TaskPath    string      `json:"TaskPath"`
			State       interface{} `json:"State"`
			Description string      `json:"Description"`
			Author      string      `json:"Author"`
		}
		if err2 := json.Unmarshal([]byte(output), &single); err2 == nil && single.TaskName != "" {
			taskRawList = []struct {
				TaskName    string      `json:"TaskName"`
				TaskPath    string      `json:"TaskPath"`
				State       interface{} `json:"State"`
				Description string      `json:"Description"`
				Author      string      `json:"Author"`
			}{single}
		} else {
			log.Printf("[WARN] Failed to parse task JSON: %v", err)
			return c.collectTaskInfoAlternative()
		}
	}

	parseCount := 0
	for _, taskRaw := range taskRawList {
		if taskRaw.TaskName == "" {
			continue
		}

		stateStr := fmt.Sprintf("%v", taskRaw.State)
		task := &types.ScheduledTask{
			Name:        taskRaw.TaskName,
			Path:        taskRaw.TaskPath,
			State:       stateStr,
			Description: taskRaw.Description,
			Author:      taskRaw.Author,
		}

		tasks = append(tasks, task)
		parseCount++
	}

	log.Printf("[INFO] Get-ScheduledTask parsed %d tasks", parseCount)

	if parseCount == 0 {
		return c.collectTaskInfoAlternative()
	}

	return tasks, nil
}

func (c *TaskInfoCollector) collectTaskInfoAlternative() ([]*types.ScheduledTask, error) {
	tasks := make([]*types.ScheduledTask, 0)

	cmd := `Get-ScheduledTask | Select-Object TaskName,TaskPath,State | ConvertTo-Json -Compress`

	log.Printf("[INFO] Collecting tasks with alternative command")

	result := utils.RunPowerShell(cmd)
	if !result.Success() || result.Output == "" {
		log.Printf("[INFO] Alternative scheduled task method also failed, trying schtasks")
		return c.collectTaskInfoSchtasks()
	}

	output := strings.TrimSpace(result.Output)
	if output == "" || output == "null" || strings.HasPrefix(output, "null") {
		return c.collectTaskInfoSchtasks()
	}

	var taskRawList []struct {
		TaskName string `json:"TaskName"`
		TaskPath string `json:"TaskPath"`
		State   string `json:"State"`
	}

	if err := json.Unmarshal([]byte(output), &taskRawList); err != nil {
		var single struct {
			TaskName string `json:"TaskName"`
			TaskPath string `json:"TaskPath"`
			State   string `json:"State"`
		}
		if err2 := json.Unmarshal([]byte(output), &single); err2 == nil && single.TaskName != "" {
			taskRawList = []struct {
				TaskName string `json:"TaskName"`
				TaskPath string `json:"TaskPath"`
				State   string `json:"State"`
			}{single}
		}
	}

	for _, taskRaw := range taskRawList {
		if taskRaw.TaskName == "" {
			continue
		}

		tasks = append(tasks, &types.ScheduledTask{
			Name: taskRaw.TaskName,
			Path: taskRaw.TaskPath,
			State: taskRaw.State,
		})
	}

	return tasks, nil
}

func (c *TaskInfoCollector) collectTaskInfoSchtasks() ([]*types.ScheduledTask, error) {
	tasks := make([]*types.ScheduledTask, 0)

	cmd := `schtasks /query /fo CSV /nh | ForEach-Object { $_ -replace '"', '' } | ForEach-Object { $parts = $_ -split ','; if ($parts.Length -ge 3) { [PSCustomObject]@{ TaskName = $parts[1]; TaskPath = $parts[0]; State = $parts[2] } | ConvertTo-Json -Compress } }`

	log.Printf("[INFO] Collecting tasks with schtasks command")

	result := utils.RunPowerShell(cmd)
	if !result.Success() || result.Output == "" {
		log.Printf("[WARN] schtasks method also failed: %v", result.Error)
		return tasks, nil
	}

	output := strings.TrimSpace(result.Output)
	if output == "" || output == "null" {
		return tasks, nil
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "null" || !strings.Contains(line, "TaskName") {
			continue
		}

		var taskRaw struct {
			TaskName string      `json:"TaskName"`
			TaskPath string      `json:"TaskPath"`
			State    interface{} `json:"State"`
		}

		if err := json.Unmarshal([]byte(line), &taskRaw); err != nil {
			continue
		}

		if taskRaw.TaskName == "" {
			continue
		}

		stateStr := fmt.Sprintf("%v", taskRaw.State)
		tasks = append(tasks, &types.ScheduledTask{
			Name:  taskRaw.TaskName,
			Path:  taskRaw.TaskPath,
			State: stateStr,
		})
	}

	log.Printf("[INFO] schtasks method parsed %d tasks", len(tasks))
	return tasks, nil
}

func (c *TaskInfoCollector) getTaskActions(taskName, taskPath string) []string {
	cmd := fmt.Sprintf(`Get-ScheduledTask -TaskName '%s' -TaskPath '%s' | Get-ScheduledTaskInfo | Select-Object -ExpandProperty Actions | ConvertTo-Json -Compress`, taskName, taskPath)

	result := utils.RunPowerShell(cmd)
	if !result.Success() {
		return []string{}
	}

	var actions []struct {
		Execute string `json:"Execute"`
	}

	if err := json.Unmarshal([]byte(result.Output), &actions); err != nil {
		return []string{}
	}

	cmds := make([]string, 0, len(actions))
	for _, a := range actions {
		if a.Execute != "" {
			cmds = append(cmds, a.Execute)
		}
	}

	return cmds
}

func (c *TaskInfoCollector) getTaskLastRunTime(taskName, taskPath string) time.Time {
	cmd := fmt.Sprintf(`(Get-ScheduledTask -TaskName '%s' -TaskPath '%s' -ErrorAction SilentlyContinue | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue).LastRunTime`, taskName, taskPath)

	result := utils.RunPowerShell(cmd)
	if result.Success() && strings.TrimSpace(result.Output) != "" && !strings.Contains(result.Output, "never") {
		output := strings.TrimSpace(result.Output)
		timeFormats := []string{
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05Z",
			"2006-01-02T15:04:05.0000000Z",
			"1/2/2006 3:04:05 PM",
			time.RFC3339,
		}
		for _, format := range timeFormats {
			if t, err := time.Parse(format, output); err == nil {
				return t
			}
		}
	}

	return time.Time{}
}

func (c *TaskInfoCollector) getTaskNextRunTime(taskName, taskPath string) time.Time {
	cmd := fmt.Sprintf(`(Get-ScheduledTask -TaskName '%s' -TaskPath '%s' -ErrorAction SilentlyContinue | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue).NextRunTime`, taskName, taskPath)

	result := utils.RunPowerShell(cmd)
	if result.Success() && strings.TrimSpace(result.Output) != "" && !strings.Contains(result.Output, "NA") && !strings.Contains(result.Output, "Disabled") {
		output := strings.TrimSpace(result.Output)
		timeFormats := []string{
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05Z",
			"2006-01-02T15:04:05.0000000Z",
			"1/2/2006 3:04:05 PM",
			time.RFC3339,
		}
		for _, format := range timeFormats {
			if t, err := time.Parse(format, output); err == nil {
				return t
			}
		}
	}

	return time.Time{}
}

func ListScheduledTasks() ([]ScheduledTaskInfo, error) {
	tasks := make([]ScheduledTaskInfo, 0)

	cmd := `$tasks = Get-ScheduledTask | ForEach-Object {
		$info = $null
		try {
			$info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction Stop
		} catch {}
		$action = if($_.Actions) { ($_.Actions | Select-Object -First 1).Execute } else { '' }
		$trigger = if($_.Triggers) { ($_.Triggers | Select-Object -First 1).CimClass.Name -replace 'MSFT_Task(.*)Trigger','$1' } else { '' }
		[PSCustomObject]@{
			TaskName = $_.TaskName
			TaskPath = $_.TaskPath
			State = $_.State.ToString()
			Description = $_.Description
			Author = $_.Author
			NextRunTime = if($info -and $info.NextRunTime) { $info.NextRunTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
			LastRunTime = if($info -and $info.LastRunTime) { $info.LastRunTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
			LastResult = if($info) { $info.LastTaskResult } else { 0 }
			RunAsUser = if($_.Principal) { $_.Principal.UserId } else { '' }
			Action = $action
			TriggerType = $trigger
		}
	}
	$tasks | ConvertTo-Json -Depth 3 -Compress`

	log.Printf("[INFO] Collecting scheduled tasks with optimized pipeline")

	result := utils.RunPowerShellWithTimeout(cmd, 180*time.Second)
	if !result.Success() {
		log.Printf("[ERROR] Get-ScheduledTask failed: %v", result.Error)
		return tasks, result.Error
	}

	output := strings.TrimSpace(result.Output)
	if output == "" {
		log.Printf("[WARN] Get-ScheduledTask returned empty result")
		return tasks, nil
	}

	log.Printf("[DEBUG] Get-ScheduledTask raw output length: %d", len(output))

	if strings.HasPrefix(output, "[") {
		var taskRawList []struct {
			TaskName    string      `json:"TaskName"`
			TaskPath    string      `json:"TaskPath"`
			State       interface{} `json:"State"`
			Description string      `json:"Description"`
			Author      string      `json:"Author"`
			NextRunTime string      `json:"NextRunTime"`
			LastRunTime string      `json:"LastRunTime"`
			LastResult  int         `json:"LastResult"`
			RunAsUser   string      `json:"RunAsUser"`
			Action      string      `json:"Action"`
			TriggerType string      `json:"TriggerType"`
		}
		if err := json.Unmarshal([]byte(output), &taskRawList); err != nil {
			log.Printf("[WARN] Failed to parse task JSON array: %v", err)
		} else {
			for _, taskRaw := range taskRawList {
				stateStr := fmt.Sprintf("%v", taskRaw.State)
				tasks = append(tasks, ScheduledTaskInfo{
					TaskName:    taskRaw.TaskName,
					TaskPath:    taskRaw.TaskPath,
					State:       stateStr,
					Description: taskRaw.Description,
					Author:      taskRaw.Author,
					NextRunTime: taskRaw.NextRunTime,
					LastRunTime: taskRaw.LastRunTime,
					LastResult:  taskRaw.LastResult,
					RunAsUser:   taskRaw.RunAsUser,
					Action:      taskRaw.Action,
					TriggerType: taskRaw.TriggerType,
				})
			}
			log.Printf("[INFO] Get-ScheduledTask parsed %d tasks from JSON array", len(taskRawList))
			return tasks, nil
		}
	}

	lines := strings.Split(output, "\n")
	parseCount := 0
	errorCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "null" || line == "[]" {
			continue
		}

		var taskRaw struct {
			TaskName    string      `json:"TaskName"`
			TaskPath    string      `json:"TaskPath"`
			State       interface{} `json:"State"`
			Description string      `json:"Description"`
			Author      string      `json:"Author"`
			NextRunTime string      `json:"NextRunTime"`
			LastRunTime string      `json:"LastRunTime"`
			LastResult  int         `json:"LastResult"`
			RunAsUser   string      `json:"RunAsUser"`
			Action      string      `json:"Action"`
			TriggerType string      `json:"TriggerType"`
		}

		if err := json.Unmarshal([]byte(line), &taskRaw); err != nil {
			log.Printf("[WARN] Failed to parse task JSON: %v, line: %s", err, line)
			errorCount++
			continue
		}

		stateStr := fmt.Sprintf("%v", taskRaw.State)
		tasks = append(tasks, ScheduledTaskInfo{
			TaskName:    taskRaw.TaskName,
			TaskPath:    taskRaw.TaskPath,
			State:       stateStr,
			Description: taskRaw.Description,
			Author:      taskRaw.Author,
			NextRunTime: taskRaw.NextRunTime,
			LastRunTime: taskRaw.LastRunTime,
			LastResult:  taskRaw.LastResult,
			RunAsUser:   taskRaw.RunAsUser,
			Action:      taskRaw.Action,
			TriggerType: taskRaw.TriggerType,
		})
		parseCount++
	}

	log.Printf("[INFO] Get-ScheduledTask parsed %d tasks, %d errors", parseCount, errorCount)

	return tasks, nil
}

func GetTaskInfo(taskName string) (*ScheduledTaskInfo, error) {
	cmd := `Get-ScheduledTask -TaskName '%s' -ErrorAction SilentlyContinue | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue | ConvertTo-Json -Compress`

	result := utils.RunPowerShell(cmd)
	if !result.Success() {
		return nil, result.Error
	}

	var taskRaw struct {
		TaskName    string      `json:"TaskName"`
		TaskPath    string      `json:"TaskPath"`
		State       interface{} `json:"State"`
		Description string      `json:"Description"`
		Author      string      `json:"Author"`
	}

	if err := json.Unmarshal([]byte(result.Output), &taskRaw); err != nil {
		return nil, err
	}

	stateStr := fmt.Sprintf("%v", taskRaw.State)
	return &ScheduledTaskInfo{
		TaskName:    taskRaw.TaskName,
		TaskPath:    taskRaw.TaskPath,
		State:       stateStr,
		Description: taskRaw.Description,
	}, nil
}

func IsTaskRunning(taskName string) bool {
	cmd := `(Get-ScheduledTask -TaskName '%s' -ErrorAction SilentlyContinue | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue).State -eq 'Running'`

	result := utils.RunPowerShell(cmd)
	return result.Success() && strings.Contains(strings.ToLower(result.Output), "true")
}

func GetTaskLastRunTime(taskName string) (time.Time, error) {
	cmd := `(Get-ScheduledTask -TaskName '%s' -ErrorAction SilentlyContinue | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue).LastRunTime`

	result := utils.RunPowerShell(cmd)
	if !result.Success() {
		return time.Time{}, result.Error
	}

	return time.Parse("2006-01-02 15:04:05", strings.TrimSpace(result.Output))
}

func GetTaskNextRunTime(taskName string) (time.Time, error) {
	cmd := `(Get-ScheduledTask -TaskName '%s' -ErrorAction SilentlyContinue | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue).NextRunTime`

	result := utils.RunPowerShell(cmd)
	if !result.Success() {
		return time.Time{}, result.Error
	}

	return time.Parse("2006-01-02 15:04:05", strings.TrimSpace(result.Output))
}
