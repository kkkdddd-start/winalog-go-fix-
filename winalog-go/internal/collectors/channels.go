package collectors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type LogChannelInfo struct {
	Name        string `json:"name"`
	LogPath     string `json:"log_path"`
	IsEVTX      bool   `json:"is_evtx"`
	FileExists  bool   `json:"file_exists"`
	FileSize    int64  `json:"file_size"`
	LastWriteTime string `json:"last_write_time"`
}

type LogFileInfo struct {
	Name        string `json:"name"`
	LogPath     string `json:"log_path"`
	FileSize    int64  `json:"file_size"`
	LastWriteTime string `json:"last_write_time"`
}

func GetLogFiles() ([]LogFileInfo, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", `
		[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
		$results = @()

		$logDir = "$env:SystemRoot\System32\winevt\Logs"
		if (Test-Path $logDir) {
			Get-ChildItem $logDir -Filter "*.evtx" -ErrorAction SilentlyContinue | ForEach-Object {
				$results += @{
					Name = $_.BaseName
					LogPath = $_.FullName
					FileSize = $_.Length
					LastWriteTime = $_.LastWriteTime.ToString("o")
				}
			}
		}

		$results | ConvertTo-Json -Compress
	`)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil

	var logFiles []LogFileInfo
	output := out.String()

	output = strings.TrimSpace(output)
	if output == "" || output == "null" || output == "[]" {
		return getLogFilesFallback()
	}

	var jsonData []map[string]interface{}
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &jsonData); err != nil {
			return getLogFilesFallback()
		}
	} else if strings.HasPrefix(output, "{") {
		var item map[string]interface{}
		if err := json.Unmarshal([]byte(output), &item); err != nil {
			return getLogFilesFallback()
		}
		jsonData = append(jsonData, item)
	}

	for _, item := range jsonData {
		name, _ := item["Name"].(string)
		logPath, _ := item["LogPath"].(string)

		if name == "" || logPath == "" {
			continue
		}

		decodedName := name
		decodedName = strings.ReplaceAll(decodedName, "%2F", "/")
		decodedName = strings.ReplaceAll(decodedName, "%4", "/")
		decodedLogPath := logPath
		decodedLogPath = strings.ReplaceAll(decodedLogPath, "%2F", "/")
		decodedLogPath = strings.ReplaceAll(decodedLogPath, "%4", "/")

		var fileSize int64
		if fs, ok := item["FileSize"].(float64); ok {
			fileSize = int64(fs)
		}

		lastWriteTime := ""
		if lwt, ok := item["LastWriteTime"].(string); ok {
			lastWriteTime = lwt
		}

		logFiles = append(logFiles, LogFileInfo{
			Name:         decodedName,
			LogPath:      decodedLogPath,
			FileSize:     fileSize,
			LastWriteTime: lastWriteTime,
		})
	}

	if len(logFiles) == 0 {
		return getLogFilesFallback()
	}

	return logFiles, nil
}

func getLogFilesFallback() ([]LogFileInfo, error) {
	logDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "winevt", "Logs")

	entries, err := os.ReadDir(logDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read log directory: %w", err)
	}

	var logFiles []LogFileInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".evtx") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		channelName := strings.TrimSuffix(name, ".evtx")
		channelName = strings.ReplaceAll(channelName, "%2F", "/")
		channelName = strings.ReplaceAll(channelName, "%4", "/")

		logFiles = append(logFiles, LogFileInfo{
			Name:         channelName,
			LogPath:      filepath.Join(logDir, name),
			FileSize:     info.Size(),
			LastWriteTime: info.ModTime().Format("o"),
		})
	}

	return logFiles, nil
}

func GetLogFilesDetailed() ([]LogFileInfo, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", `
		[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
		$results = @()

		function Get-FileDetails($path) {
			if (Test-Path $path) {
				$file = Get-Item $path
				return @{
					Exists = $true
					Size = $file.Length
					LastWrite = $file.LastWriteTime.ToString("o")
				}
			}
			return @{ Exists = $false; Size = 0; LastWrite = "" }
		}

		$logDir = "$env:SystemRoot\System32\winevt\Logs"

		$logFiles = @{}
		if (Test-Path $logDir) {
			Get-ChildItem $logDir -Filter "*.evtx" -ErrorAction SilentlyContinue | ForEach-Object {
				$details = Get-FileDetails $_.FullName
				$logFiles[$_.BaseName] = @{
					Name = $_.BaseName
					LogPath = $_.FullName
					FileSize = $details.Size
					LastWriteTime = $details.LastWrite
				}
			}
		}

		$legacyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog"
		if (Test-Path $legacyPath) {
			Get-ChildItem $legacyPath -ErrorAction SilentlyContinue | ForEach-Object {
				$logName = $_.PSChildName
				$filePath = (Get-ItemProperty $_.PSPath -Name "File" -ErrorAction SilentlyContinue).File
				if ($filePath) {
					$resolvedPath = [System.Environment]::ExpandEnvironmentVariables($filePath)
					$details = Get-FileDetails $resolvedPath
					$baseName = [System.IO.Path]::GetFileNameWithoutExtension($resolvedPath)
					if (-not $logFiles.ContainsKey($baseName)) {
						$logFiles[$baseName] = @{
							Name = $logName
							LogPath = $resolvedPath
							FileSize = $details.Size
							LastWriteTime = $details.LastWrite
						}
					}
				}
			}
		}

		$logFiles.Values | ConvertTo-Json -Compress
	`)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return getLogFilesFallback()
	}

	output := out.String()
	output = strings.TrimSpace(output)
	if output == "" || output == "null" || output == "[]" {
		return getLogFilesFallback()
	}

	var jsonData []map[string]interface{}
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &jsonData); err != nil {
			return getLogFilesFallback()
		}
	} else if strings.HasPrefix(output, "{") {
		var item map[string]interface{}
		if err := json.Unmarshal([]byte(output), &item); err != nil {
			return getLogFilesFallback()
		}
		jsonData = append(jsonData, item)
	}

	var logFiles []LogFileInfo
	for _, item := range jsonData {
		name, _ := item["Name"].(string)
		logPath, _ := item["LogPath"].(string)

		if name == "" || logPath == "" {
			continue
		}

		decodedName := name
		decodedName = strings.ReplaceAll(decodedName, "%2F", "/")
		decodedName = strings.ReplaceAll(decodedName, "%4", "/")
		decodedLogPath := logPath
		decodedLogPath = strings.ReplaceAll(decodedLogPath, "%2F", "/")
		decodedLogPath = strings.ReplaceAll(decodedLogPath, "%4", "/")

		var fileSize int64
		if fs, ok := item["FileSize"].(float64); ok {
			fileSize = int64(fs)
		}

		lastWriteTime := ""
		if lwt, ok := item["LastWriteTime"].(string); ok {
			lastWriteTime = lwt
		}

		logFiles = append(logFiles, LogFileInfo{
			Name:         decodedName,
			LogPath:      decodedLogPath,
			FileSize:     fileSize,
			LastWriteTime: lastWriteTime,
		})
	}

	if len(logFiles) == 0 {
		return getLogFilesFallback()
	}

	return logFiles, nil
}

func GetChannelFilePaths() ([]LogChannelInfo, error) {
	logFiles, err := GetLogFiles()
	if err != nil {
		return nil, err
	}

	var channels []LogChannelInfo
	for _, f := range logFiles {
		channels = append(channels, LogChannelInfo{
			Name:    f.Name,
			LogPath: f.LogPath,
			IsEVTX:  strings.HasSuffix(strings.ToLower(f.LogPath), ".evtx"),
		})
	}

	return channels, nil
}

func GetChannelFilePathsFallback() ([]LogChannelInfo, error) {
	logDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "winevt", "Logs")

	entries, err := os.ReadDir(logDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read log directory: %w", err)
	}

	var channels []LogChannelInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".evtx") {
			continue
		}

		channelName := strings.TrimSuffix(name, ".evtx")
		channelName = strings.ReplaceAll(channelName, "%2F", "/")
		channelName = strings.ReplaceAll(channelName, "%4", "/")

		channels = append(channels, LogChannelInfo{
			Name:    channelName,
			LogPath: filepath.Join(logDir, name),
			IsEVTX:  true,
		})
	}

	return channels, nil
}

func parseChannelFilePaths(output string) ([]LogChannelInfo, error) {
	var channels []LogChannelInfo

	output = strings.TrimSpace(output)
	if output == "" || output == "null" {
		return GetChannelFilePathsFallback()
	}

	var jsonData []map[string]interface{}
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &jsonData); err != nil {
			return GetChannelFilePathsFallback()
		}
	} else if strings.HasPrefix(output, "{") {
		var item map[string]interface{}
		if err := json.Unmarshal([]byte(output), &item); err != nil {
			return GetChannelFilePathsFallback()
		}
		jsonData = append(jsonData, item)
	} else {
		return GetChannelFilePathsFallback()
	}

	for _, item := range jsonData {
		name, _ := item["Name"].(string)
		logPath, _ := item["LogPath"].(string)
		isEVTX, _ := item["IsEVTX"].(bool)

		if name != "" && logPath != "" {
			decodedName := name
			decodedName = strings.ReplaceAll(decodedName, "%2F", "/")
			decodedName = strings.ReplaceAll(decodedName, "%4", "/")
			decodedLogPath := logPath
			decodedLogPath = strings.ReplaceAll(decodedLogPath, "%2F", "/")
			decodedLogPath = strings.ReplaceAll(decodedLogPath, "%4", "/")
			decodedLogPath = strings.ReplaceAll(decodedLogPath, "/", "\\")
			channels = append(channels, LogChannelInfo{
				Name:    decodedName,
				LogPath: decodedLogPath,
				IsEVTX:  isEVTX,
			})
		}
	}

	if len(channels) == 0 {
		return GetChannelFilePathsFallback()
	}

	return channels, nil
}

func GetRegisteredChannels() ([]string, error) {
	cmd := `Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 } | Select-Object -First 200 -ExpandProperty LogName`

	result := utils.RunPowerShell(cmd)
	if !result.Success() {
		return nil, fmt.Errorf("failed to get channels: %v", result.Error)
	}

	lines := strings.Split(strings.TrimSpace(result.Output), "\n")
	var channels []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			channels = append(channels, line)
		}
	}

	return channels, nil
}

// CategorizeChannel 分类日志通道
func CategorizeChannel(name string) string {
	switch {
	case matchRegex(`^(?i)Security$`, name):
		return "Windows Event Logs"
	case matchRegex(`^(?i)System$`, name):
		return "Windows Event Logs"
	case matchRegex(`^(?i)Application$`, name):
		return "Windows Event Logs"
	case matchRegex(`^(?i)Setup$`, name):
		return "Windows Event Logs"
	case matchRegex(`(?i)Sysmon`, name):
		return "Sysmon"
	case matchRegex(`(?i)PowerShell`, name):
		return "PowerShell"
	case matchRegex(`(?i)WMI-Activity`, name):
		return "WMI"
	case matchRegex(`(?i)TaskScheduler`, name):
		return "Task Scheduler"
	case matchRegex(`(?i)^Microsoft-Windows-`, name):
		return "Microsoft Windows"
	default:
		return "Other"
	}
}

func matchRegex(pattern, s string) bool {
	pattern = strings.Trim(pattern, "^$")
	var re *regexp.Regexp
	var err error
	if strings.HasPrefix(pattern, "(?i)") {
		pattern = strings.TrimPrefix(pattern, "(?i)")
		re, err = regexp.Compile("(?i)" + pattern)
	} else {
		re, err = regexp.Compile(pattern)
	}
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

// isFormatEnabled 检查格式是否启用
func isFormatEnabled(formats []string, format string) bool {
	for _, f := range formats {
		if f == format {
			return true
		}
	}
	return false
}

// shouldExcludeChannel 检查是否应该排除通道
func shouldExcludeChannel(channel string, excludePatterns []string) bool {
	for _, pattern := range excludePatterns {
		if strings.Contains(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(channel, prefix) {
				return true
			}
		} else if channel == pattern {
			return true
		}
	}
	return false
}
