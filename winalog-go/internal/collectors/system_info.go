//go:build windows

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type SystemInfoCollector struct {
	BaseCollector
}

func NewSystemInfoCollector() *SystemInfoCollector {
	return &SystemInfoCollector{
		BaseCollector: BaseCollector{
			info: CollectorInfo{
				Name:          "system_info",
				Description:   "Collect system information",
				RequiresAdmin: false,
				Version:       "1.0.0",
			},
		},
	}
}

func (c *SystemInfoCollector) Collect(ctx context.Context) ([]interface{}, error) {
	info := c.collectSystemInfo()
	return []interface{}{info}, nil
}

func (c *SystemInfoCollector) collectSystemInfo() *types.SystemInfo {
	info := &types.SystemInfo{}

	info.Hostname, _ = os.Hostname()
	info.LocalTime = time.Now()
	info.OSName = runtime.GOOS
	info.Architecture = runtime.GOARCH

	if runtime.GOOS == "windows" {
		c.collectWindowsInfo(info)
	} else {
		c.collectLinuxInfo(info)
	}

	return info
}

func (c *SystemInfoCollector) collectWindowsInfo(info *types.SystemInfo) {
	result := collectAllSystemInfo()

	if winVersion, err := utils.GetWindowsVersion(); err == nil {
		info.OSVersion = fmt.Sprintf("Windows %d.%d (Build %d)",
			winVersion.Major, winVersion.Minor, winVersion.Build)
		if winVersion.CSDVersion != "" {
			info.OSVersion += " " + winVersion.CSDVersion
		}
	}

	info.Domain = result.Domain
	info.Uptime = result.Uptime
	info.BootTime = time.Now().Add(-result.Uptime)
	info.TimeZone = result.TimeZone
	info.CPUCores = result.CPUCores
	info.CPUModel = result.CPUModel
	info.MemoryTotal = result.MemoryTotal
	info.MemoryFree = result.MemoryFree

	info.Admin = utils.IsAdmin()
}

type windowsSystemInfo struct {
	Domain      string
	Uptime      time.Duration
	TimeZone    string
	CPUCores    int
	CPUModel    string
	MemoryTotal uint64
	MemoryFree  uint64
}

func collectAllSystemInfo() windowsSystemInfo {
	cmd := `(Get-CimInstance Win32_OperatingSystem | Select-Object Domain, LastBootUpTime, TotalVisibleMemorySize, FreePhysicalMemory | ConvertTo-Json -Compress) + "|||" + (Get-CimInstance Win32_Processor | Select-Object NumberOfCores, Name | ConvertTo-Json -Compress) + "|||" + (Get-TimeZone | Select-Object Id, DisplayName, BaseUtcOffset | ConvertTo-Json -Compress)`

	result := utils.RunPowerShell(cmd)
	info := windowsSystemInfo{
		CPUCores: runtime.NumCPU(),
	}

	if result.Success() && result.Output != "" {
		parts := strings.Split(result.Output, "|||")
		if len(parts) >= 1 {
			var osRaw struct {
				Domain                string `json:"Domain"`
				LastBootUpTime        string `json:"LastBootUpTime"`
				TotalVisibleMemorySize int64 `json:"TotalVisibleMemorySize"`
				FreePhysicalMemory    int64 `json:"FreePhysicalMemory"`
			}
			if err := json.Unmarshal([]byte(parts[0]), &osRaw); err == nil {
				info.Domain = osRaw.Domain
				info.MemoryTotal = uint64(osRaw.TotalVisibleMemorySize) * 1024
				info.MemoryFree = uint64(osRaw.FreePhysicalMemory) * 1024

				info.Uptime = parseUptimeWithTimezone(osRaw.LastBootUpTime)
			}
		}
		if len(parts) >= 2 {
			var cpuRaw struct {
				NumberOfCores int    `json:"NumberOfCores"`
				Name         string `json:"Name"`
			}
			if err := json.Unmarshal([]byte(parts[1]), &cpuRaw); err == nil {
				if cpuRaw.NumberOfCores > 0 {
					info.CPUCores = cpuRaw.NumberOfCores
				}
				info.CPUModel = cpuRaw.Name
			}
		}
		if len(parts) >= 3 {
			var tzRaw struct {
				Id          string `json:"Id"`
				DisplayName string `json:"DisplayName"`
				BaseUtcOffset string `json:"BaseUtcOffset"`
			}
			if err := json.Unmarshal([]byte(parts[2]), &tzRaw); err == nil {
				info.TimeZone = fmt.Sprintf("%s (%s, %s)", tzRaw.Id, tzRaw.DisplayName, tzRaw.BaseUtcOffset)
			}
		}
	}

	if info.MemoryTotal == 0 {
		info.TimeZone = getTimeZoneFallback()
		info.Uptime = getUptimeFallback()
	}

	return info
}

func parseUptimeWithTimezone(lastBootStr string) time.Duration {
	formats := []string{
		"20060102150405.000000-000",
		"20060102150405.000000+000",
		"20060102150405.000000+480",
		"20060102150405.000000-480",
		"2006-01-02 15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, lastBootStr); err == nil {
			return time.Since(t)
		}
	}
	return 0
}

func getTimeZoneFallback() string {
	cmd := `Get-TimeZone | Select-Object -ExpandProperty Id`
	result := utils.RunPowerShell(cmd)
	if result.Success() {
		return strings.TrimSpace(result.Output)
	}
	return "Unknown"
}

func getUptimeFallback() time.Duration {
	cmd := `(Get-CimInstance Win32_OperatingSystem).LastBootUpTime`
	result := utils.RunPowerShell(cmd)
	if !result.Success() {
		return 0
	}
	return parseUptimeWithTimezone(strings.TrimSpace(result.Output))
}

func (c *SystemInfoCollector) collectLinuxInfo(info *types.SystemInfo) {
	info.OSVersion = "Linux"

	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		var uptimeSeconds float64
		fmt.Sscanf(string(data), "%f", &uptimeSeconds)
		info.Uptime = time.Duration(uptimeSeconds) * time.Second
		info.BootTime = time.Now().Add(-info.Uptime)
	}

	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		var memTotal, memFree int64
		for _, line := range lines {
			var key string
			var value int64
			if n, _ := fmt.Sscanf(line, "%s %d", &key, &value); n == 2 {
				if key == "MemTotal:" {
					memTotal = value * 1024
				} else if key == "MemAvailable:" {
					memFree = value * 1024
				}
			}
		}
		info.MemoryTotal = uint64(memTotal)
		info.MemoryFree = uint64(memFree)
	}

	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		var modelName string
		var coreCount int
		for _, line := range lines {
			if strings.HasPrefix(line, "processor") {
				coreCount++
			}
			if strings.HasPrefix(line, "model name") {
				parts := strings.Split(line, ":")
				if len(parts) == 2 {
					modelName = strings.TrimSpace(parts[1])
				}
			}
		}
		info.CPUCores = coreCount
		info.CPUModel = modelName
	}
}

func getComputerDomain() (string, error) {
	cmd := `(Get-CimInstance Win32_ComputerSystem).Domain`
	result := utils.RunPowerShell(cmd)
	if result.Success() {
		return strings.TrimSpace(result.Output), nil
	}
	return "", result.Error
}

func getSystemUptime() (time.Duration, error) {
	cmd := `(Get-CimInstance Win32_OperatingSystem).LastBootUpTime`
	result := utils.RunPowerShell(cmd)
	if !result.Success() {
		return 0, result.Error
	}

	lastBootStr := strings.TrimSpace(result.Output)
	return parseUptimeWithTimezone(lastBootStr), nil
}

func getTimeZone() string {
	cmd := `Get-TimeZone | Select-Object Id, DisplayName, BaseUtcOffset | ConvertTo-Json -Compress`
	result := utils.RunPowerShell(cmd)
	if result.Success() && result.Output != "" {
		var tzRaw struct {
			Id          string `json:"Id"`
			DisplayName string `json:"DisplayName"`
			BaseUtcOffset string `json:"BaseUtcOffset"`
		}
		if err := json.Unmarshal([]byte(result.Output), &tzRaw); err == nil {
			return fmt.Sprintf("%s (%s, %s)", tzRaw.Id, tzRaw.DisplayName, tzRaw.BaseUtcOffset)
		}
	}
	return "Unknown"
}

func getCPUInfo() (int, string) {
	cmd := `Get-CimInstance Win32_Processor | Select-Object NumberOfCores, Name | ConvertTo-Json -Compress`
	result := utils.RunPowerShell(cmd)
	if !result.Success() {
		return runtime.NumCPU(), ""
	}

	var cpuRaw struct {
		NumberOfCores int    `json:"NumberOfCores"`
		Name          string `json:"Name"`
	}

	if err := json.Unmarshal([]byte(result.Output), &cpuRaw); err != nil {
		return runtime.NumCPU(), ""
	}

	return cpuRaw.NumberOfCores, cpuRaw.Name
}

func getMemoryInfo() (uint64, uint64) {
	cmd := `Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory | ConvertTo-Json -Compress`
	result := utils.RunPowerShell(cmd)
	if !result.Success() {
		return 0, 0
	}

	var memRaw struct {
		TotalVisibleMemorySize int64 `json:"TotalVisibleMemorySize"`
		FreePhysicalMemory     int64 `json:"FreePhysicalMemory"`
	}

	if err := json.Unmarshal([]byte(result.Output), &memRaw); err != nil {
		return 0, 0
	}

	total := uint64(memRaw.TotalVisibleMemorySize) * 1024
	free := uint64(memRaw.FreePhysicalMemory) * 1024
	return total, free
}

func (c *SystemInfoCollector) getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func (c *SystemInfoCollector) getBootTime() (time.Time, error) {
	uptime, err := getSystemUptime()
	if err != nil {
		return time.Time{}, err
	}
	return time.Now().Add(-uptime), nil
}

func CollectSystemInfo(ctx context.Context) (*types.SystemInfo, error) {
	collector := NewSystemInfoCollector()
	results, err := collector.Collect(ctx)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, nil
	}
	return results[0].(*types.SystemInfo), nil
}
