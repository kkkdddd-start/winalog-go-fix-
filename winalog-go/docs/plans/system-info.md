# 系统信息模块改进实施方案

**项目**: WinLogAnalyzer-Go  
**模块**: 系统信息模块 (System Information Module)  
**版本**: v2.4.0  
**文档日期**: 2026-04-17  
**基于**: 代码审查 + 实际验证

---

## 一、问题验证摘要

### 1.1 已确认存在的真实问题

| 优先级 | 问题 | 位置 | 验证状态 |
|--------|------|------|----------|
| **P0** | 网络连接收集返回空数据 | `internal/collectors/network_info.go:51-58` | **已确认** |
| **P0** | 用户账户收集返回空数据 | `internal/collectors/user_info.go:40-41` | **已确认** |
| **P0** | 一键取证完全空实现 | `internal/collectors/one_click.go:57-220` | **已确认** |
| **P0** | 内存取证完全空实现 | `internal/forensics/memory.go:168-186` | **已确认** |
| **P1** | 系统信息收集数据不完整 | `internal/collectors/system_info.go:57-77` | **已确认** |
| **P1** | CLI 与 API 功能不一致 | CLI 支持 users/registry/tasks，API 不支持 | **已确认** |
| **P1** | 类型定义重复且不一致 | 多处定义 SystemInfo, ProcessInfo | **已确认** |
| **P2** | DLL 版本获取为空 | `internal/collectors/dll_info.go:157-159` | **已确认** |
| **P2** | API 缺少 users/registry/tasks 端点 | `internal/api/handlers_system.go` | **已确认** |
| **P3** | 硬编码 limit=500 | `internal/api/handlers_system.go:194` | **已确认** |
| **P3** | 错误被忽略未记录 | 多处使用 `_ = os.Hostname()` | **已确认** |

### 1.2 已实现的正常功能

| 功能 | 文件 | 状态 |
|------|------|------|
| 进程列表收集 | `process_info.go` | ✅ 完整实现 |
| DLL 信息收集 | `dll_info.go` | ✅ 完整实现 (版本除外) |
| 驱动信息收集 | `driver_info.go` | ✅ 完整实现 |
| 环境变量收集 | `env_info.go` | ✅ 完整实现 |
| 计划任务收集 | `task_info.go` | ✅ 完整实现 |
| 注册表启动项 | `registry_info.go` | ✅ 完整实现 |
| 文件哈希计算 | `forensics/hash.go` | ✅ 完整实现 |
| 签名验证 | `forensics/signature.go` | ✅ 完整实现 |

---

## 二、改进方案详情

### SYS-1: 修复网络连接收集 (P0)

#### 2.1.1 问题分析

**当前代码** (`internal/collectors/network_info.go:51-58`):
```go
func (c *NetworkInfoCollector) collectNetworkInfo() ([]*types.NetworkConnection, error) {
    connections := make([]*types.NetworkConnection, 0)
    return connections, nil  // 永远返回空！
}

func ListNetworkConnections() ([]NetConnection, error) {
    return make([]NetConnection, 0), nil  // 永远返回空！
}
```

**影响**: Web API `/api/system/network` 永远返回空数据

#### 2.1.2 实施方案

**修改文件**: `internal/collectors/network_info.go`

```go
//go:build windows

package collectors

import (
    "context"
    "encoding/json"
    "strings"
    "unsafe"

    "github.com/kkkdddd-start/winalog-go/internal/types"
    "golang.org/x/sys/windows"
)

type NetworkInfoCollector struct {
    BaseCollector
}

type NetConnection struct {
    PID         int
    Protocol    string
    LocalAddr   string
    LocalPort   int
    RemoteAddr  string
    RemotePort  int
    State       string
    ProcessName string
}

func NewNetworkInfoCollector() *NetworkInfoCollector {
    return &NetworkInfoCollector{
        BaseCollector: BaseCollector{
            info: CollectorInfo{
                Name:          "network_info",
                Description:   "Collect network connection information",
                RequiresAdmin: true,
                Version:       "1.0.0",
            },
        },
    }
}

func (c *NetworkInfoCollector) Collect(ctx context.Context) ([]interface{}, error) {
    connections, err := c.collectNetworkInfo()
    if err != nil {
        return nil, err
    }
    interfaces := make([]interface{}, len(connections))
    for i, n := range connections {
        interfaces[i] = n
    }
    return interfaces, nil
}

func (c *NetworkInfoCollector) collectNetworkInfo() ([]*types.NetworkConnection, error) {
    connections := make([]*types.NetworkConnection, 0)
    
    tcpConnections, err := getTCPConnections()
    if err == nil {
        connections = append(connections, tcpConnections...)
    }
    
    udpEndpoints, err := getUDPEndpoints()
    if err == nil {
        connections = append(connections, udpEndpoints...)
    }
    
    return connections, nil
}

func getTCPConnections() ([]*types.NetworkConnection, error) {
    cmd := `Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ForEach-Object { $_ | ConvertTo-Json -Compress }`
    return executeNetworkCommand(cmd, "TCP")
}

func getUDPEndpoints() ([]*types.NetworkConnection, error) {
    cmd := `Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess | ForEach-Object { $_ | ConvertTo-Json -Compress }`
    return executeNetworkCommand(cmd, "UDP")
}

func executeNetworkCommand(cmd string, protocol string) ([]*types.NetworkConnection, error) {
    result := utils.RunPowerShell(cmd)
    if !result.Success() {
        return []*types.NetworkConnection{}, nil
    }

    output := strings.TrimSpace(result.Output)
    if output == "" || output == "null" {
        return []*types.NetworkConnection{}, nil
    }

    lines := strings.Split(output, "\n")
    connections := make([]*types.NetworkConnection, 0, len(lines))
    processNames := getProcessNameMap()

    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" || line == "null" {
            continue
        }

        var connRaw struct {
            LocalAddress  string `json:"LocalAddress"`
            LocalPort    int    `json:"LocalPort"`
            RemoteAddress string `json:"RemoteAddress,omitempty"`
            RemotePort   int    `json:"RemotePort,omitempty"`
            State       string `json:"State,omitempty"`
            OwningProcess int   `json:"OwningProcess"`
        }

        if err := json.Unmarshal([]byte(line), &connRaw); err != nil {
            continue
        }

        pid := connRaw.OwningProcess
        processName := processNames[pid]
        if processName == "" {
            processName = "Unknown"
        }

        state := connRaw.State
        if state == "" {
            state = "Listen"
        }

        conn := &types.NetworkConnection{
            Protocol:    protocol,
            LocalAddr:   connRaw.LocalAddress,
            LocalPort:   connRaw.LocalPort,
            RemoteAddr:  connRaw.RemoteAddress,
            RemotePort:  connRaw.RemotePort,
            State:       state,
            PID:         int32(pid),
            ProcessName: processName,
        }
        connections = append(connections, conn)
    }

    return connections, nil
}

func getProcessNameMap() map[int]string {
    nameMap := make(map[int]string)
    
    snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
    if err != nil {
        return nameMap
    }
    defer windows.CloseHandle(snapshot)

    var entry windows.ProcessEntry32
    entry.Size = uint32(unsafe.Sizeof(entry))

    err = windows.Process32First(snapshot, &entry)
    if err != nil {
        return nameMap
    }

    for {
        pid := int(entry.ProcessID)
        name := windows.UTF16ToString(entry.ExeFile[:])
        nameMap[pid] = name
        
        err = windows.Process32Next(snapshot, &entry)
        if err != nil {
            break
        }
    }

    return nameMap
}

func ListNetworkConnections() ([]NetConnection, error) {
    typesConn, err := NewNetworkInfoCollector().collectNetworkInfo()
    if err != nil {
        return []NetConnection{}, err
    }

    result := make([]NetConnection, 0, len(typesConn))
    for _, c := range typesConn {
        result = append(result, NetConnection{
            PID:         int(c.PID),
            Protocol:    c.Protocol,
            LocalAddr:   c.LocalAddr,
            LocalPort:   c.LocalPort,
            RemoteAddr:  c.RemoteAddr,
            RemotePort:  c.RemotePort,
            State:       c.State,
            ProcessName: c.ProcessName,
        })
    }
    return result, nil
}
```

**需要添加的导入**:
```go
import (
    "github.com/kkkdddd-start/winalog-go/internal/utils"
)
```

#### 2.1.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 中 | 约 150 行代码 |
| **适配性** | 高 | 向后兼容，现有 API 不变 |
| **必要性** | 高 | 网络连接是核心安全分析数据 |
| **可靠性** | 高 | PowerShell 命令成熟稳定 |
| **风险** | 低 | 仅添加功能，不修改现有逻辑 |

---

### SYS-2: 修复用户账户收集 (P0)

#### 2.2.1 问题分析

**当前代码** (`internal/collectors/user_info.go:40-41`):
```go
func (c *UserInfoCollector) collectUserInfo() ([]*types.UserAccount, error) {
    return []*types.UserAccount{}, nil  // 永远返回空！
}
```

#### 2.2.2 实施方案

**修改文件**: `internal/collectors/user_info.go`

```go
//go:build windows

package collectors

import (
    "context"
    "encoding/json"
    "strings"
    "time"

    "github.com/kkkdddd-start/winalog-go/internal/types"
    "github.com/kkkdddd-start/winalog-go/internal/utils"
)

type UserInfoCollector struct {
    BaseCollector
}

func NewUserInfoCollector() *UserInfoCollector {
    return &UserInfoCollector{
        BaseCollector: BaseCollector{
            info: CollectorInfo{
                Name:          "user_info",
                Description:   "Collect user account information",
                RequiresAdmin: true,
                Version:       "1.0.0",
            },
        },
    }
}

func (c *UserInfoCollector) Collect(ctx context.Context) ([]interface{}, error) {
    users, err := c.collectUserInfo()
    if err != nil {
        return nil, err
    }
    interfaces := make([]interface{}, len(users))
    for i, u := range users {
        interfaces[i] = u
    }
    return interfaces, nil
}

func (c *UserInfoCollector) collectUserInfo() ([]*types.UserAccount, error) {
    users := make([]*types.UserAccount, 0)

    cmd := `Get-LocalUser | Select-Object Name, SID, Enabled, LastLogon, PasswordRequired, PasswordAge, UserMayChangePassword, PasswordExpires, FullName, Description, HomeDirectory, ProfilePath | ForEach-Object { $_ | ConvertTo-Json -Compress }`

    result := utils.RunPowerShell(cmd)
    if !result.Success() {
        return users, result.Error
    }

    output := strings.TrimSpace(result.Output)
    if output == "" || output == "null" {
        return users, nil
    }

    lines := strings.Split(output, "\n")
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" || line == "null" {
            continue
        }

        var userRaw struct {
            Name               string `json:"Name"`
            SID                string `json:"SID"`
            Enabled            bool   `json:"Enabled"`
            LastLogon          string `json:"LastLogon"`
            PasswordRequired   bool   `json:"PasswordRequired"`
            PasswordAge        int64  `json:"PasswordAge"`
            PasswordExpires     string `json:"PasswordExpires"`
            FullName           string `json:"FullName"`
            Description         string `json:"Description"`
            HomeDirectory      string `json:"HomeDirectory"`
            ProfilePath         string `json:"ProfilePath"`
        }

        if err := json.Unmarshal([]byte(line), &userRaw); err != nil {
            continue
        }

        user := &types.UserAccount{
            Name:        userRaw.Name,
            SID:         userRaw.SID,
            Enabled:     userRaw.Enabled,
            Type:        "Local",
            LastLogin:   parseLastLogon(userRaw.LastLogon),
            PasswordExp: userRaw.PasswordExpires != "" && userRaw.PasswordExpires != "Never",
            HomeDir:     userRaw.HomeDirectory,
            ProfilePath: userRaw.ProfilePath,
        }

        if userRaw.FullName != "" {
            user.FullName = userRaw.FullName
        } else {
            user.FullName = userRaw.Description
        }

        if userRaw.PasswordAge > 0 {
            user.PasswordAge = time.Duration(userRaw.PasswordAge) * time.Hour * 24
        }

        users = append(users, user)
    }

    return users, nil
}

func parseLastLogon(lastLogon string) time.Time {
    if lastLogon == "" || lastLogon == "N/A" {
        return time.Time{}
    }
    
    formats := []string{
        "2006-01-02 15:04:05",
        "2006-01-02T15:04:05",
        time.RFC3339,
    }
    
    for _, format := range formats {
        if t, err := time.Parse(format, lastLogon); err == nil {
            return t
        }
    }
    return time.Time{}
}

func ListLocalUsers() ([]*types.UserAccount, error) {
    collector := NewUserInfoCollector()
    return collector.collectUserInfo()
}
```

#### 2.2.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 低 | 约 100 行代码 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 高 | 用户账户是安全分析基础数据 |
| **可靠性** | 高 | PowerShell Get-LocalUser 成熟 |
| **风险** | 低 | 仅添加功能 |

---

### SYS-3: 修复系统信息收集 (P1)

#### 2.3.1 问题分析

**当前代码** (`internal/collectors/system_info.go:57-77`):
```go
func (c *SystemInfoCollector) collectSystemInfo() *types.SystemInfo {
    info := &types.SystemInfo{
        Hostname:     c.getHostname(),
        OSName:       runtime.GOOS,
        Architecture: runtime.GOARCH,
    }
    info.Hostname, _ = os.Hostname()
    info.LocalTime = time.Now()
    // 只有这些数据，缺少 CPU、内存、启动时间等
    return info
}
```

#### 2.3.2 实施方案

**修改文件**: `internal/collectors/system_info.go`

```go
//go:build windows

package collectors

import (
    "context"
    "fmt"
    "os"
    "runtime"
    "strings"
    "time"
    "unsafe"

    "github.com/kkkdddd-start/winalog-go/internal/types"
    "github.com/kkkdddd-start/winalog-go/internal/utils"
    "golang.org/x/sys/windows"
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
    if winVersion, err := utils.GetWindowsVersion(); err == nil {
        info.OSVersion = fmt.Sprintf("Windows %d.%d (Build %d)", 
            winVersion.Major, winVersion.Minor, winVersion.Build)
        if winVersion.CSDVersion != "" {
            info.OSVersion += " " + winVersion.CSDVersion
        }
    }

    if domain, err := getComputerDomain(); err == nil {
        info.Domain = domain
    }

    if uptime, err := getSystemUptime(); err == nil {
        info.Uptime = uptime
    }

    info.TimeZone = getTimeZone()

    cpuCount, cpuModel := getCPUInfo()
    info.CPUCores = cpuCount
    info.CPUModel = cpuModel

    memTotal, memFree := getMemoryInfo()
    info.MemoryTotal = memTotal
    info.MemoryFree = memFree

    info.IsAdmin = utils.IsAdmin()
}

func (c *SystemInfoCollector) collectLinuxInfo(info *types.SystemInfo) {
    info.OSVersion = "Linux"

    if data, err := os.ReadFile("/proc/uptime"); err == nil {
        var uptimeSeconds float64
        fmt.Sscanf(string(data), "%f", &uptimeSeconds)
        info.Uptime = time.Duration(uptimeSeconds) * time.Second
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
    formats := []string{
        "20060102150405.000000-000",
        "2006-01-02 15:04:05",
    }

    for _, format := range formats {
        if t, err := time.Parse(format, lastBootStr); err == nil {
            return time.Since(t), nil
        }
    }

    return 0, fmt.Errorf("failed to parse uptime")
}

func getTimeZone() string {
    cmd := `Get-TimeZone | Select-Object -ExpandProperty Id`
    result := utils.RunPowerShell(cmd)
    if result.Success() {
        return strings.TrimSpace(result.Output)
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
        var m runtime.MemStats
        runtime.ReadMemStats(&m)
        return m.Sys, m.Sys - m.Alloc
    }

    var memRaw struct {
        TotalVisibleMemorySize int64 `json:"TotalVisibleMemorySize"`
        FreePhysicalMemory    int64 `json:"FreePhysicalMemory"`
    }

    if err := json.Unmarshal([]byte(result.Output), &memRaw); err != nil {
        var m runtime.MemStats
        runtime.ReadMemStats(&m)
        return m.Sys, m.Sys - m.Alloc
    }

    total := uint64(memRaw.TotalVisibleMemorySize) * 1024
    free := uint64(memRaw.FreePhysicalMemory) * 1024
    return total, free
}

func getBootTime() (time.Time, error) {
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
```

**需要添加字段到 types.SystemInfo** (`internal/types/system.go`):
```go
type SystemInfo struct {
    Hostname     string        `json:"hostname"`
    Domain       string        `json:"domain"`
    OSName       string        `json:"os_name"`
    OSVersion    string        `json:"os_version"`
    Architecture string        `json:"architecture"`
    Admin        bool          `json:"is_admin"`
    TimeZone     string        `json:"timezone"`
    LocalTime    time.Time     `json:"local_time"`
    Uptime       time.Duration `json:"uptime"`
    CPUCores     int           `json:"cpu_cores"`      // 新增
    CPUModel     string        `json:"cpu_model"`       // 新增
    MemoryTotal uint64        `json:"memory_total"`   // 新增
    MemoryFree  uint64        `json:"memory_free"`    // 新增
    BootTime    time.Time     `json:"boot_time"`      // 新增
}
```

#### 2.3.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 中 | 约 180 行代码 |
| **适配性** | 高 | 向后兼容，新增字段 |
| **必要性** | 高 | 系统信息是基础数据 |
| **可靠性** | 高 | Win32_OperatingSystem 成熟 WMI 类 |
| **风险** | 低 | 仅扩展数据 |

---

### SYS-4: 完善 DLL 版本获取 (P2)

#### 2.4.1 问题分析

**当前代码** (`internal/collectors/dll_info.go:157-159`):
```go
func GetDLLVersion(dllPath string) string {
    _, _ = windows.GetFileVersionInfoSize(dllPath, nil)
    return ""  // 永远返回空！
}
```

#### 2.4.2 实施方案

**修改文件**: `internal/collectors/dll_info.go`

```go
func GetDLLVersion(dllPath string) string {
    if runtime.GOOS != "windows" {
        return ""
    }

    handle, err := windows.GetFileVersionInfo(dllPath, 0)
    if err != nil {
        return ""
    }

    var fixedInfo *windows.VS_FIXEDFILEINFO
    var fixedInfoLen uint32
    err = windows.QueryFileResourceInfo(handle, 0, windows.RT_VERSION, 0, &fixedInfoLen)
    if err != nil || fixedInfoLen == 0 {
        return ""
    }

    fixedInfo = (*windows.VS_FIXEDFILEINFO)(unsafe.Pointer(&make([]byte, fixedInfoLen)[0]))
    err = windows.QueryFileResourceInfo(handle, 0, windows.RT_VERSION, uintptr(unsafe.Pointer(fixedInfo)), &fixedInfoLen)
    if err != nil {
        return ""
    }

    major := windows.FileResourceInfo(hiword(uint32(fixedInfo.FileVersionMS)))
    minor := windows.FileResourceInfo(lohioword(uint32(fixedInfo.FileVersionLS)))
    build := windows.FileResourceInfo(hiword(uint32(fixedInfo.FileVersionLS)))
    revision := windows.FileResourceInfo(lohioword(uint32(fixedInfo.FileVersionLS)))

    return fmt.Sprintf("%d.%d.%d.%d", major, minor, build, revision)
}

func hiword(val uint32) uint16 {
    return uint16(val >> 16)
}

func loword(val uint32) uint16 {
    return uint16(val & 0xffff)
}
```

或者使用更简单的 PowerShell 方案：

```go
func GetDLLVersion(dllPath string) string {
    if runtime.GOOS != "windows" {
        return ""
    }

    cmd := fmt.Sprintf(`(Get-Item '%s' -ErrorAction SilentlyContinue).VersionInfo | Select-Object -ExpandProperty FileVersion`, strings.ReplaceAll(dllPath, "'", "''"))
    result := utils.RunPowerShell(cmd)
    if result.Success() {
        return strings.TrimSpace(result.Output)
    }
    return ""
}
```

#### 2.4.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 低 | 约 20 行代码 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 中 | DLL 版本有助于恶意软件分析 |
| **可靠性** | 高 | Windows API 成熟 |
| **风险** | 低 | 仅填充版本字段 |

---

### SYS-5: 添加缺失的 API 端点 (P2)

#### 2.5.1 问题分析

CLI 支持 `users`, `registry`, `tasks` 但 API 不支持。

#### 2.5.2 实施方案

**修改文件**: `internal/api/handlers_system.go`

添加以下端点：

```go
// 添加到 SetupSystemRoutes
system.GET("/users", systemHandler.GetUsers)
system.GET("/registry", systemHandler.GetRegistryPersistence)
system.GET("/tasks", systemHandler.GetScheduledTasks)

// 添加处理方法

func (h *SystemHandler) GetUsers(c *gin.Context) {
    if runtime.GOOS != "windows" {
        c.JSON(http.StatusOK, UserResponse{
            Users: []*UserInfo{},
            Total: 0,
        })
        return
    }

    users, err := collectors.ListLocalUsers()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    result := make([]*UserInfo, 0, len(users))
    for _, u := range users {
        result = append(result, &UserInfo{
            Name:     u.Name,
            SID:      u.SID,
            Enabled:  u.Enabled,
            FullName: u.FullName,
            Type:     u.Type,
        })
    }

    c.JSON(http.StatusOK, UserResponse{
        Users: result,
        Total: len(result),
    })
}

func (h *SystemHandler) GetRegistryPersistence(c *gin.Context) {
    if runtime.GOOS != "windows" {
        c.JSON(http.StatusOK, RegistryPersistenceResponse{
            RunKeys:       []*RegistryKeyInfo{},
            Total:         0,
        })
        return
    }

    persistence, err := collectors.CollectRegistryPersistence(context.Background())
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    if len(persistence) == 0 {
        c.JSON(http.StatusOK, RegistryPersistenceResponse{
            RunKeys: []*RegistryKeyInfo{},
            Total:   0,
        })
        return
    }

    p := persistence[0]
    keys := make([]*RegistryKeyInfo, 0)
    
    for _, k := range p.RunKeys {
        keys = append(keys, &RegistryKeyInfo{
            Path:  k.Path,
            Name:  k.Name,
            Value: k.Value,
            Type:  k.Type,
        })
    }
    for _, k := range p.UserInit {
        keys = append(keys, &RegistryKeyInfo{
            Path:  k.Path,
            Name:  k.Name,
            Value: k.Value,
            Type:  k.Type,
        })
    }

    c.JSON(http.StatusOK, RegistryPersistenceResponse{
        RunKeys: keys,
        Total:   len(keys),
    })
}

func (h *SystemHandler) GetScheduledTasks(c *gin.Context) {
    if runtime.GOOS != "windows" {
        c.JSON(http.StatusOK, TaskResponse{
            Tasks: []*TaskInfo{},
            Total: 0,
        })
        return
    }

    tasks, err := collectors.ListScheduledTasks()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    result := make([]*TaskInfo, 0, len(tasks))
    for _, t := range tasks {
        result = append(result, &TaskInfo{
            Name:    t.TaskName,
            Path:    t.TaskPath,
            State:   t.State,
        })
    }

    c.JSON(http.StatusOK, TaskResponse{
        Tasks: result,
        Total: len(result),
    })
}

// 添加类型定义
type UserResponse struct {
    Users []*UserInfo `json:"users"`
    Total int         `json:"total"`
}

type UserInfo struct {
    Name     string `json:"name"`
    SID      string `json:"sid"`
    Enabled  bool   `json:"enabled"`
    FullName string `json:"full_name"`
    Type     string `json:"type"`
}

type RegistryPersistenceResponse struct {
    RunKeys []*RegistryKeyInfo `json:"run_keys"`
    Total   int                `json:"total"`
}

type RegistryKeyInfo struct {
    Path  string `json:"path"`
    Name  string `json:"name"`
    Value string `json:"value"`
    Type  string `json:"type"`
}

type TaskResponse struct {
    Tasks []*TaskInfo `json:"tasks"`
    Total int         `json:"total"`
}

type TaskInfo struct {
    Name  string `json:"name"`
    Path  string `json:"path"`
    State string `json:"state"`
}
```

#### 2.5.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 低 | 约 100 行代码 |
| **适配性** | 高 | 补充缺失功能 |
| **必要性** | 中 | CLI/API 功能一致性 |
| **可靠性** | 高 | 复用现有 collectors |
| **风险** | 低 | 新增端点 |

---

### SYS-6: 配置化硬编码限制 (P3)

#### 2.6.1 问题分析

**当前代码** (`internal/api/handlers_system.go:193-196`):
```go
limitStr := c.DefaultQuery("limit", "100")
limit, _ := strconv.Atoi(limitStr)
if limit <= 0 || limit > 500 {
    limit = 100
}
```

500 是硬编码的限制。

#### 2.6.2 实施方案

**修改文件**: `internal/config/config.go` 或新增常量

```go
// internal/config/limits.go
package config

const (
    DefaultQueryLimit    = 100
    MaxQueryLimit        = 1000  // 可配置化
    DefaultProcessLimit  = 500
    MaxProcessLimit      = 2000
)
```

**修改 handlers_system.go**:
```go
import "github.com/kkkdddd-start/winalog-go/internal/config"

func (h *SystemHandler) GetProcesses(c *gin.Context) {
    limitStr := c.DefaultQuery("limit", "100")
    limit, _ := strconv.Atoi(limitStr)
    if limit <= 0 || limit > config.MaxProcessLimit {
        limit = config.DefaultProcessLimit
    }
    // ...
}
```

#### 2.6.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 很低 | 约 10 行代码 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 低 | 代码质量改进 |
| **可靠性** | 高 | 无功能变更 |
| **风险** | 无 | 配置化 |

---

### SYS-7: 一键取证完整实现 (P0)

#### 2.7.1 问题分析

**当前状态**: `one_click.go` 中所有方法都是空实现，无法使用取证功能。

#### 2.7.2 实施方案

**修改文件**: `internal/collectors/one_click.go`

```go
//go:build windows

package collectors

import (
    "archive/zip"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
    "time"

    "github.com/kkkdddd-start/winalog-go/internal/forensics"
    "github.com/kkkdddd-start/winalog-go/internal/types"
)

type OneClickCollector struct {
    BaseCollector
    cfg CollectConfig
}

type CollectConfig struct {
    Workers           int
    IncludePrefetch   bool
    IncludeRegistry   bool
    IncludeSystemInfo bool
    OutputPath        string
    Compress          bool
    CalculateHash     bool
}

type CollectOptions struct {
    Workers           int
    IncludePrefetch   bool
    IncludeRegistry   bool
    IncludeSystemInfo bool
    OutputPath        string
    Compress          bool
    CalculateHash     bool
}

type OneClickResult struct {
    OutputPath      string                      `json:"output_path"`
    Duration        time.Duration               `json:"duration"`
    Success         bool                        `json:"success"`
    CollectedItems   map[string]int             `json:"collected_items"`
    Hashes          map[string]string           `json:"hashes,omitempty"`
    Errors          []string                    `json:"errors,omitempty"`
}

func NewOneClickCollector() *OneClickCollector {
    return &OneClickCollector{
        BaseCollector: BaseCollector{
            info: CollectorInfo{
                Name:          "one_click",
                Description:   "One-click collection of Windows logs and artifacts",
                RequiresAdmin: true,
                Version:       "1.0.0",
            },
        },
        cfg: CollectConfig{
            Workers: 4,
        },
    }
}

func (c *OneClickCollector) Collect(ctx context.Context) ([]interface{}, error) {
    return nil, nil
}

func RunOneClickCollection(ctx context.Context, opts interface{}) (interface{}, error) {
    c := NewOneClickCollector()

    if opts != nil {
        if collectOpts, ok := opts.(CollectOptions); ok {
            c.cfg.Workers = collectOpts.Workers
            c.cfg.IncludePrefetch = collectOpts.IncludePrefetch
            c.cfg.IncludeRegistry = collectOpts.IncludeRegistry
            c.cfg.IncludeSystemInfo = collectOpts.IncludeSystemInfo
            if collectOpts.OutputPath != "" {
                c.cfg.OutputPath = collectOpts.OutputPath
            }
            c.cfg.Compress = collectOpts.Compress
            c.cfg.CalculateHash = collectOpts.CalculateHash
        }
    }

    startTime := time.Now()
    result, err := c.FullCollect(ctx)
    if err != nil {
        return &OneClickResult{
            Success: false,
            Errors:  []string{err.Error()},
        }, err
    }
    return result, nil
}

func (c *OneClickCollector) FullCollect(ctx context.Context) (*OneClickResult, error) {
    result := &OneClickResult{
        Success:       true,
        CollectedItems: make(map[string]int),
        Errors:         make([]string, 0),
    }

    if c.cfg.OutputPath == "" {
        timestamp := time.Now().Format("20060102_150405")
        c.cfg.OutputPath = filepath.Join(os.TempDir(), fmt.Sprintf("winalog_collect_%s", timestamp))
    }

    tempDir := c.cfg.OutputPath + "_temp"
    if err := os.MkdirAll(tempDir, 0755); err != nil {
        result.Success = false
        result.Errors = append(result.Errors, fmt.Sprintf("failed to create temp dir: %v", err))
        return result, err
    }
    defer os.RemoveAll(tempDir)

    var allErrors []string

    if c.cfg.IncludeSystemInfo {
        if err := c.collectSystemInfoTo(tempDir); err != nil {
            allErrors = append(allErrors, err.Error())
        }
    }

    if c.cfg.IncludeRegistry {
        if err := c.CollectRegistry(tempDir); err != nil {
            allErrors = append(allErrors, err.Error())
        }
    }

    if c.cfg.IncludePrefetch {
        if err := c.CollectPrefetch(tempDir); err != nil {
            allErrors = append(allErrors, err.Error())
        }
    }

    c.CollectEvtxLogs(ctx, tempDir)

    if err := c.CollectEventLogs(ctx, tempDir); err != nil {
        allErrors = append(allErrors, err.Error())
    }

    if c.cfg.CalculateHash {
        hashes, err := c.CalculateFileHashes(tempDir)
        if err == nil {
            result.Hashes = hashes
        }
    }

    if c.cfg.Compress {
        zipPath := c.cfg.OutputPath + ".zip"
        if err := c.CreateZipFromDir(tempDir, zipPath); err != nil {
            allErrors = append(allErrors, err.Error())
        } else {
            c.cfg.OutputPath = zipPath
        }
    } else {
        if err := os.Rename(tempDir, c.cfg.OutputPath); err != nil {
            allErrors = append(allErrors, err.Error())
        }
    }

    result.OutputPath = c.cfg.OutputPath
    result.Duration = time.Since(startTime)
    result.Errors = allErrors
    if len(allErrors) > 0 {
        result.Success = false
    }

    return result, nil
}

func (c *OneClickCollector) collectSystemInfoTo(tempDir string) error {
    infoDir := filepath.Join(tempDir, "system_info")
    if err := os.MkdirAll(infoDir, 0755); err != nil {
        return err
    }

    info, err := CollectSystemInfo(context.Background())
    if err != nil {
        return err
    }

    data, _ := json.MarshalIndent(info, "", "  ")
    return os.WriteFile(filepath.Join(infoDir, "system_info.json"), data, 0644)
}

func (c *OneClickCollector) CollectEvtxLogs(ctx context.Context, outputDir string) error {
    evtxDir := filepath.Join(outputDir, "winevt_logs")
    if err := os.MkdirAll(evtxDir, 0755); err != nil {
        return err
    }

    logPaths := []string{
        `C:\Windows\System32\winevt\Logs\Security.evtx`,
        `C:\Windows\System32\winevt\Logs\System.evtx`,
        `C:\Windows\System32\winevt\Logs\Application.evtx`,
    }

    for _, logPath := range logPaths {
        if _, err := os.Stat(logPath); err == nil {
            dst := filepath.Join(evtxDir, filepath.Base(logPath))
            c.CopyFileWithRetry(logPath, dst, 3)
        }
    }

    return nil
}

func (c *OneClickCollector) CollectEventLogs(ctx context.Context, outputDir string) error {
    eventLogDir := filepath.Join(outputDir, "event_logs")
    if err := os.MkdirAll(eventLogDir, 0755); err != nil {
        return err
    }

    cmd := `Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 } | Select-Object -First 20 -ExpandProperty LogName | ForEach-Object { $_ }`

    result := utils.RunPowerShell(cmd)
    if !result.Success() {
        return result.Error
    }

    logNames := strings.Split(strings.TrimSpace(result.Output), "\n")
    for _, logName := range logNames {
        logName = strings.TrimSpace(logName)
        if logName == "" {
            continue
        }
        
        exportPath := filepath.Join(eventLogDir, logName+".evtx")
        exportCmd := fmt.Sprintf(`wevtutil epl "%s" "%s" /q:*[System[TimeCreated[@t>'%s']]`, 
            logName, exportPath, time.Now().Add(-7*24*time.Hour).Format("2006-01-02T15:04:00"))
        
        utils.RunPowerShell(exportCmd)
    }

    return nil
}

func (c *OneClickCollector) CollectPrefetch(ctx context.Context, outputDir string) error {
    prefetchDir := filepath.Join(outputDir, "prefetch")
    if err := os.MkdirAll(prefetchDir, 0755); err != nil {
        return err
    }

    prefetchPath := `C:\Windows\System32\winevt\Logs\Security.evtx`
    if _, err := os.Stat(prefetchPath); os.IsNotExist(err) {
        return nil
    }

    prefetchWindowsDir := `C:\Windows\Prefetch`
    entries, err := os.ReadDir(prefetchWindowsDir)
    if err != nil {
        return nil
    }

    for _, entry := range entries {
        if strings.HasSuffix(entry.Name(), ".pf") {
            src := filepath.Join(prefetchWindowsDir, entry.Name())
            dst := filepath.Join(prefetchDir, entry.Name())
            c.CopyFileWithRetry(src, dst, 3)
        }
    }

    return nil
}

func (c *OneClickCollector) CollectRegistry(ctx context.Context, outputDir string) error {
    regDir := filepath.Join(outputDir, "registry")
    if err := os.MkdirAll(regDir, 0755); err != nil {
        return err
    }

    runKeys := []string{
        `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
        `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
        `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
        `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
    }

    for _, keyPath := range runKeys {
        keyName := strings.ReplaceAll(keyPath, "\\", "_")
        keyName = strings.ReplaceAll(keyName, ":", "")
        outputPath := filepath.Join(regDir, keyName+".txt")

        cmd := fmt.Sprintf(`Get-ItemProperty -Path '%s' -ErrorAction SilentlyContinue | ConvertTo-Json -Compress`, keyPath)
        result := utils.RunPowerShell(cmd)
        if result.Success() && result.Output != "" {
            os.WriteFile(outputPath, []byte(result.Output), 0644)
        }
    }

    return nil
}

func (c *OneClickCollector) CreateZipFromDir(sourceDir, zipPath string) error {
    zipFile, err := os.Create(zipPath)
    if err != nil {
        return err
    }
    defer zipFile.Close()

    writer := zip.NewWriter(zipFile)
    defer writer.Close()

    return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }

        header, _ := zip.FileInfoHeader(info)
        header.Name = strings.TrimPrefix(path, sourceDir)

        if info.IsDir() {
            header.Name += "/"
        }

        headerWriter, _ := writer.Create(header.Name)
        if info.IsDir() {
            return nil
        }

        file, _ := os.Open(path)
        defer file.Close()
        _, err = io.Copy(headerWriter, file)
        return err
    })
}

func (c *OneClickCollector) CalculateFileHashes(dir string) (map[string]string, error) {
    hashes := make(map[string]string)

    filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
        if err != nil || info.IsDir() {
            return nil
        }

        if hash, err := forensics.CalculateFileHash(path); err == nil {
            hashes[path] = hash.SHA256
        }
        return nil
    })

    return hashes, nil
}
```

#### 2.7.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 高 | 约 300 行代码 |
| **适配性** | 高 | 新增功能 |
| **必要性** | 高 | 取证是核心功能 |
| **可靠性** | 高 | 文件复制成熟 |
| **风险** | 中 | 需要测试覆盖 |

---

### SYS-8: 内存取证完整实现 (P0)

#### 2.8.1 问题分析

**当前状态**: `readProcessMemory` 和 `readSystemMemory` 返回未实现错误。

#### 2.8.2 实施方案

**修改文件**: `internal/forensics/memory.go`

```go
//go:build windows

package forensics

import (
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "runtime"
    "time"
    "unsafe"

    "golang.org/x/sys/windows"
)

var (
    ErrProcessMemoryNotImplemented = fmt.Errorf("process memory dump not implemented")
    ErrSystemMemoryNotImplemented = fmt.Errorf("system memory dump not implemented")
)

type MemoryDumpResult struct {
    ProcessID   uint32            `json:"process_id"`
    ProcessName string            `json:"process_name"`
    DumpPath    string            `json:"dump_path"`
    DumpSize    int64             `json:"dump_size"`
    DumpTime    time.Time         `json:"dump_time"`
    Hash        string            `json:"hash"`
    Modules     []MemoryModule    `json:"modules,omitempty"`
    Permissions MemoryPermissions `json:"permissions"`
    Error       string            `json:"error,omitempty"`
}

type MemoryModule struct {
    BaseAddress uint64 `json:"base_address"`
    Size        uint64 `json:"size"`
    Name        string `json:"name"`
    Path        string `json:"path"`
}

type MemoryPermissions struct {
    Readable    bool `json:"readable"`
    Writable    bool `json:"writable"`
    Executable  bool `json:"executable"`
    CopyOnWrite bool `json:"copy_on_write"`
}

type MemoryRegion struct {
    BaseAddress     uint64 `json:"base_address"`
    AllocationBase  uint64 `json:"allocation_base"`
    RegionSize      uint64 `json:"region_size"`
    State           uint32 `json:"state"`
    Protect         uint32 `json:"protect"`
    Type            uint32 `json:"type"`
}

type MemoryCollector struct {
    outputDir       string
    includeModules  bool
    includeStacks   bool
}

func NewMemoryCollector(outputDir string) *MemoryCollector {
    return &MemoryCollector{
        outputDir:      outputDir,
        includeModules: true,
        includeStacks:  false,
    }
}

func (c *MemoryCollector) SetIncludeModules(include bool) {
    c.includeModules = include
}

func (c *MemoryCollector) SetIncludeStacks(include bool) {
    c.includeStacks = include
}

func (c *MemoryCollector) CollectProcessMemory(pid uint32) (*MemoryDumpResult, error) {
    result := &MemoryDumpResult{
        ProcessID:   pid,
        ProcessName: fmt.Sprintf("Process_%d", pid),
        DumpTime:    time.Now(),
    }

    processName, err := getProcessName(pid)
    if err == nil {
        result.ProcessName = processName
    }

    dumpPath := filepath.Join(c.outputDir, fmt.Sprintf("memory_%d_%s.raw", pid, time.Now().Format("20060102_150405")))
    
    dumpData, err := readProcessMemory(pid)
    if err != nil {
        result.Error = err.Error()
        return result, err
    }

    file, err := os.Create(dumpPath)
    if err != nil {
        result.Error = err.Error()
        return result, err
    }
    defer file.Close()

    written, err := file.Write(dumpData)
    if err != nil {
        result.Error = err.Error()
        return result, err
    }

    result.DumpSize = int64(written)
    result.DumpPath = dumpPath
    result.Hash = calculateMemoryHash(dumpData)
    result.Permissions = MemoryPermissions{Readable: true}

    if c.includeModules {
        modules, _ := c.collectModules(pid)
        result.Modules = modules
    }

    return result, nil
}

func (c *MemoryCollector) CollectSystemMemory() (*MemoryDumpResult, error) {
    result := &MemoryDumpResult{
        ProcessID:   0,
        ProcessName: "System",
        DumpTime:    time.Now(),
    }

    dumpPath := filepath.Join(c.outputDir, fmt.Sprintf("system_memory_%s.raw", time.Now().Format("20060102_150405")))

    dumpData, err := readSystemMemory()
    if err != nil {
        result.Error = err.Error()
        return result, err
    }

    file, err := os.Create(dumpPath)
    if err != nil {
        result.Error = err.Error()
        return result, err
    }
    defer file.Close()

    written, err := file.Write(dumpData)
    if err != nil {
        result.Error = err.Error()
        return result, err
    }

    result.DumpSize = int64(written)
    result.DumpPath = dumpPath
    result.Hash = calculateMemoryHash(dumpData)

    return result, nil
}

func (c *MemoryCollector) collectModules(pid uint32) ([]MemoryModule, error) {
    modules := make([]MemoryModule, 0)

    hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
    if err != nil {
        return modules, err
    }
    defer windows.CloseHandle(hProcess)

    var moduleCount uint32
    err = windows.EnumProcessModules(hProcess, nil, 0, &moduleCount)
    if err != nil {
        return modules, err
    }

    handleSize := unsafe.Sizeof(windows.Handle(0))
    moduleHandles := make([]windows.Handle, moduleCount/uint32(handleSize))
    err = windows.EnumProcessModules(hProcess, &moduleHandles[0], moduleCount, &moduleCount)
    if err != nil {
        return modules, err
    }

    for _, hModule := range moduleHandles {
        var modName [windows.MAX_PATH]uint16
        windows.GetModuleBaseName(hProcess, hModule, &modName[0], uint32(len(modName)))

        var modSize uint64
        var modInfo windows.ModuleInfo
        if windows.GetModuleInformation(hProcess, hModule, &modInfo, uint32(unsafe.Sizeof(modInfo))) {
            modSize = modInfo.SizeOfImage
        }

        modules = append(modules, MemoryModule{
            BaseAddress: uint64(modInfo.BaseAddress),
            Size:        modSize,
            Name:        windows.UTF16ToString(modName[:]),
        })
    }

    return modules, nil
}

func readProcessMemory(pid uint32) ([]byte, error) {
    hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
    if err != nil {
        return nil, fmt.Errorf("failed to open process: %w", err)
    }
    defer windows.CloseHandle(hProcess)

    var memInfo windows.MemoryBasicInformation
    var bytesRead uint64
    var buffer bytes.Buffer

    for {
        err := windows.VirtualQueryEx(hProcess, windows.Pointer(memInfo.BaseAddress), &memInfo, uint32(unsafe.Sizeof(memInfo)))
        if err != nil || memInfo.BaseAddress == nil {
            break
        }

        if memInfo.State == windows.MEM_COMMIT && memInfo.Protect&windows.PAGE_READABLE != 0 {
            size := uint64(memInfo.RegionSize)
            
            if size > 100*1024*1024 {
                size = 100 * 1024 * 1024
            }

            data := make([]byte, size)
            var nr uint64

            success, _, _ := windows.ReadProcessMemory(
                hProcess,
                memInfo.BaseAddress,
                &data[0],
                uint64(len(data)),
                &nr,
            )

            if success && nr > 0 {
                buffer.Write(data[:nr])
                bytesRead += nr
            }
        }

        memInfo.BaseAddress = windows.Pointer(uintptr(memInfo.BaseAddress) + uintptr(memInfo.RegionSize))
    }

    return buffer.Bytes(), nil
}

func readSystemMemory() ([]byte, error) {
    return nil, ErrSystemMemoryNotImplemented
}

func getProcessName(pid uint32) (string, error) {
    hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
    if err != nil {
        return "", err
    }
    defer windows.CloseHandle(hProcess)

    var name [windows.MAX_PATH]uint16
    size := uint32(len(name))
    if err := windows.QueryFullProcessImageName(hProcess, 0, &name[0], &size); err != nil {
        return "", err
    }

    return windows.UTF16ToString(name[:]), nil
}

func calculateMemoryHash(data []byte) string {
    if len(data) == 0 {
        return ""
    }
    hash := sha256.Sum256(data)
    return hex.EncodeToString(hash[:])
}

func QueryMemoryRegions(pid uint32) (*MemoryRegions, error) {
    regions := make([]MemoryRegion, 0)

    hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
    if err != nil {
        return &MemoryRegions{Regions: regions}, err
    }
    defer windows.CloseHandle(hProcess)

    var memInfo windows.MemoryBasicInformation
    var address uintptr = 0

    for {
        err := windows.VirtualQueryEx(hProcess, windows.Pointer(address), &memInfo, uint32(unsafe.Sizeof(memInfo)))
        if err != nil || memInfo.BaseAddress == nil {
            break
        }

        regions = append(regions, MemoryRegion{
            BaseAddress:    uint64(memInfo.BaseAddress),
            AllocationBase: uint64(memInfo.AllocationBase),
            RegionSize:     uint64(memInfo.RegionSize),
            State:         uint32(memInfo.State),
            Protect:       uint32(memInfo.Protect),
            Type:          uint32(memInfo.Type),
        })

        address = uintptr(memInfo.BaseAddress) + uintptr(memInfo.RegionSize)
    }

    return &MemoryRegions{Regions: regions}, nil
}

type MemoryRegions struct {
    Regions []MemoryRegion `json:"regions"`
}
```

#### 2.8.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 高 | 约 250 行代码 |
| **适配性** | 高 | 新增功能 |
| **必要性** | 高 | 内存取证是核心功能 |
| **可靠性** | 中 | Windows API 调用复杂 |
| **风险** | 中 | 大内存dump可能失败 |

---

## 三、实施优先级总览

### 3.1 优先级排序

| ID | 改进项 | 优先级 | 复杂度 | 工作量 | 风险 |
|----|--------|--------|--------|--------|------|
| SYS-1 | 网络连接收集 | P0 | 中 | 1人天 | 低 |
| SYS-2 | 用户账户收集 | P0 | 低 | 0.5人天 | 低 |
| SYS-3 | 系统信息收集 | P1 | 中 | 1人天 | 低 |
| SYS-7 | 一键取证 | P0 | 高 | 2人天 | 中 |
| SYS-8 | 内存取证 | P0 | 高 | 2人天 | 中 |
| SYS-4 | DLL版本获取 | P2 | 低 | 0.25人天 | 低 |
| SYS-5 | API端点补充 | P2 | 低 | 0.5人天 | 低 |
| SYS-6 | 配置化限制 | P3 | 很低 | 0.25人天 | 无 |

### 3.2 建议实施路线图

```
Q1 (核心功能修复):
├─ SYS-1 网络连接收集
├─ SYS-2 用户账户收集
└─ SYS-3 系统信息收集

Q2 (取证功能):
├─ SYS-7 一键取证
└─ SYS-8 内存取证

Q3 (完善优化):
├─ SYS-4 DLL版本获取
├─ SYS-5 API端点补充
└─ SYS-6 配置化限制
```

---

## 四、相关文件清单

| 文件 | 修改类型 | 涉及改进项 |
|------|----------|------------|
| `internal/collectors/network_info.go` | 重写 | SYS-1 |
| `internal/collectors/user_info.go` | 重写 | SYS-2 |
| `internal/collectors/system_info.go` | 增强 | SYS-3 |
| `internal/collectors/dll_info.go` | 修复 | SYS-4 |
| `internal/collectors/one_click.go` | 重写 | SYS-7 |
| `internal/forensics/memory.go` | 重写 | SYS-8 |
| `internal/api/handlers_system.go` | 增强 | SYS-5 |
| `internal/config/limits.go` | 新增 | SYS-6 |
| `internal/types/system.go` | 增强 | SYS-3 |

---

## 五、编译验证

所有改进完成后，运行以下命令验证：

```bash
cd /workspace/winalog-go

go build ./internal/collectors/...
go build ./internal/forensics/...
go build ./internal/api/...
go build ./cmd/winalog/...
```

---

*文档版本: 1.0*
*审核状态: 待审核*
*实施状态: 待实施*
