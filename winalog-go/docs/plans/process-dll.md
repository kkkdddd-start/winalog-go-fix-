# PROCESS SIGNATURE AND DLL COLLECTION IMPROVEMENT PLAN

## 问题概述

当前实现存在以下问题：
1. 进程列表签名未采集 - `ListProcesses()` 只返回 PID 和 Name
2. 进程详情签名未填充 - `ProcessInfo` 类型有 `Signature` 字段但未使用
3. 没有签名的进程缺少视觉标记
4. DLL采集与进程采集分离，用户需要分开操作

## 改进方案

### PROC-1: 进程签名采集

**问题等级**: P1

**当前状态**:
- `ListProcesses()` 只返回 PID 和 ProcessName
- `ProcessInfo` 结构体有 `Signature` 字段但未填充
- 签名验证功能存在于 `forensics.VerifySignature()` 但未被调用

**目标状态**:
- 进程列表采集时同时获取签名信息
- `ProcessInfo.Signature` 字段被正确填充
- 未签名进程有明确标记

**实施方案**:

1. 修改 `ProcessInfo` 结构体 (在 `internal/types/system.go`):
```go
type ProcessInfo struct {
    PID             int              `json:"pid"`
    Name            string           `json:"name"`
    ExecutablePath  string           `json:"executable_path"`
    CommandLine     string           `json:"command_line"`
    Username        string           `json:"username"`
    SessionID       int              `json:"session_id"`
    CPUPercent      float64          `json:"cpu_percent"`
    MemoryUsageMB   int64            `json:"memory_usage_mb"`
    StartTime       time.Time        `json:"start_time"`
    Status          string           `json:"status"`
    ParentPID       int              `json:"parent_pid"`
    Signature       *SignatureInfo  `json:"signature,omitempty"`
    IsSigned        bool             `json:"is_signed"`
    HasSignature    bool             `json:"-"` // 用于UI标记，不序列化
}

type SignatureInfo struct {
    Status      string `json:"status"`      // "signed", "unsigned", "invalid", "error"
    Issuer      string `json:"issuer"`
    Subject     string `json:"subject"`
    ValidFrom   string `json:"valid_from"`
    ValidTo     string `json:"valid_to"`
    Thumbprint  string `json:"thumbprint"`
    SerialNum   string `json:"serial_number"`
}
```

2. 修改 `ListProcesses()` 函数 (在 `internal/collectors/process_info.go`):
- 添加签名验证逻辑
- 对每个进程调用 `forensics.VerifySignature(exePath)`
- 填充 `Signature` 和 `IsSigned` 字段

3. 修改 TUI 进程视图 (在 `internal/tui/`):
- 未签名进程显示为黄色
- 已签名进程显示为绿色
- 无效签名显示为红色

### PROC-2: DLL按进程采集

**问题等级**: P1

**当前状态**:
- DLL采集是独立功能，用户需要手动选择进程
- 用户先采集进程列表，再单独采集DLL
- 无法直接看到某个进程加载了哪些DLL

**目标状态**:
- 提供"按进程采集DLL"功能
- 用户点击进程后可以查看该进程的DLL
- DLL信息包含所属进程的PID和名称

**实施方案**:

1. 修改 `DllInfo` 结构体 (在 `internal/types/system.go`):
```go
type DllInfo struct {
    Path          string `json:"path"`
    Size          int64  `json:"size"`
    ModifiedTime  string `json:"modified_time"`
    Version       string `json:"version"`
    Description   string `json:"description"`
    Company       string `json:"company"`
    Product       string `json:"product"`
    Hash          string `json:"hash"`
    Signature     *SignatureInfo `json:"signature,omitempty"`
    IsSigned      bool   `json:"is_signed"`
    ProcessID     int    `json:"process_id,omitempty"`    // 所属进程PID
    ProcessName   string `json:"process_name,omitempty"`  // 所属进程名称
}
```

2. 新增 `GetProcessDLLs(pid int)` 函数 (在 `internal/collectors/dll_info.go`):
- 根据PID获取该进程加载的所有DLL
- 填充 ProcessID 和 ProcessName 字段
- 复用现有的 DLL 信息采集逻辑

3. 新增 CLI 命令 `winalog process dlls <pid>` (在 `cmd/winalog/commands/`):
- 采集指定进程的DLL信息

4. 新增 API 端点:
- `GET /api/v1/process/:pid/dlls` - 获取指定进程的DLL列表

5. 修改 TUI DLL视图:
- 添加"按进程筛选"选项
- 显示 DLL 所属进程信息

### PROC-3: 一键采集增强

**问题等级**: P0

**目标**: 在一键取证功能中整合进程签名和DLL按进程采集

**实施方案**:

1. 修改 `OneClickForensics` 函数流程:
```
1. 采集系统信息 (基础信息)
2. 采集进程列表 (包含签名)
3. 对每个进程采集DLL (可选，用户选择)
4. 采集网络连接
5. 采集用户账户
6. 采集注册表启动项
7. 采集计划任务
8. 生成报告
```

2. 添加配置选项:
- `collect_process_signatures`: 是否采集进程签名 (默认true)
- `collect_process_dlls`: 是否按进程采集DLL (默认false，大型系统可能很慢)
- `dll_collection_mode`: "none" | "selected" | "all"
- `selected_pids`: 当 mode 为 "selected" 时，指定要采集DLL的PID列表

## 实施优先级

| 编号 | 改进项 | 优先级 | 复杂度 | 说明 |
|------|--------|--------|--------|------|
| PROC-1 | 进程签名采集 | P1 | 中 | 需要修改多个文件 |
| PROC-2 | DLL按进程采集 | P1 | 中 | 需要新增函数和API |
| PROC-3 | 一键采集增强 | P0 | 高 | 整合上述功能 |

## 涉及文件

### PROC-1:
- `internal/types/system.go` - 结构体修改
- `internal/collectors/process_info.go` - 添加签名采集
- `internal/forensics/signature.go` - 可能需要优化批量验证
- `internal/tui/` - TUI显示修改

### PROC-2:
- `internal/types/system.go` - DllInfo结构体修改
- `internal/collectors/dll_info.go` - 新增GetProcessDLLs函数
- `cmd/winalog/commands/` - 新增CLI命令
- `internal/api/handlers_dll.go` - 新增API处理器
- `internal/tui/` - DLL视图修改

### PROC-3:
- `internal/collectors/one_click.go` - 整合现有采集器
- 可能需要修改 `internal/collectors/system_info.go` 协调采集

## 注意事项

1. **性能考虑**: 签名验证可能较慢，需要添加超时和缓存
2. **管理员权限**: 某些进程信息采集需要管理员权限
3. **错误处理**: 签名验证失败不应阻止进程列表返回
4. **向后兼容**: API响应格式变更需要考虑版本控制

## 依赖关系

- PROC-1 可独立实施
- PROC-2 依赖 PROC-1 (需要 SignatureInfo 类型)
- PROC-3 依赖 PROC-1 和 PROC-2
