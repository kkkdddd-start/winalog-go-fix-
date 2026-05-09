# Persistence 模块

**路径**: `internal/persistence/`

Windows 持久化技术检测模块，检测常见持久化手法并映射到 MITRE ATT&CK T1546 系列。

## 概述

持久化检测模块提供 9 种检测器，覆盖：
- 注册表持久化 (Run Key, UserInit, AppInit, IFEO)
- 辅助功能后门
- COM 劫持
- WMI 事件订阅
- Windows 服务持久化

## 核心类型

### Detection

```go
type Detection struct {
    ID                string                 // 唯一标识
    Time              time.Time              // 检测时间
    Technique         Technique              // MITRE Technique ID
    Category          string                 // 分类: Registry/ScheduledTask/Service/WMI/COM
    Severity          Severity               // critical/high/medium/low/info
    Title             string                 // 检测标题
    Description       string                 // 详细描述
    Evidence          Evidence               // 证据信息
    MITRERef          []string               // MITRE 参考
    RecommendedAction string                 // 建议操作
    FalsePositiveRisk string                 // 误报风险: Low/Medium/High
}
```

### Evidence

```go
type Evidence struct {
    Type     EvidenceType  // registry/file/wmi/service/task/com
    Path     string        // 注册表路径或文件路径
    Key      string        // 注册表键
    Value    string        // 注册表值
    Expected string        // 期望值（用于比对）
    Process  string        // 关联进程
    FilePath string        // 文件路径
    Command  string        // 命令行
}
```

### Technique 枚举

```go
const (
    TechniqueT1546001 Technique = "T1546.001"  // Accessibility Features
    TechniqueT1546002 Technique = "T1546.002"  // SCM
    TechniqueT1546003 Technique = "T1546.003"  // WMI Event Subscription
    TechniqueT1546007 Technique = "T1546.007"  // Netsh Helper DLL
    TechniqueT1546008 Technique = "T1546.008"  // LSASS
    TechniqueT1546010 Technique = "T1546.010"  // AppInit_DLLs
    TechniqueT1546012 Technique = "T1546.012"  // IFEO
    TechniqueT1546015 Technique = "T1546.015"  // COM Hijacking
    TechniqueT1546016 Technique = "T1546.016"  // Startup Items
    TechniqueT1053    Technique = "T1053"     // Scheduled Task
    TechniqueT1053020 Technique = "T1053.020"  // Cron
    TechniqueT1543003 Technique = "T1543.003"  // Windows Service
    TechniqueT1197    Technique = "T1197"     // BITS Jobs
    TechniqueT1098    Technique = "T1098"     // Account Manipulation
)
```

## 检测器接口

```go
type Detector interface {
    Name() string                                    // 检测器名称
    Detect(ctx context.Context) ([]*Detection, error) // 执行检测
    RequiresAdmin() bool                             // 是否需要管理员权限
    GetTechnique() Technique                        // 对应 Technique
}
```

## DetectionEngine

```go
type DetectionEngine struct {
    detectors     map[string]Detector
    result        *DetectionResult
    mu            sync.RWMutex
    adminRequired bool
}

func NewDetectionEngine() *DetectionEngine

// 注册检测器
func (e *DetectionEngine) Register(d Detector)

// 执行所有检测
func (e *DetectionEngine) Detect(ctx context.Context) *DetectionResult

// 按类别检测
func (e *DetectionEngine) DetectCategory(ctx context.Context, category string) *DetectionResult

// 按技术检测
func (e *DetectionEngine) DetectTechnique(ctx context.Context, technique Technique) *DetectionResult

// 列出所有检测器
func (e *DetectionEngine) ListDetectors() []DetectorInfo
```

## 内置检测器

### 1. RunKeyDetector

检测注册表 Run 键持久化。

```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

**可疑指标**:
- 路径包含 `%TEMP%`, `%APPDATA%`, 网络路径
- Base64 编码的值
- 未知程序路径

### 2. UserInitDetector

检测 Winlogon UserInit 持久化。

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
```

**检测项**:
- Userinit 值被修改
- 添加了额外的启动脚本

### 3. StartupFolderDetector

检测启动文件夹持久化。

```
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

### 4. AccessibilityDetector

检测辅助功能后门。

**目标程序**:
- `sethc.exe` - 粘滞键 (按 5 次 Shift)
- `utilman.exe` - 轻松访问管理器
- `osk.exe` - 屏幕键盘
- `magnify.exe` - 放大镜
- `narrator.exe` - 讲述人
- `displayswitch.exe` - 显示切换
- `mspaint.exe` - 画图

**Technique**: T1546.001

### 5. COMHijackDetector

检测 COM 对象劫持。

```
HKCR\CLSID\{...}\InprocServer32
```

**检测项**:
- 路径不在 System32/SysWOW64
- 路径包含 TEMP 或网络路径
- Empty CLSID
- ADO Stream Object (已知恶意利用)

**Technique**: T1546.015

### 6. IFEODetector

检测 Image File Execution Options 劫持。

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
```

**检测项**:
- Debugger 值被修改
- GlobalFlag 值异常
- ShutdownFlags 值异常

**Technique**: T1546.012

### 7. AppInitDetector

检测 AppInit_DLLs 持久化。

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs
```

**Technique**: T1546.010

### 8. WMIPersistenceDetector

检测 WMI 永久事件订阅。

**订阅类型**:
- CommandLineEventConsumer - 执行命令
- ActiveScriptEventConsumer - 执行脚本
- NTEventLogEventConsumer - 写入 Windows 事件日志

**Technique**: T1546.003

### 9. ServicePersistenceDetector

检测 Windows 服务持久化。

**基于事件**:
- Event ID 4697: A service was installed

**检测项**:
- 服务路径异常
- 服务名称可疑
- 服务类型非标准

**Technique**: T1543.003

## 持久化类别

```go
var PersistenceCategories = []PersistenceCategory{
    {Name: "Registry", Techniques: []Technique{
        TechniqueT1546001, TechniqueT1546010, 
        TechniqueT1546012, TechniqueT1546015,
    }},
    {Name: "ScheduledTask", Techniques: []Technique{
        TechniqueT1053, TechniqueT1053020,
    }},
    {Name: "Service", Techniques: []Technique{
        TechniqueT1543003,
    }},
    {Name: "WMI", Techniques: []Technique{
        TechniqueT1546003,
    }},
    {Name: "COM", Techniques: []Technique{
        TechniqueT1546015,
    }},
    {Name: "BITS", Techniques: []Technique{
        TechniqueT1197,
    }},
}
```

## 快速函数

```go
// 运行所有检测
func RunAllDetectors(ctx context.Context) *DetectionResult

// 按类别检测
func DetectByCategory(ctx context.Context, category string) *DetectionResult

// 按技术检测
func DetectByTechnique(ctx context.Context, technique Technique) *DetectionResult
```

## 使用示例

```go
// 创建检测引擎
engine := persistence.NewDetectionEngine()
engine.Register(persistence.NewRunKeyDetector())
engine.Register(persistence.NewAccessibilityDetector())
engine.Register(persistence.NewCOMHijackDetector())
// ... 注册更多检测器

// 执行检测
ctx := context.Background()
result := engine.Detect(ctx)

// 处理结果
for _, det := range result.Detections {
    fmt.Printf("[%s] %s: %s\n", 
        det.Severity, det.Technique, det.Title)
}

// 生成报告
jsonData, _ := result.ToJSON()
fmt.Println(string(jsonData))
```

## 与告警系统集成

```go
// 转换为告警
func (d *Detection) ToAlert() *types.Alert {
    return &types.Alert{
        RuleName:  string(d.Technique),
        Severity:  d.Severity.ToAlertSeverity(),
        Message:   d.Description,
        MITREAttack: d.MITRERef,
    }
}
```

## 性能目标

| 指标 | 目标 |
|------|------|
| 完整检测耗时 | < 30 秒 |
| 内存占用 | < 50MB |
| 误报率 | < 5% |

## 文件列表

```
internal/persistence/
├── types.go           # 核心类型定义
├── detector.go        # 检测引擎
├── registry.go        # Run Key / UserInit 检测
├── accessibility.go    # 辅助功能后门检测
├── com.go             # COM 劫持检测
├── ifeo.go            # IFEO 检测
├── appinit.go         # AppInit_DLLs 检测
├── wmi.go             # WMI 持久化检测
├── service.go         # Windows 服务检测
└── persistence_test.go # 测试文件
```
