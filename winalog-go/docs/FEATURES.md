# WinLogAnalyzer-Go 功能详细清单

**项目**: WinLogAnalyzer  
**版本**: Go v2.4.0  
**日期**: 2026-04-17  
**状态**: 已完成实现

---

## 一、CLI 命令模块 (`cmd/winalog/commands/`)

| 命令 | 功能 | 详细说明 |
|------|------|----------|
| `import` | 批量导入 EVTX/ETL/LOG/CSV | 支持并行 workers、批量插入、增量导入、进度回调 |
| `search` | 全文搜索事件 | 关键字/正则/事件ID/时间范围/级别/用户/计算机过滤 |
| `collect` | 一键采集 | 自动发现日志源、并行采集、ZIP 打包、SHA256 校验 |
| `alert` | 告警管理 | 列表、详情、解决、删除、导出、备注、误报标记 |
| `analyze` | 分析器执行 | 运行各种安全分析器 |
| `report` | 报告生成 | HTML/JSON/PDF 格式综合报告 |
| `dashboard` | 仪表板统计 | 采集统计、事件概览 |
| `config` | 配置管理 | 查看/设置配置 |
| `persistence` | 持久化检测 | Windows 持久化技术检测 |
| `system` | 系统信息 | 进程、网络、用户、注册表等 |
| `ueba` | UEBA 分析 | 用户行为异常检测 |
| `whitelist` | 白名单管理 | 告警抑制规则管理 |
| `db` | 数据库管理 | 状态、优化、清理 |
| `tui` | 终端界面 | Bubble Tea TUI (11 个视图) |
| `serve` | Web UI + API | React + Gin HTTP API |

---

## 二、核心引擎 (`internal/engine/`)

### 2.1 分析引擎 (`engine.go`)

**功能需求**:
```go
type Engine struct {
    db          *storage.DB
    parsers     map[string]parsers.Parser
    alertEngine *alerts.Engine
    corrEngine  *correlation.Engine
}

type ImportRequest struct {
    Paths          []string
    LogName        string
    Incremental    bool      // 增量导入 (默认 true)
    SkipPatterns   []string  // 跳过 Diagnostics/Debug
    Workers        int       // 并行数 (默认 4)
    BatchSize      int       // 批处理大小 (默认 10000)
    CalculateHash  bool      // 计算 SHA256
    ProgressCallback func(*ImportProgress)
}

type ImportProgress struct {
    TotalFiles     int
    CurrentFile    int
    CurrentFileName string
    EventsImported int64
    BytesProcessed int64
}
```

**处理流程**:
1. 解析文件列表
2. 识别文件类型 (EVTX/ETL/CSV/LOG)
3. 启动 Worker Pool 并行解析
4. 批量写入数据库
5. 触发告警评估
6. 更新统计

---

### 2.2 事件管道 (`pipeline.go`)

**功能需求**:
```go
type EventPipeline struct {
    parsers     []parsers.Parser
    workers     int
    batchSize   int
    bufferSize  int
}

// Worker Pool 并行处理
// 流式解析 + 批量插入
// 支持取消 (context)
// 支持进度回调
```

---

## 三、解析器 (`internal/parsers/`)

### 3.1 解析器接口 (`parser.go`)

**功能需求**:
```go
type Parser interface {
    CanParse(path string) bool              // 是否能解析
    Parse(path string) <-chan *Event        // 流式解析
    ParseBatch(path string) ([]*Event, error) // 批量解析
    GetType() string                        // 返回解析器类型
}

type ParserRegistry struct {
    parsers map[string]Parser
}

func (r *ParserRegistry) Register(p Parser)
func (r *ParserRegistry) Get(path string) Parser
```

### 3.2 EVTX 解析 (`evtx/`)

**功能需求**:
```go
type EvtxParser struct {
    useWevtutil bool  // 备用 wevtutil
}

func (p *EvtxParser) CanParse(path string) bool {
    ext := strings.ToLower(filepath.Ext(path))
    return ext == ".evtx"
}

func (p *EvtxParser) Parse(path string) <-chan *Event {
    // 1. 尝试原生解析
    // 2. 失败则使用 wevtutil
    // 3. 流式输出事件
}

type EvtxRecord struct {
    EventRecordID int64
    TimeCreated  time.Time
    EventID      int32
    Level        int
    Source       string
    Computer     string
    Channel      string
    Message      string
    XML          string
    Data         map[string]string
}
```

**支持的事件**:
- Windows Security Event Log (4688, 4624, 4625, etc.)
- Sysmon Event Log (Event ID 1-22)
- Microsoft-Windows-*

---

### 3.3 ETL 解析 (`etl/`)

**功能需求**:
```go
type EtlParser struct{}

func (p *EtlParser) Parse(path string) <-chan *Event {
    // 解析 ETW trace 文件
    // 提取事件头和数据
}
```

---

### 3.4 CSV/LOG 解析 (`csv/`)

**功能需求**:
```go
type CsvParser struct {
    Delimiter   string
    HasHeader   bool
    Columns     []string
}

func (p *CsvParser) Parse(path string) <-chan *Event {
    // 读取 CSV 文件
    // 映射到 Event 结构
}
```

---

### 3.5 IIS 解析 (`iis/`)

**功能需求**:
```go
type IISParser struct {
    Format string  // "w3c", "ncsa", "iis", "central"
}

type IISLog struct {
    Date        time.Time
    Time        time.Time
    ClientIP    string
    UserName    string
    Method      string
    URIStem     string
    URIQuery    string
    Status      int
    BytesSent   int64
    UserAgent   string
    Referer     string
}
```

---

### 3.6 Sysmon 解析 (`sysmon/`)

**功能需求**:
```go
type SysmonParser struct{}

type SysmonEvent struct {
    EventID   int
    Schema    string
    Image     string
    CommandLine string
    TargetFilename string
    Hashes    map[string]string
    ParentImage string
    ParentCommandLine string
    UserName  string
    Computer  string
    TimeCreated time.Time
}
```

---

## 四、采集器 (`internal/collectors/`)

### 4.1 系统信息采集

#### 4.1.1 元数据 (`system_info.go`)

**功能需求**:
```go
type SystemInfo struct {
    Hostname     string `json:"hostname"`
    Domain       string `json:"domain"`
    OSName       string `json:"os_name"`
    OSVersion    string `json:"os_version"`
    Architecture string `json:"architecture"`
    Admin        bool   `json:"is_admin"`
    TimeZone     string `json:"timezone"`
    LocalTime    time.Time `json:"local_time"`
    Uptime       time.Duration `json:"uptime"`
}
```

#### 4.1.2 进程信息 (`process_info.go`)

**功能需求**:
```go
type ProcessInfo struct {
    PID           int32  `json:"pid"`
    Name          string `json:"name"`
    PPID          int32  `json:"ppid"`
    Path          string `json:"path"`
    CommandLine   string `json:"command_line"`
    User          string `json:"user"`
    CPUPercent    float64 `json:"cpu_percent"`
    MemoryMB      float64 `json:"memory_mb"`
    StartTime     time.Time `json:"start_time"`
    Signature     string `json:"signature"`
    HashSHA256    string `json:"hash_sha256"`
    IsElevated    bool   `json:"is_elevated"`
}
```

#### 4.1.3 网络连接 (`network_info.go`)

**功能需求**:
```go
type NetworkConnection struct {
    Protocol    string `json:"protocol"`     // TCP/UDP
    LocalAddr   string `json:"local_addr"`
    LocalPort   int    `json:"local_port"`
    RemoteAddr  string `json:"remote_addr"`
    RemotePort  int    `json:"remote_port"`
    State       string `json:"state"`        // ESTABLISHED/LISTENING/etc.
    PID         int32  `json:"pid"`
    ProcessName string `json:"process_name"`
    Created     time.Time `json:"created"`
}
```

#### 4.1.4 用户账户 (`user_info.go`)

**功能需求**:
```go
type UserAccount struct {
    SID         string `json:"sid"`
    Name        string `json:"name"`
    Domain      string `json:"domain"`
    FullName    string `json:"full_name"`
    Type        string `json:"type"`          // User/Group/Admin
    Enabled     bool   `json:"enabled"`
    LastLogin   time.Time `json:"last_login"`
    PasswordAge time.Duration `json:"password_age"`
    PasswordExp bool   `json:"password_expires"`
    HomeDir     string `json:"home_dir"`
    ProfilePath string `json:"profile_path"`
}
```

#### 4.1.5 注册表自启动 (`registry_info.go`)

**功能需求**:
```go
type RegistryInfo struct {
    Path        string `json:"path"`
    Name        string `json:"name"`
    Value       string `json:"value"`
    Type        string `json:"type"`
    Source      string `json:"source"`        // Run/UserInit/etc.
    Enabled     bool   `json:"enabled"`
}

type RegistryPersistence struct {
    RunKeys     []*RegistryInfo  // HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    UserInit    []*RegistryInfo  // UserInit MPR
    TaskScheduler []*RegistryInfo // Scheduled Tasks
}
```

#### 4.1.6 计划任务 (`task_info.go`)

**功能需求**:
```go
type ScheduledTask struct {
    Name         string `json:"name"`
    Path         string `json:"path"`
    State        string `json:"state"`      // Ready/Disabled/Running
    LastRun      time.Time `json:"last_run"`
    NextRun      time.Time `json:"next_run"`
    LastResult   int `json:"last_result"`
    Description  string `json:"description"`
    Author       string `json:"author"`
    Actions      []TaskAction `json:"actions"`
    Triggers     []TaskTrigger `json:"triggers"`
}

type TaskAction struct {
    Type    string `json:"type"`  // Execute
    Path    string `json:"path"`
    Args    string `json:"args"`
}

type TaskTrigger struct {
    Type    string `json:"type"`
    Start  time.Time `json:"start"`
}
```

#### 4.1.7 驱动信息 (`driver_info.go`)

**功能需求**:
```go
type DriverInfo struct {
    Name        string `json:"name"`
    Description string `json:"description"`
    Type        string `json:"type"`      // Kernel/Filter/FS
    Status      string `json:"status"`    // Running/Stopped
    Started     bool   `json:"started"`
    FilePath    string `json:"file_path"`
    HashSHA256  string `json:"hash_sha256"`
    Signature   string `json:"signature"`
    Signer      string `json:"signer"`
}
```

#### 4.1.8 环境变量 (`env_info.go`)

**功能需求**:
```go
type EnvInfo struct {
    Key    string `json:"key"`
    Value  string `json:"value"`
    Type   string `json:"type"`  // System/User
}
```

#### 4.1.9 DLL 模块 (`dll_info.go`)

**功能需求**:
```go
type DLLModule struct {
    ProcessID   int32  `json:"process_id"`
    ProcessName string `json:"process_name"`
    BaseAddress string `json:"base_address"`
    Size        uint32 `json:"size"`
    Path        string `json:"path"`
    HashSHA256  string `json:"hash_sha256"`
}
```

---

### 4.2 持久化检测 (`internal/collectors/persistence/`)

#### 4.2.1 Prefetch (`prefetch.go`)

**功能需求**:
```go
type PrefetchInfo struct {
    Path       string    `json:"path"`
    Size       uint32    `json:"size"`
    LastRun    time.Time `json:"last_run"`
    RunCount   uint32    `json:"run_count"`
    Modified   time.Time `json:"modified"`
}
```

#### 4.2.2 ShimCache (`shimcache.go`)

**功能需求**:
```go
type ShimCacheEntry struct {
    Path      string    `json:"path"`
    Size      uint32    `json:"size"`
    Executed  bool      `json:"executed"`
    LastMod   time.Time `json:"last_modified"`
    LastUpd   time.Time `json:"last_update"`
}
```

#### 4.2.3 Amcache (`amcache.go`)

**功能需求**:
```go
type AmcacheEntry struct {
    VolumeGUID   string `json:"volume_guid"`
    Path         string `json:"path"`
    FileKey      string `json:"file_key"`
    Size         int64  `json:"size"`
    Hash         string `json:"hash"`
    ProductName  string `json:"product_name"`
    CompanyName  string `json:"company_name"`
    LastMod      time.Time `json:"last_modified"`
    Created      time.Time `json:"created"`
}
```

#### 4.2.4 UserAssist (`userassist.go`)

**功能需求**:
```go
type UserAssistEntry struct {
    Path       string    `json:"path"`
    FocusCount int       `json:"focus_count"`
    TimeFocus  int       `json:"time_focus"`
    LastRun    time.Time `json:"last_run"`
    SessionID  int       `json:"session_id"`
}
```

#### 4.2.5 USN Journal (`usnjournal.go`)

**功能需求**:
```go
type USNEntry struct {
    USN         int64     `json:"usn"`
    Timestamp   time.Time `json:"timestamp"`
    Reason      string    `json:"reason"`
    Path        string    `json:"path"`
    FileName    string    `json:"file_name"`
    FileAttributes string `json:"file_attributes"`
}
```

---

### 4.3 持久化技术检测 (`internal/persistence/`)

Phase 5 新增模块，检测 Windows 持久化技术，覆盖 MITRE ATT&CK T1546 系列。

#### 4.3.1 检测引擎 (`detector.go`)

```go
type DetectionEngine struct {
    detectors     map[string]Detector
    result        *DetectionResult
}

func RunAllDetectors(ctx context.Context) *DetectionResult
func DetectByCategory(ctx context.Context, category string) *DetectionResult
func DetectByTechnique(ctx context.Context, technique Technique) *DetectionResult
```

#### 4.3.2 注册表持久化检测 (`registry.go`)

| 检测器 | 描述 | Technique |
|--------|------|-----------|
| RunKeyDetector | Run/RunOnce 键 | T1546.001 |
| UserInitDetector | Winlogon UserInit | T1546.001 |
| StartupFolderDetector | 启动文件夹 | T1546.016 |

**检测内容**:
- HKLM/HKCU 下的 Run/RunOnce 键
- Winlogon Userinit 值修改
- All Users/Current User 启动文件夹

**可疑指标**:
- 路径包含 `%TEMP%`, `%APPDATA%`, 网络路径
- Base64 编码的值
- 未知程序路径

#### 4.3.3 辅助功能后门检测 (`accessibility.go`)

| 程序 | 激活方式 | Technique |
|------|----------|-----------|
| sethc.exe | 按 5 次 Shift | T1546.001 |
| utilman.exe | Windows + U | T1546.001 |
| osk.exe | Windows + O | T1546.001 |
| magnify.exe | Windows + = | T1546.001 |
| narrator.exe | Windows + Enter | T1546.001 |

#### 4.3.4 COM 劫持检测 (`com.go`)

**目标注册表**:
```
HKCR\CLSID\{...}\InprocServer32
```

**检测项**:
- 路径不在 System32/SysWOW64
- 路径包含 TEMP 或网络路径
- Empty CLSID
- ADO Stream Object

#### 4.3.5 IFEO 检测 (`ifeo.go`)

**目标注册表**:
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
```

**检测项**:
- Debugger 值被修改
- GlobalFlag 异常
- ShutdownFlags 异常

#### 4.3.6 AppInit_DLLs 检测 (`appinit.go`)

**目标注册表**:
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
```

#### 4.3.7 WMI 持久化检测 (`wmi.go`)

**订阅类型**:
- CommandLineEventConsumer - 执行命令
- ActiveScriptEventConsumer - 执行脚本
- NTEventLogEventConsumer - 写入事件日志

#### 4.3.8 服务持久化检测 (`service.go`)

**基于事件**:
- Event ID 4697: A service was installed

---

### 4.4 一键采集 (`one_click.go`)

**功能需求**:
```go
type OneClickCollector struct {
    outputPath   string
    compressLevel int      // 压缩级别 (0-9)
    calculateHash bool     // 计算 SHA256
    excludePatterns []string // 排除模式
    workers       int      // 并行数
}

type CollectOptions struct {
    OutputPath     string
    IncludeLogs    bool     // 采集日志
    IncludePrefetch bool    // 采集 Prefetch
    IncludeShimcache bool   // 采集 ShimCache
    IncludeAmcache  bool    // 采集 Amcache
    IncludeUserassist bool  // 采集 UserAssist
    IncludeRegistry  bool   // 采集注册表
    IncludeTasks     bool   // 采集计划任务
    IncludeSystemInfo bool  // 采集系统信息
    Compress        bool    // ZIP 压缩
    CompressLevel   int     // 压缩级别
    CalculateHash   bool    // SHA256 校验
    Password        string  // ZIP 密码 (可选)
}

type CollectResult struct {
    Success      bool
    OutputPath   string
    FileCount    int
    TotalSize    int64
    Duration     time.Duration
    Hash         string
    Errors       []error
}
```

**采集流程**:
1. 发现日志源 (`_discover_log_sources`)
2. 检测文件锁定 (`_is_file_locked`)
3. 并行复制文件 (Worker Pool)
4. 采集系统信息
5. 计算 SHA256 校验
6. 打包为 ZIP
7. 生成采集报告

---

### 4.5 实时采集 (`internal/collectors/live/`)

#### 4.5.1 基础采集器 (`collector.go`)

**功能需求**:
```go
type LiveCollector struct {
    config        *MonitorConfig
    eventChan     chan *Event
    statsChan     chan *LiveStats
    statusChan    chan *Status
    cancelFunc    context.CancelFunc
    
    // 去重
    dedupCache    *DedupCache
    dedupWindow   time.Duration
    
    // 自适应轮询
    pollInterval  time.Duration
    eventRate     float64
}

type MonitorConfig struct {
    LogSources   []LogSourceConfig
    Filters      MonitorFilters
    BufferSize   int           // 默认 50000
    DedupWindow  time.Duration // 默认 60s
    PollInterval PollIntervalConfig
}

type LogSourceConfig struct {
    Name     string
    Enabled  bool
    Channels []string
}

type MonitorFilters struct {
    EventIDs  []int32
    Levels    []int
    Keywords  []string
    Exclude   []string
}

type PollIntervalConfig struct {
    Initial   time.Duration // 默认 1s
    Min       time.Duration // 默认 0.2s
    Max       time.Duration // 默认 5s
    Adaptive  bool         // 默认 true
}

type LiveStats struct {
    TotalEvents   int64
    EventsPerSec  float64
    QueueSize     int
    QueueCapacity int
    Uptime        time.Duration
    ErrorCount    int
}
```

#### 4.4.2 书签支持 (`bookmark.go`)

**功能需求**:
```go
type BookmarkManager struct {
    bookmarkPath string
    bookmarks    map[string]*Bookmark
}

type Bookmark struct {
    LogName      string    `json:"log_name"`
    EventRecordID int64    `json:"event_record_id"`
    Timestamp    time.Time `json:"timestamp"`
    LastUpdated  time.Time `json:"last_updated"`
}

// 断点续采: 保存书签 → 中断 → 重启后从书签继续
```

#### 4.4.3 过滤采集 (`filtered.go`)

**功能需求**:
```go
type FilteredCollector struct {
    eventIDsFilter  []int32   // 事件ID白名单
    levelFilter     []int     // 级别白名单
    keywordFilter   []string  // 关键字包含
    excludeFilter   []string  // 关键字排除
}

func (f *FilteredCollector) ShouldCollect(event *Event) bool {
    // 检查事件ID
    if len(f.eventIDsFilter) > 0 && !contains(f.eventIDsFilter, event.EventID) {
        return false
    }
    
    // 检查级别
    if len(f.levelFilter) > 0 && !contains(f.levelFilter, int(event.Level)) {
        return false
    }
    
    // 检查关键字
    for _, kw := range f.keywordFilter {
        if !strings.Contains(event.Message, kw) {
            return false
        }
    }
    
    // 检查排除关键字
    for _, ex := range f.excludeFilter {
        if strings.Contains(event.Message, ex) {
            return false
        }
    }
    
    return true
}
```

---

## 五、告警引擎 (`internal/alerts/`)

### 5.1 告警引擎核心 (`engine.go`)

**功能需求**:
```go
type Engine struct {
    rules         []*rules.AlertRule
    dedupCache    *DedupCache
    suppressRules []*SuppressRule
    upgradeRules  []*AlertUpgradeRule
    stats         *AlertStats
    mu            sync.RWMutex
}

type Alert struct {
    ID           int64     `json:"id"`
    RuleName     string    `json:"rule_name"`
    Severity     Severity  `json:"severity"`
    Message      string    `json:"message"`
    EventIDs     []int32   `json:"event_ids"`
    FirstSeen    time.Time `json:"first_seen"`
    LastSeen     time.Time `json:"last_seen"`
    Count        int       `json:"count"`
    MITREAttack  []string  `json:"mitre_attack"`
    Resolved     bool      `json:"resolved"`
    ResolvedTime *time.Time `json:"resolved_time"`
    Notes        string    `json:"notes"`
    FalsePositive bool     `json:"false_positive"`
    LogName      string    `json:"log_name"`
    RuleScore    float64   `json:"rule_score"`
}
```

### 5.2 规则评估 (`evaluator.go`)

**功能需求**:
```go
func (e *Engine) Evaluate(event *Event) []*Alert {
    var alerts []*Alert
    
    for _, rule := range e.rules {
        if !rule.Enabled {
            continue
        }
        
        if e.matches(rule, event) {
            key := e.generateKey(rule, event)
            
            // 检查去重
            if e.dedupCache.IsDuplicate(key) {
                continue
            }
            
            // 检查抑制
            if e.IsSuppressed(event) {
                continue
            }
            
            e.dedupCache.Mark(key)
            alerts = append(alerts, e.createAlert(rule, event))
        }
    }
    
    return alerts
}
```

### 5.3 去重机制 (`dedup.go`)

**功能需求**:
```go
type DedupCache struct {
    data map[string]time.Time
    mu   sync.RWMutex
    ttl  time.Duration
}

func (c *DedupCache) IsDuplicate(key string) bool {
    c.mu.RLock()
    _, exists := c.data[key]
    c.mu.RUnlock()
    return exists
}

func (c *DedupCache) Mark(key string) {
    c.mu.Lock()
    c.data[key] = time.Now()
    c.mu.Unlock()
}

func (c *DedupCache) Cleanup() {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    cutoff := time.Now().Add(-c.ttl)
    for key, t := range c.data {
        if t.Before(cutoff) {
            delete(c.data, key)
        }
    }
}
```

### 5.4 告警统计 (`stats.go`)

**功能需求**:
```go
type AlertStats struct {
    Total        int64            `json:"total"`
    BySeverity   map[string]int64 `json:"by_severity"`
    ByStatus     map[string]int64 `json:"by_status"`
    ByRule       []*RuleCount     `json:"by_rule"`
    Trend        []*TrendPoint    `json:"trend"`
    AvgPerDay    float64          `json:"avg_per_day"`
}

type RuleCount struct {
    RuleName   string  `json:"rule_name"`
    Count      int64   `json:"count"`
    Percentage float64 `json:"percentage"`
}

type TrendPoint struct {
    Date  string `json:"date"`
    Count int64  `json:"count"`
}

// GET /api/alerts/stats
```

### 5.5 告警趋势 (`trend.go`)

**功能需求**:
```go
type AlertTrend struct {
    Daily     []*TrendPoint    // 每日趋势
    Weekly    []*TrendPoint    // 每周趋势
    ByHour    []*TrendPoint    // 每小时分布
    ByDayOfWeek []*TrendPoint  // 每周分布
}

func (e *Engine) CalculateTrend(days int) *AlertTrend {
    // SQL: SELECT DATE(first_seen), COUNT(*) FROM alerts GROUP BY DATE(first_seen)
    // 计算同比/环比增长率
    // 检测异常峰值
}
```

### 5.6 告警升级 (`upgrade.go`)

**功能需求**:
```go
type AlertUpgradeRule struct {
    ID          int64
    Name        string
    Condition   string  // "time_passed" / "count_threshold"
    Threshold   int
    NewSeverity Severity
    Notify      bool
    Enabled     bool
}

// time_passed: 告警未解决超过 X 小时
// count_threshold: 同一规则触发次数超过 X 次

func (e *Engine) CheckUpgrade(alert *Alert) {
    for _, rule := range e.upgradeRules {
        if !rule.Enabled {
            continue
        }
        
        switch rule.Condition {
        case "time_passed":
            hours := time.Since(alert.FirstSeen).Hours()
            if hours >= float64(rule.Threshold) {
                e.upgradeAlert(alert, rule)
            }
        case "count_threshold":
            count := e.getAlertCount(alert.RuleName)
            if count >= rule.Threshold {
                e.upgradeAlert(alert, rule)
            }
        }
    }
}
```

### 5.7 告警抑制 (`suppress.go`)

**功能需求**:
```go
type SuppressRule struct {
    ID         int64
    Name       string
    Conditions []Condition
    Duration   time.Duration
    Scope      string  // "rule" / "source" / "global"
    Enabled    bool
    ExpiresAt  time.Time
}

type Condition struct {
    Field    string
    Operator string  // equals / contains / regex
    Value    interface{}
}

func (e *Engine) IsSuppressed(alert *Alert) bool {
    for _, rule := range e.suppressRules {
        if !rule.Enabled {
            continue
        }
        
        if !rule.ExpiresAt.IsZero() && time.Now().After(rule.ExpiresAt) {
            continue
        }
        
        if e.matchesConditions(alert, rule.Conditions) {
            return true
        }
    }
    return false
}
```

---

## 六、关联引擎 (`internal/correlation/`)

### 6.1 关联引擎核心 (`engine.go`)

**功能需求**:
```go
type Engine struct {
    rules      []*rules.CorrelationRule
    eventIndex map[int32][]*Event
    timeIndex  map[int64][]*Event
    mu         sync.RWMutex
}

type CorrelationResult struct {
    ID          string     `json:"id"`
    RuleName    string     `json:"rule_name"`
    Description string     `json:"description"`
    Severity    Severity   `json:"severity"`
    Events      []*Event   `json:"events"`
    StartTime   time.Time  `json:"start_time"`
    EndTime     time.Time  `json:"end_time"`
    MITREAttack []string   `json:"mitre_attack"`
}

func (e *Engine) Analyze(ctx context.Context, timeWindow time.Duration) []*CorrelationResult {
    results := make([]*CorrelationResult, 0)
    
    for _, rule := range e.rules {
        if !rule.Enabled {
            continue
        }
        
        chains := e.findChains(rule, timeWindow)
        for _, chain := range chains {
            results = append(results, e.chainToResult(rule, chain))
        }
    }
    
    return results
}
```

### 6.2 模式匹配 (`matcher.go`)

**功能需求**:
```go
func (e *Engine) matches(rule *rules.CorrelationRule, event *Event) bool {
    for _, condition := range rule.Conditions {
        // 检查事件ID
        if !contains(condition.EventIDs, event.EventID) {
            return false
        }
        
        // 检查过滤器
        for _, filter := range condition.Filters {
            if !e.matchFilter(event, filter) {
                return false
            }
        }
    }
    return true
}
```

### 6.3 事件链 (`chain.go`)

**功能需求**:
```go
func (e *Engine) findChains(rule *rules.CorrelationRule, timeWindow time.Duration) [][]*Event {
    chains := make([][]*Event, 0)
    
    // 回溯查找事件链
    var backtrack func(idx int, events []*Event, chain []*Event)
    backtrack = func(idx int, events []*Event, chain []*Event) {
        if idx >= len(rule.Conditions) {
            if len(chain) >= 2 {
                chains = append(chains, append([]*Event{}, chain...))
            }
            return
        }
        
        condition := rule.Conditions[idx]
        matching := e.findMatchingEvents(condition, events)
        
        for _, event := range matching {
            // 检查 join_field
            if !e.matchesJoinField(rule, chain, event) {
                continue
            }
            
            chain = append(chain, event)
            backtrack(idx+1, events, chain)
            chain = chain[:len(chain)-1]
        }
    }
    
    // 从第一个条件开始
    firstEvents := e.findMatchingEvents(rule.Conditions[0], nil)
    for _, event := range firstEvents {
        backtrack(1, nil, []*Event{event})
    }
    
    return chains
}
```

---

## 七、规则系统 (`internal/rules/`)

### 7.1 统一规则接口 (`rule.go`)

**功能需求**:
```go
type Severity string

const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
    SeverityInfo     Severity = "info"
)

type BaseRule struct {
    Name        string     `json:"name"`
    Description string     `json:"description"`
    Severity    Severity   `json:"severity"`
    MITREAttack []string   `json:"mitre_attack"`
    Enabled     bool       `json:"enabled"`
    Tags        []string   `json:"tags"`
}

type AlertRule struct {
    BaseRule
    EventIDs       []int32     `json:"event_ids"`
    Filters        []Filter    `json:"filters"`
    ConditionOp    LogicalOp   `json:"condition_op"`  // AND/OR
    GroupBy        string      `json:"group_by"`
    Threshold      int         `json:"threshold"`
    TimeWindow     time.Duration `json:"time_window"`
    RuleScore      float64     `json:"rule_score"`
    Recommendations []string   `json:"recommendations"`
}

type CorrelationRule struct {
    BaseRule
    TimeWindow   time.Duration `json:"time_window"`
    Conditions   []Condition   `json:"conditions"`
    JoinField    string        `json:"join_field"`
    CrossBucket  bool          `json:"cross_bucket"`
}

type LogicalOp string

const (
    OpAnd LogicalOp = "AND"
    OpOr  LogicalOp = "OR"
)
```

### 7.2 规则加载 (`loader.go`)

**功能需求**:
```go
type Loader struct {
    rulesDir string
}

func (l *Loader) LoadRules() ([]*AlertRule, []*CorrelationRule, error) {
    // 1. 扫描 rules/ 目录
    // 2. 解析 YAML 文件
    // 3. 验证规则语法
    // 4. 返回规则列表
}

func (l *Loader) ValidateRule(rule interface{}) error {
    // 检查必填字段
    // 检查事件ID格式
    // 检查 MITRE ID 格式
    // 检查阈值范围
}
```

### 7.3 规则定义 (`builtin/definitions.go`)

**内置规则 (90+)**:

| 类别 | 规则数 | 示例 |
|------|--------|------|
| 凭据访问 | 10+ | Weak Password, Cached Credentials, DCSync |
| 暴力破解 | 5+ | RDP Brute Force, SMB Brute Force, WinRM Brute Force |
| 横向移动 | 15+ | Pass-the-Hash, WMI Remote Exec, SMB Lateral |
| 权限维持 | 12+ | Scheduled Task Persistence, Registry Run, COM Hijack |
| Kerberos | 5+ | Golden Ticket, Silver Ticket, Kerberoasting |
| PowerShell | 10+ | Encoded Command, Suspicious Profile, Download |
| WinRM | 15+ | WinRM Remote Exec, PS Remote Session, Brute Force |
| UEBA | 3+ | Off-hours Login, Massive File Access, Privilege Escalation |
| 防御规避 | 12+ | Disable Security Tools, Clear Logs, AMSI Bypass |
| 勒索软件 | 3+ | Shadow Copy Deletion, File Encryption |
| 威胁检测 | 10+ | Cobalt Strike, Mimikatz, DNS Tunneling, LOLBAS |
| 其他攻击 | 5+ | Malware Execution, DLL Search Order, BloodHound |

**关联规则 (6)**:
- brute-force-attack: 暴力破解攻击模式
- lateral-movement: 横向移动攻击模式
- privilege-escalation-chain: 权限提升攻击链
- persistence-chain: 持久化攻击链
- credential-dump-chain: 凭据窃取攻击链
- ransomware-preparation: 勒索软件准备阶段

### 7.4 MITRE ATT&CK (`builtin/mitre.go`)

**功能需求**:
```go
var MITRE ATTACK_MAPPINGS = map[string]MITREMapping{
    "T1078": {
        Name:        "Valid Accounts",
        Tactics:     []string{"Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"},
        Description: "Adversaries may obtain and abuse credentials...",
    },
    "T1110": {
        Name:        "Brute Force",
        Tactics:     []string{"Credential Access"},
        Description: "Adversaries may use brute force...",
    },
    // ...
}
```

---

## 八、分析器 (`internal/analyzers/`)

### 8.1 暴力破解检测 (`brute_force.go`)

**功能需求**:
```go
type BruteForceResult struct {
    Type          string    `json:"type"`  // rdp/smb/ldap
    TargetAccount string    `json:"target_account"`
    SourceIP      string    `json:"source_ip"`
    Attempts      int       `json:"attempts"`
    TimeWindow    time.Duration `json:"time_window"`
    ThreatLevel   Severity  `json:"threat_level"`
    FirstAttempt  time.Time `json:"first_attempt"`
    LastAttempt   time.Time `json:"last_attempt"`
}

func (a *BruteForceAnalyzer) Analyze(events []*Event) []*BruteForceResult {
    // 1. 过滤失败登录事件 (4625)
    // 2. 按账户聚合
    // 3. 按 IP 聚合
    // 4. 计算时间密度
    // 5. 检测阈值超过
}
```

### 8.2 登录分析 (`login.go`)

**功能需求**:
```go
type LoginAnalysis struct {
    TotalSuccess   int64   `json:"total_success"`
    TotalFailure   int64   `json:"total_failure"`
    SuccessByType  map[int]int64 `json:"success_by_type"`
    FailureByType  map[int]int64 `json:"failure_by_type"`
    TopUsers       []*UserLogin  `json:"top_users"`
    SuspiciousLogins []*SuspiciousLogin `json:"suspicious_logins"`
}

type UserLogin struct {
    Username    string `json:"username"`
    Count       int64  `json:"count"`
    LastLogin   time.Time `json:"last_login"`
}

type SuspiciousLogin struct {
    Username    string `json:"username"`
    Type       string `json:"type"`
    SourceIP    string `json:"source_ip"`
    Time        time.Time `json:"time"`
    Reason      string `json:"reason"`
}
```

### 8.3 Kerberos 分析 (`kerberos.go`)

**功能需求**:
```go
type KerberosAnalysis struct {
    TicketWarnings []*TicketWarning `json:"ticket_warnings"`
    GoldenTicket   []*GoldenTicket  `json:"golden_ticket"`
    SilverTicket   []*SilverTicket  `json:"silver_ticket"`
}

type GoldenTicket struct {
    Username    string    `json:"username"`
    Lifetime    time.Duration `json:"lifetime"`
    EndTime     time.Time `json:"end_time"`
    ThreatLevel Severity  `json:"threat_level"`
}

type TicketWarning struct {
    Type    string    `json:"type"`
    Message string    `json:"message"`
    Count   int       `json:"count"`
}
```

### 8.4 PowerShell 分析 (`powershell.go`)

**功能需求**:
```go
type PowerShellAnalysis struct {
    TotalCommands int64           `json:"total_commands"`
    EncodedCmds   int64           `json:"encoded_commands"`
    SuspiciousCmds []*SuspiciousCmd `json:"suspicious_commands"`
    RiskScore     float64         `json:"risk_score"`
}

type SuspiciousCmd struct {
    Time        time.Time `json:"time"`
    Command     string    `json:"command"`
    User        string    `json:"user"`
    RiskLevel   string    `json:"risk_level"`
    Reasons     []string  `json:"reasons"`
}
```

### 8.5 数据外泄分析 (`data_exfiltration.go`)

**功能需求**:
```go
type DataExfiltrationAnalyzer struct {
    BaseAnalyzer
}

type DataExfiltrationResult struct {
    SuspiciousTransfers []*SuspiciousTransfer `json:"suspicious_transfers"`
    LargeFileAccess     []*LargeFileAccess     `json:"large_file_access"`
    ExternalDestinations []*ExternalDestination `json:"external_destinations"`
    RiskScore           float64               `json:"risk_score"`
}

type SuspiciousTransfer struct {
    User       string    `json:"user"`
    SourcePath string    `json:"source_path"`
    DestIP     string    `json:"dest_ip"`
    BytesOut   int64     `json:"bytes_out"`
    Timestamp  time.Time `json:"timestamp"`
    RiskLevel  string    `json:"risk_level"`
}
```

### 8.6 横向移动分析 (`lateral_movement.go`)

**功能需求**:
```go
type LateralMovementAnalyzer struct {
    BaseAnalyzer
}

type LateralMovementResult struct {
    SuspiciousConnections []*SuspiciousConnection `json:"suspicious_connections"`
    RemoteExecutions     []*RemoteExecution     `json:"remote_executions"`
    PassTheHash         []*PassTheHashEvent    `json:"pass_the_hash"`
    RiskScore           float64               `json:"risk_score"`
}

type SuspiciousConnection struct {
    SourceIP   string    `json:"source_ip"`
    DestIP     string    `json:"dest_ip"`
    Protocol   string    `json:"protocol"`
    Port       int       `json:"port"`
    Timestamp  time.Time `json:"timestamp"`
    RiskLevel  string    `json:"risk_level"`
}
```

---

## 九、存储 (`internal/storage/`)

### 9.1 数据库 (`db.go`)

**功能需求**:
```go
type DB struct {
    conn *sql.DB
    path string
}

func NewDB(path string) (*DB, error) {
    db := &DB{path: path}
    
    // 打开 SQLite WAL 模式
    conn, err := sql.Open("sqlite3", path+"?_journal_mode=WAL")
    if err != nil {
        return nil, err
    }
    
    db.conn = conn
    
    // 创建表
    if err := db.createTables(); err != nil {
        return nil, err
    }
    
    return db, nil
}
```

### 9.2 Schema (`schema.go`)

**数据表**:

| 表名 | 说明 |
|------|------|
| `events` | 事件表 (含 FTS5 全文搜索) |
| `events_fts` | 事件全文搜索虚拟表 |
| `alerts` | 告警表 |
| `import_log` | 导入日志 |
| `machine_context` | 机器上下文 |
| `multi_machine_analysis` | 多机分析 |
| `global_timeline` | 全局时间线 |
| `sessions` | 会话表 |
| `evidence_chain` | 证据链 (区块链式结构) |
| `evidence_file` | 证据文件 |
| `processes` | 系统进程快照 |
| `network_connections` | 网络连接 |
| `system_info` | 系统信息快照 |
| `reports` | 报告表 |
| `suppress_rules` | 告警抑制规则 |
| `rule_states` | 规则启用/禁用状态 |

### 9.3 Repository (`repository.go`)

**功能需求**:
```go
type EventRepository interface {
    Insert(*Event) error
    InsertBatch([]*Event) error
    GetByID(int64) (*Event, error)
    Search(*SearchRequest) ([]*Event, int64, error)
    DeleteByImportID(int64) error
}

type AlertRepository interface {
    Insert(*Alert) error
    Update(*Alert) error
    GetByID(int64) (*Alert, error)
    List(*AlertQuery) ([]*Alert, int64, error)
    Resolve(int64, string) error
    Delete(int64) error
}
```

---

## 十、报告 (`internal/reports/`)

### 10.1 报告生成 (`generator.go`)

**功能需求**:
```go
type Generator struct {
    templateDir string
}

type ReportRequest struct {
    Type      string  // "comprehensive" / "security" / "alert"
    Format    string  // "html" / "json"
    TimeRange *TimeRange
    Filters   *ReportFilters
}

type TimeRange struct {
    Start time.Time
    End   time.Time
}

type ReportFilters struct {
    EventIDs  []int32
    Levels    []int
    LogNames  []string
    Computers []string
}
```

### 10.2 安全统计 (`security_stats.go`)

**功能需求**:
```go
type SecurityStats struct {
    TotalEvents      int64              `json:"total_events"`
    EventDistribution map[string]int64  `json:"event_distribution"`
    LevelDistribution map[string]int64  `json:"level_distribution"`
    TopEventIDs      []*EventIDCount    `json:"top_event_ids"`
    LoginStats       *LoginStatistics   `json:"login_stats"`
    BruteForceStats  []*BruteForceStats `json:"brute_force_stats"`
    IOCSummary       *IOCSummary        `json:"ioc_summary"`
    MITREDistribution map[string]int64  `json:"mitre_distribution"`
}

type LoginStatistics struct {
    SuccessLogins  int64 `json:"success_logins"`
    FailedLogins   int64 `json:"failed_logins"`
    SuccessByType  map[int]int64 `json:"success_by_type"`
    FailedByType   map[int]int64 `json:"failed_by_type"`
}

type IOCSummary struct {
    IPs      []*IOCount `json:"ips"`
    Domains  []*IOCount `json:"domains"`
    Hashes   []*IOCount `json:"hashes"`
    URLs     []*IOCount `json:"urls"`
}
```

---

## 十一、导出器 (`internal/exporters/`)

### 11.1 导出接口设计

**功能需求**:
```go
type Exporter interface {
    Export(events []*Event, writer io.Writer) error
    ContentType() string
    FileExtension() string
}

type ExporterFactory struct{}

func (f *ExporterFactory) Create(format string) Exporter {
    switch format {
    case "csv":
        return &CsvExporter{}
    case "excel", "xlsx":
        return &ExcelExporter{}
    case "json":
        return &JsonExporter{}
    default:
        return &JsonExporter{}
    }
}
```

### 11.2 JSON 导出

**功能需求**:
```go
type JsonExporter struct {
    prettyPrint bool
}

func (e *JsonExporter) Export(events []*Event, writer io.Writer) error {
    encoder := json.NewEncoder(writer)
    if e.prettyPrint {
        encoder.SetIndent("", "  ")
    }
    return encoder.Encode(events)
}
```

### 11.3 CSV 导出

**功能需求**:
```go
type CsvExporter struct {
    delimiter rune
}

func (e *CsvExporter) Export(events []*Event, writer io.Writer) error {
    w := csv.NewWriter(writer)
    
    // 写入表头
    headers := []string{"ID", "Timestamp", "EventID", "Level", "Source", "LogName", "Computer", "User", "UserSID", "Message", "SessionID", "IPAddress", "ImportTime"}
    w.Write(headers)
    
    // 写入数据
    for _, event := range events {
        row := []string{
            fmt.Sprintf("%d", event.ID),
            event.Timestamp.Format(time.RFC3339),
            fmt.Sprintf("%d", event.EventID),
            event.Level.String(),
            event.Source,
            event.LogName,
            event.Computer,
            nilToString(event.User),
            nilToString(event.UserSID),
            event.Message,
            nilToString(event.SessionID),
            nilToString(event.IPAddress),
            event.ImportTime.Format(time.RFC3339),
        }
        w.Write(row)
    }
    
    w.Flush()
    return w.Error()
}
```

### 11.4 Excel 导出

**功能需求**:
```go
type ExcelExporter struct{}

func (e *ExcelExporter) Export(events []*Event, writer io.Writer) error {
    f := excelize.NewFile()
    defer f.Close()
    
    // 创建工作表
    sheet := "Events"
    index, _ := f.NewSheet(sheet)
    f.SetActiveSheet(index)
    
    // 写入表头
    headers := []string{"ID", "Timestamp", "EventID", "Level", "Source", "LogName", "Computer", "User", "Message"}
    for i, h := range headers {
        cell, _ := excelize.CoordinatesToCellName(i+1, 1)
        f.SetCellValue(sheet, cell, h)
    }
    
    // 写入数据
    for rowIdx, event := range events {
        f.SetCellValue(sheet, fmt.Sprintf("A%d", rowIdx+2), event.ID)
        f.SetCellValue(sheet, fmt.Sprintf("B%d", rowIdx+2), event.Timestamp.Format(time.RFC3339))
        f.SetCellValue(sheet, fmt.Sprintf("C%d", rowIdx+2), event.EventID)
        f.SetCellValue(sheet, fmt.Sprintf("D%d", rowIdx+2), event.Level.String())
        f.SetCellValue(sheet, fmt.Sprintf("E%d", rowIdx+2), event.Source)
        f.SetCellValue(sheet, fmt.Sprintf("F%d", rowIdx+2), event.LogName)
        f.SetCellValue(sheet, fmt.Sprintf("G%d", rowIdx+2), event.Computer)
        f.SetCellValue(sheet, fmt.Sprintf("H%d", rowIdx+2), nilToString(event.User))
        f.SetCellValue(sheet, fmt.Sprintf("I%d", rowIdx+2), event.Message)
    }
    
    return f.Write(writer)
}
```

### 11.5 API 导出接口 (支持过滤)

**接口设计**:
```
POST /api/events/export
Content-Type: application/json

{
    "format": "csv" | "excel" | "json",
    "filters": {
        "event_ids": [4624, 4625],
        "levels": [1, 2],
        "log_names": ["Security"],
        "computers": ["WORKSTATION1"],
        "start_time": "2024-01-01T00:00:00Z",
        "end_time": "2024-01-31T23:59:59Z",
        "keywords": "登录失败",
        "limit": 10000
    }
}
```

**响应**:
- CSV/Excel: 直接返回文件流
- JSON: 返回 JSON 数据

**过滤条件**:
| 字段 | 类型 | 说明 |
|------|------|------|
| event_ids | []int32 | 事件ID列表 |
| levels | []int | 事件级别 |
| log_names | []string | 日志名称 |
| computers | []string | 计算机名 |
| users | []string | 用户名 |
| start_time | string | 开始时间 (RFC3339) |
| end_time | string | 结束时间 (RFC3339) |
| keywords | string | 关键字搜索 |
| limit | int | 导出上限 (默认10000) |

---

## 十二、时间线 (`internal/timeline/`)

### 12.1 时间线构建 (`builder.go`)

**功能需求**:
```go
type TimelineBuilder struct {
    events []*Event
}

type TimelineEvent struct {
    Event      *Event
    Group      string      // 机器名或自定义分组
    Category   string      // 事件类别
    Severity   string      // 严重级别
    MITRE      []string    // MITRE ATT&CK ID
    AttackChain *string   // 攻击链 ID
}

func (b *TimelineBuilder) Build() []*TimelineEvent {
    // 1. 按时间排序
    // 2. 按机器分组
    // 3. 分类事件
    // 4. 关联攻击链
}
```

### 12.2 可视化 (`visualizer.go`)

**功能需求**:
```go
type TimelineVisualizer struct {
    timeRange TimeRange
    groups    []string
    filters   TimelineFilters
}

type TimelineFilters struct {
    Levels    []int
    Groups    []string
    EventIDs  []int32
    MITRE     []string
    SearchText string
}

// Web UI 组件
// - 缩放控制 (滚轮)
// - 平移 (拖拽)
// - 框选 (Shift+鼠标)
// - 点击查看详情
// - MITRE 标签
// - 缩略图导航
```

---

## 十三、多机分析 (`internal/multi/`)

**功能需求**:
```go
type MultiMachineAnalyzer struct {
    machines map[string]*MachineContext
}

type MachineContext struct {
    ID        string    `json:"id"`
    Name      string    `json:"name"`
    IP        string    `json:"ip"`
    Role      string    `json:"role"`  // DC/Server/Workstation
    Events    []*Event  `json:"events"`
    FirstSeen time.Time `json:"first_seen"`
    LastSeen  time.Time `json:"last_seen"`
}

type LateralMovement struct {
    SourceMachine string    `json:"source_machine"`
    TargetMachine string    `json:"target_machine"`
    User          string    `json:"user"`
    Technique     string    `json:"technique"`
    Time          time.Time `json:"time"`
    Evidence      []*Event  `json:"evidence"`
}
```

---

## 十四、取证 (`internal/forensics/`)

### 14.1 哈希计算 (`hash.go`)

**功能需求**:
```go
type HashResult struct {
    FilePath string `json:"file_path"`
    SHA256   string `json:"sha256"`
    MD5      string `json:"md5,omitempty"`
    SHA1     string `json:"sha1,omitempty"`
    Size     int64  `json:"size"`
}

func CalculateFileHash(path string) (*HashResult, error) {
    file, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer file.Close()
    
    sha256Hash := sha256.New()
    md5Hash := md5.New()
    
    writer := io.MultiWriter(sha256Hash, md5Hash)
    if _, err := io.Copy(writer, file); err != nil {
        return nil, err
    }
    
    info, _ := file.Stat()
    
    return &HashResult{
        FilePath: path,
        SHA256:   hex.EncodeToString(sha256Hash.Sum(nil)),
        MD5:      hex.EncodeToString(md5Hash.Sum(nil)),
        Size:     info.Size(),
    }, nil
}
```

### 14.2 数字签名 (`signature.go`)

**功能需求**:
```go
type SignatureResult struct {
    Status       string `json:"status"`  // Valid/Invalid/None
    Signer       string `json:"signer,omitempty"`
    Issuer       string `json:"issuer,omitempty"`
    Thumbprint   string `json:"thumbprint,omitempty"`
    NotBefore    time.Time `json:"not_before,omitempty"`
    NotAfter     time.Time `json:"not_after,omitempty"`
}

func VerifySignature(path string) (*SignatureResult, error) {
    // 使用 Windows API 获取 Authenticode 签名
    // 返回签名状态和详细信息
}
```

### 14.3 证据链 (`chain.go`)

**功能需求**:
```go
type EvidenceChain struct {
    ID            string    `json:"id"`
    Timestamp     time.Time `json:"timestamp"`
    Operator      string    `json:"operator"`
    Action        string    `json:"action"`
    InputHash     string    `json:"input_hash"`
    OutputHash    string    `json:"output_hash"`
    PreviousHash  string    `json:"previous_hash"`  // 区块链式结构
}

type EvidenceManifest struct {
    CollectedAt   time.Time     `json:"collected_at"`
    Collector     string        `json:"collector"`
    MachineName   string        `json:"machine_name"`
    MachineID     string        `json:"machine_id"`
    Files         []HashResult   `json:"files"`
    DigitalSignature *Signature `json:"digital_signature,omitempty"`
}
```

---

## 十五、可观测性 (`internal/observability/`)

### 15.1 Metrics (`metrics.go`)

**功能需求**:
```go
type MetricsCollector struct {
    eventsTotal     prometheus.Counter
    eventsImported  prometheus.Counter
    alertsTriggered prometheus.Counter
    importDuration  prometheus.Histogram
    queryDuration   prometheus.Histogram
    dbSize          prometheus.Gauge
    activeSessions  prometheus.Gauge
}

// Prometheus 端点: GET /metrics
```

### 15.2 日志 (`logging.go`)

**功能需求**:
```go
type LoggerConfig struct {
    Level      string  // debug/info/warn/error
    Format     string  // json/plain
    Output     string  // stdout/file
    FilePath   string
    MaxSize    int     // MB
    MaxBackups int
    MaxAge     int     // days
}
```

---

## 十六、TUI 界面 (`internal/tui/`)

### 16.1 视图列表

| 视图 | 功能 | 快捷键 |
|------|------|--------|
| Dashboard | 统计概览、告警摘要 | `d` |
| Events | 事件列表、分页、过滤 | `e` |
| Event Detail | 事件详情 | `Enter` |
| Alerts | 告警列表、处置 | `a` |
| Alert Detail | 告警详情 | `Enter` |
| Search | 搜索界面 | `/` |
| Timeline | 时间线 | `t` |
| Collect | 一键采集 | `c` |
| Live Monitor | 实时监控 | `l` |
| Help | 帮助信息 | `?` |
| Settings | 配置管理 | `,` |
| Persistence | 持久化检测 | `p` |

### 16.2 键位映射

```go
var keyMap = KeyMap{
    // 全局
    "q":        "退出",
    "?":        "帮助",
    "/":        "搜索",
    "esc":      "返回",
    
    // 导航
    "j":        "下移",
    "k":        "上移",
    "g":        "跳转到顶部",
    "G":        "跳转到底部",
    "h":        "左移/返回",
    "l":        "右移/进入",
    
    // 操作
    "enter":    "选择/查看详情",
    "r":        "刷新",
    "i":        "导入",
    "e":        "导出",
    "d":        "删除",
    "space":    "选中/取消选中",
}
```

---

## 十七、Web UI (`internal/gui/src/`)

### 17.1 页面列表

| 页面 | 路由 | 功能 |
|------|------|------|
| Dashboard | `/` | 统计图表、告警概览 |
| Events | `/events` | 事件列表、筛选、分页 |
| Event Detail | `/events/:id` | 事件详情、XML |
| Alerts | `/alerts` | 告警列表、管理 |
| Alert Detail | `/alerts/:id` | 告警详情、处置 |
| Timeline | `/timeline` | 攻击链可视化 |
| Reports | `/reports` | 报告生成 |
| Forensics | `/forensics` | 取证采集、Hash 验证 |
| SystemInfo | `/system-info` | 系统信息采集 |
| Rules | `/rules` | 规则管理、编辑器 |
| Settings | `/settings` | 配置管理 |
| Metrics | `/metrics` | Prometheus 指标 |
| Collect | `/collect` | 一键采集 |
| Live | `/live` | 实时监控 |
| Multi | `/multi` | 多机分析 |
| Query | `/query` | SQL 查询 |
| Persistence | `/persistence` | 持久化检测 |
| Suppress | `/suppress` | 白名单管理 |
| Correlation | `/correlation` | 关联分析 |
| UEBA | `/ueba` | 用户行为分析 |
| Analyze | `/analyze` | 分析器执行 |

### 17.2 组件列表

| 组件 | 功能 |
|------|------|
| Table | 虚拟滚动、分页、可选择列 |
| Badge | 级别/状态标签 |
| Chart | Chart.js 图表 |
| Modal | 弹窗对话框 |
| Pagination | 分页导航 |
| LevelBadge | 事件级别着色 |
| SeverityBadge | 告警严重级别着色 |
| StatusBadge | 告警状态着色 |
| SearchBar | 搜索输入框 |
| DateRangePicker | 日期范围选择 |
| FilterPanel | 过滤器面板 |
| EventDetail | 事件详情面板 |
| AlertDetail | 告警详情面板 |
| Timeline | 时间线组件 |

---

## 功能统计

| 类别 | 模块数 | 功能数 |
|------|--------|--------|
| CLI 命令 | 15 | 15 |
| 核心引擎 | 3 | 5+ |
| 解析器 | 6 | 10+ |
| 系统信息采集 | 12 | 40+ |
| 持久化检测 | 15 | 50+ |
| 实时采集 | 4+ | 15+ |
| 告警引擎 | 7 | 25+ |
| 关联引擎 | 3 | 10+ |
| 规则系统 | 7 | 90+ |
| 分析器 | 8 | 15+ |
| 存储 | 15 | 50+ |
| 报告 | 6+ | 15+ |
| 导出器 | 6 | 10+ |
| 时间线 | 2 | 10+ |
| 多机分析 | 1 | 5+ |
| 取证 | 6 | 15+ |
| 可观测性 | 3 | 10+ |
| API Handlers | 20+ | 80+ |
| TUI | 12 | 35+ |
| Web UI | 21 | 60+ |
| **总计** | ~170 | **~500+** |

---

## 十八、实现状态跟踪 (2026-04-17 更新)

### 18.1 已完成模块 ✅

| 模块 | 状态 | 文件数 | 说明 |
|------|------|--------|------|
| **CLI 命令** | ✅ 完成 | 15 | import, search, collect, alert, analyze, report, dashboard, config, persistence, system, ueba, whitelist, db, tui, serve |
| **核心引擎** | ✅ 完成 | 3 | engine.go, importer.go, pipeline.go |
| **解析器** | ✅ 完成 | 6 | evtx, etl, csv, iis, sysmon, parser.go |
| **系统信息采集** | ✅ 完成 | 10+ | process, network, registry, driver, dll, task, user, env, system_info, one_click |
| **持久化检测** | ✅ 完成 | 15 | RunKey, UserInit, StartupFolder, Accessibility, COM, IFEO, AppInit, WMI, Service, LSA, Winsock, BHO, PrintMonitor, BootExecute, ETW |
| **实时采集** | ✅ 完成 | 4+ | collector, filtered, bookmark, stats |
| **告警引擎** | ✅ 完成 | 7 | engine, dedup, evaluator, stats, trend, upgrade, suppress |
| **关联引擎** | ✅ 完成 | 3 | engine, matcher, chain |
| **规则系统** | ✅ 完成 | 4+ | rule, loader, validator, custom_rules, builtin |
| **分析器** | ✅ 完成 | 8 | brute_force, login, kerberos, powershell, data_exfiltration, lateral_movement, privilege_escalation, persistence |
| **存储** | ✅ 完成 | 5+ | db, events, alerts, system, schema |
| **报告** | ✅ 完成 | 4+ | generator, html, json, security_stats, template |
| **导出器** | ✅ 完成 | 5 | csv, evtx, excel, json, timeline |
| **时间线** | ✅ 完成 | 2 | builder, visualizer |
| **取证** | ✅ 完成 | 5 | chain, hash, memory, signature, timestamp |
| **可观测性** | ✅ 完成 | 3 | logging, metrics, system |
| **API Handlers** | ✅ 完成 | 16 | handlers, handlers_analyze, handlers_collect, handlers_dashboard, handlers_forensics, handlers_live, handlers_persistence, handlers_reports, handlers_rules, handlers_settings, handlers_suppress, handlers_system, handlers_ueba |
| **TUI** | ✅ 完成 | 4 | model, update, view, styles |
| **Web UI** | ✅ 完成 | React+Vite | React + TypeScript + Vite + Chart.js |

### 18.2 API 路由清单

| 路由组 | 端点数 | 说明 |
|--------|--------|------|
| `/api/health` | 1 | 健康检查 |
| `/api/events` | 4 | 列表、详情、搜索、导出 |
| `/api/alerts` | 12 | 列表、详情、解决、误报、趋势、运行分析、批量操作 |
| `/api/timeline` | 5 | 时间线、统计、攻击链、导出、删除 |
| `/api/import` | 2 | 导入日志、状态查询 |
| `/api/live` | 2 | 实时事件流(SSE)、统计 |
| `/api/dashboard` | 1 | 采集统计 |
| `/api/persistence` | 5 | 检测、分类、技术列表、实时检测流 |
| `/api/system` | 11 | 信息、指标、进程、网络、驱动、用户、注册表、任务 |
| `/api/rules` | 14 | CRUD、切换、验证、导入导出、模板 |
| `/api/reports` | 9 | 列表、生成、详情、模板管理、导出 |
| `/api/forensics` | 10 | 哈希、签名、证据、清单、链式取证、内存 dump |
| `/api/settings` | 3 | 获取、保存、重置 |
| `/api/analyze` | 4 | 运行分析、列出分析器、获取分析器信息 |
| `/api/collect` | 3 | 开始采集、导入日志、状态查询 |
| `/api/suppress` | 6 | 白名单规则 CRUD、切换 |
| `/api/ueba` | 3 | 分析、用户画像、异常详情 |
| `/api/correlation` | 1 | 关联分析 |
| `/api/multi` | 2 | 多机分析、横向移动 |
| `/api/query` | 1 | SQL 查询执行 |
| `/api/ui` | 4 | Dashboard概览、告警分组、指标、事件分布 |
| `/api/policy` | 4 | 策略模板管理 |

### 18.3 分析器清单

| 分析器 | 功能 | MITRE |
|--------|------|-------|
| BruteForceAnalyzer | 暴力破解检测 | T1110 |
| LoginAnalyzer | 登录分析 | T1078 |
| KerberosAnalyzer | Kerberos攻击检测 | T1558 |
| PowerShellAnalyzer | PowerShell命令分析 | T1059.001 |
| DataExfiltrationAnalyzer | 数据外泄检测 | T1041 |
| LateralMovementAnalyzer | 横向移动检测 | T1021 |
| PrivilegeEscalationAnalyzer | 权限提升分析 | T1068 |
| PersistenceAnalyzer | 持久化行为分析 | T1543 |

### 18.4 持久化检测器清单 (15个)

| 检测器 | 技术ID | 说明 |
|--------|--------|------|
| RunKeyDetector | T1547.001 | 注册表Run键 |
| UserInitDetector | T1547.001 | UserInit执行 |
| StartupFolderDetector | T1547.001 | 启动文件夹 |
| AccessibilityDetector | T1546.008 | 辅助功能 |
| COMHijackDetector | T1546.015 | COM劫持 |
| IFEODetector | T1546.008 | IFEO注入 |
| AppInitDetector | T1546.016 | AppInit DLL |
| WMIPersistenceDetector | T1546.003 | WMI持久化 |
| ServicePersistenceDetector | T1543.003 | 服务创建 |
| LSAPersistenceDetector | T1546.008 | LSA保护 |
| WinsockDetector | T1546.011 | Winsock LSP |
| BHODetector | T1546.008 | 浏览器扩展 |
| PrintMonitorDetector | T1546.010 | 打印监视器 |
| BootExecuteDetector | T1546.009 | Boot执行 |
| ETWDetector | T1546.006 | ETW绕过 |

---

*文档版本: v2.4.0 | 更新日期: 2026-04-17 | 状态: 实现完成*
