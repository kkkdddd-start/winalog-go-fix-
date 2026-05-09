# WinLogAnalyzer-Go 架构文档

## 系统概述

WinLogAnalyzer-Go 是一个高性能的 Windows 安全取证与日志分析工具，使用 Go 语言重写自 Python 版本。

| 指标 | 目标 |
|------|------|
| EVTX 解析速度 | ≥150万条/分钟 |
| 内存占用 (1GB EVTX) | ≤200MB |
| 启动时间 | ≤100ms |

## 核心架构

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI (Cobra)                             │
│  import, search, collect, alert, analyze, report, correlate... │
└─────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                        TUI (Bubble Tea)                         │
│              Dashboard, Events, Alerts, Timeline...              │
└─────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                     API Server (Gin)                            │
│                  REST API + WebSocket                            │
└─────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Engine (Core)                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Import   │  │ Search   │  │ Analyze │  │ Export  │       │
│  │ Pipeline │  │ Engine   │  │ Engine  │  │ Engine  │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
└─────────────────────────────────────────────────────────────────┘
                                   │
          ┌────────────────────────┼────────────────────────┐
          ▼                        ▼                        ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│   Parsers        │  │   Storage       │  │   Alerts         │
│  ┌─────────────┐ │  │  ┌─────────────┐│  │  ┌─────────────┐│
│  │ EVTX       │ │  │  │ SQLite      ││  │  │ Engine      ││
│  │ ETL        │ │  │  │ (modernc)  ││  │  │ Evaluator   ││
│  │ CSV        │ │  │  └─────────────┘│  │  │ Dedup       ││
│  │ IIS        │ │  └──────────────────┘  │  │ Stats       ││
│  │ Sysmon     │ │                         │  └─────────────┘│
│  └─────────────┘ │                                                │
└──────────────────┘                                                │
                                   │                                 │
                                   ▼                                 │
                     ┌──────────────────────────────┐               │
                     │      Correlation Engine      │◄──────────────┘
                     │  ┌────────┐ ┌────────────┐  │
                     │  │ Event  │ │ Chain      │  │
                     │  │ Index  │ │ Builder    │  │
                     │  │ Matcher│ │            │  │
                     │  └────────┘ └────────────┘  │
                     └──────────────────────────────┘
```

## 核心模块

### 1. Engine (`internal/engine/`)

核心引擎，负责日志导入和搜索。

**关键组件**:
- `Engine` - 主引擎，协调各组件
- `ImportConfig` - 导入配置 (Worker数, BatchSize等)
- `ImportProgress` - 导入进度回调
- `ImportRequest/Result` - 导入请求/结果
- `searchCache` - 搜索结果缓存

**导入流程**:
```
1. collectFiles() - 收集待导入文件 (.evtx, .etl, .csv, .log, .txt)
2. 创建 Worker Pool (大小由 Workers 配置，默认4)
3. 并发导入文件:
   - 获取对应 Parser
   - Parse() 返回事件 Channel
   - Batch Insert 到数据库
4. 记录 ImportLog
```

**搜索流程**:
```
1. 生成缓存 key
2. 检查缓存
3. 调用 eventRepo.Search()
4. 返回分页结果
```

### 2. Parsers (`internal/parsers/`)

解析器注册表，支持多种日志格式。

**Parser 接口**:
```go
type Parser interface {
    CanParse(path string) bool
    Parse(path string) <-chan *types.Event
    ParseBatch(path string) ([]*types.Event, error)
    GetType() string
}
```

**支持的格式**:
| 格式 | Parser | 文件扩展名 |
|------|--------|-----------|
| Windows Event Log | `EvtxParser` | .evtx |
| Event Trace Log | `EtlParser` | .etl |
| CSV/LOG | `CsvParser` | .csv, .log, .txt |
| IIS W3C Extended | `IISParser` | .log |
| Sysmon | `SysmonParser` | .evtx |

### 3. Storage (`internal/storage/`)

SQLite 存储层，使用 `modernc.org/sqlite` (Pure Go)。

**关键文件**:
- `db.go` - 数据库连接和配置
- `schema.go` - 数据库 Schema 定义
- `events.go` - 事件仓库 (EventRepo)
- `alerts.go` - 告警仓库 (AlertRepo)
- `persistence.go` - 取证持久化存储
- `repository.go` - 通用仓储接口

**数据库配置**:
- WAL 模式 (`_journal_mode=WAL`)
- 超时 30 秒 (`_busy_timeout=30000`)
- 同步模式 NORMAL
- 单连接写入 (`SetMaxOpenConns(1)`)

**EventRepo 关键方法**:
```go
type EventRepo struct {
    db *DB
}

func (r *EventRepo) Insert(event *types.Event) error
func (r *EventRepo) InsertBatch(events []*types.Event) error
func (r *EventRepo) GetByID(id int64) (*types.Event, error)
func (r *EventRepo) GetByIDs(ids []int64) ([]*types.Event, error)
func (r *EventRepo) Search(req *types.SearchRequest) ([]*types.Event, int64, error)
```

**AlertRepo 关键方法**:
```go
type AlertRepo struct {
    db *DB
}

func (r *AlertRepo) Insert(alert *types.Alert) error
func (r *AlertRepo) InsertBatch(alerts []*types.Alert) error
func (r *AlertRepo) GetByID(id int64) (*types.Alert, error)
func (r *AlertRepo) Query(filter *AlertFilter) ([]*types.Alert, error)
func (r *AlertRepo) GetStats() (*AlertStats, error)
```

### 4. Alerts (`internal/alerts/`)

告警引擎，负责规则评估和告警生成。

**组件**:
- `Engine` - 告警引擎主类
- `DedupCache` - 去重缓存 (基于时间窗口)
- `Evaluator` - 规则评估器
- `AlertStats` - 告警统计
- `AlertTrend` - 告警趋势
- `AlertUpgradeCache` - 告警升级缓存
- `SuppressCache` - 告警抑制缓存

**评估流程**:
```go
func (e *Engine) Evaluate(ctx context.Context, event *types.Event) ([]*types.Alert, error) {
    for _, rule := range e.rules {
        // 1. 检查是否被抑制
        if e.suppressCache.IsSuppressed(rule, event) {
            continue
        }
        // 2. 评估规则条件
        if matched, err := e.evaluator.Evaluate(rule, event); err != nil || !matched {
            continue
        }
        // 3. 检查去重
        if e.dedup.IsDuplicate(rule.Name, event) {
            continue
        }
        // 4. 创建告警
        alert := e.createAlert(rule, event)
        // 5. 记录去重
        e.dedup.Mark(rule.Name, event)
        e.trend.Record(alert)
    }
}
```

**批量评估**:
```go
func (e *Engine) EvaluateBatch(ctx context.Context, events []*types.Event) ([]*types.Alert, error)
func (e *Engine) EvaluateBatchWithProgress(ctx context.Context, events []*types.Event, callback ProgressCallback) ([]*types.Alert, error)
```

**策略模板**:
```go
func (e *Engine) LoadPolicyTemplate(templateName string, ruleName string, params map[string]string) error
func (e *Engine) ApplyPolicyTemplates() error
```

### 5. Rules (`internal/rules/`)

规则系统，支持 AlertRule 和 CorrelationRule。

**AlertRule 结构**:
```go
type AlertRule struct {
    Name           string
    Description    string
    Enabled        bool
    Severity       types.Severity
    Score          float64
    MitreAttack    string
    Priority       int      // 1-100，默认 50
    Weight         float64  // 告警权重，默认 1.0
    Filter         *Filter
    Conditions     *Conditions
    Threshold      int
    TimeWindow     time.Duration
    AggregationKey string
    Message        string
    Tags           []string
}
```

**Filter 结构**:
```go
type Filter struct {
    EventIDs         []int32
    Levels           []int
    LogNames         []string
    Sources          []string
    Computers        []string
    Keywords         string
    KeywordMode      LogicalOp
    TimeRange        *types.TimeRange
    LogonTypes       []int
    ExcludeUsers     []string
    ExcludeComputers []string
    ExcludeDomains   []string
    MinFailureCount  int
    IpAddress        []string
    ProcessNames     []string
}
```

**CorrelationRule 结构**:
```go
type CorrelationRule struct {
    Name        string
    Description string
    Enabled     bool
    Severity    types.Severity
    Patterns    []*Pattern
    TimeWindow  time.Duration
    Join        string
    MitreAttack string
    Tags        []string
}

type Pattern struct {
    EventID    int32
    Conditions []*Condition
    Join       string
    TimeWindow time.Duration
    MinCount   int
    MaxCount   int
    Ordered    bool
    Negate     bool
}
```

### 6. Correlation (`internal/correlation/`)

关联分析引擎，负责事件关联和攻击链检测。

**组件**:
- `Engine` - 关联分析主引擎
- `EventIndex` - 事件索引（内存缓存）
- `Matcher` - 模式匹配器
- `ChainBuilder` - 攻击链构建器

**Engine 结构**:
```go
type Engine struct {
    mu      sync.RWMutex
    events  map[int64]*types.Event
    index   *EventIndex
    matcher *Matcher
    chain   *ChainBuilder
    maxAge  time.Duration
}

type EventIndex struct {
    mu              sync.RWMutex
    eventRepo       *storage.EventRepo
    eventsCache     map[int64]*types.Event
    byID            map[int64]time.Time
    byTime          []indexEntry
    byEID           map[int32][]int64
    maxAge          time.Duration
    lastCleanup     time.Time
    cleanupInterval time.Duration
}
```

**关联分析流程**:
```go
func (e *Engine) Analyze(ctx context.Context, rules []*rules.CorrelationRule) ([]*types.CorrelationResult, error) {
    for _, rule := range rules {
        if !rule.Enabled {
            continue
        }
        ruleResults := e.analyzeRule(rule)
        results = append(results, ruleResults...)
    }
    return results, nil
}

func (e *Engine) analyzeRule(rule *rules.CorrelationRule) []*types.CorrelationResult {
    seenChains := make(map[string]bool)
    for i, pattern := range patterns {
        if i == len(patterns)-1 {
            break  // 跳过最后一个模式
        }
        events := e.index.GetByEventID(pattern.EventID)
        // 查找关联事件并构建结果
    }
    return allResults
}
```

**Join 类型**:
- `user` - 按用户名或用户SID关联
- `computer` - 按计算机名关联
- `ip` - 按IP地址关联
- 默认 - 返回所有匹配事件

**ChainBuilder**:
```go
type ChainBuilder struct {
    eventRepo *storage.EventRepo
    config    *ChainConfig
}

var DefaultChainConfig = &ChainConfig{
    StartEventIDs: map[int32]bool{
        4624: true, 4625: true, 4634: true, 4648: true,
        4672: true, 4688: true, 4698: true, 4697: true,
    },
    Transitions: map[int32][]int32{
        4624: {4634, 4672, 4688},
        4625: {4624},
        4648: {4624, 4672},
        4688: {4698, 4697},
    },
}
```

### 7. Collectors (`internal/collectors/`)

采集器接口与实现。

**Collector 接口**:
```go
type Collector interface {
    Name() string
    Collect(ctx context.Context) ([]interface{}, error)
    RequiresAdmin() bool
}
```

**Live 采集** (`collectors/live/`):
- `EvtLiveCollector` - Windows Event Log 实时采集
- `LiveCollector` - 多采集器管理框架
- `Bookmark` - 事件书签
- `EventFilter` - 事件过滤器
- `CollectStats` - 采集统计

**Persistence 采集** (`collectors/persistence/`):
- `UserAssistCollector` - 用户辅助数据
- `AmcacheCollector` - AMCache
- `PrefetchCollector` - Prefetch
- `ShimcacheCollector` - ShimCache
- `USNJournalCollector` - USN 日志

### 8. Reports (`internal/reports/`)

报告生成模块。

**ReportService**:
```go
type ReportService struct {
    db        *storage.DB
    generator *Generator
}

func (s *ReportService) Generate(req *ReportRequest) (*Report, error)
func (s *ReportService) ExportHTML(req *ReportRequest, w io.Writer) error
func (s *ReportService) ExportHTMLFromReport(report *Report, w io.Writer) error
func (s *ReportService) ExportJSON(req *ReportRequest) ([]byte, error)
func (s *ReportService) ExportPDF(req *ReportRequest, w io.Writer) error
func (s *ReportService) GenerateAsync(req *ReportRequest, callback func(*Report, error))
```

**Generator** (`generator.go`):
```go
type Generator struct {
    db *storage.DB
}

func (g *Generator) Generate(req *ReportRequest) (*Report, error)
func (g *Generator) generateSecurityReport(req *ReportRequest) (*Report, error)
func (g *Generator) generateTimelineReport(req *ReportRequest) (*Report, error)
func (g *Generator) generateAlertsReport(req *ReportRequest) (*Report, error)
func (g *Generator) generateEventsReport(req *ReportRequest) (*Report, error)
```

**Report 结构**:
```go
type Report struct {
    GeneratedAt time.Time
    Title       string
    Type        ReportType
    TimeRange   TimeRange
    Summary     ReportSummary
    Stats       *SecurityStats
    TopAlerts   []*types.Alert
    TopEvents   []*types.Event
    EventDist   *EventDist
    LoginStats  *LoginStats
    IOCs        *IOCSummary
    MITREDist   *MITREDist
    RawEvents   []*types.Event
}
```

**报告类型** (`ReportType`):
| 类型 | 说明 |
|------|------|
| `ReportTypeSummary` | 安全摘要 |
| `ReportTypeTimeline` | 时间线 |
| `ReportTypeAlerts` | 告警详情 |
| `ReportTypeEvents` | 原始事件 |
| `ReportTypeLogin` | 登录分析 |
| `ReportTypeFile` | 文件操作 |
| `ReportTypeNetwork` | 网络活动 |
| `ReportTypeThreat` | 威胁检测 |

### 9. Analyzers (`internal/analyzers/`)

分析器模块，提供特定类型的分析功能。

**分析器列表**:
- `BruteForceAnalyzer` - 暴力破解检测
- `LateralMovementAnalyzer` - 横向移动检测
- `PersistenceAnalyzer` - 持久化检测
- `PrivilegeEscalationAnalyzer` - 权限提升检测
- `LoginAnalyzer` - 登录分析
- `PowerShellAnalyzer` - PowerShell 分析
- `KerberosAnalyzer` - Kerberos 分析
- `DataExfiltrationAnalyzer` - 数据泄露分析

### 10. Exporters (`internal/exporters/`)

数据导出接口与实现。

**Exporter 接口**:
```go
type Exporter interface {
    Export(events []*types.Event, writer io.Writer) error
    ContentType() string
    FileExtension() string
}
```

**支持格式**:
| 格式 | Exporter | 文件扩展名 |
|------|----------|-----------|
| JSON | `JsonExporter` | .json |
| CSV | `CsvExporter` | .csv |
| Excel | `ExcelExporter` | .xlsx |
| Timeline CSV | `TimelineExporter` | .csv |
| Timeline JSON | `TimelineJSONExporter` | .json |
| EVTX | `EvtxExporter` | .evtx |

### 11. Timeline (`internal/timeline/`)

时间线构建与分析。

### 12. Forensics (`internal/forensics/`)

取证功能模块。

### 13. Multi (`internal/multi/`)

多机关联分析。

### 14. Types (`internal/types/`)

核心类型定义。

**Event 结构**:
```go
type Event struct {
    ID              int64
    Timestamp       time.Time
    EventID         int32
    Level           EventLevel
    Source          string
    LogName         string
    Computer        string
    User            *string
    UserSID         *string
    Message         string
    RawXML          *string
    SessionID       *string
    IPAddress       *string
    ImportTime      time.Time
    ImportID        int64
    ExtractedFields map[string]interface{}
}
```

**Alert 结构**:
```go
type Alert struct {
    ID            int64
    RuleName      string
    Severity      Severity
    Message       string
    EventIDs      []int32
    FirstSeen     time.Time
    LastSeen      time.Time
    Count         int
    MITREAttack   []string
    Resolved      bool
    ResolvedTime  *time.Time
    Notes         string
    FalsePositive bool
    LogName       string
    RuleScore     float64
}
```

**CorrelationResult 结构**:
```go
type CorrelationResult struct {
    ID          string
    RuleName    string
    Description string
    Severity    Severity
    Events      []*Event
    StartTime   time.Time
    EndTime     time.Time
}
```

### 15. API (`internal/api/`)

Gin HTTP API 服务器。

**路由**:
```
/api/v1/
  ├── /events          # 事件查询
  ├── /alerts          # 告警管理
  ├── /import          # 导入接口
  ├── /stats           # 统计信息
  ├── /search          # 搜索
  └── /timeline        # 时间线
```

### 16. TUI (`internal/tui/`)

Bubble Tea 终端界面。

**视图** (11个):
- `ViewDashboard` - 仪表盘
- `ViewEvents` - 事件列表
- `ViewEventDetail` - 事件详情
- `ViewAlerts` - 告警列表
- `ViewAlertDetail` - 告警详情
- `ViewSearch` - 搜索
- `ViewTimeline` - 时间线
- `ViewCollect` - 采集
- `ViewHelp` - 帮助
- `ViewSettings` - 设置

### 17. CLI (`cmd/winalog/commands/`)

Cobra CLI 命令实现。

**命令列表**:
| 命令 | 文件 | 说明 |
|------|------|------|
| import | `import.go` | 导入日志文件 |
| search | `search.go` | 搜索事件 |
| collect | `collect.go` | 一键采集 |
| analyze | `analyze.go` | 分析命令 |
| alert | `alert.go` | 告警管理 |
| correlate | `analyze.go` | 关联分析 |
| report | `report.go` | 报告生成 |
| system | `system.go` | 系统管理 |
| persistence | `persistence.go` | 取证持久化 |
| whitelist | `whitelist.go` | 白名单管理 |
| ueba | `ueba.go` | UEBA分析 |
| dashboard | `dashboard.go` | 仪表盘 |
| config | `config.go` | 配置管理 |

## 并发模型

### Worker Pool 模式

```go
workerPool := make(chan struct{}, e.importCfg.Workers)
var wg sync.WaitGroup

for i, file := range files {
    workerPool <- struct{}{}
    wg.Add(1)
    go func(idx int, path string) {
        defer wg.Done()
        defer func() { <-workerPool }()
        // 处理文件...
    }(i, file)
}
wg.Wait()
```

### 事件通道 Pipeline

```go
events := parser.Parse(path)
for event := range events {
    batch = append(batch, event)
    if len(batch) >= e.importCfg.BatchSize {
        e.eventRepo.InsertBatch(batch)
        batch = batch[:0]
    }
}
```

## 依赖关系

```
CLI/Commands
     │
     ├── Engine ─────────────► Storage (SQLite)
     │       │
     │       └──► Parsers ────┤
     │                        │
     ├── Alerts ◄─────────────┤
     │       │
     │       └──► Rules       │
     │
     ├── Correlation ◄────────┤
     │       │
     │       ├──► Rules       │
     │       └──► Matcher     │
     │
     ├── TUI ◄───────────────► Engine
     │
     ├── API ◄───────────────► Engine
     │       │
     │       └──► Storage
     │
     ├── Reports ◄────────────► Storage
     │       │
     │       └──► Generator
     │
     ├── Exporters ◄──────────► Storage
     │
     ├── Analyzers ◄──────────► Storage
     │
     ├── Collectors ──────────► Storage
     │
     ├── Multi ───────────────► Storage
     │
     └── Forensics ───────────► Storage
```

## 设计决策

### 1. Pure Go SQLite

使用 `modernc.org/sqlite` 而非 `github.com/mattn/go-sqlite3`:
- 无 CGO 依赖
- 编译为单个可执行文件
- 跨平台编译更简单

### 2. Worker Pool for Import

并发导入多个文件，提高 IO 利用率:
- 默认 4 个 Worker
- 可配置 `Workers` 参数
- 使用 WaitGroup 等待完成

### 3. Channel-based Streaming

Parser 使用 Channel 返回事件:
- 内存占用低
- 支持取消
- 边解析边写入

### 4. Interface Segregation

各模块通过接口交互:
- `Parser` 接口
- `Collector` 接口
- `Exporter` 接口
- `Rule` 接口

便于测试和替换实现。

### 5. EventIndex 缓存

关联分析使用内存索引:
- 按 EventID 索引事件
- 按时间范围查询
- 自动过期清理

### 6. Correlation 去重

关联分析结果去重:
- 基于事件对 ID 去重
- 跳过最后一个模式避免虚假链
