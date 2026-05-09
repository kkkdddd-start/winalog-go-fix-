# WinLogAnalyzer-Go 接口文档

## Parser 接口

定义在 `internal/parsers/parser.go`

```go
type Parser interface {
    // CanParse 判断解析器是否能解析指定路径
    CanParse(path string) bool
    
    // Parse 返回事件 Channel，支持流式处理
    Parse(path string) <-chan *types.Event
    
    // ParseBatch 批量解析，返回所有事件
    ParseBatch(path string) ([]*types.Event, error)
    
    // GetType 返回解析器类型
    GetType() string
}
```

### ParserRegistry

```go
type ParserRegistry struct {
    parsers map[string]Parser
}

// 注册解析器
func (r *ParserRegistry) Register(p Parser)

// 根据路径获取解析器
func (r *ParserRegistry) Get(path string) Parser

// 根据类型获取解析器
func (r *ParserRegistry) GetByType(parserType string) Parser

// 列出所有解析器
func (r *ParserRegistry) List() []Parser

// 列出所有解析器类型
func (r *ParserRegistry) ListTypes() []string
```

### 实现

| 解析器 | 类型字符串 | 支持扩展名 |
|--------|-----------|-----------|
| `EvtxParser` | "evtx" | .evtx |
| `EtlParser` | "etl" | .etl |
| `CsvParser` | "csv" | .csv, .log, .txt |
| `IISParser` | "iis" | .log |
| `SysmonParser` | "sysmon" | .evtx |

---

## Collector 接口

定义在 `internal/collectors/collector.go`

```go
type Collector interface {
    // Name 返回采集器名称
    Name() string
    
    // Collect 执行数据采集
    Collect(ctx context.Context) ([]interface{}, error)
    
    // RequiresAdmin 是否需要管理员权限
    RequiresAdmin() bool
}
```

### CollectorInfo

```go
type CollectorInfo struct {
    Name          string
    Description   string
    RequiresAdmin bool
    Version       string
}
```

### MultiCollector

```go
type MultiCollector struct {
    collectors []Collector
}

// 创建多采集器
func NewMultiCollector(collectors ...Collector) *MultiCollector

// 添加采集器
func (mc *MultiCollector) Add(c Collector)

// 顺序采集
func (mc *MultiCollector) Collect(ctx context.Context) ([]*CollectResult, error)

// 并行采集
func (mc *MultiCollector) CollectParallel(ctx context.Context, workers int) ([]*CollectResult, error)

// 列出所有采集器
func (mc *MultiCollector) List() []CollectorInfo
```

### CollectResult

```go
type CollectResult struct {
    Collector string
    Data      []interface{}
    Duration  time.Duration
    Error     error
    Timestamp time.Time
}
```

---

## Exporter 接口

定义在 `internal/exporters/exporter.go`

```go
type Exporter interface {
    // Export 导出事件到 Writer
    Export(events []*types.Event, writer io.Writer) error
    
    // ContentType 返回 MIME 类型
    ContentType() string
    
    // FileExtension 返回文件扩展名
    FileExtension() string
}
```

### ExporterFactory

```go
type ExporterFactory struct{}

// 创建导出器
// 支持格式: csv, excel, json, timeline-csv, timeline-json, timeline-html
func (f *ExporterFactory) Create(format string) Exporter
```

### 实现

| 导出器 | ContentType | FileExtension | 备注 |
|--------|-------------|---------------|------|
| `JsonExporter` | application/json | .json | 支持 prettyPrint |
| `CsvExporter` | text/csv | .csv | 自定义分隔符 |
| `ExcelExporter` | application/vnd.openxmlformats | .xlsx | Excel 2007+ |
| `TimelineExporter` | text/csv | .csv | 时间线专用 |
| `TimelineJSONExporter` | application/json | .json | 时间线 JSON |
| `TimelineHTMLExporter` | text/html | .html | 时间线 HTML |

---

## Rule 接口

定义在 `internal/rules/rule.go`

### AlertRule

```go
type AlertRule struct {
    Name           string           // 规则名称
    Description    string           // 规则描述
    Enabled        bool             // 是否启用
    Severity       Severity         // 严重级别
    Score          float64          // 规则得分
    MitreAttack    string           // MITRE ATT&CK ID
    Filter         *Filter          // 简单过滤条件
    Conditions     *Conditions      // 复杂条件
    Threshold      int              // 触发阈值
    TimeWindow     time.Duration    // 时间窗口
    AggregationKey string           // 聚合键
    Message        string           // 告警消息模板
    Tags           []string         // 标签
}

func (r *AlertRule) Validate() error
func (r *AlertRule) BuildMessage(event *types.Event) string
```

### CorrelationRule

```go
type CorrelationRule struct {
    Name        string
    Description string
    Enabled     bool
    Severity    Severity
    Patterns    []*Pattern
    TimeWindow  time.Duration
    Join        string
    MitreAttack string
    Tags        []string
}

func (r *CorrelationRule) Validate() error
```

### Filter

```go
type Filter struct {
    EventIDs    []int32
    Levels      []int
    LogNames    []string
    Sources     []string
    Computers   []string
    Keywords    string
    KeywordMode LogicalOp  // AND/OR
    TimeRange   *types.TimeRange
}
```

### Conditions

```go
type Conditions struct {
    Any  []*Condition  // 任一条件满足
    All  []*Condition  // 所有条件满足
    None []*Condition  // 所有条件都不满足
}

type Condition struct {
    Field    string  // 字段名
    Operator string  // 操作符: equals, contains, regex, gt, lt, gte, lte
    Value    string  // 比较值
    Regex    bool    // 是否正则
}
```

---

## Storage 接口

定义在 `internal/storage/`

### DB

```go
type DB struct {
    conn    *sql.DB
    path    string
    writeMu sync.Mutex
}

func NewDB(path string) (*DB, error)
func (d *DB) Close() error
func (d *DB) Ping() error
func (d *DB) Path() string

// 执行写操作
func (d *DB) Exec(query string, args ...interface{}) (sql.Result, error)

// 执行读操作
func (d *DB) Query(query string, args ...interface{}) (*sql.Rows, error)
func (d *DB) QueryRow(query string, args ...interface{}) *sql.Row

// 事务
func (d *DB) Begin() (*sql.Tx, error)
func (d *DB) BeginTx() (*sql.Tx, func(), error)

// 数据库维护
func (d *DB) Vacuum() error
func (d *DB) Analyze() error
func (d *DB) GetStats() (*DBStats, error)
```

### EventRepo

```go
type EventRepo struct {
    db *DB
}

func NewEventRepo(db *DB) *EventRepo

func (r *EventRepo) Insert(event *types.Event) error
func (r *EventRepo) InsertBatch(events []*types.Event) error
func (r *EventRepo) GetByID(id int64) (*types.Event, error)
func (r *EventRepo) Search(req *types.SearchRequest) ([]*types.Event, int64, error)
func (r *EventRepo) Count() (int64, error)
func (r *EventRepo) DeleteOlderThan(t time.Time) error
```

### AlertRepo

```go
type AlertRepo struct {
    db *DB
}

func NewAlertRepo(db *DB) *AlertRepo

func (r *AlertRepo) Insert(alert *types.Alert) error
func (r *AlertRepo) InsertBatch(alerts []*types.Alert) error
func (r *AlertRepo) Update(alert *types.Alert) error
func (r *AlertRepo) Delete(id int64) error
func (r *AlertRepo) GetByID(id int64) (*types.Alert, error)
func (r *AlertRepo) Query(filter *AlertFilter) ([]*types.Alert, error)
func (r *AlertRepo) GetStats() (*AlertStats, error)
```

### AlertFilter

```go
type AlertFilter struct {
    StartTime *time.Time
    EndTime   *time.Time
    Severity  []string
    RuleName  string
    Resolved  *bool
    Limit     int
    Offset    int
}
```

---

## Engine 接口

定义在 `internal/engine/engine.go`

```go
type Engine struct {
    db        *storage.DB
    parsers   *parsers.ParserRegistry
    eventRepo *storage.EventRepo
    alertRepo *storage.AlertRepo
    importCfg ImportConfig
}

func NewEngine(db *storage.DB) *Engine

// 导入日志
func (e *Engine) Import(ctx context.Context, req *ImportRequest, progressFn func(*ImportProgress)) (*ImportResult, error)

// 搜索事件
func (e *Engine) Search(req *types.SearchRequest) (*types.SearchResponse, error)

// 获取统计
func (e *Engine) GetStats() (*storage.DBStats, error)

// 获取解析器注册表
func (e *Engine) GetParserRegistry() *parsers.ParserRegistry
```

### ImportConfig

```go
type ImportConfig struct {
    Workers          int      // 并发 Worker 数
    BatchSize        int      // 批量插入大小
    SkipPatterns     []string // 跳过文件模式
    Incremental      bool     // 增量导入
    CalculateHash    bool     // 计算文件哈希
    ProgressCallback bool     // 进度回调
}
```

### ImportRequest/Result

```go
type ImportRequest struct {
    Paths            []string
    LogName          string
    Incremental      bool
    SkipPatterns     []string
    Workers          int
    BatchSize        int
    CalculateHash    bool
    ProgressCallback func(*ImportProgress)
}

type ImportResult struct {
    StartTime      time.Time
    Duration       time.Duration
    TotalFiles     int
    FilesImported  int
    FilesFailed    int
    EventsImported int64
    Errors         []*types.ImportError
}
```

---

## Alert Engine 接口

定义在 `internal/alerts/engine.go`

```go
type Engine struct {
    db            *storage.DB
    alertRepo     *storage.AlertRepo
    dedup         *DedupCache
    evaluator     *Evaluator
    stats         *AlertStats
    trend         *AlertTrend
    upgradeRules  *AlertUpgradeCache
    suppressCache *SuppressCache
    rules         map[string]*rules.AlertRule
}

func NewEngine(db *storage.DB, cfg EngineConfig) *Engine

// 规则管理
func (e *Engine) LoadRules(ruleList []*rules.AlertRule)
func (e *Engine) AddRule(rule *rules.AlertRule)
func (e *Engine) RemoveRule(name string)
func (e *Engine) GetRules() []*rules.AlertRule

// 评估
func (e *Engine) Evaluate(ctx context.Context, event *types.Event) ([]*types.Alert, error)
func (e *Engine) EvaluateBatch(ctx context.Context, events []*types.Event) ([]*types.Alert, error)

// 告警管理
func (e *Engine) SaveAlert(alert *types.Alert) error
func (e *Engine) SaveAlerts(alerts []*types.Alert) error
func (e *Engine) GetAlert(id int64) (*types.Alert, error)
func (e *Engine) GetAlerts(filter *storage.AlertFilter) ([]*types.Alert, error)
func (e *Engine) ResolveAlert(id int64, notes string) error
func (e *Engine) DeleteAlert(id int64) error
func (e *Engine) MarkFalsePositive(id int64) error

// 统计
func (e *Engine) GetStats() (*AlertStats, error)
func (e *Engine) GetTrends() (*AlertTrend, error)

// 抑制与升级
func (e *Engine) AddUpgradeRule(rule *types.AlertUpgradeRule)
func (e *Engine) CheckUpgrade(alert *types.Alert) (bool, *types.AlertUpgradeRule)
func (e *Engine) AddSuppressRule(rule *types.SuppressRule)
func (e *Engine) ClearSuppressions()
func (e *Engine) ClearDedup()
```

---

## Timeline 接口

定义在 `internal/timeline/builder.go`

```go
type TimelineBuilder struct {
    events       []*types.Event
    filter       *TimelineFilter
    attackChains []*AttackChain
}

func NewTimelineBuilder() *TimelineBuilder

func (b *TimelineBuilder) SetEvents(events []*types.Event)
func (b *TimelineBuilder) SetFilter(filter *TimelineFilter)
func (b *TimelineBuilder) Build() (*Timeline, error)

// 攻击链检测
func (b *TimelineBuilder) GetAttackChains() []*AttackChain

// 分组
func (b *TimelineBuilder) GroupByComputer() map[string]*Timeline
func (b *TimelineBuilder) GroupByCategory() map[string]*Timeline
```

### TimelineFilter

```go
type TimelineFilter struct {
    StartTime  time.Time
    EndTime    time.Time
    EventIDs   map[int32]bool   // O(1) 查找
    Levels     map[EventLevel]bool
    LogNames   map[string]bool
    Sources    map[string]bool
    Computers  map[string]bool
    Users      map[string]bool
    Keywords   string
    MITREIDs   []string
    IncludeRaw bool
}
```

### Timeline

```go
type Timeline struct {
    Entries    []*TimelineEntry
    TotalCount int
    StartTime  time.Time
    EndTime    time.Time
    Duration   time.Duration
}

type TimelineEntry struct {
    ID          int64
    Timestamp   time.Time
    EventID     int32
    Level       string
    Category    string
    Source      string
    LogName     string
    Computer    string
    User        string
    Message     string
    MITREAttack []string
    AttackChain string
    RawXML      string
}
```

### AttackChain

```go
type AttackChain struct {
    ID          string
    Name        string
    Description string
    Technique   string  // MITRE ID
    Tactic      string
    Severity    string
    Events      []*types.Event
    StartTime   time.Time
    EndTime     time.Time
    Duration    time.Duration
}
```

---

## Multi-Analyzer 接口

定义在 `internal/multi/analyzer.go`

```go
type MultiMachineAnalyzer struct {
    db       *storage.DB
    machines map[string]*MachineContext
    mu       sync.RWMutex
}

func NewMultiMachineAnalyzer(db *storage.DB) *MultiMachineAnalyzer

// 机器管理
func (a *MultiMachineAnalyzer) AddMachine(ctx *MachineContext)
func (a *MultiMachineAnalyzer) GetMachine(id string) (*MachineContext, bool)
func (a *MultiMachineAnalyzer) ListMachines() []*MachineContext

// 分析
func (a *MultiMachineAnalyzer) Analyze() (*CrossMachineResult, error)

// 角色检测
func (a *MultiMachineAnalyzer) DetectDC() []*MachineContext
func (a *MultiMachineAnalyzer) DetectServers() []*MachineContext
func (a *MultiMachineAnalyzer) DetectWorkstations() []*MachineContext
```

### MachineContext

```go
type MachineContext struct {
    ID        string
    Name      string
    IP        string
    Role      string  // DC, Server, Workstation
    Events    []*types.Event
    FirstSeen time.Time
    LastSeen  time.Time
}
```

### LateralMovement

```go
type LateralMovement struct {
    SourceMachine string
    TargetMachine string
    User          string
    Technique     string
    Time          time.Time
    Evidence      []*types.Event
}
```

---

## Forensics 接口

定义在 `internal/forensics/`

### Hash

```go
type HashResult struct {
    FilePath string
    SHA256   string
    MD5      string
    SHA1     string
    Size     int64
}

func CalculateFileHash(path string) (*HashResult, error)
func VerifyFileHash(path, expectedSHA256 string) (bool, *HashResult, error)
```

### Signature

```go
type SignatureResult struct {
    Status      string
    Signer      string
    Issuer      string
    Thumbprint  string
    NotBefore   *time.Time
    NotAfter    *time.Time
    Description string
}

var (
    ErrPlatformNotSupported = fmt.Errorf("signature verification is only supported on Windows")
    ErrPathIsDirectory      = fmt.Errorf("path is a directory")
)

func VerifySignature(path string) (*SignatureResult, error)
func IsSigned(path string) (bool, *SignatureResult, error)
```

### Evidence Chain

```go
type EvidenceChain struct {
    ID           string
    Timestamp    time.Time
    Operator     string
    Action       string
    InputHash    string
    OutputHash   string
    PreviousHash string
    FilePath     string
    Description  string
}

type EvidenceManifest struct {
    ID          string
    CreatedAt   time.Time
    CollectedBy string
    MachineID   string
    Files       []*EvidenceFile
    Chain       []*EvidenceChain
    TotalSize   int64
    Hash        string
}

type EvidenceFile struct {
    ID          string
    FilePath    string
    FileHash    string
    Size        int64
    CollectedAt time.Time
    Collector   string
}

func NewEvidenceChain(operator, action, inputHash string) *EvidenceChain
func (e *EvidenceChain) CalculateHash() string
func (e *EvidenceChain) Link(previousHash string)
func GenerateManifest(files []*EvidenceFile, collectedBy, machineID string) *EvidenceManifest
func (m *EvidenceManifest) AddChainEntry(entry *EvidenceChain)
```

### Memory

```go
type MemoryDumpResult struct {
    ProcessID   uint32
    ProcessName string
    DumpPath    string
    DumpSize    int64
    DumpTime    time.Time
    Hash        string
    Modules     []MemoryModule
    Permissions MemoryPermissions
    Error       string
}

type MemoryCollector struct {
    outputDir      string
    includeModules bool
    includeStacks  bool
}

func NewMemoryCollector(outputDir string) *MemoryCollector
func (c *MemoryCollector) CollectProcessMemory(pid uint32) (*MemoryDumpResult, error)
func (c *MemoryCollector) CollectSystemMemory() (*MemoryDumpResult, error)
```

---

## API Server 接口

定义在 `internal/api/server.go`

```go
type Server struct {
    engine    *gin.Engine
    db        *storage.DB
    addr      string
    alertEng  *AlertHandler
    importEng *ImportHandler
    liveEng   *LiveHandler
}

func NewServer(db *storage.DB, addr string) *Server
func (s *Server) Start() error
func (s *Server) Stop() error
```

### Handlers

```go
type AlertHandler struct {
    db *storage.DB
}

type ImportHandler struct {
    db *storage.DB
}

type LiveHandler struct{}
```

### Routes

设置在 `internal/api/routes.go`:

```
GET  /api/v1/events          # 事件列表
GET  /api/v1/events/:id      # 事件详情
GET  /api/v1/alerts          # 告警列表
GET  /api/v1/alerts/:id      # 告警详情
POST /api/v1/alerts/:id/resolve  # 解决告警
POST /api/v1/import          # 导入文件
GET  /api/v1/stats           # 统计信息
GET  /api/v1/search          # 搜索
GET  /api/v1/timeline        # 时间线
```

---

## TUI Model 接口

定义在 `internal/tui/model.go`

```go
type Model struct {
    engine *engine.Engine
    db     *storage.DB
    cfg    *config.Config
}

func NewModel(cfg *config.Config) (*Model, error)

type ViewType int

const (
    ViewDashboard ViewType = iota
    ViewEvents
    ViewEventDetail
    ViewAlerts
    ViewAlertDetail
    ViewSearch
    ViewTimeline
    ViewCollect
    ViewHelp
    ViewSettings
)

func (m *Model) Width() int
func (m *Model) Height() int
func (m *Model) CurrentView() ViewType
func (m *Model) SelectedIdx() int
```
