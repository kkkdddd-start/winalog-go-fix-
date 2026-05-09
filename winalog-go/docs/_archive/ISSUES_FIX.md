# WinLogAnalyzer-Go 设计文档问题修复清单

**项目**: WinLogAnalyzer-Go  
**日期**: 2026-04-13  
**状态**: 待修复

---

## 一、严重问题 (阻碍开发)

### 问题 1: 目录结构与 FEATURES.md 不一致

**严重程度**: 🔴 严重  
**影响**: 目录结构不完整，开发时缺少文件指引

**问题详情**:

| 模块 | design.md 现状 | FEATURES.md 要求 | 修复方案 |
|------|---------------|-----------------|----------|
| `internal/collectors/live/` | 3 个文件 | 应有 4 个文件 | 添加 `stats.go` |
| `internal/collectors/` | 缺少文件 | 系统信息采集 10 个 | 添加 `dll_info.go`, `user_info.go` |
| `internal/alerts/` | 2 个文件 | 应有 7 个文件 | 添加 `evaluator.go`, `stats.go`, `trend.go`, `upgrade.go`, `suppress.go` |
| `internal/storage/` | 2 个文件 | 应有 5 个文件 | 添加 `repository.go`, `events.go`, `alerts.go` |
| `internal/reports/` | 3 个文件 | 应有 4 个文件 | 添加 `security_stats.go` |
| `internal/rules/builtin/` | 3 个文件 | 应有 4 个文件 | 添加 `mitre.go` |

**修复文件清单**:

```
internal/
├── alerts/
│   ├── engine.go           ✅ 已存在
│   ├── dedup.go            ✅ 已存在
│   ├── evaluator.go        🆕 需要添加
│   ├── stats.go           🆕 需要添加
│   ├── trend.go           🆕 需要添加
│   ├── upgrade.go         🆕 需要添加
│   └── suppress.go        🆕 需要添加
├── collectors/
│   ├── live/
│   │   ├── collector.go    ✅ 已存在
│   │   ├── bookmark.go    ✅ 已存在
│   │   ├── filtered.go    ✅ 已存在
│   │   └── stats.go       🆕 需要添加
│   ├── dll_info.go        🆕 需要添加
│   └── user_info.go       🆕 需要添加
├── storage/
│   ├── db.go              ✅ 已存在
│   ├── schema.go         ✅ 已存在
│   ├── repository.go      🆕 需要添加
│   ├── events.go         🆕 需要添加
│   └── alerts.go          🆕 需要添加
├── reports/
│   ├── generator.go       ✅ 已存在
│   ├── html.go            ✅ 已存在
│   ├── json.go           ✅ 已存在
│   └── security_stats.go  🆕 需要添加
└── rules/builtin/
    ├── registry.go        ✅ 已存在
    ├── definitions.go     ✅ 已存在
    ├── explanations.go    ✅ 已存在
    └── mitre.go          🆕 需要添加
```

---

### 问题 2: 告警引擎设计不完整

**严重程度**: 🔴 严重  
**影响**: 告警统计、趋势分析、告警升级、告警抑制功能缺失

**问题详情**:

FEATURES.md 要求 7 个模块，design.md 仅实现 2 个。

**修复方案**: 添加缺失的 5 个文件

#### 2.1 `internal/alerts/evaluator.go` - 规则评估

```go
// 功能需求:

// 1. 规则条件匹配
func (e *Engine) matches(rule *AlertRule, event *Event) bool

// 2. 过滤器匹配
func (e *Engine) matchFilter(event *Event, filter Filter) bool

// 3. 时间窗口聚合
func (e *Engine) aggregateTimeWindow(rule *AlertRule, event *Event) (bool, int)

// 4. 阈值检测
func (e *Engine) checkThreshold(rule *AlertRule, key string) bool
```

#### 2.2 `internal/alerts/stats.go` - 告警统计

```go
// 功能需求:

type AlertStats struct {
    Total        int64            `json:"total"`
    BySeverity   map[string]int64 `json:"by_severity"`
    ByStatus     map[string]int64 `json:"by_status"`
    ByRule       []*RuleCount     `json:"by_rule"`
    Trend        []*TrendPoint    `json:"trend"`
    AvgPerDay    float64          `json:"avg_per_day"`
    RuleScoreAvg float64          `json:"rule_score_avg"`
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

func (e *Engine) CalculateStats() (*AlertStats, error)
func (e *Engine) GetTopRules(limit int) ([]*RuleCount, error)
```

#### 2.3 `internal/alerts/trend.go` - 告警趋势

```go
// 功能需求:

type AlertTrend struct {
    Daily       []*TrendPoint     `json:"daily"`
    Weekly      []*TrendPoint     `json:"weekly"`
    ByHour      []*TrendPoint     `json:"by_hour"`
    ByDayOfWeek []*TrendPoint     `json:"by_day_of_week"`
}

func (e *Engine) CalculateTrend(days int) (*AlertTrend, error)
func (e *Engine) DetectAnomalies(trend *AlertTrend) ([]*Anomaly, error)
```

#### 2.4 `internal/alerts/upgrade.go` - 告警升级

```go
// 功能需求:

type AlertUpgradeRule struct {
    ID          int64     `json:"id"`
    Name        string    `json:"name"`
    Condition   string    `json:"condition"`   // "time_passed" | "count_threshold"
    Threshold   int       `json:"threshold"`
    NewSeverity Severity  `json:"new_severity"`
    Notify      bool      `json:"notify"`
    Enabled     bool      `json:"enabled"`
}

func (e *Engine) CheckUpgrade(alert *Alert)
func (e *Engine) UpgradeAlert(alert *Alert, rule *AlertUpgradeRule) error
func (e *Engine) GetUpgradeRules() []*AlertUpgradeRule
func (e *Engine) AddUpgradeRule(rule *AlertUpgradeRule) error
func (e *Engine) RemoveUpgradeRule(id int64) error
```

#### 2.5 `internal/alerts/suppress.go` - 告警抑制

```go
// 功能需求:

type SuppressRule struct {
    ID         int64       `json:"id"`
    Name       string      `json:"name"`
    Conditions []Condition `json:"conditions"`
    Duration   time.Duration `json:"duration"`
    Scope      string      `json:"scope"`  // "rule" | "source" | "global"
    Enabled   bool        `json:"enabled"`
    ExpiresAt time.Time   `json:"expires_at,omitempty"`
    CreatedAt time.Time   `json:"created_at"`
}

type Condition struct {
    Field    string      `json:"field"`
    Operator string      `json:"operator"`  // "equals" | "contains" | "regex"
    Value    interface{} `json:"value"`
}

func (e *Engine) IsSuppressed(alert *Alert) bool
func (e *Engine) AddSuppressRule(rule *SuppressRule) error
func (e *Engine) RemoveSuppressRule(id int64) error
func (e *Engine) GetSuppressRules() []*SuppressRule
```

---

### 问题 3: 缺少 API Handler 详细设计

**严重程度**: 🔴 严重  
**影响**: 无法进行 API 开发

**问题详情**:

design.md 仅列出 API 端点，缺少 Handler 的详细设计。

**修复方案**: 添加 `internal/api/handlers.go` 详细设计

#### 3.1 搜索请求/响应结构

```go
// internal/api/handlers.go

// SearchRequest 搜索请求
type SearchRequest struct {
    Keywords    string   `json:"keywords" form:"keywords"`
    KeywordMode string   `json:"keyword_mode" form:"keyword_mode"`  // "AND" | "OR"
    Regex       bool     `json:"regex" form:"regex"`
    EventIDs    []int32  `json:"event_ids" form:"event_ids"`
    Levels      []int    `json:"levels" form:"levels"`
    LogNames    []string `json:"log_names" form:"log_names"`
    Sources     []string `json:"sources" form:"sources"`
    Users       []string `json:"users" form:"users"`
    Computers   []string `json:"computers" form:"computers"`
    StartTime   string   `json:"start_time" form:"start_time"`
    EndTime     string   `json:"end_time" form:"end_time"`
    Page        int      `json:"page" form:"page,default=1"`
    PageSize    int      `json:"page_size" form:"page_size,default=100"`
    SortBy      string   `json:"sort_by" form:"sort_by,default=timestamp"`
    SortOrder   string   `json:"sort_order" form:"sort_order,default=desc"`
    Highlight   bool     `json:"highlight" form:"highlight"`
}

// SearchResponse 搜索响应
type SearchResponse struct {
    Events     []*EventWithHighlight `json:"events"`
    Total      int64                `json:"total"`
    Page       int                  `json:"page"`
    PageSize   int                  `json:"page_size"`
    TotalPages int                  `json:"total_pages"`
    QueryTime  int64                `json:"query_time_ms"`
    SearchID   string               `json:"search_id,omitempty"`
}

// EventWithHighlight 带高亮的事件
type EventWithHighlight struct {
    *Event
    Highlight *HighlightResult `json:"highlight,omitempty"`
}

// HighlightResult 高亮结果
type HighlightResult struct {
    Message  []HighlightField `json:"message,omitempty"`
    User     []HighlightField `json:"user,omitempty"`
    Computer []HighlightField `json:"computer,omitempty"`
}

// HighlightField 高亮字段
type HighlightField struct {
    Field string `json:"field"`
    Text  string `json:"text"`
    Spans []Span `json:"spans"`
}

// Span 高亮片段
type Span struct {
    Start int    `json:"start"`
    End   int    `json:"end"`
    Match string `json:"match"`
}
```

#### 3.2 告警 Handler

```go
// AlertHandler 告警处理器
type AlertHandler struct {
    engine *alerts.Engine
}

// GET /api/alerts
func (h *AlertHandler) ListAlerts(c *gin.Context) {
    var req ListAlertsRequest
    if err := c.ShouldBindQuery(&req); err != nil {
        c.JSON(400, ErrorResponse{Error: err.Error()})
        return
    }
    
    alerts, total, err := h.engine.ListAlerts(req.Page, req.PageSize, req.Severity, req.Resolved)
    if err != nil {
        c.JSON(500, ErrorResponse{Error: err.Error()})
        return
    }
    
    c.JSON(200, ListAlertsResponse{
        Alerts:    alerts,
        Total:     total,
        Page:      req.Page,
        PageSize:  req.PageSize,
    })
}

// GET /api/alerts/stats
func (h *AlertHandler) GetAlertStats(c *gin.Context) {
    stats, err := h.engine.CalculateStats()
    if err != nil {
        c.JSON(500, ErrorResponse{Error: err.Error()})
        return
    }
    c.JSON(200, stats)
}

// POST /api/alerts/:id/resolve
func (h *AlertHandler) ResolveAlert(c *gin.Context) {
    id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
    
    var req ResolveAlertRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, ErrorResponse{Error: err.Error()})
        return
    }
    
    if err := h.engine.ResolveAlert(id, req.Notes); err != nil {
        c.JSON(500, ErrorResponse{Error: err.Error()})
        return
    }
    
    c.JSON(200, SuccessResponse{Message: "Alert resolved"})
}

// POST /api/alerts/:id/false-positive
func (h *AlertHandler) MarkFalsePositive(c *gin.Context) {
    id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
    
    var req MarkFalsePositiveRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, ErrorResponse{Error: err.Error()})
        return
    }
    
    if err := h.engine.MarkFalsePositive(id, req.Reason); err != nil {
        c.JSON(500, ErrorResponse{Error: err.Error()})
        return
    }
    
    c.JSON(200, SuccessResponse{Message: "Alert marked as false positive"})
}
```

---

### 问题 4: 实时监控设计不完整

**严重程度**: 🔴 严重  
**影响**: 实时推送机制缺失

**问题详情**:

未说明如何实现实时推送 (WebSocket vs SSE)。

**修复方案**: 添加实时监控详细设计

```go
// internal/collectors/live/stats.go

type LiveStats struct {
    TotalEvents   int64     `json:"total_events"`
    EventsPerSec  float64   `json:"events_per_sec"`
    QueueSize     int       `json:"queue_size"`
    QueueCapacity int       `json:"queue_capacity"`
    Uptime        time.Duration `json:"uptime"`
    ErrorCount    int       `json:"error_count"`
}

// internal/api/handlers_live.go

// LiveEventMessage 实时事件消息
type LiveEventMessage struct {
    Type string      `json:"type"`  // "event" | "stats" | "error" | "status"
    Data interface{} `json:"data"`
}

// SSE 端点: GET /api/live/events
func (h *LiveHandler) StreamEventsSSE(c *gin.Context) {
    // 设置 SSE headers
    c.Header("Content-Type", "text/event-stream")
    c.Header("Cache-Control", "no-cache")
    c.Header("Connection", "keep-alive")
    
    // 获取事件通道
    eventChan := h.collector.Subscribe()
    statsChan := h.collector.StatsChannel()
    
    // 使用 ticker 定期发送 stats
    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case event := <-eventChan:
            c.SSEvent("event", LiveEventMessage{
                Type: "event",
                Data: event,
            })
        case stats := <-statsChan:
            c.SSEvent("stats", LiveEventMessage{
                Type: "stats",
                Data: stats,
            })
        case <-ticker.C:
            // 定期心跳
            c.SSEvent("ping", "")
        case <-c.Request.Context().Done():
            return
        }
    }
}
```

---

### 问题 5: 数据类型不一致

**严重程度**: 🔴 严重  
**影响**: 不同模块间类型不兼容

**问题详情**:

| 文档 | Alert 结构 | 问题 |
|------|-----------|------|
| requirements.md | 有 `Notes`, `LogName`, `RuleScore` | ✅ 完整 |
| design.md | 缺少 `db` tag，缺少 `FalsePositive` | ❌ 不完整 |
| FEATURES.md | 有 `FalsePositive`, `db` tag | ✅ 最完整 |

**修复方案**: 以 FEATURES.md 为准，更新 design.md

```go
// internal/types/alert.go

type Alert struct {
    ID           int64      `json:"id" db:"id"`
    RuleName     string     `json:"rule_name" db:"rule_name"`
    Severity     Severity   `json:"severity" db:"severity"`
    Message      string     `json:"message" db:"message"`
    EventIDs     []int32    `json:"event_ids" db:"event_ids"`  // JSON 数组，存储为 TEXT
    FirstSeen    time.Time  `json:"first_seen" db:"first_seen"`
    LastSeen     time.Time  `json:"last_seen" db:"last_seen"`
    Count        int        `json:"count" db:"count"`
    MITREAttack  []string   `json:"mitre_attack,omitempty" db:"mitre_attack"`
    Resolved     bool       `json:"resolved" db:"resolved"`
    ResolvedTime *time.Time `json:"resolved_time,omitempty" db:"resolved_time"`
    Notes        string     `json:"notes,omitempty" db:"notes"`
    FalsePositive bool      `json:"false_positive" db:"false_positive"`
    LogName      string     `json:"log_name" db:"log_name"`
    RuleScore    float64    `json:"rule_score" db:"rule_score"`
}
```

---

## 二、中等问题 (需要补充)

### 问题 6: 依赖选择需要确认

**严重程度**: 🟡 中等  
**影响**: requirements.md 与 design.md 不一致

**问题**: `go-sqlite3` 需要 CGO，与"单二进制"目标冲突

**修复**: 更新 requirements.md，确认使用 `modernc.org/sqlite`

---

### 问题 7: 错误处理细节缺失

**严重程度**: 🟡 中等  
**影响**: 无法统一错误处理

**修复方案**: 扩展错误码定义

```go
// internal/types/errors.go

const (
    // 通用错误
    ErrCodeSuccess         ErrorCode = "SUCCESS"
    ErrCodeInternalError   ErrorCode = "INTERNAL_ERROR"
    ErrCodeInvalidParam    ErrorCode = "INVALID_PARAM"
    ErrCodeNotFound        ErrorCode = "NOT_FOUND"
    ErrCodeUnauthorized    ErrorCode = "UNAUTHORIZED"
    
    // 导入相关
    ErrCodeParseFailed     ErrorCode = "PARSE_FAILED"
    ErrCodeImportFailed    ErrorCode = "IMPORT_FAILED"
    ErrCodeFileNotFound    ErrorCode = "FILE_NOT_FOUND"
    ErrCodeFileLocked      ErrorCode = "FILE_LOCKED"
    ErrCodeInvalidFormat   ErrorCode = "INVALID_FORMAT"
    
    // 数据库相关
    ErrCodeDBError         ErrorCode = "DB_ERROR"
    ErrCodeDBReadOnly      ErrorCode = "DB_READ_ONLY"
    
    // 规则相关
    ErrCodeRuleInvalid     ErrorCode = "RULE_INVALID"
    ErrCodeRuleNotFound    ErrorCode = "RULE_NOT_FOUND"
    ErrCodeRuleDisabled    ErrorCode = "RULE_DISABLED"
    
    // 搜索相关
    ErrCodeSearchFailed    ErrorCode = "SEARCH_FAILED"
    ErrCodeInvalidQuery    ErrorCode = "INVALID_QUERY"
    ErrCodeResultTooLarge  ErrorCode = "RESULT_TOO_LARGE"
    
    // 告警相关
    ErrCodeAlertNotFound   ErrorCode = "ALERT_NOT_FOUND"
    ErrCodeAlertAlreadyResolved ErrorCode = "ALREADY_RESOLVED"
    
    // 取证相关
    ErrCodeHashMismatch    ErrorCode = "HASH_MISMATCH"
    ErrCodeSignatureInvalid ErrorCode = "SIGNATURE_INVALID"
)
```

---

### 问题 8: 配置结构不完整

**严重程度**: 🟡 中等  
**影响**: 无法支持高级配置

**修复方案**: 扩展配置结构

```go
// internal/config/config.go

type Config struct {
    Database   DatabaseConfig   `yaml:"database"`
    Import     ImportConfig     `yaml:"import"`
    Search     SearchConfig     `yaml:"search"`
    Alerts     AlertsConfig     `yaml:"alerts"`
    Correlation CorrelationConfig `yaml:"correlation"`
    Report     ReportConfig     `yaml:"report"`
    Forensics  ForensicsConfig  `yaml:"forensics"`
    API        APIConfig        `yaml:"api"`
    Log        LogConfig        `yaml:"log"`
}

type AlertsConfig struct {
    Enabled         bool              `yaml:"enabled"`
    DedupWindow     time.Duration     `yaml:"dedup_window"`
    UpgradeRules    []*AlertUpgradeRule `yaml:"upgrade_rules,omitempty"`
    SuppressRules   []*SuppressRule   `yaml:"suppress_rules,omitempty"`
    StatsRetention  time.Duration     `yaml:"stats_retention"`  // 默认 30 天
}

type SearchConfig struct {
    MaxResults      int           `yaml:"max_results"`    // 默认 100000
    Timeout         time.Duration `yaml:"timeout"`       // 默认 30s
    HighlightMaxLength int       `yaml:"highlight_max_length"` // 高亮最大长度
}
```

---

### 问题 9: 采集器 one_click.go 设计不完整

**严重程度**: 🟡 中等  
**影响**: 无法实现文件锁定检测和 IIS 路径自动发现

**修复方案**: 添加缺失方法

```go
// internal/collectors/one_click.go

// 发现日志源
func (c *OneClickCollector) discoverLogSources() ([]LogSource, error) {
    sources := []LogSource{}
    
    // 1. 发现 Windows 事件日志
    logs := []string{"Security", "System", "Application"}
    for _, log := range logs {
        sources = append(sources, LogSource{
            Type: "eventlog",
            Name: log,
            Path: fmt.Sprintf("C:\\Windows\\System32\\winevt\\Logs\\%s.evtx", log),
        })
    }
    
    // 2. 发现 IIS 日志 (从注册表读取)
    iisPath, err := c.getIISLogPath()
    if err == nil && iisPath != "" {
        sources = append(sources, LogSource{
            Type: "iis",
            Name: "IIS",
            Path: iisPath,
        })
    }
    
    return sources, nil
}

// 获取 IIS 日志路径
func (c *OneClickCollector) getIISLogPath() (string, error) {
    // 读取注册表: MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\LogFileDirectory
    cmd := exec.Command("powershell", "-Command", `
        (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\W3SVC\\Parameters' -Name LogFileDirectory).LogFileDirectory
    `)
    output, err := cmd.Output()
    if err != nil {
        return "", err
    }
    return strings.TrimSpace(string(output)), nil
}

// 检测文件是否被锁定
func (c *OneClickCollector) isFileLocked(path string) bool {
    // 使用 Windows API: CreateFile with FILE_FLAG_WRITE | FILE_FLAG_READ
    // 如果失败说明文件被占用
    handle, err := windows.CreateFile(
        windows.StringToUTF16Ptr(path),
        windows.GENERIC_READ|windows.GENERIC_WRITE,
        0,
        nil,
        windows.OPEN_EXISTING,
        windows.FILE_ATTRIBUTE_NORMAL,
        0,
    )
    if err != nil {
        return true
    }
    windows.CloseHandle(handle)
    return false
}
```

---

## 三、文档结构问题

### 问题 10: 章节编号错误

**严重程度**: 🟡 低  
**影响**: 文档可读性差

**问题详情**:
- 第 1526 行 "## 9. 取证模块设计" 下面又出现 "### 8.1"
- 第 1624 行 "## 9. 规则系统设计" 与第 1526 行重复

**修复方案**: 重编号章节

```
## 9. 取证模块设计
### 9.1 证据完整性校验
### 9.2 证据链保护

## 10. 规则系统设计
### 10.1 统一规则接口
### 10.2 规则加载器

## 11. 数据库设计

## 12. 配置文件设计

## 13. 错误处理设计

## 14. 测试策略

## 15. 构建与部署

## 16. 移植对照表

## 17. 关键技术决策

## 18. 后续规划

## 19. 附录
```

---

## 四、修复优先级

| 优先级 | 问题 | 工作量 | 状态 |
|--------|------|--------|------|
| **P0** | 问题 1: 目录结构不完整 | 大 | 待修复 |
| **P0** | 问题 2: 告警引擎不完整 | 大 | 待修复 |
| **P0** | 问题 3: API Handler 缺失 | 大 | 待修复 |
| **P0** | 问题 4: 实时监控缺失 | 中 | 待修复 |
| **P0** | 问题 5: 数据类型不一致 | 小 | 待修复 |
| **P1** | 问题 6: 依赖确认 | 小 | 待修复 |
| **P1** | 问题 7: 错误处理细节 | 中 | 待修复 |
| **P1** | 问题 8: 配置结构不完整 | 中 | 待修复 |
| **P1** | 问题 9: 采集器不完整 | 中 | 待修复 |
| **P2** | 问题 10: 章节编号 | 小 | 待修复 |

---

## 五、修复跟踪

| 日期 | 修复内容 | 修复人 |
|------|----------|--------|
| 2026-04-13 | 创建问题修复清单 | - |

---

*文档版本: v1.0*
