# Reports 模块

安全报告生成模块，提供多种报告类型的生成和导出功能。

## 核心组件

### 1. ReportService (`service.go`)

统一报告服务层，封装报告生成和导出逻辑。

```go
type ReportService struct {
    db        *storage.DB
    generator *Generator
}
```

**核心方法**:

| 方法 | 说明 |
|------|------|
| `Generate(req *ReportRequest)` | 生成报告 |
| `ExportHTML(req *ReportRequest, w io.Writer)` | 导出 HTML |
| `ExportHTMLFromReport(report *Report, w io.Writer)` | 从报告对象导出 HTML |
| `ExportJSON(req *ReportRequest)` | 导出 JSON |
| `ExportPDF(req *ReportRequest, w io.Writer)` | 导出 PDF |
| `GenerateAsync(req *ReportRequest, callback)` | 异步生成 |
| `GenerateFromAPIRequest(apiReq *APIReportRequest)` | 从 API 请求生成 |

### 2. Generator (`generator.go`)

报告生成器核心，根据报告类型生成不同报告。

```go
type Generator struct {
    db     *storage.DB
    stats  *SecurityStats
    config *GeneratorConfig
}
```

**报告类型** (`ReportType`):

| 类型标识 | 说明 | 生成方法 |
|----------|------|----------|
| `alert_report` | 告警详情报告 | `generateAlertReport` |
| `event_report` | 原始事件报告 | `generateEventReport` |
| `timeline_report` | 时间线报告 | `generateTimelineReport` |
| `security_summary` / `""` | 安全摘要报告 | `generateSecuritySummaryReport` |

### 3. Report 结构

```go
type Report struct {
    GeneratedAt      time.Time         `json:"generated_at"`
    Title            string            `json:"title"`
    Type             ReportType        `json:"type"`
    TimeRange        TimeRange         `json:"time_range"`
    Summary          ReportSummary     `json:"summary"`
    Stats            *SecurityStats    `json:"stats,omitempty"`
    TopAlerts        []*types.Alert    `json:"top_alerts,omitempty"`
    TopEvents        []*types.Event    `json:"top_events,omitempty"`
    EventDist        *EventDist        `json:"event_distribution,omitempty"`
    LoginStats       *LoginStats       `json:"login_stats,omitempty"`
    IOCs             *IOCSummary       `json:"iocs,omitempty"`
    MITREDist        *MITREDist        `json:"mitre_distribution,omitempty"`
    RawEvents        []*types.Event    `json:"raw_events,omitempty"`
    ExecutiveSummary *ExecutiveSummary `json:"executive_summary,omitempty"`
    TimelineAnalysis *TimelineAnalysis `json:"timeline_analysis,omitempty"`
    ThreatLandscape  *ThreatLandscape  `json:"threat_landscape,omitempty"`
    Recommendations  []Recommendation  `json:"recommendations,omitempty"`
    AttackPatterns   []*AttackPattern  `json:"attack_patterns,omitempty"`
    ComplianceStatus *ComplianceStatus `json:"compliance_status,omitempty"`
    Timeline         []TimelineEntry   `json:"timeline,omitempty"`
}
```

### 4. ReportRequest

```go
type ReportRequest struct {
    Type         string       // 报告类型
    Title        string       // 报告标题
    Format       ReportFormat // 格式: html/json
    StartTime    time.Time    // 开始时间
    EndTime      time.Time    // 结束时间
    IncludeRaw   bool         // 包含原始事件
    IncludeIOC   bool         // 包含 IOC
    IncludeMITRE bool         // 包含 MITRE 分布
}
```

### 5. APIReportRequest

API 层请求结构：

```go
type APIReportRequest struct {
    Type         string // 报告类型
    Format       string // 格式
    StartTime    string // RFC3339 格式
    EndTime      string // RFC3339 格式
    IncludeRaw   bool
    IncludeIOC   bool
    IncludeMITRE bool
    Compression  bool
    Title        string
    Description  string
}
```

## 报告组件类型

### ReportSummary

```go
type ReportSummary struct {
    TotalEvents    int64    `json:"total_events"`
    TotalAlerts    int64    `json:"total_alerts"`
    CriticalEvents int64    `json:"critical_events"`
    HighAlerts     int64    `json:"high_alerts"`
    TimeRangeDays  float64  `json:"time_range_days"`
    Computers      []string `json:"computers"`
}
```

### SecurityStats

安全统计数据，包括：
- 事件级别分布
- 日志名称分布
- 来源分布
- Top Event IDs
- IOC 统计

### EventDist

事件分布统计：

```go
type EventDist struct {
    ByLevel     map[string]int64 `json:"by_level"`
    ByLogName   map[string]int64 `json:"by_log_name"`
    BySource    map[string]int64 `json:"by_source"`
    TopEventIDs []EventIDCount   `json:"top_event_ids"`
}
```

### ExecutiveSummary

执行摘要：

```go
type ExecutiveSummary struct {
    RiskScore        float64  `json:"risk_score"`
    RiskLevel        string   `json:"risk_level"`
    TotalAlerts      int64    `json:"total_alerts"`
    ResolvedAlerts   int64    `json:"resolved_alerts"`
    UnresolvedAlerts int64    `json:"unresolved_alerts"`
    TopThreat        string   `json:"top_threat"`
    KeyFindings      []string `json:"key_findings"`
    ActionItems      int      `json:"action_items"`
}
```

### ThreatLandscape

威胁态势：

```go
type ThreatLandscape struct {
    CriticalThreats  int64          `json:"critical_threats"`
    HighThreats      int64          `json:"high_threats"`
    MediumThreats    int64          `json:"medium_threats"`
    LowThreats       int64          `json:"low_threats"`
    TopAttackVectors []AttackVector `json:"top_attack_vectors"`
    AffectedSystems  []string       `json:"affected_systems"`
}
```

## 导出格式

| 格式 | 导出方法 | 依赖 |
|------|----------|------|
| HTML | `ExportHTML` | `html.go` (HTMLReport) |
| JSON | `ExportJSON` | 标准库 `encoding/json` |
| PDF | `ExportPDF` | `github.com/jung-kurt/gofpdf` |

## 文件结构

```
internal/reports/
├── generator.go        # 报告生成核心
├── service.go          # ReportService 统一服务层
├── api_adapter.go      # API 类型适配器
├── html.go             # HTML 报告生成
├── json.go             # JSON 导出
├── security_stats.go   # 安全统计计算
├── template/           # 模板管理
│   └── manager.go
└── *_test.go          # 测试文件
```

## 使用示例

### CLI 报告生成

```go
service := reports.NewReportService(db)
report, err := service.Generate(&reports.ReportRequest{
    Type:      "security_summary",
    Title:     "Daily Security Report",
    StartTime: startTime,
    EndTime:   endTime,
})
```

### API HTML 导出

```go
service := reports.NewReportService(db)
err := service.ExportHTML(req, writer)
```

### 异步生成

```go
service.GenerateAsync(req, func(report *reports.Report, err error) {
    if err != nil {
        log.Printf("Report generation failed: %v", err)
        return
    }
    fmt.Printf("Report generated: %s\n", report.Title)
})
```

## 重构历史

### R7 统一服务层重构

**问题**:
- TopEvents 未填充
- Timeline 无数据
- IncludeIOC/IncludeMITRE 丢失
- CLI 报告类型支持不完整
- API HTML 导出功能缺失

**解决方案**:
- 引入 `ReportService` 作为统一入口
- `ExportHTMLFromReport` 支持从已有报告导出
- 修复 `Type` 字段分派到各个生成方法
