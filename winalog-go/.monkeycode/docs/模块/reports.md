# 报告生成模块 (Reports)

## 概述

报告生成模块提供安全分析报告的生成功能,支持 HTML、JSON、PDF 三种输出格式。模块从数据库中提取事件、告警、持久化检测等数据,生成包含安全摘要、威胁态势、MITRE ATT&CK 分布等内容的综合报告。

## 目录

- [核心结构](#核心结构)
- [Generator](#generator)
- [ReportService](#reportservice)
- [报告内容](#报告内容)
- [报告模板](#报告模板)
- [架构设计](#架构设计)

## 核心结构

### Generator

报告生成的核心组件,从数据库提取数据并组装报告:

```go
// internal/reports/generator.go
type Generator struct {
    db     *storage.DB
    stats  *SecurityStats
    config *GeneratorConfig
}

type GeneratorConfig struct {
    Title        string
    StartTime    time.Time
    EndTime      time.Time
    Format       ReportFormat
    IncludeRaw   bool
    IncludeIOC   bool
    IncludeMITRE bool
}

type ReportFormat string

const (
    FormatHTML ReportFormat = "html"
    FormatJSON ReportFormat = "json"
)
```

### ReportRequest

报告生成请求参数:

```go
type ReportRequest struct {
    Type         string         // 报告类型
    Title        string         // 报告标题
    Format       ReportFormat   // 输出格式
    Language     string         // "en" 或 "zh"
    StartTime    time.Time      // 时间范围起始
    EndTime      time.Time      // 时间范围结束
    IncludeRaw   bool           // 是否包含原始事件
    IncludeIOC   bool           // 是否包含 IOC
    IncludeMITRE bool           // 是否包含 MITRE 分布
}
```

### Report

完整的报告数据结构:

```go
type Report struct {
    GeneratedAt       time.Time          `json:"generated_at"`
    Title             string             `json:"title"`
    Language          string             `json:"language"`
    TimeRange         TimeRange          `json:"time_range"`
    Summary           ReportSummary      `json:"summary"`
    Stats             *SecurityStats     `json:"stats,omitempty"`
    TopAlerts         []*types.Alert     `json:"top_alerts,omitempty"`
    TopEvents         []*types.Event     `json:"top_events,omitempty"`
    EventDist         *EventDist         `json:"event_distribution,omitempty"`
    LoginStats        *LoginStats        `json:"login_stats,omitempty"`
    IOCs              *IOCSummary        `json:"iocs,omitempty"`
    MITREDist         *MITREDist         `json:"mitre_distribution,omitempty"`
    RawEvents         []*types.Event     `json:"raw_events,omitempty"`
    ExecutiveSummary  *ExecutiveSummary  `json:"executive_summary,omitempty"`
    TimelineAnalysis  *TimelineAnalysis  `json:"timeline_analysis,omitempty"`
    ThreatLandscape   *ThreatLandscape   `json:"threat_landscape,omitempty"`
    Recommendations   []Recommendation   `json:"recommendations,omitempty"`
    AttackPatterns    []*AttackPattern   `json:"attack_patterns,omitempty"`
    ComplianceStatus  *ComplianceStatus  `json:"compliance_status,omitempty"`
    Timeline          []TimelineEntry    `json:"timeline,omitempty"`
    SystemSnapshot    *SystemSnapshot    `json:"system_snapshot,omitempty"`
    PersistenceReport *PersistenceReport `json:"persistence_report,omitempty"`
}
```

## Generator

### 报告类型

| 类型 | 对应方法 | 说明 |
|------|----------|------|
| `security`, `security_summary`, `""` | `generateSecuritySummaryReport` | 安全综合报告 (默认) |
| `alert`, `alert_report` | `generateAlertReport` | 告警报告 |
| `event`, `event_report` | `generateEventReport` | 事件报告 |
| `timeline`, `timeline_report` | `generateTimelineReport` | 时间线报告 |
| `persistence`, `persistence_report` | `generatePersistenceReport` | 持久化检测报告 |

### 核心方法

| 方法 | 说明 |
|------|------|
| `Generate(req *ReportRequest)` | 生成报告 (同步) |
| `GenerateWithContext(ctx, req)` | 生成报告 (支持上下文取消) |
| `generateSecuritySummaryReport` | 安全综合报告,包含所有模块数据 |
| `calculateSecurityStats` | 计算安全统计信息 |
| `extractIOCs` | 提取 IOC (IP、用户、计算机、文件路径) |
| `calculateMITREDistribution` | 计算 MITRE ATT&CK 分布 |
| `generateExecutiveSummary` | 生成高管摘要 (风险评分、关键发现) |
| `generateTimelineAnalysis` | 时间线分析 (按小时/天统计) |
| `generateThreatLandscape` | 威胁态势分析 |
| `generateRecommendations` | 生成修复建议 |
| `generateAttackPatterns` | 攻击模式分析 |
| `generateComplianceStatus` | 合规状态检查 |
| `buildTimeline` | 构建时间线条目 |

### 风险评分计算

```go
if summary.TotalAlerts > 0 {
    summary.RiskScore = float64(summary.UnresolvedAlerts) / float64(summary.TotalAlerts) * 100
}

// 风险等级划分
// >= 75: Critical
// >= 50: High
// >= 25: Medium
// <  25: Low
```

## ReportService

报告服务层,封装 Generator 并提供多种导出方式:

```go
// internal/reports/service.go
type ReportService struct {
    db        *storage.DB
    generator *Generator
}

func NewReportService(db *storage.DB) *ReportService
func (s *ReportService) Generate(req *ReportRequest) (*Report, error)
func (s *ReportService) ExportHTML(req *ReportRequest, w io.Writer) error
func (s *ReportService) ExportJSON(req *ReportRequest) ([]byte, error)
func (s *ReportService) ExportPDF(req *ReportRequest, w io.Writer) error
func (s *ReportService) GenerateAsync(req *ReportRequest, callback func(*Report, error))
func (s *ReportService) GenerateAsyncWithContext(ctx, req, callback)
func (s *ReportService) GenerateFromAPIRequest(apiReq *APIReportRequest) (*Report, error)
```

### PDF 生成

使用 `gofpdf` 库生成 PDF 报告:

```go
func generatePDF(report *Report, w io.Writer) error {
    pdf := gofpdf.New("P", "mm", "A4", "")
    // 封面、摘要、告警详情等
}
```

## 报告内容

### ExecutiveSummary

高管摘要包含:

- `RiskScore`: 风险评分 (0-100)
- `RiskLevel`: 风险等级 (Critical/High/Medium/Low)
- `TotalAlerts`: 告警总数
- `ResolvedAlerts`: 已解决告警
- `UnresolvedAlerts`: 未解决告警
- `TopThreat`: 主要威胁
- `KeyFindings`: 关键发现列表
- `ActionItems`: 待处理事项数量

### SystemSnapshot

系统快照包含:

- 主机名、域名、OS 版本、架构
- 管理员权限状态
- 时区、本地时间、运行时间
- CPU 核心数、内存总量/剩余
- 网络连接快照
- 顶级进程列表
- DNS 缓存

### TimelineAnalysis

时间线分析:

- `EventsByHour`: 按小时事件分布
- `EventsByDay`: 按天事件分布
- `AlertsByHour`: 按小时告警分布
- `AlertsByDay`: 按天告警分布
- `PeakActivityHour`: 活跃高峰小时
- `PeakActivityDay`: 活跃高峰日期

### MITRE ATT&CK 映射

内置技术到战术的映射:

```go
var techniqueToTactic = map[string]string{
    "T1003": "Credential Access",
    "T1021": "Lateral Movement",
    "T1053": "Persistence",
    // ... 80+ 条映射
}
```

## 报告模板

位于 `reports/template/` 目录:

| 文件 | 说明 |
|------|------|
| `manager.go` | 模板管理器 |
| `template.go` | 模板加载和渲染 |
| `report.html` | HTML 报告模板 |

## 架构设计

```mermaid
graph TD
    A["API 请求"] --> B["ReportService"]
    B --> C["Generator.GenerateWithContext"]
    C --> D{"报告类型"}
    D -->|security| E["generateSecuritySummaryReport"]
    D -->|alert| F["generateAlertReport"]
    D -->|event| G["generateEventReport"]
    D -->|timeline| H["generateTimelineReport"]
    D -->|persistence| I["generatePersistenceReport"]
    
    E --> J["calculateSecurityStats"]
    E --> K["extractIOCs"]
    E --> L["calculateMITREDistribution"]
    E --> M["generateExecutiveSummary"]
    E --> N["generateRecommendations"]
    E --> O["collectSystemSnapshot"]
    E --> P["collectPersistenceReport"]
    
    B --> Q{"导出格式"}
    Q -->|HTML| R["ExportHTMLFromReport"]
    Q -->|JSON| S["ExportJSON"]
    Q -->|PDF| T["generatePDF (gofpdf)"]