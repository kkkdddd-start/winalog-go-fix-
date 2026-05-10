# 类型定义模块 (Types)

## 概述

类型定义模块是整个项目的基础数据层,定义了所有核心数据类型,包括事件、告警、规则、过滤器和搜索请求。其他所有模块都依赖此模块的类型。

## 目录

- [Event](#event)
- [EventLevel](#eventlevel)
- [Alert](#alert)
- [Severity](#severity)
- [Filter](#filter)
- [规则系统](#规则系统)
- [搜索](#搜索)
- [辅助函数](#辅助函数)

## Event

核心事件类型,表示一条 Windows 事件日志:

```go
// internal/types/event.go
type Event struct {
    ID              int64                  `json:"id" db:"id"`
    Timestamp       time.Time              `json:"timestamp" db:"timestamp"`
    EventID         int32                  `json:"event_id" db:"event_id"`
    Level           EventLevel             `json:"level" db:"level"`
    Source          string                 `json:"source" db:"source"`
    LogName         string                 `json:"log_name" db:"log_name"`
    Computer        string                 `json:"computer" db:"computer"`
    User            *string                `json:"user,omitempty" db:"user"`
    UserSID         *string                `json:"user_sid,omitempty" db:"user_sid"`
    Message         string                 `json:"message" db:"message"`
    RawXML          *string                `json:"raw_xml,omitempty" db:"raw_xml"`
    SessionID       *string                `json:"session_id,omitempty" db:"session_id"`
    IPAddress       *string                `json:"ip_address,omitempty" db:"ip_address"`
    ImportTime      time.Time              `json:"import_time" db:"import_time"`
    ImportID        int64                  `json:"import_id,omitempty" db:"import_id"`
    WindowsRecordID uint64                 `json:"-" db:"-"`
    ExtractedFields map[string]interface{} `json:"extracted_fields,omitempty" db:"-"`
}
```

### Event 辅助方法

| 方法 | 说明 |
|------|------|
| `ToMap()` | 转换为 map,用于数据库插入 |
| `ToSlice()` | 转换为切片,用于批量插入 |
| `SetExtractedField(key, value)` | 设置提取字段 |
| `GetExtractedField(key)` | 获取提取字段 |
| `GetLogonType()` | 获取登录类型 (int) |
| `GetTargetUserName()` | 获取目标用户名 |
| `GetSubjectUserName()` | 获取主体用户名 |
| `GetProcessId()` | 获取进程 ID |
| `GetProcessName()` | 获取进程名 |
| `GetCommandLine()` | 获取命令行 |
| `GetServiceName()` | 获取服务名 |
| `GetDestPort()` | 获取目标端口 |
| `ParseRawXML()` | 解析 RawXML 到 ExtractedFields |
| `ExtractKeyFields()` | 提取关键字段到 map |

### 数据库辅助

```go
var EventColumns = []string{
    "id", "timestamp", "event_id", "level", "source", "log_name",
    "computer", "user", "user_sid", "message", "raw_xml",
    "session_id", "ip_address", "import_time", "import_id",
}

func ScanEvent(row interface{ Scan(...interface{}) error }) (*Event, error)
```

## EventLevel

```go
type EventLevel string

const (
    EventLevelCritical EventLevel = "Critical"
    EventLevelError    EventLevel = "Error"
    EventLevelWarning  EventLevel = "Warning"
    EventLevelInfo     EventLevel = "Info"
    EventLevelVerbose  EventLevel = "Verbose"
)
```

### 方法

| 方法 | 说明 |
|------|------|
| `String()` | 返回字符串表示 |
| `IsValid()` | 验证是否为有效级别 |

### 转换函数

```go
func EventLevelFromInt(level int) EventLevel
// 1 -> Critical, 2 -> Error, 3 -> Warning, 4 -> Info, 5 -> Verbose
```

## Alert

告警类型,由规则引擎生成:

```go
type Alert struct {
    ID            int64      `json:"id" db:"id"`
    RuleName      string     `json:"rule_name" db:"rule_name"`
    Severity      Severity   `json:"severity" db:"severity"`
    Message       string     `json:"message" db:"message"`
    EventIDs      []int32    `json:"event_ids" db:"event_ids"`
    EventDBIDs    []int64    `json:"event_db_ids" db:"event_db_ids"`
    FirstSeen     time.Time  `json:"first_seen" db:"first_seen"`
    LastSeen      time.Time  `json:"last_seen" db:"last_seen"`
    Count         int        `json:"count" db:"count"`
    MITREAttack   []string   `json:"mitre_attack,omitempty"`
    Resolved      bool       `json:"resolved" db:"resolved"`
    ResolvedTime  *time.Time `json:"resolved_time,omitempty"`
    Notes         string     `json:"notes,omitempty"`
    Explanation   string     `json:"explanation,omitempty"`
    Recommendation string    `json:"recommendation,omitempty"`
    RealCase      string     `json:"real_case,omitempty"`
    FalsePositive bool       `json:"false_positive" db:"false_positive"`
    LogName       string     `json:"log_name" db:"log_name"`
    RuleScore     float64    `json:"rule_score" db:"rule_score"`
}
```

## Severity

```go
type Severity string

const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
    SeverityInfo     Severity = "info"
)
```

### 方法

| 方法 | 说明 |
|------|------|
| `String()` | 返回字符串 |
| `Level()` | 转换为 EventLevel |

Severity 到 EventLevel 的映射:

| Severity | EventLevel |
|----------|-----------|
| critical | Critical |
| high | Error |
| medium | Warning |
| low | Info |
| info | Verbose |

## Filter

事件过滤器,支持多种比较操作:

```go
type Filter struct {
    Field    string      `json:"field"`
    Operator string      `json:"operator"`
    Value    interface{} `json:"value"`
}
```

### 操作符

| 操作符 | 说明 |
|--------|------|
| `equals` | 相等 |
| `not_equals` | 不相等 |
| `contains` | 包含 (不区分大小写) |
| `not_contains` | 不包含 |
| `regex` | 正则匹配 |
| `gt` | 大于 |
| `gte` | 大于等于 |
| `lt` | 小于 |
| `lte` | 小于等于 |

### 支持字段

| 字段 | 数据源 |
|------|--------|
| `event_id` | `event.EventID` |
| `level` | `event.Level` |
| `source` | `event.Source` |
| `log_name` | `event.LogName` |
| `computer` | `event.Computer` |
| `user` | `event.User` |
| `message` | `event.Message` |
| `ip_address` | `event.IPAddress` |

## 规则系统

### BaseRule

```go
type BaseRule struct {
    Name        string   `json:"name"`
    Description string   `json:"description"`
    Severity    Severity `json:"severity"`
    MITREAttack []string `json:"mitre_attack,omitempty"`
    Enabled     bool     `json:"enabled"`
    Tags        []string `json:"tags,omitempty"`
}
```

### AlertRule

告警规则:

```go
type AlertRule struct {
    BaseRule
    EventIDs        []int32       `json:"event_ids"`
    Filters         []Filter      `json:"filters,omitempty"`
    ConditionOp     LogicalOp     `json:"condition_op"`   // AND / OR
    GroupBy         string        `json:"group_by,omitempty"`
    Threshold       int           `json:"threshold"`
    TimeWindow      time.Duration `json:"time_window"`
    RuleScore       float64       `json:"rule_score"`
    Recommendations []string      `json:"recommendations,omitempty"`
}
```

### CorrelationRule

关联规则:

```go
type CorrelationRule struct {
    BaseRule
    TimeWindow  time.Duration `json:"time_window"`
    Conditions  []Condition   `json:"conditions"`
    JoinField   string        `json:"join_field,omitempty"`
    CrossBucket bool          `json:"cross_bucket"`
}
```

### Rule 接口

```go
type Rule interface {
    GetName() string
    GetSeverity() Severity
    GetRuleType() string  // "alert" 或 "correlation"
    IsEnabled() bool
}
```

### 规则评分

```go
var DefaultRuleWeights = map[string]float64{
    "mitre_coverage": 0.3,
    "false_positive": 0.2,
    "severity":       0.2,
    "hit_rate":       0.15,
    "recency":        0.15,
}

func CalculateRuleScore(rule *AlertRule, stats *AlertStats) float64
```

### AlertUpgradeRule & SuppressRule

```go
type AlertUpgradeRule struct {
    ID          int64    `json:"id"`
    Name        string   `json:"name"`
    Condition   string   `json:"condition"`
    Threshold   int      `json:"threshold"`
    NewSeverity Severity `json:"new_severity"`
    Notify      bool     `json:"notify"`
    Enabled     bool     `json:"enabled"`
}

type SuppressRule struct {
    ID         int64               `json:"id"`
    Name       string              `json:"name"`
    Conditions []SuppressCondition `json:"conditions"`
    Duration   time.Duration       `json:"duration"`
    Scope      string              `json:"scope"`
    Enabled    bool                `json:"enabled"`
}
```

## 搜索

### SearchRequest

```go
type SearchRequest struct {
    EventIDs   []int32
    StartTime  *time.Time
    EndTime    *time.Time
    PageSize   int
    // ... 其他搜索条件
}
```

### 统计类型

```go
type EventIDCount struct {
    EventID int32 `json:"event_id" db:"event_id"`
    Count   int64 `json:"count" db:"count"`
}

type LevelDistribution struct {
    Level EventLevel `json:"level" db:"level"`
    Count int64      `json:"count" db:"count"`
}

type LogNameDistribution struct {
    LogName string `json:"log_name" db:"log_name"`
    Count   int64  `json:"count" db:"count"`
}
```

### CorrelationResult

关联分析结果:

```go
type CorrelationResult struct {
    ID          string    `json:"id"`
    RuleName    string    `json:"rule_name"`
    Description string    `json:"description"`
    Severity    Severity  `json:"severity"`
    Events      []*Event  `json:"events"`
    StartTime   time.Time `json:"start_time"`
    EndTime     time.Time `json:"end_time"`
    MITREAttack []string  `json:"mitre_attack,omitempty"`
}
```

### AlertStats

```go
type AlertStats struct {
    Total        int64            `json:"total"`
    BySeverity   map[string]int64 `json:"by_severity"`
    ByStatus     map[string]int64 `json:"by_status"`
    ByRule       []*RuleCount     `json:"by_rule"`
    Trend        []*TrendPoint    `json:"trend"`
    AvgPerDay    float64          `json:"avg_per_day"`
    RuleScoreAvg float64          `json:"rule_score_avg"`
}
```

### AlertTrend

```go
type AlertTrend struct {
    Daily       []*TrendPoint `json:"daily"`
    Weekly      []*TrendPoint `json:"weekly"`
    ByHour      []*TrendPoint `json:"by_hour"`
    ByDayOfWeek []*TrendPoint `json:"by_day_of_week"`
}
```

### AttackChain (types 包)

```go
type AttackChain struct {
    ID          string    `json:"id"`
    EventIDs    []int64   `json:"event_ids"`
    StartTime   time.Time `json:"start_time"`
    EndTime     time.Time `json:"end_time"`
    Severity    Severity  `json:"severity"`
    Description string    `json:"description"`
    Technique   string    `json:"technique"`
    Events      []*Event  `json:"events"`
}
```

## 辅助函数

| 函数 | 说明 |
|------|------|
| `IsExternalIP(ip string) bool` | 判断是否为外网 IP (排除 10.x, 172.16-31.x, 192.168.x, 127.x) |
| `eventLevelToScore(level EventLevel) float64` | EventLevel 转分数 (Critical=5, Error=4, Warning=3, Info=2, Verbose=1) |
| `ParseSeverity(s string) (Severity, error)` | 字符串转 Severity |
| `ScoreValue(s Severity) float64` | Severity 转分数 (Critical=100, High=75, Medium=50, Low=25, Info=10) |
