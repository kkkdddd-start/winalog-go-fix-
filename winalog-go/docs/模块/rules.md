# Rules 模块

**路径**: `internal/rules/`

规则系统，定义 AlertRule 和 CorrelationRule。

## 规则类型

### AlertRule

简单告警规则，基于过滤条件触发。

```go
type AlertRule struct {
    Name           string           // 规则名称
    Description    string           // 规则描述
    Enabled        bool             // 是否启用
    Severity       Severity         // 严重级别
    Score          float64          // 规则得分 (0-100)
    MitreAttack    string           // MITRE ATT&CK ID (如 "T1003")
    Filter         *Filter          // 简单过滤条件
    Conditions     *Conditions      // 复杂条件
    Threshold      int              // 触发阈值
    TimeWindow     time.Duration    // 时间窗口 (用于 Threshold)
    AggregationKey string           // 聚合键 (如 "Computer", "User")
    Message        string           // 告警消息模板
    Tags           []string         // 标签
}
```

### CorrelationRule

关联规则，基于多个事件模式触发。

```go
type CorrelationRule struct {
    Name        string           // 规则名称
    Description string           // 规则描述
    Enabled     bool             // 是否启用
    Severity    Severity         // 严重级别
    Patterns    []*Pattern       // 事件模式 (至少2个)
    TimeWindow  time.Duration    // 时间窗口
    Join        string           // 连接方式 (AND/OR)
    MitreAttack string           // MITRE ATT&CK ID
    Tags        []string         // 标签
}
```

## Severity 严重级别

```go
type Severity string

const (
    SeverityCritical Severity = "critical"  // 100分
    SeverityHigh     Severity = "high"     // 75分
    SeverityMedium   Severity = "medium"  // 50分
    SeverityLow      Severity = "low"      // 25分
    SeverityInfo     Severity = "info"     // 10分
)

func (s Severity) ScoreValue() float64
```

## Filter 过滤条件

```go
type Filter struct {
    EventIDs    []int32          // Event ID 列表
    Levels      []int            // 级别列表
    LogNames    []string         // 日志名列表
    Sources     []string         // 源列表
    Computers   []string         // 计算机名列表
    Keywords    string           // 关键字 (AND/OR 模式)
    KeywordMode LogicalOp        // AND 或 OR
    TimeRange   *types.TimeRange // 时间范围
}
```

## Conditions 条件

支持 AND/OR/NONE 逻辑组合。

```go
type Conditions struct {
    Any  []*Condition  // 任一条件满足时触发
    All  []*Condition  // 所有条件都满足时触发
    None []*Condition   // 所有条件都不满足时触发
}

type Condition struct {
    Field    string  // 字段名 (EventID, Level, Source, Computer, User, Message...)
    Operator string  // 操作符
    Value    string  // 比较值
    Regex    bool    // 是否正则匹配
}
```

**支持的操作符**:
| 操作符 | 说明 |
|--------|------|
| `equals` | 等于 |
| `not_equals` | 不等于 |
| `contains` | 包含 |
| `not_contains` | 不包含 |
| `starts_with` | 开头是 |
| `ends_with` | 结尾是 |
| `regex` | 正则匹配 |
| `gt` | 大于 |
| `lt` | 小于 |
| `gte` | 大于等于 |
| `lte` | 小于等于 |

## Pattern 模式 (用于 CorrelationRule)

```go
type Pattern struct {
    EventID    int32          // Event ID
    Conditions []*Condition   // 附加条件
    Join       string         // 连接方式
    TimeWindow time.Duration  // 时间窗口
}
```

## 消息模板

AlertRule 的 Message 字段支持模板替换:

```go
func (r *AlertRule) BuildMessage(event *types.Event) string
```

**支持的模板变量**:
| 变量 | 说明 |
|------|------|
| `{{.EventID}}` | Event ID |
| `{{.Source}}` | 来源 |
| `{{.Computer}}` | 计算机名 |
| `{{.User}}` | 用户名或 SID |
| `{{.Message}}` | 事件消息 |

**示例**:

```go
&AlertRule{
    Name:    "BruteForceLogin",
    Message: "Detected {{.Count}} failed login attempts for user {{.User}} on {{.Computer}}",
    // ...
}
```

## 规则验证

```go
func (r *AlertRule) Validate() error

func (r *CorrelationRule) Validate() error
```

**AlertRule 验证**:
- 规则名称不能为空
- 严重级别不能为空
- 必须有 Filter 或 Conditions

**CorrelationRule 验证**:
- 规则名称不能为空
- 至少需要 2 个 Pattern
- 每个 Pattern 的 EventID 不能为 0

## 内置规则

### 内置 AlertRule

定义在 `internal/rules/builtin/definitions.go`:

| 规则名 | 说明 | MITRE |
|--------|------|-------|
| `BruteForceLogin` | 暴力破解检测 | T1110 |
| `FailedLogin` | 登录失败检测 | - |
| `SuccessfulLogin` | 成功登录检测 | - |
| `AccountCreated` | 账户创建检测 | T1136 |
| `AccountModified` | 账户修改检测 | T1098 |
| `SuspiciousProcess` | 可疑进程检测 | T1055 |
| `PowerShellExecution` | PowerShell 执行检测 | T1059 |

### 内置规则注册表

```go
type Registry struct {
    rules map[string]*AlertRule
}

func NewRegistry() *Registry
func (r *Registry) Get(name string) (*AlertRule, bool)
func (r *Registry) List() []*AlertRule
func (r *Registry) LoadDefaults()
```

## 规则加载

```go
// 从文件加载 YAML 规则
func LoadRulesFromFile(path string) ([]*AlertRule, error)

// 从目录加载所有规则
func LoadRulesFromDir(dir string) ([]*AlertRule, error)

// 验证规则
func ValidateRule(rule *AlertRule) error
```

## 规则 YAML 格式

```yaml
name: BruteForceLogin
description: Detect brute force login attempts
enabled: true
severity: high
score: 80
mitre_attack: T1110

filter:
  event_ids:
    - 4625  # Failed login
  levels:
    - 4     # Information
  keywords: "logon failure"
  keyword_mode: AND

conditions:
  all:
    - field: EventID
      operator: equals
      value: "4625"
    - field: Message
      operator: contains
      value: "Logon Type: 3"

threshold: 5
time_window: 5m
aggregation_key: User

message: "Brute force detected: {{.Count}} failed logins for {{.User}}"
tags:
  - authentication
  - security
```

## 使用示例

```go
// 创建规则
rule := &AlertRule{
    Name:        "SuspiciousLogin",
    Description: "Detect logins from unusual locations",
    Enabled:     true,
    Severity:    SeverityHigh,
    Score:       75.0,
    MitreAttack: "T1110",
    Filter: &Filter{
        EventIDs: []int32{4624, 4625},
    },
    Conditions: &Conditions{
        All: []*Condition{
            {Field: "EventID", Operator: "equals", Value: "4624"},
            {Field: "Computer", Operator: "not_equals", Value: "TRUSTED_SERVER"},
        },
    },
    Message: "Suspicious login for user {{.User}} from {{.IPAddress}}",
}

// 验证规则
if err := rule.Validate(); err != nil {
    return err
}

// 构建消息
msg := rule.BuildMessage(event)
fmt.Println(msg)
```
