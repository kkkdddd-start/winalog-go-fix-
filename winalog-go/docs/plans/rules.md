# Rules 模块改进实施方案

**项目**: WinLogAnalyzer-Go  
**模块**: `internal/rules/` + CLI + API  
**文档日期**: 2026-04-17  
**版本**: v2.1

---

## 一、问题摘要

### 1.1 已验证的问题

| 优先级 | 问题 | 位置 | 验证状态 | 说明 |
|--------|------|------|----------|------|
| **P1** | 验证逻辑重复 | `rule.go:156` vs `loader.go:130` | **已确认** | 两处 Validate 逻辑重复 |
| **P1** | MITRE ID 验证过于简单 | `loader.go:202-217` | **已确认** | 只检查 "T." 前缀 |
| **P1** | 规则优先级/权重机制缺失 | `rule.go` | **已确认** | 无法控制评估顺序 |
| **P2** | Condition 字段支持不完整 | `evaluator.go:238-263` | **已确认** | 不支持 ip_address 等 |
| **P2** | YAML 解析函数为空实现 | `validator.go:205-207` | **已确认** | unmarshalYAML 返回 nil |
| **P2** | API 无分页 | `handlers_rules.go:60-157` | **已确认** | 大数据量性能问题 |
| **P2** | Filter EventIDs 用遍历查找 | `evaluator.go:89-100` | **已确认** | O(n) 应改为 O(1) |
| **P2** | Level 范围定义冲突 | `rule.go:205` vs `loader.go:190` | **已确认** | 1-5 vs 0-4 |
| **P3** | 硬编码时间戳 | `custom_rules.go:270-272` | **已确认** | 返回 "2024-01-01" |
| **P3** | CLI 无规则管理命令 | `cmd/winalog/commands/` | **已确认** | 只有 alert 命令 |
| **P3** | 阈值聚合内存存储 | `evaluator.go:25-28` | **已确认** | 重启丢失 |

### 1.2 已排除的问题

| 问题 | 原判断 | 实际情况 |
|------|--------|----------|
| 规则评估逻辑缺失 | P0 | **已有完整实现** (`evaluator.go:64-498`) |
| 内置规则可被 API 修改 | P0 | **设计需求**，用户需要能够修改 |

---

## 二、P1 级问题修复

### ISSUE-1: 验证逻辑重复

#### 2.1.1 问题分析

**现状**: `rule.go:156` 的 `AlertRule.Validate()` 和 `loader.go:130` 的 `Validator.ValidateAlertRule()` 有重复验证逻辑。

**代码位置**:
- `rule.go:156-195` - AlertRule 自带的 Validate
- `loader.go:130-162` - Loader.Validator 的 ValidateAlertRule

**重复内容**:
```go
// rule.go
func (r *AlertRule) Validate() error {
    if r.Name == "" { return err }
    if r.Severity == "" { return err }
    if r.Filter == nil && r.Conditions == nil { return err }
    // Severity 有效值验证
    // Filter 验证
    // Conditions 验证
}

// loader.go
func (v *Validator) ValidateAlertRule(rule *AlertRule) error {
    if rule.Name == "" { return err }  // 重复
    if rule.Severity == "" { return err }  // 重复
    if rule.Filter == nil && rule.Conditions == nil { return err }  // 重复
    // Severity 有效值验证  // 重复
    // Filter 验证  // 重复
    // 无 Conditions 验证
}
```

#### 2.1.2 实施方案

**修改文件**:
- `internal/rules/rule.go`
- `internal/rules/loader.go`

**步骤 1**: 修改 `rule.go`，增强 Validate 方法

```go
// internal/rules/rule.go

// AlertRule.Validate 保持不变，增加 MITRE ID 验证
func (r *AlertRule) Validate() error {
    if r.Name == "" {
        return fmt.Errorf("rule name is required")
    }
    if r.Severity == "" {
        return fmt.Errorf("severity is required")
    }
    if r.Filter == nil && r.Conditions == nil {
        return fmt.Errorf("either filter or conditions is required")
    }

    // 验证 Severity 有效值
    validSeverities := map[Severity]bool{
        SeverityCritical: true,
        SeverityHigh:     true,
        SeverityMedium:   true,
        SeverityLow:      true,
        SeverityInfo:     true,
    }
    if !validSeverities[r.Severity] {
        return fmt.Errorf("invalid severity: %s", r.Severity)
    }

    // 验证 MITRE ID (新增)
    if r.MitreAttack != "" {
        if err := validateMitreIDFormat(r.MitreAttack); err != nil {
            return err
        }
    }

    // 验证 Filter
    if r.Filter != nil {
        if err := r.validateFilter(r.Filter); err != nil {
            return fmt.Errorf("filter validation failed: %w", err)
        }
    }

    // 验证 Conditions
    if r.Conditions != nil {
        if err := r.validateConditions(r.Conditions); err != nil {
            return fmt.Errorf("conditions validation failed: %w", err)
        }
    }

    // 验证 Threshold 与 TimeWindow
    if r.Threshold > 0 && r.TimeWindow == 0 {
        return fmt.Errorf("threshold requires time_window to be set")
    }

    return nil
}

// 新增：MITRE ID 格式验证
var mitreIDRegex = regexp.MustCompile(`^(T\d{4}(?:\.\d{3})?)$`)

func validateMitreIDFormat(id string) error {
    if id == "" {
        return nil
    }
    
    // 格式验证：T1234 或 T1234.001
    if !mitreIDRegex.MatchString(id) {
        return fmt.Errorf("invalid mitre_attack format: %s (expected T#### or T####.###)", id)
    }
    
    // 提取战术编号
    tacticStr := strings.TrimPrefix(id, "T")
    if strings.Contains(tacticStr, ".") {
        tacticStr = strings.Split(tacticStr, ".")[0]
    }
    
    tacticNum, err := strconv.Atoi(tacticStr)
    if err != nil {
        return fmt.Errorf("invalid mitre_attack: %s", id)
    }
    
    // T1xxx = Enterprise, T2xxx = Mobile, T3xxx = ICS
    tacticType := tacticNum / 1000
    if tacticType < 1 || tacticType > 3 {
        return fmt.Errorf("invalid mitre_attack: %s (tactic type must be 1-3)", id)
    }
    
    return nil
}
```

**步骤 2**: 修改 `loader.go`，委托给 rule.Validate()

```go
// internal/rules/loader.go

func (v *Validator) ValidateAlertRule(rule *AlertRule) error {
    // 委托给 rule.Validate()，避免重复
    return rule.Validate()
}

// 移除 loader.go 中重复的 validateFilter 方法
// 保留 Validator.ValidateCorrelationRule 用于关联规则验证
```

**步骤 3**: 修改 `validator.go` 中的 ValidationResult 验证

```go
// internal/rules/validator.go

func (v *ValidationResult) validateAlertRuleFields(rule *AlertRule) {
    // 名称长度警告
    if len(rule.Name) > 100 {
        v.AddWarning("rule name exceeds 100 characters")
    }

    // MITRE ID 格式警告 (增强验证)
    if rule.MitreAttack != "" {
        if err := validateMitreIDFormat(rule.MitreAttack); err != nil {
            v.AddWarning("invalid MITRE ATT&CK ID format: " + err.Error())
        }
    }

    // Score 范围警告
    if rule.Score < 0 || rule.Score > 100 {
        v.AddWarning("score should be between 0 and 100")
    }

    // Threshold 警告
    if rule.Threshold > 0 && rule.TimeWindow == 0 {
        v.AddWarning("threshold set but time_window is zero")
    }

    // Filter 字段验证
    if rule.Filter != nil {
        v.validateFilterFields(rule.Filter)
    }

    // Conditions 字段验证
    if rule.Conditions != nil {
        v.validateConditionsFields(rule.Conditions)
    }
}
```

#### 2.1.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 低 | 约 30 行修改 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | **高** | 消除代码重复，符合单一职责 |
| **可靠性** | 高 | 统一验证入口 |
| **风险** | 低 | 仅重构，无功能变更 |
| **验证方式** | `go test ./internal/rules/...` | 运行现有测试 |

---

### ISSUE-2: MITRE ID 验证过于简单

#### 2.2.1 问题分析

**现状**: `loader.go:202-217` 的 `ValidateMITREID` 只检查是否以 "T." 开头：

```go
func (v *Validator) ValidateMITREID(id string) bool {
    if len(id) < 5 {
        return false
    }
    parts := strings.Split(id, ".")
    if len(parts) != 2 {
        return false
    }
    if parts[0] != "T" {  // 问题：parts[0] 是 "T"，不是 "T."
        return false
    }
    return true
}
```

**问题**:
1. 逻辑错误：`strings.Split("T1234", ".")` 返回 `["T1234"]`，len=1，不是 2
2. 不验证编号有效性
3. 不验证战术类型

#### 2.2.2 实施方案

**修改文件**: `internal/rules/loader.go`

```go
// 替换现有的 ValidateMITREID 方法
func (v *Validator) ValidateMITREID(id string) bool {
    return validateMitreIDFormat(id) == nil
}

// 使用 ISSUE-1 中定义的 validateMitreIDFormat
// 该函数已在 rule.go 中定义
```

或者，如果不想依赖 rule.go 的函数，在 loader.go 中直接定义：

```go
// internal/rules/loader.go

var mitreIDRegex = regexp.MustCompile(`^(T\d{4}(?:\.\d{3})?)$`)

func validateMitreID(id string) error {
    if id == "" {
        return nil
    }
    
    if !mitreIDRegex.MatchString(id) {
        return fmt.Errorf("invalid mitre_id format: %s (expected T#### or T####.###)", id)
    }
    
    // 提取战术编号部分
    tacticStr := strings.TrimPrefix(id, "T")
    if strings.Contains(tacticStr, ".") {
        tacticStr = strings.Split(tacticStr, ".")[0]
    }
    
    tacticNum, err := strconv.Atoi(tacticStr)
    if err != nil {
        return fmt.Errorf("invalid mitre_id: %s", id)
    }
    
    // 战术类型验证
    tacticType := tacticNum / 1000
    if tacticType < 1 || tacticType > 3 {
        return fmt.Errorf("invalid mitre_id: %s (tactic type must be 1-3)", id)
    }
    
    return nil
}
```

#### 2.2.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 低 | 约 25 行 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | **高** | 修复逻辑错误，提高数据质量 |
| **可靠性** | 高 | 正则 + 数值验证 |
| **风险** | 低 | 现有无效 MITRE ID 会失败 |

---

### ISSUE-3: 规则优先级/权重机制缺失

#### 2.3.1 问题分析

**现状**: AlertRule 无 Priority 和 Weight 字段，规则按加载顺序评估。

**影响**:
1. 无法让高优先级规则先评估
2. 无法区分规则重要性
3. 无法按优先级排序输出告警

#### 2.3.2 实施方案

**修改文件**: `internal/rules/rule.go`

**步骤 1**: 在 AlertRule 结构中添加字段

```go
type AlertRule struct {
    Name           string         `yaml:"name"`
    Description    string         `yaml:"description"`
    Enabled        bool           `yaml:"enabled"`
    Severity       Severity       `yaml:"severity"`
    Score          float64        `yaml:"score"`
    MitreAttack    string         `yaml:"mitre_attack,omitempty"`
    
    // 新增字段
    Priority       int            `yaml:"priority"`    // 1-100，默认 50，值越大优先级越高
    Weight         float64        `yaml:"weight"`      // 告警权重，默认 1.0
    
    Filter         *Filter        `yaml:"filter"`
    Conditions     *Conditions    `yaml:"conditions,omitempty"`
    Threshold      int            `yaml:"threshold,omitempty"`
    TimeWindow     time.Duration  `yaml:"time_window,omitempty"`
    AggregationKey string         `yaml:"aggregation_key,omitempty"`
    Message        string         `yaml:"message"`
    Tags           []string       `yaml:"tags,omitempty"`
    Level          string         `yaml:"level,omitempty"`
    // ... 其他现有字段
}
```

**步骤 2**: 添加 getter 方法和默认值处理

```go
// GetPriority 返回规则优先级，范围 1-100，默认 50
func (r *AlertRule) GetPriority() int {
    if r.Priority <= 0 {
        return 50
    }
    if r.Priority > 100 {
        return 100
    }
    return r.Priority
}

// GetWeight 返回告警权重，默认 1.0
func (r *AlertRule) GetWeight() float64 {
    if r.Weight <= 0 {
        return 1.0
    }
    return r.Weight
}

// GetEffectiveScore 返回加权后的评分
func (r *AlertRule) GetEffectiveScore() float64 {
    return r.Score * r.GetWeight()
}
```

**步骤 3**: 添加规则排序器

```go
// RuleSorter 实现 sort.Interface 用于规则排序
type RuleSorter struct {
    rules []*AlertRule
}

func (s *RuleSorter) Len() int {
    return len(s.rules)
}

func (s *RuleSorter) Less(i, j int) bool {
    // 按优先级降序排序
    pi := s.rules[i].GetPriority()
    pj := s.rules[j].GetPriority()
    if pi != pj {
        return pi > pj
    }
    // 优先级相同按权重降序
    return s.rules[i].GetWeight() > s.rules[j].GetWeight()
}

func (s *RuleSorter) Swap(i, j int) {
    s.rules[i], s.rules[j] = s.rules[j], s.rules[i]
}

// SortRules 按优先级和权重排序规则
func SortRules(rules []*AlertRule) {
    sorter := &RuleSorter{rules: rules}
    sort.Sort(sorter)
}
```

**步骤 4**: 修改 Loader 加载时排序

```go
// internal/rules/loader.go

func (l *Loader) Load() ([]*AlertRule, []*CorrelationRule, error) {
    alertRules := make([]*AlertRule, 0)
    correlationRules := make([]*CorrelationRule, 0)

    for _, path := range l.rulePaths {
        rules, corrRules, err := l.loadFromPath(path)
        if err != nil {
            continue
        }
        alertRules = append(alertRules, rules...)
        correlationRules = append(correlationRules, corrRules...)
    }

    // 按优先级排序
    SortRules(alertRules)

    return alertRules, correlationRules, nil
}
```

**步骤 5**: 修改 API Handler 返回排序后的规则

```go
// internal/api/handlers_rules.go

func (h *RulesHandler) ListRules(c *gin.Context) {
    alertRules := builtin.GetAlertRules()
    customRules := h.customManager.List()
    
    // ... 现有转换逻辑 ...
    
    // 按优先级排序
    rules.SortRules(alertRules)  // 新增
    
    // ...
}
```

#### 2.3.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 低 | 约 60 行 |
| **适配性** | 高 | 向后兼容，新增字段有默认值 |
| **必要性** | **高** | 规则管理基础功能 |
| **可靠性** | 高 | 标准 sort.Interface 实现 |
| **风险** | 低 | 仅新增字段和排序 |

---

## 三、P2 级问题修复

### ISSUE-4: Condition 字段支持不完整

#### 3.1.1 问题分析

**现状**: `evaluator.go:238-263` 的 `matchCondition` 只支持以下字段：
- event_id, level, source, log_name, computer, user, message

**不支持的常用字段**:
- `ip_address` - IP 地址匹配
- `process_name` - 进程名匹配
- `command_line` - 命令行匹配
- `service_name` - 服务名匹配
- `logon_type` - 登录类型匹配
- `status` - 状态码匹配

#### 3.2.2 实施方案

**修改文件**: `internal/rules/rule.go` 和 `internal/alerts/evaluator.go`

**步骤 1**: 扩展 validConditionFields

```go
// internal/rules/rule.go

var validConditionFields = map[string]bool{
    // 基础字段
    "event_id":      true,
    "level":         true,
    "source":        true,
    "log_name":      true,
    "computer":      true,
    "user":          true,
    "message":       true,
    "ip_address":    true,
    // 新增字段
    "process_name":   true,
    "command_line":   true,
    "service_name":   true,
    "logon_type":     true,
    "status":         true,
    "provider_name":  true,
    "workstation":    true,
    "domain":         true,
}
```

**步骤 2**: 修改 matchCondition 支持新字段

```go
// internal/alerts/evaluator.go

func (e *Evaluator) matchCondition(cond *rules.Condition, event *types.Event) bool {
    field := strings.ToLower(cond.Field)

    switch field {
    case "event_id":
        return e.compareValue(event.EventID, cond.Operator, cond.Value)
    case "level":
        return e.compareValue(int(event.Level), cond.Operator, cond.Value)
    case "source":
        return e.compareString(event.Source, cond.Operator, cond.Value, cond.Regex)
    case "log_name":
        return e.compareString(event.LogName, cond.Operator, cond.Value, cond.Regex)
    case "computer":
        return e.compareString(event.Computer, cond.Operator, cond.Value, cond.Regex)
    case "user":
        var userStr string
        if event.User != nil {
            userStr = *event.User
        }
        return e.compareString(userStr, cond.Operator, cond.Value, cond.Regex)
    case "message":
        return e.compareString(event.Message, cond.Operator, cond.Value, cond.Regex)
    case "ip_address":
        var ipStr string
        if event.IPAddress != nil {
            ipStr = *event.IPAddress
        }
        return e.compareString(ipStr, cond.Operator, cond.Value, cond.Regex)
    // 新增字段支持
    case "process_name":
        return e.compareString(event.ProcessName, cond.Operator, cond.Value, cond.Regex)
    case "command_line":
        return e.compareString(event.CommandLine, cond.Operator, cond.Value, cond.Regex)
    case "service_name":
        return e.compareString(event.ServiceName, cond.Operator, cond.Value, cond.Regex)
    case "logon_type":
        return e.compareValue(event.LogonType, cond.Operator, cond.Value)
    case "status":
        return e.compareString(event.Status, cond.Operator, cond.Value, cond.Regex)
    case "provider_name":
        return e.compareString(event.ProviderName, cond.Operator, cond.Value, cond.Regex)
    case "workstation":
        return e.compareString(event.Workstation, cond.Operator, cond.Value, cond.Regex)
    case "domain":
        return e.compareString(event.Domain, cond.Operator, cond.Value, cond.Regex)
    default:
        // 尝试从 ExtendedData 获取
        if event.ExtendedData != nil {
            if val, ok := event.ExtendedData[field]; ok {
                return e.compareString(val, cond.Operator, cond.Value, cond.Regex)
            }
        }
        return false
    }
}
```

**步骤 3**: 确保 Event 类型有新字段

```go
// internal/types/event.go
// 检查并添加缺失的字段

type Event struct {
    // ... 现有字段 ...
    
    // 新增字段 (如果不存在)
    ProcessName   string `json:"process_name,omitempty"`
    CommandLine   string `json:"command_line,omitempty"`
    ServiceName   string `json:"service_name,omitempty"`
    LogonType     int    `json:"logon_type,omitempty"`
    Status        string `json:"status,omitempty"`
    ProviderName  string `json:"provider_name,omitempty"`
    Workstation   string `json:"workstation,omitempty"`
    Domain        string `json:"domain,omitempty"`
}
```

#### 3.2.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 低 | 约 40 行 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 中 | 规则灵活性提升 |
| **可靠性** | 高 | 安全的字段访问 |
| **风险** | 低 | 仅新增字段支持 |

---

### ISSUE-5: YAML 解析函数为空实现

#### 3.3.1 问题分析

**现状**: `validator.go:205-207` 的 `unmarshalYAML` 返回 nil：

```go
func unmarshalYAML(data string, v interface{}) error {
    return nil  // 空实现！
}
```

**影响**: 无法通过 `ValidateRuleSyntax` API 验证 YAML 语法。

#### 3.3.2 实施方案

**修改文件**: `internal/rules/validator.go`

```go
func unmarshalYAML(data string, v interface{}) error {
    return yaml.Unmarshal([]byte(data), v)
}
```

或者，更完整的实现支持自定义错误：

```go
func unmarshalYAML(data string, v interface{}) error {
    if data == "" {
        return fmt.Errorf("empty YAML data")
    }
    
    err := yaml.Unmarshal([]byte(data), v)
    if err != nil {
        return fmt.Errorf("YAML parse error: %w", err)
    }
    
    return nil
}
```

#### 3.3.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 很低 | 3 行 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | **高** | ValidateRuleSyntax API 依赖此函数 |
| **可靠性** | 高 | yaml.Unmarshal 标准库 |
| **风险** | 无 | 直接使用标准库 |

---

### ISSUE-6: API 无分页

#### 3.4.1 问题分析

**现状**: `handlers_rules.go:60-157` 的 `ListRules` 返回全部规则，无分页。

**影响**:
1. 内置规则 70+ 条 + 自定义规则，大数据量时性能差
2. 网络传输量大
3. 前端渲染压力

#### 3.4.2 实施方案

**修改文件**: `internal/api/handlers_rules.go`

**步骤 1**: 添加分页请求/响应结构

```go
// internal/api/handlers_rules.go

type ListRulesRequest struct {
    Page     int    `form:"page"`      // 页码，从 1 开始
    PageSize int    `form:"page_size"` // 每页数量，默认 20，最大 100
    Severity string `form:"severity"`  // 过滤：critical/high/medium/low/info
    Enabled  *bool  `form:"enabled"`   // 过滤：true/false
    Keyword  string `form:"keyword"`   // 搜索：规则名称关键词
}

type ListRulesResponse struct {
    Rules      []RuleInfo `json:"rules"`
    TotalCount int        `json:"total_count"`
    Page       int        `json:"page"`
    PageSize   int        `json:"page_size"`
    TotalPages int        `json:"total_pages"`
}
```

**步骤 2**: 修改 ListRules 实现分页

```go
func (h *RulesHandler) ListRules(c *gin.Context) {
    var req ListRulesRequest
    if err := c.ShouldBindQuery(&req); err != nil {
        req.Page = 1
        req.PageSize = 20
    }
    
    // 设置默认值
    if req.Page < 1 {
        req.Page = 1
    }
    if req.PageSize < 1 {
        req.PageSize = 20
    }
    if req.PageSize > 100 {
        req.PageSize = 100
    }

    // 获取所有规则
    alertRules := builtin.GetAlertRules()
    customRules := h.customManager.List()

    // 转换为 RuleInfo 并过滤
    allRules := make([]RuleInfo, 0, len(alertRules)+len(customRules))
    
    for _, rule := range alertRules {
        ruleInfo := convertToRuleInfo(rule, false)
        
        // 应用过滤
        if !applyRuleFilter(ruleInfo, &req) {
            continue
        }
        allRules = append(allRules, ruleInfo)
    }

    for _, rule := range customRules {
        ruleInfo := convertToRuleInfoFromCustom(rule)
        
        if !applyRuleFilter(ruleInfo, &req) {
            continue
        }
        allRules = append(allRules, ruleInfo)
    }

    // 计算分页
    totalCount := len(allRules)
    totalPages := (totalCount + req.PageSize - 1) / req.PageSize
    
    start := (req.Page - 1) * req.PageSize
    end := start + req.PageSize
    if start > totalCount {
        start = totalCount
    }
    if end > totalCount {
        end = totalCount
    }

    // 返回分页结果
    c.JSON(http.StatusOK, ListRulesResponse{
        Rules:      allRules[start:end],
        TotalCount: totalCount,
        Page:       req.Page,
        PageSize:   req.PageSize,
        TotalPages: totalPages,
    })
}

func applyRuleFilter(rule RuleInfo, req *ListRulesRequest) bool {
    // Severity 过滤
    if req.Severity != "" && rule.Severity != req.Severity {
        return false
    }
    
    // Enabled 过滤
    if req.Enabled != nil && rule.Enabled != *req.Enabled {
        return false
    }
    
    // 关键词搜索
    if req.Keyword != "" {
        keyword := strings.ToLower(req.Keyword)
        name := strings.ToLower(rule.Name)
        desc := strings.ToLower(rule.Description)
        if !strings.Contains(name, keyword) && !strings.Contains(desc, keyword) {
            return false
        }
    }
    
    return true
}

func convertToRuleInfo(rule *rules.AlertRule, isCustom bool) RuleInfo {
    // ... 现有转换逻辑
}

func convertToRuleInfoFromCustom(rule *rules.CustomRule) RuleInfo {
    // ... 现有转换逻辑
}
```

#### 3.4.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 中 | 约 80 行 |
| **适配性** | 高 | 向后兼容，新增参数有默认值 |
| **必要性** | 中 | 大数据量时性能提升 |
| **可靠性** | 高 | 标准分页模式 |
| **风险** | 低 | 仅性能优化 |

---

### ISSUE-7: Filter EventIDs 用遍历查找

#### 3.5.1 问题分析

**现状**: `evaluator.go:89-100` 用遍历查找 EventID：

```go
if len(filter.EventIDs) > 0 {
    found := false
    for _, eid := range filter.EventIDs {  // O(n) 遍历
        if event.EventID == eid {
            found = true
            break
        }
    }
    if !found {
        return false
    }
}
```

**影响**: EventIDs 列表大时（如 100+ 个 ID）性能差。

#### 3.5.2 实施方案

**修改文件**: `internal/rules/filter.go` (新建) 或 `internal/alerts/evaluator.go`

**方案 1**: 使用 map 缓存（推荐）

```go
// internal/rules/filter.go

package rules

// FilterMatcher 提供高效的 Filter 匹配
type FilterMatcher struct {
    eventIDSet map[int32]bool  // 用于 O(1) 查找
    levelSet   map[int]bool
    // ... 其他 set
}

func NewFilterMatcher(f *Filter) *FilterMatcher {
    m := &FilterMatcher{
        eventIDSet: make(map[int32]bool, len(f.EventIDs)),
        levelSet:   make(map[int]bool, len(f.Levels)),
    }
    
    for _, eid := range f.EventIDs {
        m.eventIDSet[eid] = true
    }
    for _, lvl := range f.Levels {
        m.levelSet[lvl] = true
    }
    
    return m
}

func (m *FilterMatcher) MatchEventID(eid int32) bool {
    if len(m.eventIDSet) == 0 {
        return true  // 无限制
    }
    return m.eventIDSet[eid]
}

func (m *FilterMatcher) MatchLevel(level int) bool {
    if len(m.levelSet) == 0 {
        return true
    }
    return m.levelSet[level]
}
```

**步骤 2**: 修改 Evaluator 使用 FilterMatcher

```go
// internal/alerts/evaluator.go

type Evaluator struct {
    mu           sync.RWMutex
    eventCount   map[eventCountKey]*eventCountEntry
    stopCh       chan struct{}
    filterCache  map[*Filter]*FilterMatcher  // 缓存编译后的 Filter
}

func NewEvaluator() *Evaluator {
    e := &Evaluator{
        eventCount:  make(map[eventCountKey]*eventCountEntry),
        stopCh:      make(chan struct{}),
        filterCache: make(map[*Filter]*FilterMatcher),
    }
    go e.cleanupExpiredEntries()
    return e
}

func (e *Evaluator) getFilterMatcher(f *rules.Filter) *rules.FilterMatcher {
    e.mu.RLock()
    matcher, exists := e.filterCache[f]
    e.mu.RUnlock()
    
    if exists {
        return matcher
    }
    
    e.mu.Lock()
    defer e.mu.Unlock()
    
    // 双重检查
    if matcher, exists = e.filterCache[f]; exists {
        return matcher
    }
    
    matcher = rules.NewFilterMatcher(f)
    e.filterCache[f] = matcher
    return matcher
}

func (e *Evaluator) matchFilter(filter *rules.Filter, event *types.Event) bool {
    if filter == nil {
        return true
    }

    matcher := e.getFilterMatcher(filter)
    
    // EventID 匹配 - O(1)
    if !matcher.MatchEventID(event.EventID) {
        return false
    }
    
    // Level 匹配 - O(1)
    if !matcher.MatchLevel(int(event.Level)) {
        return false
    }
    
    // 保留其他需要遍历的检查...
    
    return true
}
```

#### 3.5.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 中 | 约 60 行 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 中 | EventIDs > 50 时效果明显 |
| **可靠性** | 高 | 缓存 + 线程安全 |
| **风险** | 中 | 内存增加（缓存） |

---

### ISSUE-8: Level 范围定义冲突

#### 3.6.1 问题分析

**现状**: 
- `rule.go:205` 验证 Level 范围 1-5
- `loader.go:190` 验证 Level 范围 0-4

**Windows 事件级别**: 0=LogAlways, 1=Critical, 2=Error, 3=Warning, 4=Info, 5=Verbose

**冲突**: 标准是 0-4，但代码中有冲突定义。

#### 3.6.2 实施方案

**修改文件**: `internal/rules/rule.go`

```go
func (r *AlertRule) validateFilter(f *Filter) error {
    for _, eid := range f.EventIDs {
        if eid < 0 || eid > 65535 {
            return fmt.Errorf("invalid event_id: %d (must be 0-65535)", eid)
        }
    }

    for _, lvl := range f.Levels {
        // Windows 事件级别: 0=LogAlways, 1=Critical, 2=Error, 3=Warning, 4=Info, 5=Verbose
        if lvl < 0 || lvl > 5 {
            return fmt.Errorf("invalid level: %d (must be 0-5)", lvl)
        }
    }

    if f.Keywords != "" && f.KeywordMode == "" {
        return fmt.Errorf("keywords requires keyword_mode to be set")
    }

    if f.TimeRange != nil {
        if f.TimeRange.End.Before(f.TimeRange.Start) {
            return fmt.Errorf("time_range end must be after start")
        }
    }

    return nil
}
```

同步修改 loader.go：

```go
// internal/rules/loader.go

func (v *Validator) validateFilter(filter *Filter) error {
    for _, eid := range filter.EventIDs {
        if eid < 0 || eid > 65535 {
            return fmt.Errorf("invalid event_id: %d", eid)
        }
    }

    for _, level := range filter.Levels {
        // 统一为 0-5
        if level < 0 || level > 5 {
            return fmt.Errorf("invalid level: %d (must be 0-5)", level)
        }
    }

    if filter.Keywords != "" && filter.KeywordMode == "" {
        filter.KeywordMode = OpAnd
    }

    return nil
}
```

#### 3.6.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 很低 | 10 行 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 中 | 修复代码冲突 |
| **可靠性** | 高 | 统一标准 |
| **风险** | 低 | 数值范围微调 |

---

## 四、P3 级问题修复

### ISSUE-9: 硬编码时间戳

#### 4.1.1 问题分析

**现状**: `custom_rules.go:270-272` 返回固定时间：

```go
func Now() string {
    return "2024-01-01T00:00:00Z"
}
```

#### 4.1.2 实施方案

**修改文件**: `internal/rules/custom_rules.go`

```go
func Now() string {
    return time.Now().UTC().Format(time.RFC3339)
}
```

**如需测试支持**：

```go
var timeNow = func() time.Time {
    return time.Now().UTC()
}

func SetTimeNow(f func() time.Time) {
    timeNow = f
}

func ResetTimeNow() {
    timeNow = func() time.Time {
        return time.Now().UTC()
    }
}

func Now() string {
    return timeNow().Format(time.RFC3339)
}
```

#### 4.1.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 很低 | 5 行 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 低 | 仅为测试友好 |
| **可靠性** | 高 | 真实时间 |
| **风险** | 无 | 无功能影响 |

---

### ISSUE-10: CLI 无规则管理命令

#### 4.2.1 问题分析

**现状**: CLI 只有 `winalog alert` 命令，没有 `winalog rule` 命令。

**缺失功能**:
- `winalog rule list` - 列出规则
- `winalog rule show <name>` - 显示规则详情
- `winalog rule validate <file>` - 验证规则文件

#### 4.2.2 实施方案

**新增文件**: `cmd/winalog/commands/rule.go`

```go
package commands

import (
    "fmt"
    "github.com/kkkdddd-start/winalog-go/internal/rules"
    "github.com/kkkdddd-start/winalog-go/internal/rules/builtin"
    "github.com/spf13/cobra"
)

var ruleCmd = &cobra.Command{
    Use:   "rule",
    Short: "Rule management",
    Long:  `Manage and view detection rules`,
}

var ruleListCmd = &cobra.Command{
    Use:   "list",
    Short: "List all rules",
    RunE:  runRuleList,
}

var ruleShowCmd = &cobra.Command{
    Use:   "show <name>",
    Short: "Show rule details",
    Args:  cobra.ExactArgs(1),
    RunE:  runRuleShow,
}

var ruleValidateCmd = &cobra.Command{
    Use:   "validate <file>",
    Short: "Validate rule YAML file",
    Args:  cobra.ExactArgs(1),
    RunE:  runRuleValidate,
}

var ruleExportCmd = &cobra.Command{
    Use:   "export [output-file]",
    Short: "Export rules to YAML",
    RunE:  runRuleExport,
}

func init() {
    ruleCmd.AddCommand(ruleListCmd)
    ruleCmd.AddCommand(ruleShowCmd)
    ruleCmd.AddCommand(ruleValidateCmd)
    ruleCmd.AddCommand(ruleExportCmd)
    
    // 添加到 rootCmd
    rootCmd.AddCommand(ruleCmd)
    
    ruleListCmd.Flags().Bool("builtin", true, "Include built-in rules")
    ruleListCmd.Flags().Bool("custom", true, "Include custom rules")
    ruleListCmd.Flags().String("severity", "", "Filter by severity")
    ruleListCmd.Flags().Bool("enabled-only", false, "Show only enabled rules")
}

func runRuleList(cmd *cobra.Command, args []string) error {
    showBuiltin, _ := cmd.Flags().GetBool("builtin")
    showCustom, _ := cmd.Flags().GetBool("custom")
    severity, _ := cmd.Flags().GetString("severity")
    enabledOnly, _ := cmd.Flags().GetBool("enabled-only")
    
    rulesList := make([]*rules.AlertRule, 0)
    
    if showBuiltin {
        rulesList = append(rulesList, builtin.GetAlertRules()...)
    }
    
    if showCustom {
        customManager := rules.NewCustomRuleManager("")
        rulesList = append(rulesList, customManager.GetAll()...)
    }
    
    // 过滤
    filtered := make([]*rules.AlertRule, 0)
    for _, r := range rulesList {
        if enabledOnly && !r.Enabled {
            continue
        }
        if severity != "" && string(r.Severity) != severity {
            continue
        }
        filtered = append(filtered, r)
    }
    
    // 按优先级排序
    rules.SortRules(filtered)
    
    fmt.Printf("%-40s %-10s %-8s %s\n", "NAME", "SEVERITY", "ENABLED", "DESCRIPTION")
    fmt.Println(strings.Repeat("-", 80))
    
    for _, r := range filtered {
        enabledStr := "false"
        if r.Enabled {
            enabledStr = "true"
        }
        desc := r.Description
        if len(desc) > 40 {
            desc = desc[:37] + "..."
        }
        fmt.Printf("%-40s %-10s %-8s %s\n", r.Name, r.Severity, enabledStr, desc)
    }
    
    fmt.Printf("\nTotal: %d rules\n", len(filtered))
    return nil
}

func runRuleShow(cmd *cobra.Command, args []string) error {
    name := args[0]
    
    // 查找内置规则
    for _, r := range builtin.GetAlertRules() {
        if r.Name == name {
            printRuleDetail(r, false)
            return nil
        }
    }
    
    // 查找自定义规则
    customManager := rules.NewCustomRuleManager("")
    if r, ok := customManager.Get(name); ok {
        printRuleDetail(r.ToAlertRule(), true)
        return nil
    }
    
    return fmt.Errorf("rule not found: %s", name)
}

func printRuleDetail(r *rules.AlertRule, isCustom bool) {
    ruleType := "Built-in"
    if isCustom {
        ruleType = "Custom"
    }
    
    fmt.Println("=== Rule Details ===")
    fmt.Printf("Name:        %s\n", r.Name)
    fmt.Printf("Type:        %s\n", ruleType)
    fmt.Printf("Description: %s\n", r.Description)
    fmt.Printf("Severity:    %s\n", r.Severity)
    fmt.Printf("Score:       %.2f\n", r.Score)
    fmt.Printf("Enabled:     %t\n", r.Enabled)
    fmt.Printf("Priority:    %d\n", r.GetPriority())
    fmt.Printf("Weight:      %.2f\n", r.GetWeight())
    fmt.Printf("MITRE:       %s\n", r.MitreAttack)
    
    if r.Filter != nil {
        fmt.Println("\nFilter:")
        if len(r.Filter.EventIDs) > 0 {
            fmt.Printf("  EventIDs: %v\n", r.Filter.EventIDs)
        }
        if len(r.Filter.Levels) > 0 {
            fmt.Printf("  Levels: %v\n", r.Filter.Levels)
        }
        if r.Filter.Keywords != "" {
            fmt.Printf("  Keywords: %s\n", r.Filter.Keywords)
        }
    }
    
    if r.Tags != nil && len(r.Tags) > 0 {
        fmt.Printf("Tags:        %s\n", strings.Join(r.Tags, ", "))
    }
}

func runRuleValidate(cmd *cobra.Command, args []string) error {
    filePath := args[0]
    
    loadedRules, err := rules.LoadRulesFromFile(filePath)
    if err != nil {
        return fmt.Errorf("failed to load rules: %w", err)
    }
    
    if len(loadedRules) == 0 {
        fmt.Println("No valid rules found in file")
        return nil
    }
    
    fmt.Printf("Validated %d rules:\n", len(loadedRules))
    for _, r := range loadedRules {
        fmt.Printf("  [OK] %s\n", r.Name)
    }
    
    return nil
}

func runRuleExport(cmd *cobra.Command, args []string) error {
    outputPath := "rules_export.yaml"
    if len(args) > 0 {
        outputPath = args[0]
    }
    
    // 导出所有内置规则
    // ... 实际实现省略
    
    fmt.Printf("Exported rules to %s\n", outputPath)
    return nil
}
```

#### 4.2.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 中 | 约 150 行 |
| **适配性** | 高 | 新增命令 |
| **必要性** | 低 | CLI 体验优化 |
| **可靠性** | 高 | 标准 Cobra 模式 |
| **风险** | 低 | 仅新增功能 |

---

### ISSUE-11: 阈值聚合内存存储

#### 4.3.1 问题分析

**现状**: `evaluator.go:25-28` 阈值计数存储在内存 map 中：

```go
type Evaluator struct {
    mu         sync.RWMutex
    eventCount map[eventCountKey]*eventCountEntry  // 内存存储
    stopCh     chan struct{}
}
```

**问题**: 服务重启后聚合状态丢失。

#### 4.3.2 实施方案

**修改文件**: `internal/alerts/evaluator.go` + `internal/storage/`

**方案**: 添加可选的持久化支持（作为 ISSUE-5 OPT-5 的简化版）

```go
// internal/alerts/evaluator.go

type Evaluator struct {
    mu          sync.RWMutex
    eventCount  map[eventCountKey]*eventCountEntry
    stopCh      chan struct{}
    db          *storage.DB  // 可选：持久化支持
    persistTick *time.Ticker
}

func NewEvaluator() *Evaluator {
    return &Evaluator{
        eventCount: make(map[eventCountKey]*eventCountEntry),
        stopCh:     make(chan struct{}),
    }
}

// 带数据库的构造函数
func NewEvaluatorWithDB(db *storage.DB) *Evaluator {
    e := NewEvaluator()
    e.db = db
    e.loadFromDB()
    e.persistTick = time.NewTicker(5 * time.Minute)
    
    go e.periodicPersist()
    
    return e
}

func (e *Evaluator) periodicPersist() {
    for {
        select {
        case <-e.persistTick.C:
            e.persistToDB()
        case <-e.stopCh:
            return
        }
    }
}

func (e *Evaluator) persistToDB() {
    if e.db == nil {
        return
    }
    // 实现持久化逻辑
}

func (e *Evaluator) loadFromDB() {
    if e.db == nil {
        return
    }
    // 实现加载逻辑
}
```

#### 4.3.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 中 | 约 80 行 |
| **适配性** | 高 | 可选功能 |
| **必要性** | 低 | 高级功能 |
| **可靠性** | 高 | 定时持久化 |
| **风险** | 中 | 数据库依赖 |

---

## 五、架构改进

### 5.1 模块职责划分（建议）

```
internal/rules/
├── rule.go              # 规则类型定义
├── validator.go         # 验证器（增强验证、语法验证）
├── loader.go            # 加载器（YAML 解析）
├── sorter.go            # 规则排序器
├── errors.go            # 错误类型定义
├── filter.go            # Filter 匹配器（优化版）
├── custom_rules.go      # 自定义规则管理器
├── builtin/
│   ├── definitions.go   # 内置规则
│   ├── registry.go      # 规则注册表
│   └── mitre.go         # MITRE 映射
└── rules_test.go        # 测试文件
```

### 5.2 错误类型定义（建议新增）

**新增文件**: `internal/rules/errors.go`

```go
package rules

import "fmt"

type RuleError struct {
    RuleName string
    Field    string
    Message  string
    Cause    error
}

func (e *RuleError) Error() string {
    if e.RuleName != "" {
        return fmt.Sprintf("rule %s: %s - %s", e.RuleName, e.Field, e.Message)
    }
    return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

func (e *RuleError) Unwrap() error {
    return e.Cause
}

var (
    ErrRuleNameRequired   = &RuleError{Field: "name", Message: "rule name is required"}
    ErrSeverityRequired   = &RuleError{Field: "severity", Message: "severity is required"}
    ErrFilterRequired     = &RuleError{Field: "filter", Message: "either filter or conditions is required"}
    ErrInvalidMitreID    = &RuleError{Field: "mitre_attack", Message: "invalid MITRE ATT&CK ID format"}
    ErrInvalidCondition   = &RuleError{Field: "condition", Message: "invalid condition field or operator"}
    ErrThresholdNoWindow  = &RuleError{Field: "threshold", Message: "threshold requires time_window"}
    ErrInvalidEventID     = &RuleError{Field: "event_id", Message: "invalid event ID (must be 0-65535)"}
    ErrInvalidLevel       = &RuleError{Field: "level", Message: "invalid level (must be 0-5)"}
)
```

---

## 六、实施汇总

### 6.1 优先级总览

| ID | 问题 | 优先级 | 复杂度 | 工作量 | 风险 |
|----|------|--------|--------|--------|------|
| ISSUE-1 | 验证逻辑重复 | **P1** | 低 | 0.5 人天 | 低 |
| ISSUE-2 | MITRE ID 验证过于简单 | **P1** | 低 | 0.25 人天 | 低 |
| ISSUE-3 | 规则优先级/权重机制 | **P1** | 低 | 0.5 人天 | 低 |
| ISSUE-4 | Condition 字段支持不完整 | P2 | 低 | 0.5 人天 | 低 |
| ISSUE-5 | YAML 解析函数为空 | P2 | 很低 | 0.1 人天 | 无 |
| ISSUE-6 | API 无分页 | P2 | 中 | 1 人天 | 低 |
| ISSUE-7 | Filter EventIDs 遍历查找 | P2 | 中 | 1 人天 | 中 |
| ISSUE-8 | Level 范围定义冲突 | P2 | 很低 | 0.1 人天 | 低 |
| ISSUE-9 | 硬编码时间戳 | P3 | 很低 | 0.1 人天 | 无 |
| ISSUE-10 | CLI 无规则管理命令 | P3 | 中 | 1 人天 | 低 |
| ISSUE-11 | 阈值聚合内存存储 | P3 | 中 | 1 人天 | 中 |

### 6.2 建议实施路线图

```
阶段 1 (P1 问题 - 1.5 周):
├─ ISSUE-1 验证逻辑统一
├─ ISSUE-2 MITRE ID 验证增强
└─ ISSUE-3 规则优先级机制

阶段 2 (P2 问题 - 2 周):
├─ ISSUE-4 Condition 字段扩展
├─ ISSUE-5 YAML 解析修复
├─ ISSUE-6 API 分页支持
├─ ISSUE-7 Filter EventIDs 优化
└─ ISSUE-8 Level 范围统一

阶段 3 (P3 问题 - 1 周):
├─ ISSUE-9 硬编码时间戳修复
├─ ISSUE-10 CLI 规则命令
└─ ISSUE-11 阈值聚合持久化 (可选)
```

### 6.3 依赖关系

```
ISSUE-3 (优先级) 
└─ 依赖 ISSUE-1 (验证统一)

ISSUE-6 (API 分页)
└─ 无依赖

ISSUE-7 (Filter 优化)
└─ 可独立实施

ISSUE-10 (CLI)
└─ 依赖 ISSUE-3 (SortRules)
```

---

## 七、验证清单

### 7.1 测试命令

```bash
cd /workspace/winalog-go/winalog-go

# 运行规则模块测试
go test ./internal/rules/... -v

# 运行 alerts 模块测试
go test ./internal/alerts/... -v

# 运行 API 测试
go test ./internal/api/... -v

# 运行完整测试
make test
```

### 7.2 手动验证步骤

1. **ISSUE-1 验证**:
   - 创建无效规则 YAML，调用 API `/api/rules/validate`
   - 验证错误消息正确

2. **ISSUE-2 验证**:
   - 创建 MITRE ID 为 "invalid" 的规则
   - 验证被拒绝

3. **ISSUE-3 验证**:
   - 创建两个优先级不同的规则
   - 调用 `ListRules` API
   - 验证返回顺序按优先级降序

4. **ISSUE-4 验证**:
   - 创建使用 `ip_address` 字段的 Condition
   - 验证规则能正确匹配事件

5. **ISSUE-6 验证**:
   - 调用 `GET /api/rules?page=2&page_size=10`
   - 验证返回分页结果

---

*文档版本: 2.1*  
*模块: Rules*  
*审核状态: 待审核*  
*实施状态: 已完成 (260417)*

## 实施记录

| 日期 | 分支 | 提交 | 说明 |
|------|------|------|------|
| 260417 | 260417-rules-improve-issues-fix | c6290b2 | 解决 ISSUE-1~9, ISSUE-10/11 已存在/可选 |

### 已解决问题

- **ISSUE-1**: 验证逻辑重复 → `loader.go` 委托给 `rule.Validate()`
- **ISSUE-2**: MITRE ID 验证 → `validateMitreIDFormat()` 
- **ISSUE-3**: 优先级/权重 → `SortRules` 函数
- **ISSUE-4**: Condition 字段 → 扩展支持 ip_address, hostname, user 等
- **ISSUE-5**: YAML 解析 → `unmarshalYAML` 实现
- **ISSUE-6**: API 分页 → `ListRulesRequest/Response`
- **ISSUE-7**: EventIDs 查找 → `FilterMatcher` O(1) 查找
- **ISSUE-8**: Level 范围 → 统一为 0-5
- **ISSUE-9**: 硬编码时间戳 → `Now()` 返回真实时间

### 不适用

- **ISSUE-10**: CLI 规则命令 → 已在 `system.go:261-296` 实现
- **ISSUE-11**: 阈值聚合持久化 → 标记为可选，暂不实施
