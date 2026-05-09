# Rules 模块深度分析报告

**项目**: WinLogAnalyzer-Go  
**模块**: `internal/rules/` + CLI + API  
**分析日期**: 2026-04-17  
**版本**: v2.4.0

---

## 一、模块架构总览

### 1.1 核心组件关系

```
┌─────────────────────────────────────────────────────────────────┐
│                        Rules 模块架构                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐    ┌──────────────────┐                    │
│  │   rule.go        │    │   loader.go      │                    │
│  │  - AlertRule     │    │  - YAML 解析      │                    │
│  │  - Correlation   │───▶│  - 文件加载       │                    │
│  │  - Filter        │    │  - Validator     │                    │
│  │  - Condition     │    └────────┬─────────┘                    │
│  └──────────────────┘             │                               │
│           │                      ▼                               │
│           ▼              ┌──────────────────┐                    │
│  ┌──────────────────┐   │  validator.go    │                    │
│  │ custom_rules.go  │   │  - 规则验证       │                    │
│  │  - 自定义规则管理 │   │  - ValidationRes │                    │
│  │  - 模板实例化     │   └──────────────────┘                    │
│  └──────────────────┘                                           │
│                                                                  │
│  ┌──────────────────┐    ┌──────────────────┐                    │
│  │ builtin/         │    │ alerts/          │                    │
│  │  - definitions   │───▶│  evaluator.go    │                    │
│  │  - registry      │    │  - 规则评估       │                    │
│  │  - mitre.go      │    │  - 阈值检测       │                    │
│  └──────────────────┘    └──────────────────┘                    │
│                                                                  │
│  ┌──────────────────┐    ┌──────────────────┐                    │
│  │ CLI (Cobra)     │    │ API (Gin)        │                    │
│  │  - alert.go     │    │  - handlers_rules│                    │
│  │  - list/run/mon │    │  - CRUD + 模板    │                    │
│  └──────────────────┘    └──────────────────┘                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 文件清单

| 文件 | 行数 | 职责 |
|------|------|------|
| `rule.go` | 310 | 规则类型定义、验证逻辑 |
| `loader.go` | 243 | YAML 加载器、验证器 |
| `validator.go` | 207 | 增强验证、语法验证 |
| `custom_rules.go` | 359 | 自定义规则、模板实例化 |
| `rules_test.go` | 395 | 单元测试 |
| `builtin/definitions.go` | 1567 | 内置规则定义 (70+ 规则) |
| `builtin/registry.go` | 65 | 规则注册表 |
| `builtin/mitre.go` | 41 | MITRE ATT&CK 映射 |

---

## 二、核心类型设计

### 2.1 AlertRule 结构

```go
type AlertRule struct {
    Name           string         // 规则名称
    Description    string         // 描述
    Enabled        bool           // 是否启用
    Severity       Severity       // 严重程度
    Score          float64        // 评分 (0-100)
    MitreAttack    string         // MITRE ATT&CK ID
    Filter         *Filter        // 过滤器
    Conditions     *Conditions    // 条件 (与/或/非)
    Threshold      int            // 阈值 (次数)
    TimeWindow     time.Duration  // 时间窗口
    AggregationKey string         // 聚合键 (user/computer/ip)
    Message        string         // 告警消息模板
    Tags           []string       // 标签
    // ... 其他字段
}
```

**设计优点**:
- 清晰的结构分离 (Filter vs Conditions)
- 支持阈值聚合 (`Threshold` + `TimeWindow` + `AggregationKey`)
- 消息模板支持变量替换 (`{{.EventID}}`, `{{.User}}` 等)

**设计问题**:
1. **Priority 字段缺失**: 无法控制规则评估顺序
2. **Weight 字段缺失**: 无法区分告警重要性
3. **Category/Group 字段缺失**: 无法对规则分组管理
4. **CreatedAt/UpdatedAt 缺失**: 无法追踪规则变更历史

### 2.2 Filter vs Conditions 设计

```go
type Filter struct {
    EventIDs         []int32    // 事件 ID 列表
    Levels           []int      // 事件级别
    LogNames         []string   // 日志名称
    Sources          []string   // 事件源
    Computers        []string   // 计算机名
    Keywords         string     // 关键词 (逗号分隔)
    KeywordMode      LogicalOp  // AND/OR
    TimeRange        *TimeRange // 时间范围
    IpAddress        []string   // IP 地址
    ProcessNames     []string   // 进程名
    // 排除条件
    ExcludeUsers     []string
    ExcludeComputers []string
    ExcludeDomains   []string
}

type Conditions struct {
    Any  []*Condition  // 任一匹配
    All  []*Condition  // 全部匹配
    None []*Condition  // 全部不匹配
}

type Condition struct {
    Field    string  // 字段名
    Operator string  // 操作符
    Value    string  // 值
    Regex    bool    // 是否正则
}
```

**设计分析**:

| 维度 | Filter | Conditions |
|------|--------|------------|
| 用途 | 快速初筛 | 精细匹配 |
| 性能 | O(1) 哈希查找 | 可能需要正则 |
| 逻辑 | 仅包含 | Any/All/None |
| 支持字段 | EventIDs, Levels, Sources 等 | 较少字段 |

**问题**:
1. `Filter.Keywords` 是字符串，`Condition` 中无 `Keywords` 支持
2. `Filter` 和 `Conditions` 语义有重叠，评估时是 AND 关系
3. `Condition` 不支持 `ExcludeUsers` 等排除逻辑

### 2.3 CorrelationRule 结构

```go
type CorrelationRule struct {
    Name        string
    Patterns    []*Pattern   // 至少 2 个模式
    TimeWindow  time.Duration
    Join        string       // AND/OR
    MitreAttack string
}

type Pattern struct {
    EventID    int32
    Conditions []*Condition
    MinCount   int
    MaxCount   int
    Ordered    bool         // 是否有序
}
```

**问题**:
- `CorrelationRule` 实际未被使用 (无 CLI 命令，无 API 端点)
- `Pattern.Ordered` 和 `MinCount/MaxCount` 未实现

---

## 三、CLI 模式分析

### 3.1 命令结构

```
winalog alert
├── list      # 列出告警
├── show      # 显示告警详情
├── resolve   # 标记已解决
├── delete    # 删除告警
├── export    # 导出告警
├── stats     # 统计信息
├── run       # 运行规则分析
└── monitor   # 持续监控模式
```

### 3.2 核心流程 (alert run)

```go
// cmd/winalog/commands/alert.go:383
func runAlertRun(cmd *cobra.Command, args []string) error {
    // 1. 获取内置规则
    builtinRules := builtin.GetAlertRules()
    
    // 2. 根据 flags 过滤规则
    if alertRunFlags.rules != "" {
        // 按名称筛选
    }
    
    // 3. 加载规则到引擎
    engine.LoadRules(enabledRules)
    
    // 4. 分批获取事件
    for {
        events, _, err := engine.GetDB().ListEvents(...)
        
        // 5. 批量评估
        alerts, err := engine.EvaluateBatch(ctx, events)
        
        // 6. 保存告警
        engine.SaveAlerts(alerts)
    }
}
```

### 3.3 CLI 存在的问题

| 问题 | 描述 | 严重程度 |
|------|------|----------|
| 无规则管理命令 | 只有 `alert` 命令，没有 `rule` 子命令 | P1 |
| 无规则 CRUD | 无法通过 CLI 创建/修改/删除规则 | P1 |
| 无规则导入导出 | 只能导出告警，不能导出规则 | P2 |
| 无规则验证 | 无法验证规则 YAML 语法 | P2 |
| 无规则列表 | 无法查看内置规则 | P2 |

---

## 四、Web API 模式分析

### 4.1 REST API 端点

```
GET    /api/rules              # 列出所有规则
GET    /api/rules/:name        # 获取规则详情
POST   /api/rules              # 创建自定义规则
PUT    /api/rules/:name        # 更新规则
DELETE /api/rules/:name        # 删除自定义规则
POST   /api/rules/:name/toggle # 启用/禁用规则
POST   /api/rules/validate     # 验证规则
POST   /api/rules/import       # 批量导入
GET    /api/rules/export       # 导出规则
GET    /api/rules/templates    # 列出模板
GET    /api/rules/templates/:name    # 获取模板
POST   /api/rules/templates/:name/instantiate # 实例化模板
```

### 4.2 API handler 实现分析

```go
// internal/api/handlers_rules.go

// ListRules - 合并内置和自定义规则
func (h *RulesHandler) ListRules(c *gin.Context) {
    alertRules := builtin.GetAlertRules()    // 内置规则
    customRules := h.customManager.List()     // 自定义规则
    
    // 转换为 RuleInfo 统一格式
    // 返回 total_count, enabled_count
}

// CreateRule - 创建自定义规则
func (h *RulesHandler) CreateRule(c *gin.Context) {
    // 1. 解析请求
    // 2. 检查名称冲突
    // 3. 转换为 CustomRule
    // 4. 保存到文件 (h.customManager.Add)
}
```

### 4.3 规则存储机制

| 规则类型 | 存储位置 | 格式 |
|----------|----------|------|
| 内置规则 | 代码内置 | Go 代码 |
| 自定义规则 | `~/.winalog/rules/` | JSON 文件 |

**问题**:
1. 自定义规则存储在用户目录，无法版本控制
2. 无数据库存储选项 (如 SQLite)
3. 无规则变更审计日志

### 4.4 API 存在的问题

| 问题 | 描述 | 严重程度 |
|------|------|----------|
| 无分页 | ListRules 返回全部规则 | P2 |
| 无过滤参数 | 无法按 severity/enabled 过滤 | P2 |
| 内置规则可修改 | UpdateRule 直接修改内置规则内存 | P0 |
| 无权限控制 | 任何人都可修改/删除规则 | P1 |
| 无规则历史 | 无法查看规则变更 | P2 |

---

## 五、规则评估引擎分析

### 5.1 评估流程

```go
// internal/alerts/evaluator.go

func (e *Evaluator) Evaluate(rule *rules.AlertRule, event *types.Event) (bool, error) {
    // 1. Filter 匹配 (快速初筛)
    if !e.matchFilter(rule.Filter, event) {
        return false, nil
    }
    
    // 2. Conditions 匹配 (精细条件)
    if rule.Conditions != nil {
        if !e.matchConditions(rule.Conditions, event) {
            return false, nil
        }
    }
    
    // 3. 阈值检测 (聚合)
    if rule.Threshold > 0 {
        if !e.checkThreshold(rule, event) {
            return false, nil
        }
    }
    
    return true, nil
}
```

### 5.2 Filter 评估

| 字段 | 评估方式 | 性能 |
|------|----------|------|
| EventIDs | 遍历匹配 | O(n) |
| Levels | 遍历匹配 | O(n) |
| LogNames | 遍历匹配 | O(n) |
| Sources | 遍历匹配 | O(n) |
| Computers | 遍历匹配 | O(n) |
| Keywords | 字符串包含 | O(m) |
| TimeRange | 时间比较 | O(1) |
| IpAddress | 遍历匹配 | O(n) |

**问题**: EventIDs 使用遍历而非哈希查找

### 5.3 Conditions 评估

```go
func (e *Evaluator) matchCondition(cond *rules.Condition, event *types.Event) bool {
    switch field {
    case "event_id":  return e.compareValue(event.EventID, cond.Operator, cond.Value)
    case "level":     return e.compareValue(int(event.Level), cond.Operator, cond.Value)
    case "source":    return e.compareString(event.Source, cond.Operator, cond.Value, cond.Regex)
    case "log_name":  return e.compareString(event.LogName, cond.Operator, cond.Value, cond.Regex)
    case "computer":  return e.compareString(event.Computer, cond.Operator, cond.Value, cond.Regex)
    case "user":      // 从 event.User 获取
    case "message":   return e.compareString(event.Message, cond.Operator, cond.Value, cond.Regex)
    default:          return false  // 未实现的字段返回 false
    }
}
```

**问题**:

| 字段 | 支持状态 | 备注 |
|------|----------|------|
| event_id | ✅ 支持 | |
| level | ✅ 支持 | |
| source | ✅ 支持 | |
| log_name | ✅ 支持 | |
| computer | ✅ 支持 | |
| user | ✅ 支持 | |
| message | ✅ 支持 | |
| ip_address | ❌ 不支持 | `Condition` 中无 ip_address |
| process_name | ❌ 不支持 | |
| command_line | ❌ 不支持 | |
| service_name | ❌ 不支持 | |
| parent_process | ❌ 不支持 | |
| target_filename | ❌ 不支持 | |
| logon_type | ❌ 不支持 | |
| status | ❌ 不支持 | |
| provider_name | ❌ 不支持 | |

### 5.4 阈值聚合机制

```go
func (e *Evaluator) checkThreshold(rule *rules.AlertRule, event *types.Event) bool {
    aggKey := e.getAggregationKey(rule, event)
    
    // 按 ruleName|aggKey 聚合
    key := eventCountKey{ruleName: rule.Name, aggKey: aggKey}
    
    // 在时间窗口内计数
    if now.Sub(entry.firstTime) > rule.TimeWindow {
        entry.count = 1  // 重置
    } else {
        entry.count++
    }
    
    return entry.count >= rule.Threshold
}
```

**问题**:
1. 内存存储，重启丢失
2. 聚合键有限 (`user`/`computer`/`source`/`ip`)
3. 只能按单一维度聚合

---

## 六、规则验证机制分析

### 6.1 验证分层

```
┌─────────────────────────────────────────────────────────────┐
│                      验证分层                                 │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────┐                                    │
│  │ rule.go Validate()  │  AlertRule 自验证                   │
│  │  - 字段必填          │  - 基础字段检查                     │
│  │  - Severity 有效值  │  - Filter/Conditions 验证           │
│  │  - Filter 验证      │                                    │
│  └─────────┬───────────┘                                    │
│            │                                                │
│            ▼                                                │
│  ┌─────────────────────┐                                    │
│  │ loader.go Validator │  Loader 验证                        │
│  │  - 基本验证          │  - 重复调用 rule.Validate()          │
│  │  - MITRE ID 格式    │  - 额外的 Filter 验证               │
│  └─────────┬───────────┘                                    │
│            │                                                │
│            ▼                                                │
│  ┌─────────────────────┐                                    │
│  │ validator.go        │  增强验证                           │
│  │  - ValidationResult │  - 字段长度警告                     │
│  │  - Warnings         │  - MITRE ID 格式警告                 │
│  │  - 规则语法验证      │  - Score 范围警告                   │
│  └─────────────────────┘                                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 验证问题

| 问题 | 位置 | 描述 |
|------|------|------|
| **验证重复** | rule.go + loader.go | `AlertRule.Validate()` 和 `Validator.ValidateAlertRule()` 重复 |
| **MITRE ID 简单** | loader.go:202-217 | 只检查 "T." 前缀，不验证编号 |
| **Level 范围冲突** | rule.go:205 vs loader.go:190 | rule.go 验证 1-5，loader.go 验证 0-4 |
| **无自定义验证入口** | API | `ValidateRule` API 不完整 |
| **YAML 解析为空** | validator.go:205-207 | `unmarshalYAML` 返回 nil |

---

## 七、模板机制分析

### 7.1 模板定义

```go
type CustomRule struct {
    IsTemplate  bool           `json:"is_template"`
    Parameters  []TemplateParam `json:"parameters,omitempty"`
    TemplateID  string         `json:"template_id,omitempty"`
}

type TemplateParam struct {
    Name        string
    Description string
    Default     string
    Required    bool
    Type        string  // string/int/boolean/select
    Options     []string // for select type
}
```

### 7.2 实例化流程

```go
func (r *CustomRule) Instantiate(paramValues map[string]string) *CustomRule {
    // 1. 复制规则
    rule := *r
    
    // 2. 替换模板变量
    for key, value := range paramValues {
        rule.Name = strings.ReplaceAll(rule.Name, "{{"+key+"}}", value)
        rule.Description = strings.ReplaceAll(rule.Description, "{{"+key+"}}", value)
        rule.Message = strings.ReplaceAll(rule.Message, "{{"+key+"}}", value)
        
        // 3. EventID 中的变量
        if rule.Filter != nil {
            for i, eventID := range rule.Filter.EventIDs {
                // 替换 EventID
            }
            // 替换 Keywords
        }
    }
    
    return &rule
}
```

### 7.3 模板机制问题

| 问题 | 描述 |
|------|------|
| 无模板存储位置 | API 创建时未保存模板 |
| 变量替换有限 | 只能替换字符串，不能替换 EventIDs 结构 |
| 无模板市场 | 无内置模板库 |
| API 不完整 | 无创建模板的 API |

---

## 八、内置规则分析

### 8.1 规则覆盖

`builtin/definitions.go` 包含 **70+ 条**内置告警规则，覆盖：

| MITRE 战术 | 规则数量 | 示例 |
|------------|----------|------|
| TA0001 Initial Access | 2 | usb-device-insertion |
| TA0002 Execution | 3 | encoded-powershell-alert |
| TA0003 Persistence | 15+ | scheduled-task-creation, registry-run-key |
| TA0004 Privilege Escalation | 5 | admin-login-unusual |
| TA0005 Defense Evasion | 8 | security-log-cleared |
| TA0006 Credential Access | 6 | pass-the-hash-suspect, mimikatz-suspect |
| TA0007 Discovery | 2 | wmi-suspicious |
| TA0008 Lateral Movement | 3 | network-connection-alert |
| TA0010 Exfiltration | 1 | network-connection-alert |
| TA0043 Reconnaissance | 1 | - |
| TA0044 Denial of Service | 1 | - |

### 8.2 规则结构示例

```go
{
    Name:           "failed-login-threshold",
    Description:    "失败登录次数超过阈值",
    Enabled:        true,
    Severity:       types.SeverityHigh,
    Score:          70,
    MitreAttack:    "T1110",  // Brute Force
    Threshold:      10,
    TimeWindow:     5 * time.Minute,
    AggregationKey: "user",
    Filter: &rules.Filter{
        EventIDs: []int32{4625},
        Levels:   []int{2},
    },
    Message: "Failed login threshold exceeded: {{.Count}} failed attempts",
    Tags:    []string{"authentication", "brute-force"},
}
```

### 8.3 内置规则问题

| 问题 | 描述 |
|------|------|
| 中文描述 | Description 是中文，与项目风格不一致 |
| 无状态字段 | 无 enabled_by_default 等 |
| 无规则版本 | 无法追踪规则变更 |
| 无规则作者 | 无法知道规则来源 |
| 规则 ID 缺失 | 应有唯一 ID 而非仅靠名称 |

---

## 九、问题汇总

### 9.1 P0 级问题 (严重)

| ID | 问题 | 位置 | 影响 |
|----|------|------|------|
| P0-1 | 内置规则可被 API 修改 | handlers_rules.go:408-418 | 安全风险 |
| P0-2 | 无规则评估引擎 | alerts/evaluator.go 已实现 | 核心功能缺失 (已实现) |
| P0-3 | CLI 无规则管理命令 | alert.go | 无法通过 CLI 管理规则 |

### 9.2 P1 级问题 (重要)

| ID | 问题 | 位置 |
|----|------|------|
| P1-1 | 验证逻辑重复 | rule.go + loader.go |
| P1-2 | MITRE ID 验证过于简单 | loader.go:202-217 |
| P1-3 | 规则无优先级机制 | rule.go |
| P1-4 | Condition 不支持 ip_address | evaluator.go:238-263 |
| P1-5 | API 无权限控制 | handlers_rules.go |
| P1-6 | 硬编码时间戳 | custom_rules.go:270-272 |

### 9.3 P2 级问题 (一般)

| ID | 问题 | 位置 |
|----|------|------|
| P2-1 | Filter EventIDs 用遍历 | evaluator.go:89-100 |
| P2-2 | 阈值聚合内存存储 | evaluator.go:406-443 |
| P2-3 | API 无分页 | handlers_rules.go:60-157 |
| P2-4 | YAML 解析为空实现 | validator.go:205-207 |
| P2-5 | 模板机制不完整 | custom_rules.go |
| P2-6 | 无规则变更审计 | - |
| P2-7 | 无规则版本控制 | - |

### 9.4 P3 级问题 (优化)

| ID | 问题 | 位置 |
|----|------|------|
| P3-1 | Level 范围定义冲突 | rule.go vs loader.go |
| P3-2 | 无规则导入导出 CLI | - |
| P3-3 | 无规则验证 CLI | - |
| P3-4 | 内置规则描述是中文 | builtin/definitions.go |
| P3-5 | CorrelationRule 未使用 | rule.go |

---

## 十、改进建议

### 10.1 架构改进

```
┌─────────────────────────────────────────────────────────────────┐
│                      改进后的架构                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                      Rules Service                        │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │   │
│  │  │ RuleStore  │  │ Evaluator   │  │ Notifier    │        │   │
│  │  │ (DB+File)  │  │ (并行评估)  │  │ (多渠道)    │        │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│  ┌───────────────────────────┼───────────────────────────┐     │
│  │                           │                           │     │
│  ▼                           ▼                           ▼     │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐    │
│  │ CLI (Cobra) │      │ REST API    │      │ TUI (Bubble)│    │
│  │ rule 命令   │      │ /api/rules  │      │ 交互式管理   │    │
│  └─────────────┘      └─────────────┘      └─────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 10.2 优先级改进建议

| 阶段 | 任务 | 优先级 |
|------|------|--------|
| **Q1** | P0-1 修复内置规则只读 | P0 |
| **Q1** | P1-3 添加规则优先级 | P1 |
| **Q1** | P1-4 扩展 Condition 字段 | P1 |
| **Q2** | P1-2 增强 MITRE 验证 | P1 |
| **Q2** | P1-5 添加 API 权限控制 | P1 |
| **Q2** | P2-3 API 分页支持 | P2 |
| **Q2** | P2-1 Filter EventIDs 优化 | P2 |
| **Q3** | P2-6 规则变更审计 | P2 |
| **Q3** | P3-1 CLI 规则管理命令 | P2 |
| **Q4** | P3-4 规则版本控制 | P3 |

### 10.3 详细改进方案

#### 10.3.1 P0-1: 内置规则只读保护

```go
// handlers_rules.go
func (h *RulesHandler) UpdateRule(c *gin.Context) {
    name := c.Param("name")
    
    // 检查是否为内置规则
    alertRules := builtin.GetAlertRules()
    for _, rule := range alertRules {
        if rule.Name == name {
            c.JSON(http.StatusForbidden, ErrorResponse{
                Error: "Cannot modify built-in rules",
                Code:  "RULE_BUILTIN",
            })
            return
        }
    }
    // ... 继续处理自定义规则
}
```

#### 10.3.2 P1-3: 规则优先级机制

```go
// rule.go
type AlertRule struct {
    // ... 现有字段
    Priority int  `yaml:"priority"` // 1-100, 默认 50
    Weight   float64 `yaml:"weight"` // 告警权重, 默认 1.0
}

// loader.go - 按优先级排序
func SortByPriority(rules []*AlertRule) {
    sort.Slice(rules, func(i, j int) bool {
        if rules[i].Priority != rules[j].Priority {
            return rules[i].Priority > rules[j].Priority
        }
        return rules[i].Weight > rules[j].Weight
    })
}
```

#### 10.3.3 P1-4: 扩展 Condition 字段

```go
// evaluator.go
func (e *Evaluator) matchCondition(cond *rules.Condition, event *types.Event) bool {
    switch field {
    // ... 现有字段
    case "ip_address":
        if event.IPAddress != nil {
            return e.compareString(*event.IPAddress, cond.Operator, cond.Value, cond.Regex)
        }
        return false
    case "process_name":
        return e.compareString(event.ProcessName, cond.Operator, cond.Value, cond.Regex)
    case "command_line":
        return e.compareString(event.CommandLine, cond.Operator, cond.Value, cond.Regex)
    case "service_name":
        return e.compareString(event.ServiceName, cond.Operator, cond.Value, cond.Regex)
    case "logon_type":
        return e.compareValue(event.LogonType, cond.Operator, cond.Value)
    // ...
    }
}
```

---

## 十一、总结

### 11.1 设计优点

1. **清晰的关注点分离**: Rule 定义、Loader、Validator 分离
2. **支持模板实例化**: 自定义规则支持参数化模板
3. **阈值聚合机制**: 支持基于时间窗口的阈值检测
4. **丰富的内置规则**: 70+ 规则覆盖 MITRE ATT&CK 多个战术
5. **RESTful API**: 完整的规则 CRUD 操作

### 11.2 主要问题

1. **架构问题**: 验证逻辑分散、内置规则可修改
2. **功能缺失**: 规则优先级、Condition 字段不完整
3. **存储问题**: 无数据库存储、无审计日志
4. **CLI 缺失**: 无规则管理命令
5. **API 问题**: 无分页、无权限控制

### 11.3 改进路线图

```
Q1 (安全/核心):
├─ 修复内置规则只读 (P0-1)
├─ 添加规则优先级机制 (P1-3)
├─ 扩展 Condition 字段 (P1-4)
└─ 统一验证逻辑 (P1-1)

Q2 (功能完善):
├─ 增强 MITRE ID 验证 (P1-2)
├─ API 权限控制 (P1-5)
├─ API 分页支持 (P2-3)
└─ Filter EventIDs 优化 (P2-1)

Q3 (体验提升):
├─ 规则变更审计 (P2-6)
├─ CLI 规则管理命令 (P3-1)
└─ 规则版本控制 (P3-4)
```

---

*文档版本: 1.0*  
*分析完整性: 核心模块已完成全面分析*  
*待确认: TUI 模式中的规则交互方式*
