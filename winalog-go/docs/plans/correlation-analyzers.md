# Correlation 与 Analyzers 模块改进实施方案

**项目**: WinLogAnalyzer-Go
**模块**: `internal/correlation/`, `internal/analyzers/`, `internal/multi/`
**文档日期**: 2026-04-17
**版本**: v1.0

---

## 一、问题汇总与验证

### 1.1 已验证的问题

| ID | 问题 | 严重性 | 验证状态 | 代码位置 |
|----|------|--------|----------|----------|
| **P1-1** | JoinEvents 方法未被调用，死代码 | 🟡 Suggestion | **已确认** | `correlation/matcher.go:81-117` |
| **P1-2** | ChainBuilder 硬编码攻击链 | 🟠 Important | **已确认** | `correlation/chain.go:40-53,85-90` |
| **P1-3** | isExternalIP 在 3 个文件中重复实现 | 🟠 Important | **已确认** | `login.go`, `lateral_movement.go`, `data_exfiltration.go` |
| **P1-4** | AnalyzeAll 吞掉所有错误 | 🟠 Important | **已确认** | `analyzers/analyzer.go:100-112` |
| **P1-5** | CLI 和 API 重复 createAnalyzerManager | 🟡 Suggestion | **已确认** | `commands/analyze.go:145`, `api/server.go:108` |
| **P1-6** | API handlers_analyze.go 硬编码 Limit=10000 无分页 | 🟠 Important | **已确认** | `api/handlers_analyze.go:83-85` |
| **P1-7** | EventIndex.byTime 无限增长无过期清理 | 🟠 Important | **已确认** | `correlation/engine.go:23` |
| **P1-8** | itoa 函数实现冗余 | 🟡 Suggestion | **已确认** | `lateral_movement.go:278`, `handlers_multi.go:309` |
| **P1-9** | PowerShellAnalyzer 在 kerberos.go 中 | 🟡 Suggestion | **已确认** | `kerberos.go:341-532` |
| **P1-10** | 字符串解析脆弱，无结构化提取 | 🟠 Important | **已确认** | `login.go:148-162` 等多处 |
| **P1-11** | Score 计算仅用平均值，忽略 severity | 🟡 Suggestion | **已确认** | `analyzers/analyzer.go:61-71` |
| **P1-12** | 缺乏分析器执行顺序控制 | 🟡 Suggestion | **已确认** | `analyzers/analyzer.go:100-112` |

### 1.2 已排除的问题

| 原问题 | 排除原因 |
|--------|----------|
| CorrelationRule Pattern 映射不一致 | 经验证 `engine.go:123` 使用 `rule.Patterns` 与 `rule.go:71` 定义一致，均为 `[]*Pattern` |

---

## 二、实施方案

---

### ISSUE-A: 提取公共 isExternalIP 函数

#### 2.1.1 问题分析

**现状**: `isExternalIP` 在 3 个文件中重复实现，代码冗余。

**代码位置**:
- `internal/analyzers/login.go:195-231`
- `internal/analyzers/lateral_movement.go:213-245`
- `internal/analyzers/data_exfiltration.go:225-257`

**问题**: 任何修改都需要同时修改 3 个文件，容易遗漏。

#### 2.1.2 实施方案

**步骤 1**: 在 `internal/types/event.go` 添加公共函数

```go
// internal/types/event.go

// IsExternalIP 判断是否为外部 IP
func IsExternalIP(ip string) bool {
    if ip == "" || ip == "-" || ip == "127.0.0.1" || ip == "::1" || ip == "::" {
        return false
    }
    parts := strings.Split(ip, ".")
    if len(parts) != 4 {
        return true
    }
    firstOctet := 0
    for _, c := range parts[0] {
        if c >= '0' && c <= '9' {
            firstOctet = firstOctet*10 + int(c-'0')
        }
    }
    if firstOctet >= 10 && firstOctet <= 11 {
        return false
    }
    if firstOctet == 192 && parts[1] == "168" {
        return false
    }
    if firstOctet == 172 {
        secondOctet := 0
        for _, c := range parts[1] {
            if c >= '0' && c <= '9' {
                secondOctet = secondOctet*10 + int(c-'0')
            }
        }
        if secondOctet >= 16 && secondOctet <= 31 {
            return false
        }
    }
    return true
}
```

**步骤 2**: 修改 login.go

```go
// internal/analyzers/login.go

// 删除 isExternalIP 方法 (lines 195-231)

// 修改 isSuspiciousLogin 方法
func (a *LoginAnalyzer) isSuspiciousLogin(e *types.Event, logonType int) bool {
    sourceIP := a.getSourceIP(e)
    if sourceIP == "" || sourceIP == "-" || sourceIP == "127.0.0.1" || sourceIP == "::1" {
        return false
    }
    if logonType == 10 && types.IsExternalIP(sourceIP) {  // 改用公共函数
        hour := e.Timestamp.Hour()
        if hour < 6 || hour > 22 {
            return true
        }
    }
    return a.isKnownSuspiciousIP(sourceIP)
}

// 修改 isSuspiciousFailedLogin 方法
func (a *LoginAnalyzer) isSuspiciousFailedLogin(e *types.Event, logonType int) bool {
    sourceIP := a.getSourceIP(e)
    if sourceIP == "" || sourceIP == "-" {
        return false
    }
    return types.IsExternalIP(sourceIP)  // 改用公共函数
}
```

**步骤 3**: 修改 lateral_movement.go

```go
// internal/analyzers/lateral_movement.go

// 删除 isExternalIP 方法 (lines 213-245)

// 修改 isSuspiciousLogin 方法
func (a *LateralMovementAnalyzer) isSuspiciousLogin(e *types.Event) bool {
    sourceIP := a.getSourceIP(e)
    if sourceIP == "" || sourceIP == "-" || sourceIP == "127.0.0.1" {
        return false
    }
    return types.IsExternalIP(sourceIP)  // 改用公共函数
}
```

**步骤 4**: 修改 data_exfiltration.go

```go
// internal/analyzers/data_exfiltration.go

// 删除 isExternalIP 方法 (lines 225-257)

// 修改相关调用处
if destIP != "" && types.IsExternalIP(destIP) {  // 改用公共函数
```

#### 2.1.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 低 | 约 40 行代码迁移 |
| **适配性** | 高 | 公共函数，无副作用 |
| **必要性** | 中 | 减少代码冗余，易维护 |
| **可靠性** | 高 | 逻辑不变，仅移动位置 |
| **风险** | 低 | 仅影响内部调用 |

---

### ISSUE-B: 修复 AnalyzeAll 错误处理

#### 2.2.1 问题分析

**现状**: `AnalyzerManager.AnalyzeAll` 吞掉所有错误:

```go
// internal/analyzers/analyzer.go:100-112
func (m *AnalyzerManager) AnalyzeAll(events []*types.Event) ([]*Result, error) {
    results := make([]*Result, 0, len(m.analyzers))
    for _, analyzer := range m.analyzers {
        result, err := analyzer.Analyze(events)
        if err != nil {
            continue  // 错误被忽略，无法排查
        }
        results = append(results, result)
    }
    return results, nil
}
```

**问题**: 单一分析器失败时用户无法感知，可能导致安全漏报。

#### 2.2.2 实施方案

**步骤 1**: 修改 `internal/analyzers/analyzer.go`

```go
// internal/analyzers/analyzer.go

// AnalyzerError 记录单个分析器的错误
type AnalyzerError struct {
    AnalyzerName string
    Err          error
}

type AnalyzerResult struct {
    AnalyzerName string
    Result       *Result
    Error        error
}

func (m *AnalyzerManager) AnalyzeAll(events []*types.Event) ([]*Result, error) {
    results := make([]*Result, 0, len(m.analyzers))
    var errors []AnalyzerError

    for name, analyzer := range m.analyzers {
        result, err := analyzer.Analyze(events)
        if err != nil {
            errors = append(errors, AnalyzerError{
                AnalyzerName: name,
                Err:          err,
            })
            continue
        }
        results = append(results, result)
    }

    if len(errors) > 0 {
        return results, &AnalyzerErrors{Errors: errors}
    }
    return results, nil
}

// AnalyzerErrors 包含多个分析器错误
type AnalyzerErrors struct {
    Errors []AnalyzerError
}

func (e *AnalyzerErrors) Error() string {
    if len(e.Errors) == 1 {
        return fmt.Sprintf("analyzer %s failed: %v", e.Errors[0].AnalyzerName, e.Errors[0].Err)
    }
    return fmt.Sprintf("%d analyzers failed", len(e.Errors))
}
```

**步骤 2**: 修改 CLI 调用处 `internal/commands/analyze.go`

```go
// internal/commands/analyze.go

// 修改 runAnalyzerWithResult 或相关调用
results, err := manager.AnalyzeAll(events)
if err != nil {
    if ae, ok := err.(*analyzers.AnalyzerErrors); ok {
        fmt.Fprintf(os.Stderr, "Warning: %v\n", ae)
        // 部分分析器失败时仍继续
    } else {
        return fmt.Errorf("analysis failed: %w", err)
    }
}
```

**步骤 3**: 修改 API 调用处 `internal/api/handlers_analyze.go`

```go
// internal/api/handlers_analyze.go

// ListAnalyzers 返回时增加错误信息
results, err := manager.AnalyzeAll(events)
if err != nil {
    // 记录错误但不阻断返回
    log.Printf("Analyzer warnings: %v", err)
}
```

#### 2.2.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 低 | 约 25 行代码 |
| **适配性** | 高 | 错误信息非阻塞 |
| **必要性** | 高 | 安全告警完整性 |
| **可靠性** | 高 | 向后兼容 |
| **风险** | 低 | 仅改变错误处理方式 |

---

### ISSUE-C: 移除死代码 JoinEvents

#### 2.3.1 问题分析

**现状**: `Matcher.JoinEvents` 方法从未被调用:

```go
// internal/correlation/matcher.go:81-117
func (m *Matcher) JoinEvents(events []*types.Event, joinField string) map[string][]*types.Event {
    joined := make(map[string][]*types.Event)
    // ... 实现存在但从未被调用
}
```

#### 2.3.2 实施方案

**直接删除** `correlation/matcher.go:81-117` 的 `JoinEvents` 方法。

#### 2.3.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 很低 | 仅删除代码 |
| **适配性** | 高 | 无外部依赖 |
| **必要性** | 中 | 减少维护负担 |
| **可靠性** | 高 | 确认无调用 |
| **风险** | 很低 | 删除死代码 |

---

### ISSUE-D: 统一 createAnalyzerManager

#### 2.4.1 问题分析

**现状**: 同一逻辑在两处重复实现:

- `cmd/winalog/commands/analyze.go:145-156`
- `internal/api/server.go:108-119`

**问题**: 添加新分析器需要同时修改两处，容易遗漏。

#### 2.4.2 实施方案

**步骤 1**: 在 `internal/analyzers/manager.go` 新建文件

```go
// internal/analyzers/manager.go
package analyzers

func NewDefaultManager() *AnalyzerManager {
    mgr := NewAnalyzerManager()
    mgr.Register(NewBruteForceAnalyzer())
    mgr.Register(NewLoginAnalyzer())
    mgr.Register(NewKerberosAnalyzer())
    mgr.Register(NewPowerShellAnalyzer())
    mgr.Register(NewDataExfiltrationAnalyzer())
    mgr.Register(NewLateralMovementAnalyzer())
    mgr.Register(NewPersistenceAnalyzer())
    mgr.Register(NewPrivilegeEscalationAnalyzer())
    return mgr
}
```

**步骤 2**: 修改 `commands/analyze.go`

```go
// cmd/winalog/commands/analyze.go

// 删除 createAnalyzerManager 函数 (lines 145-156)

// 修改 runAnalyzeDynamic 函数
func runAnalyzeDynamic(cmd *cobra.Command, args []string) error {
    manager := analyzers.NewDefaultManager()  // 使用公共函数
    // ...
}
```

**步骤 3**: 修改 `api/server.go`

```go
// internal/api/server.go

// 删除 createAnalyzerManager 函数 (lines 108-119)

// 修改 NewServer 函数
func NewServer(...) (*Server, error) {
    // ...
    s.analyzeEng = NewAnalyzeHandler(s.db, analyzers.NewDefaultManager())  // 使用公共函数
    // ...
}
```

#### 2.4.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 低 | 约 20 行代码 |
| **适配性** | 高 | 单一数据源 |
| **必要性** | 中 | 防止维护不一致 |
| **可靠性** | 高 | 逻辑不变 |
| **风险** | 低 | 向后兼容 |

---

### ISSUE-E: API 分页支持

#### 2.5.1 问题分析

**现状**: `handlers_analyze.go:83-85` 硬编码 Limit=10000，无分页参数:

```go
filter := &storage.EventFilter{
    Limit: 10000,  // 硬编码
}
```

**问题**: 大数据量场景无法分批获取和分析。

#### 2.5.2 实施方案

**步骤 1**: 修改 `AnalyzeRequest` 结构

```go
// internal/api/handlers_analyze.go

type AnalyzeRequest struct {
    Type      string `json:"type" binding:"required"`
    StartTime string `json:"start_time"`
    EndTime   string `json:"end_time"`
    Hours     int    `json:"hours"`
    Limit     int    `json:"limit"`   // 新增
    Offset    int    `json:"offset"`  // 新增
}
```

**步骤 2**: 修改 RunAnalysis handler

```go
func (h *AnalyzeHandler) RunAnalysis(c *gin.Context) {
    // ...
    limit := req.Limit
    if limit <= 0 || limit > 100000 {
        limit = 10000  // 默认值，限制最大值
    }
    offset := req.Offset
    if offset < 0 {
        offset = 0
    }

    filter := &storage.EventFilter{
        Limit:  limit,
        Offset: offset,
    }
    // ...
}
```

**步骤 3**: 修改 AnalyzeResult 添加分页信息

```go
type AnalyzeResult struct {
    Type      string           `json:"type"`
    Severity  string           `json:"severity"`
    Score     float64          `json:"score"`
    Summary   string           `json:"summary"`
    Findings  []AnalyzeFinding `json:"findings"`
    Timestamp int64            `json:"timestamp"`
    Pagination *Pagination     `json:"pagination,omitempty"`
}

type Pagination struct {
    Limit   int   `json:"limit"`
    Offset  int   `json:"offset"`
    Total   int64 `json:"total"`
}
```

#### 2.5.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 中 | 约 30 行代码 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 中 | 大数据量场景需要 |
| **可靠性** | 高 | 参数校验完善 |
| **风险** | 低 | 新增可选参数 |

---

### ISSUE-F: EventIndex 过期清理机制

#### 2.6.1 问题分析

**现状**: `EventIndex.byTime` 是无限增长的 slice:

```go
type EventIndex struct {
    mu     sync.RWMutex
    byID   map[int64]*types.Event
    byTime []*types.Event  // 无限增长
    byEID  map[int32][]*types.Event
}
```

**问题**: 长时间运行会导致内存膨胀。

#### 2.6.2 实施方案

**步骤 1**: 修改 `EventIndex` 添加过期配置

```go
type EventIndex struct {
    mu           sync.RWMutex
    byID         map[int64]*types.Event
    byTime       []*types.Event
    byEID        map[int32][]*types.Event
    maxAge       time.Duration  // 最大保留时间
    lastCleanup  time.Time
    cleanupInterval time.Duration
}
```

**步骤 2**: 修改 `NewEventIndex`

```go
func NewEventIndex(maxAge time.Duration) *EventIndex {
    return &EventIndex{
        byID:              make(map[int64]*types.Event),
        byEID:             make(map[int32][]*types.Event),
        maxAge:            maxAge,
        lastCleanup:       time.Now(),
        cleanupInterval:   5 * time.Minute,
    }
}
```

**步骤 3**: 添加 Cleanup 方法

```go
func (idx *EventIndex) Cleanup() {
    idx.mu.Lock()
    defer idx.mu.Unlock()

    if idx.maxAge <= 0 {
        return
    }

    cutoff := time.Now().Add(-idx.maxAge)
    if len(idx.byTime) == 0 || idx.byTime[0].Timestamp.After(cutoff) {
        return
    }

    // 找到需要保留的事件分界点
    splitIdx := 0
    for i, event := range idx.byTime {
        if event.Timestamp.After(cutoff) {
            break
        }
        splitIdx = i + 1
    }

    // 移除过期事件
    oldEvents := idx.byTime[:splitIdx]
    idx.byTime = idx.byTime[splitIdx:]

    // 从 byID 和 byEID 中移除
    for _, event := range oldEvents {
        delete(idx.byID, event.ID)
        if slice, ok := idx.byEID[event.EventID]; ok {
            newSlice := make([]*types.Event, 0, len(slice))
            for _, e := range slice {
                if e.ID != event.ID {
                    newSlice = append(newSlice, e)
                }
            }
            if len(newSlice) > 0 {
                idx.byEID[event.EventID] = newSlice
            } else {
                delete(idx.byEID, event.EventID)
            }
        }
    }
}
```

**步骤 4**: 在 `Add` 时触发延迟清理

```go
func (idx *EventIndex) Add(event *types.Event) {
    idx.mu.Lock()
    defer idx.mu.Unlock()

    // 延迟清理：每 5 分钟执行一次
    if time.Since(idx.lastCleanup) > idx.cleanupInterval {
        go idx.cleanupLocked()
        idx.lastCleanup = time.Now()
    }

    idx.byID[event.ID] = event
    idx.byTime = append(idx.byTime, event)
    idx.byEID[event.EventID] = append(idx.byEID[event.EventID], event)
}

func (idx *EventIndex) cleanupLocked() {
    if idx.maxAge <= 0 {
        return
    }
    cutoff := time.Now().Add(-idx.maxAge)
    
    // 快速跳过：找到第一个未过期事件
    splitIdx := 0
    for i, event := range idx.byTime {
        if event.Timestamp.After(cutoff) {
            break
        }
        splitIdx = i + 1
    }

    if splitIdx == 0 {
        return
    }

    oldEvents := idx.byTime[:splitIdx]
    idx.byTime = idx.byTime[splitIdx:]

    for _, event := range oldEvents {
        delete(idx.byID, event.ID)
    }
}
```

**步骤 5**: 修改 `NewEngine` 添加 maxAge 参数

```go
func NewEngine(maxAge time.Duration) *Engine {
    return &Engine{
        events: make(map[int64]*types.Event),
        index:  NewEventIndex(maxAge),
        matcher: NewMatcher(),
        chain:   NewChainBuilder(),
    }
}
```

#### 2.6.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 中 | 约 80 行代码 |
| **适配性** | 高 | 可配置，可禁用 |
| **必要性** | 高 | 防止内存泄漏 |
| **可靠性** | 高 | 后台异步执行 |
| **风险** | 中 | 清理时可能短暂阻塞 |

---

### ISSUE-G: 替换 itoa 为 strconv.Itoa

#### 2.7.1 问题分析

**现状**: 两处自定义 itoa 实现:

```go
// lateral_movement.go:278
func itoa(i int) string {
    return string(rune('0'+i/100000%10)) + ... // 复杂且易错
}

// handlers_multi.go:309
func itoa(i int) string {
    return string(rune('0'+i/10000%10)) + ... // 与上面不一致
}
```

**问题**: 实现不一致，且无法处理大数。

#### 2.7.2 实施方案

**步骤 1**: 删除 `lateral_movement.go:278-280` 的 itoa 函数

**步骤 2**: 删除 `handlers_multi.go:309-311` 的 itoa 函数

**步骤 3**: 在使用处添加 `strconv` import 并替换

```go
import "strconv"

// lateral_movement.go:272-276
sb.WriteString(" Lateral Movement Analysis: " +
    " RDP=" + strconv.Itoa(analysis.RDPConnections) +
    " PSExec=" + strconv.Itoa(analysis.PSExecEvents) +
    " WMI=" + strconv.Itoa(analysis.WMIEvents) +
    " Total=" + strconv.Itoa(analysis.TotalEvents))
```

#### 2.7.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 很低 | 仅删除+替换 |
| **适配性** | 高 | 标准库 |
| **必要性** | 中 | 修复潜在 bug |
| **可靠性** | 高 | strconv.Itoa 经过充分测试 |
| **风险** | 很低 | 行为完全一致 |

---

### ISSUE-H: 拆分 PowerShellAnalyzer

#### 2.8.1 问题分析

**现状**: `PowerShellAnalyzer` 定义在 `kerberos.go` 中:

```go
// internal/analyzers/kerberos.go
type PowerShellAnalyzer struct {  // line 341
    BaseAnalyzer
}
// ... 约 190 行代码
```

**问题**: 违反单一职责，文件职责不清晰。

#### 2.8.2 实施方案

**步骤 1**: 移动 `PowerShellAnalyzer` 到新文件 `internal/analyzers/powershell.go`

**步骤 2**: 删除 `kerberos.go` 中的 PowerShellAnalyzer 相关代码 (lines 341-532)

**步骤 3**: 更新 `manager.go` import

```go
// internal/analyzers/manager.go
func NewDefaultManager() *AnalyzerManager {
    mgr := NewAnalyzerManager()
    // ...
    mgr.Register(NewPowerShellAnalyzer())  // 无需变更，import 存在
    // ...
}
```

#### 2.8.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 低 | 仅移动代码 |
| **适配性** | 高 | 无逻辑变更 |
| **必要性** | 低 | 代码组织优化 |
| **可靠性** | 高 | 移动而非修改 |
| **风险** | 很低 | 仅影响文件结构 |

---

### ISSUE-I: ChainBuilder 配置化解攻击链

#### 2.9.1 问题分析

**现状**: 攻击链硬编码:

```go
// correlation/chain.go:40-53
knownChains := map[int32]bool{
    4624: true, 4625: true, 4634: true, 4648: true,
    4672: true, 4688: true, 4698: true, 4697: true,
}

// correlation/chain.go:85-90
transitionMap := map[int32][]int32{
    4624: {4634, 4672, 4688},
    4625: {4624},
    4648: {4624, 4672},
    4688: {4698, 4697},
}
```

**问题**: 无法灵活配置新攻击链，需要代码修改。

#### 2.9.2 实施方案

**步骤 1**: 添加配置结构

```go
// internal/correlation/chain.go

type ChainConfig struct {
    StartEventIDs map[int32]bool         // 可启动链的事件
    Transitions    map[int32][]int32      // 事件转换关系
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

**步骤 2**: 修改 ChainBuilder 使用配置

```go
type ChainBuilder struct {
    config *ChainConfig
}

func NewChainBuilder() *ChainBuilder {
    return &ChainBuilder{config: DefaultChainConfig}
}

func NewChainBuilderWithConfig(cfg *ChainConfig) *ChainBuilder {
    return &ChainBuilder{config: cfg}
}

func (cb *ChainBuilder) FindChains(startEvent *types.Event, maxDepth int) ([]*types.CorrelationResult, error) {
    chains := make([]*types.CorrelationResult, 0)
    if !cb.config.StartEventIDs[startEvent.EventID] {
        return chains, nil
    }
    // ... 使用 cb.config.Transitions
}
```

**步骤 3**: 添加配置文件加载 (可选)

```go
// 从 YAML/JSON 加载自定义配置
func LoadChainConfig(path string) (*ChainConfig, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    var cfg ChainConfig
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return nil, err
    }
    return &cfg, nil
}
```

#### 2.9.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 中 | 约 60 行代码 |
| **适配性** | 高 | 向后兼容默认配置 |
| **必要性** | 中 | 提升灵活性 |
| **可靠性** | 高 | 配置可选 |
| **风险** | 低 | 默认值保持行为不变 |

---

### ISSUE-J: 改进 Score 计算逻辑

#### 2.10.1 问题分析

**现状**: `CalculateOverallScore` 仅用平均值:

```go
func (r *Result) CalculateOverallScore() float64 {
    if len(r.Findings) == 0 { return 0 }
    var total float64
    for _, f := range r.Findings {
        total += f.Score
    }
    return total / float64(len(r.Findings))
}
```

**问题**: 未考虑 severity 权重，high/critical 问题应占更高权重。

#### 2.10.2 实施方案

**步骤 1**: 添加 severity 权重常量

```go
// internal/analyzers/analyzer.go

var severityWeights = map[string]float64{
    "critical": 1.5,
    "high":     1.2,
    "medium":   1.0,
    "low":      0.8,
    "info":     0.5,
}
```

**步骤 2**: 修改 CalculateOverallScore

```go
func (r *Result) CalculateOverallScore() float64 {
    if len(r.Findings) == 0 {
        return 0
    }

    var totalScore float64
    var totalWeight float64

    for _, f := range r.Findings {
        weight := severityWeights[f.Severity]
        if weight == 0 {
            weight = 1.0
        }
        totalScore += f.Score * weight
        totalWeight += weight
    }

    if totalWeight == 0 {
        return 0
    }
    return totalScore / totalWeight
}
```

#### 2.10.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 很低 | 约 15 行代码 |
| **适配性** | 高 | 改变计算结果但合理 |
| **必要性** | 低 | 改进建议 |
| **可靠性** | 高 | 权重可配置 |
| **风险** | 低 | 评分语义更准确 |

---

## 三、架构改进

### 3.1 模块职责划分 (建议)

```
internal/analyzers/
├── analyzer.go          # Analyzer 接口, AnalyzerManager, Result
├── brute_force.go       # BruteForceAnalyzer
├── login.go            # LoginAnalyzer
├── kerberos.go         # KerberosAnalyzer (不含 PowerShell)
├── powershell.go        # PowerShellAnalyzer (新拆)
├── lateral_movement.go  # LateralMovementAnalyzer
├── persistence.go      # PersistenceAnalyzer
├── data_exfiltration.go # DataExfiltrationAnalyzer
├── privilege_escalation.go # PrivilegeEscalationAnalyzer
├── utils.go            # 公共工具函数 (isExternalIP 等)
└── manager.go          # NewDefaultManager

internal/correlation/
├── engine.go           # 关联分析引擎
├── chain.go            # 攻击链构建器 (配置化)
├── matcher.go          # 事件匹配器 (移除 JoinEvents)
└── config.go           # 链配置 (可选)

internal/types/
├── event.go           # Event 类型, IsExternalIP
├── result.go           # AnalyzeResult 等
└── errors.go           # AnalyzerErrors
```

---

## 四、实施汇总

### 4.1 优先级总览

| ID | 问题 | 优先级 | 复杂度 | 工作量 | 风险 |
|----|------|--------|--------|--------|------|
| ISSUE-A | 提取公共 isExternalIP | **P1** | 低 | 1 人天 | 低 |
| ISSUE-B | 修复 AnalyzeAll 错误处理 | **P1** | 低 | 0.5 人天 | 低 |
| ISSUE-C | 移除死代码 JoinEvents | **P2** | 很低 | 0.1 人天 | 低 |
| ISSUE-D | 统一 createAnalyzerManager | **P2** | 低 | 0.5 人天 | 低 |
| ISSUE-E | API 分页支持 | **P2** | 中 | 1 人天 | 低 |
| ISSUE-F | EventIndex 过期清理 | **P2** | 中 | 1.5 人天 | 中 |
| ISSUE-G | 替换 itoa | **P3** | 很低 | 0.1 人天 | 低 |
| ISSUE-H | 拆分 PowerShellAnalyzer | **P3** | 低 | 0.3 人天 | 低 |
| ISSUE-I | ChainBuilder 配置化 | **P3** | 中 | 1 人天 | 低 |
| ISSUE-J | 改进 Score 计算 | **P3** | 很低 | 0.2 人天 | 低 |

### 4.2 建议实施路线图

```
阶段 1 (P1 问题 - 1 天):
├─ ISSUE-A 提取公共 isExternalIP
└─ ISSUE-B 修复 AnalyzeAll 错误处理

阶段 2 (P2 问题 - 3 天):
├─ ISSUE-C 移除死代码 JoinEvents
├─ ISSUE-D 统一 createAnalyzerManager
├─ ISSUE-E API 分页支持
└─ ISSUE-F EventIndex 过期清理

阶段 3 (P3 问题 - 2 天):
├─ ISSUE-G 替换 itoa
├─ ISSUE-H 拆分 PowerShellAnalyzer
├─ ISSUE-I ChainBuilder 配置化
└─ ISSUE-J 改进 Score 计算
```

### 4.3 依赖关系

```
ISSUE-D (统一 Manager)
├─ 依赖: 无
└─ 被 ISSUE-H 依赖

ISSUE-A (公共 isExternalIP)
├─ 依赖: 无
└─ 被 ISSUE-B 依赖 (错误处理时可能需要)

ISSUE-F (过期清理)
├─ 依赖: 无
└─ 被所有长期运行场景需要
```

---

## 五、验证清单

### 5.1 测试命令

```bash
cd winalog-go/winalog-go

# 运行 analyzers 模块测试
go test ./internal/analyzers/... -v

# 运行 correlation 模块测试
go test ./internal/correlation/... -v

# 运行完整测试
go test ./... -v -count=1

# 构建验证
go build ./...
```

### 5.2 手动验证步骤

1. **ISSUE-A 验证**:
   - 运行 `winalog analyze brute-force`
   - 运行 `winalog analyze login`
   - 验证两个分析器对外部 IP 判断一致

2. **ISSUE-B 验证**:
   - 修改某 Analyzer.Analyze 返回错误
   - 调用 AnalyzeAll，验证错误被正确记录

3. **ISSUE-E 验证**:
   - 调用 `POST /api/analyze/brute-force` 带 `limit=100&offset=200`
   - 验证返回分页结果

4. **ISSUE-F 验证**:
   - 长时间运行 correlation engine
   - 监控内存使用，验证不会无限增长

---

## 六、附录

### A. 问题验证记录

| 问题 | 验证方法 | 结果 |
|------|----------|------|
| JoinEvents 未使用 | `grep -r "JoinEvents" internal/` | 仅定义处，无调用 |
| isExternalIP 重复 | `grep -r "func.*isExternalIP" internal/` | 3 处定义 |
| 硬编码攻击链 | 读取 chain.go:40-90 | 确认存在 |
| createAnalyzerManager 重复 | `grep -r "createAnalyzerManager" --include="*.go"` | 2 处定义 |
| API 无分页 | 读取 handlers_analyze.go:83-85 | Limit=10000 硬编码 |
| EventIndex 无限增长 | 读取 engine.go:23 | 确认 byTime 无清理 |

### B. 相关文件

- `internal/analyzers/analyzer.go` - 分析器接口和管理器
- `internal/analyzers/login.go` - 登录分析器
- `internal/analyzers/brute_force.go` - 暴力破解分析器
- `internal/analyzers/kerberos.go` - Kerberos 分析器
- `internal/analyzers/lateral_movement.go` - 横向移动分析器
- `internal/analyzers/persistence.go` - 持久化分析器
- `internal/analyzers/data_exfiltration.go` - 数据外泄分析器
- `internal/analyzers/privilege_escalation.go` - 权限提升分析器
- `internal/correlation/engine.go` - 关联分析引擎
- `internal/correlation/chain.go` - 攻击链构建器
- `internal/correlation/matcher.go` - 事件匹配器
- `internal/api/handlers_analyze.go` - 分析 API 处理器
- `internal/api/server.go` - API 服务器
- `cmd/winalog/commands/analyze.go` - CLI 分析命令
- `internal/types/event.go` - 事件类型

---

*文档版本: 1.0*
*模块: Correlation + Analyzers*
*审核状态: 待审核*
*实施状态: 待实施*
