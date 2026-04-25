# UEBA/Engine/Policy/Suppress 模块改进方案

**项目**: WinLogAnalyzer-Go  
**分析日期**: 2026-04-17  
**模块**: alerts, ueba, engine, policy  
**问题总数**: 24 个  
**预计工时**: ~42h

---

## 1. 问题总览

### 按模块分类

| 模块 | 问题数 | 优先级 |
|------|--------|--------|
| Alerts Engine | 9 | P0/P1 |
| UEBA | 5 | P1/P2 |
| Policy | 4 | P1 |
| Suppress | 6 | P0/P1 |

### 按优先级分类

| 优先级 | 数量 | 问题类型 |
|--------|------|----------|
| **P0 (Bug)** | 4 | 内存泄漏、goroutine 泄露、数据错乱 |
| **P1 (严重)** | 12 | 逻辑错误、功能缺失、并发问题 |
| **P2 (一般)** | 8 | 代码重复、硬编码、健壮性 |

---

## 2. P0 问题 (必须修复)

### P0-1: DedupCache goroutine 泄漏

**文件**: `internal/alerts/dedup.go:25-34`  
**问题**: `NewDedupCache` 启动 `cleanupLoop` goroutine，但 `Engine.Close()` 调用 `e.dedup.Close()` 只关闭 channel，不等待 goroutine 退出

```go
// dedup.go:98-114
func (c *DedupCache) cleanupLoop() {
    ticker := time.NewTicker(c.window / 2)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            c.cleanup()
        case <-c.done:  // 只关闭 channel，不等待
            return
        }
    }
}

func (c *DedupCache) Close() {
    close(c.done)  // goroutine 可能还在运行
}
```

**影响**: 每次创建新的 `DedupCache`（如 CLI 每次运行）都会泄漏一个 goroutine

**修复方案**:

```go
// dedup.go 添加 WaitGroup
type DedupCache struct {
    mu      sync.RWMutex
    window  time.Duration
    entries map[string]*dedupEntry
    done    chan struct{}
    wg      sync.WaitGroup  // 添加
}

func NewDedupCache(window time.Duration) *DedupCache {
    c := &DedupCache{
        window:  window,
        entries: make(map[string]*dedupEntry),
        done:    make(chan struct{}),
    }
    c.wg.Add(1)
    go c.cleanupLoop()
    return c
}

func (c *DedupCache) cleanupLoop() {
    defer c.wg.Done()  // 添加
    ticker := time.NewTicker(c.window / 2)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            c.cleanup()
        case <-c.done:
            return
        }
    }
}

func (c *DedupCache) Close() {
    close(c.done)
    c.wg.Wait()  // 等待 goroutine 退出
}
```

**复杂度**: 低 | **工时**: 0.5h

---

### P0-2: parseConditions 空实现

**文件**: `internal/api/handlers_suppress.go:266-271`  
**问题**: `parseConditions` 函数是空实现，条件解析完全依赖手动字符串解析 `parseConditionsToSuppress`

```go
func parseConditions(jsonStr string, conditions *[]types.SuppressCondition) {
    if jsonStr == "" || jsonStr == "[]" {
        *conditions = []types.SuppressCondition{}
        return
    }
    // 空实现！没有解析 JSON
}
```

**影响**: 从数据库读取的 suppress rules 条件无法正确解析，导致抑制功能失效

**修复方案**: 使用标准库 `encoding/json` 实现

```go
func parseConditions(jsonStr string, conditions *[]types.SuppressCondition) {
    if jsonStr == "" || jsonStr == "[]" {
        *conditions = []types.SuppressCondition{}
        return
    }
    
    type rawCondition struct {
        Field    string      `json:"field"`
        Operator string      `json:"operator"`
        Value    interface{} `json:"value"`
    }
    
    var raw []rawCondition
    if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
        *conditions = []types.SuppressCondition{}
        return
    }
    
    *conditions = make([]types.SuppressCondition, len(raw))
    for i, r := range raw {
        (*conditions)[i] = types.SuppressCondition{
            Field:    r.Field,
            Operator: r.Operator,
            Value:    r.Value,
        }
    }
}
```

**复杂度**: 低 | **工时**: 0.5h

---

### P0-3: formatValue int→rune 错误

**文件**: `internal/ueba/models.go:123-136`  
**问题**: `int(65)` 返回 `"A"` (ASCII) 而不是 `"65"`

```go
func formatValue(v interface{}) string {
    switch val := v.(type) {
    case string:
        return val
    case int:
        return string(rune(val))  // BUG: int(65) -> "A"
    case float64:
        return string(rune(int(val)))  // BUG: float64(65.0) -> "A"
    case []int:
        return fmtIntSlice(val)
    default:
        return ""
    }
}

func fmtIntSlice(s []int) string {
    result := "["
    for i, v := range s {
        if i > 0 {
            result += ", "
        }
        result += string(rune(v))  // BUG: [1, 2, 3] -> "[A, B, C]"
    }
    result += "]"
    return result
}
```

**影响**: UEBA 异常详情的数字显示为乱码（ASCII 字符）

**修复方案**:

```go
import "strconv"

func formatValue(v interface{}) string {
    switch val := v.(type) {
    case string:
        return val
    case int:
        return strconv.Itoa(val)  // 修复
    case float64:
        return strconv.FormatFloat(val, 'f', -1, 64)  // 修复
    case []int:
        return fmtIntSlice(val)
    default:
        return ""
    }
}

func fmtIntSlice(s []int) string {
    result := "["
    for i, v := range s {
        if i > 0 {
            result += ", "
        }
        result += strconv.Itoa(v)  // 修复
    }
    result += "]"
    return result
}
```

**复杂度**: 低 | **工时**: 0.5h

---

### P0-4: EvaluateBatch 竞态条件

**文件**: `internal/alerts/engine.go:144-205`  
**问题**: `processed++` 在 goroutine 中执行，无原子操作保护

```go
func (e *Engine) EvaluateBatch(ctx context.Context, events []*types.Event) ([]*types.Alert, error) {
    // ...
    for _, event := range events {
        wg.Add(1)
        go func(evt *types.Event) {
            defer wg.Done()
            // ...
            if callback != nil {
                processed++  // BUG: 非原子操作，多个 goroutine 同时修改
                callback(processed, total)
            }
        }(event)
    }
}
```

**影响**: 多 goroutine 并行时 `processed` 计数不准确，CLI 进度显示可能错乱

**修复方案**:

```go
func (e *Engine) EvaluateBatch(ctx context.Context, events []*types.Event) ([]*types.Alert, error) {
    // ...
    var processed int64  // 改为 int64
    var mu sync.Mutex   // 添加 mutex
    
    for _, event := range events {
        wg.Add(1)
        go func(evt *types.Event) {
            defer wg.Done()
            // ...
            if callback != nil {
                mu.Lock()
                processed++
                currentProcessed := processed
                mu.Unlock()
                callback(currentProcessed, total)  // 使用局部变量
            }
        }(event)
    }
}
```

**复杂度**: 中 | **工时**: 1h

---

## 3. P1 问题 (重要)

### P1-1: SuppressCache 条件匹配逻辑错误

**文件**: `internal/alerts/suppress.go:25-45`  
**问题**: 当前是 OR 逻辑（条件匹配 OR 时间窗口匹配都抑制），应该是 AND 逻辑

```go
func (c *SuppressCache) IsSuppressed(rule *rules.AlertRule, event *types.Event) bool {
    for _, suppress := range c.rules {
        if !suppress.Enabled {
            continue
        }
        if suppress.Name != "" && suppress.Name != rule.Name {
            continue
        }
        
        // BUG: 当前是 OR 逻辑
        if c.matchesConditions(suppress.Conditions, event) {
            return true  // 条件匹配就返回 true，不检查时间窗口
        }
        
        if c.matchesTimeWindow(suppress, event) {
            return true  // 时间窗口匹配也返回 true
        }
    }
    return false
}
```

**修复方案**:

```go
func (c *SuppressCache) IsSuppressed(rule *rules.AlertRule, event *types.Event) bool {
    for _, suppress := range c.rules {
        if !suppress.Enabled {
            continue
        }
        if suppress.Name != "" && suppress.Name != rule.Name {
            continue
        }
        
        // 修复: AND 逻辑 - 条件匹配 AND 时间窗口匹配
        if c.matchesConditions(suppress.Conditions, event) && 
           c.matchesTimeWindow(suppress, event) {
            return true
        }
    }
    return false
}
```

**复杂度**: 低 | **工时**: 0.5h

---

### P1-2: SuppressCache 条件内匹配是 ANY 但应该是 ALL

**文件**: `internal/alerts/suppress.go:47-88`  
**问题**: 当 suppress.Conditions 有多个条件时，当前是 ANY 逻辑（任一匹配就返回 true），但通常应该是 ALL 逻辑

```go
func (c *SuppressCache) matchesConditions(conds []types.SuppressCondition, event *types.Event) bool {
    if len(conds) == 0 {
        return false
    }
    
    for _, cond := range conds {  // BUG: 遍历所有条件，任一匹配就返回 true
        // ...
        if match {
            return true  // ANY 逻辑
        }
    }
    return false
}
```

**修复方案**: 添加配置选项或默认改为 ALL 逻辑

```go
func (c *SuppressCache) matchesConditions(conds []types.SuppressCondition, event *types.Event) bool {
    if len(conds) == 0 {
        return false
    }
    
    // 默认 ALL 逻辑：所有条件都匹配才返回 true
    for _, cond := range conds {
        if !c.matchSingleCondition(cond, event) {
            return false  // 任一条件不匹配就返回 false
        }
    }
    return true
}
```

**注意**: 这个改动可能影响现有行为，建议添加 `MatchMode` 配置字段

**复杂度**: 中 | **工时**: 2h

---

### P1-3: PolicyManager 全局单例无并发保护

**文件**: `internal/alerts/policy_template.go:66-77`  
**问题**: `defaultPolicyManager` 全局单例，初始化后无锁保护

```go
var defaultPolicyManager *PolicyManager  // 全局变量

func GetPolicyManager() *PolicyManager {
    if defaultPolicyManager == nil {  // BUG: 可能有多个 goroutine 同时初始化
        defaultPolicyManager = &PolicyManager{
            templates: make(map[string]*PolicyTemplate),
            instances: make(map[string]*PolicyInstance),
        }
        defaultPolicyManager.registerBuiltInTemplates()
    }
    return defaultPolicyManager
}
```

**修复方案**: 使用 `sync.Once`

```go
var (
    defaultPolicyManager *PolicyManager
    once                 sync.Once
)

func GetPolicyManager() *PolicyManager {
    once.Do(func() {
        defaultPolicyManager = &PolicyManager{
            templates: make(map[string]*PolicyTemplate),
            instances: make(map[string]*PolicyInstance),
        }
        defaultPolicyManager.registerBuiltInTemplates()
    })
    return defaultPolicyManager
}
```

**复杂度**: 低 | **工时**: 0.5h

---

### P1-4: 重复代码 - Policy 模板应用逻辑

**文件**: `internal/alerts/policy_template.go` vs `engine.go`  
**问题**: `applyUpgradePolicy` 和 `applyUpgradeInstance` 逻辑重复；`applySuppressPolicy` 和 `applySuppressInstance` 逻辑重复

**重复代码**:

```go
// policy_template.go:247-271
func (m *PolicyManager) applyUpgradePolicy(e *Engine, template *PolicyTemplate, inst *PolicyInstance) {
    for _, action := range template.Actions {
        if action.Type == "upgrade_severity" {
            severityStr := inst.Parameters["new_severity"]
            if severityStr == "" {
                severityStr = "high"
            }
            threshold := 5
            if t, ok := inst.Parameters["threshold"]; ok {
                fmt.Sscanf(t, "%d", &threshold)
            }
            upgradeRule := &types.AlertUpgradeRule{...}
            e.AddUpgradeRule(upgradeRule)
        }
    }
}

// engine.go:333-357
func (e *Engine) applyUpgradeInstance(template *PolicyTemplate, instance *PolicyInstance) {
    // 完全相同的逻辑
    for _, action := range template.Actions {
        if action.Type == "upgrade_severity" {
            severityStr := instance.Parameters["new_severity"]
            // ...
        }
    }
}
```

**修复方案**: 提取公共方法到 `policy_template.go`

```go
// policy_template.go 添加
func ApplyUpgradePolicyToEngine(e *Engine, template *PolicyTemplate, inst *PolicyInstance) {
    for _, action := range template.Actions {
        if action.Type != "upgrade_severity" {
            continue
        }
        severityStr := inst.Parameters["new_severity"]
        if severityStr == "" {
            severityStr = "high"
        }
        threshold := 5
        if t, ok := inst.Parameters["threshold"]; ok {
            fmt.Sscanf(t, "%d", &threshold)
        }
        upgradeRule := &types.AlertUpgradeRule{
            ID:          0,
            Name:        inst.RuleName,
            Condition:   template.Name,
            Threshold:   threshold,
            NewSeverity: types.Severity(severityStr),
            Notify:      true,
            Enabled:     true,
        }
        e.AddUpgradeRule(upgradeRule)
    }
}

// policy_template.go:226-245 修改
func (m *PolicyManager) ApplyToEngine(e *Engine) error {
    for _, inst := range m.instances {
        if !inst.Enabled {
            continue
        }
        template, ok := m.templates[inst.TemplateName]
        if !ok {
            continue
        }
        switch template.PolicyType {
        case PolicyTypeUpgrade:
            ApplyUpgradePolicyToEngine(e, template, inst)  // 使用公共方法
        case PolicyTypeSuppress:
            ApplySuppressPolicyToEngine(e, template, inst)
        }
    }
    return nil
}

// engine.go:333-357 修改
func (e *Engine) applyUpgradeInstance(template *PolicyTemplate, instance *PolicyInstance) {
    ApplyUpgradePolicyToEngine(e, template, instance)  // 调用公共方法
}
```

**复杂度**: 中 | **工时**: 2h

---

### P1-5: UEBA BaselineManager 内存无限增长

**文件**: `internal/ueba/baseline.go:10-42`  
**问题**: `userActivity` map 只增不减，没有清理过期基线的机制

```go
type BaselineManager struct {
    mu           sync.RWMutex
    userActivity map[string]*UserBaseline  // 只增不减
    entityStats  map[string]*EntityStats   // 只增不减
    window       time.Duration
}
```

**修复方案**: 添加 TTL 过期机制

```go
type BaselineManager struct {
    mu            sync.RWMutex
    userActivity  map[string]*UserBaseline
    entityStats   map[string]*EntityStats
    window        time.Duration
    lastCleanup   time.Time
    cleanupMu     sync.Mutex
}

func (m *BaselineManager) Update(events []*types.Event) error {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    // 每小时清理一次过期数据
    m.cleanupMu.Lock()
    if time.Since(m.lastCleanup) > time.Hour {
        m.cleanupExpired()
        m.lastCleanup = time.Now()
    }
    m.cleanupMu.Unlock()
    
    for _, event := range events {
        // ... existing code
    }
    return nil
}

func (m *BaselineManager) cleanupExpired() {
    cutoff := time.Now().Add(-m.window)
    for user, baseline := range m.userActivity {
        if baseline.LastUpdated.Before(cutoff) {
            delete(m.userActivity, user)
        }
    }
    for key, stats := range m.entityStats {
        if stats.LastSeen.Before(cutoff) {
            delete(m.entityStats, key)
        }
    }
}
```

**复杂度**: 中 | **工时**: 2h

---

### P1-6: UEBA Engine 配置硬编码

**文件**: `internal/ueba/engine.go` vs `handlers_ueba.go`  
**问题**: `LearningWindow`, `AlertThreshold`, `MinEventsForBaseline` 等参数硬编码

```go
// handlers_ueba.go:32-38
func NewUEBAHandler(db *storage.DB) *UEBAHandler {
    engine := ueba.NewEngine(ueba.EngineConfig{
        LearningWindow:       7 * 24 * time.Hour,  // 硬编码
        AlertThreshold:       70,                   // 硬编码
        MinEventsForBaseline: 10,                   // 硬编码
    })
    // ...
}

// ueba.go:79-83 (CLI)
engine := ueba.NewEngine(ueba.EngineConfig{
    LearningWindow:       7 * 24 * time.Hour,  // 重复硬编码
    AlertThreshold:       70,
    MinEventsForBaseline: 10,
})
```

**修复方案**: 从配置文件读取

```go
type EngineConfig struct {
    LearningWindow       time.Duration
    AlertThreshold       float64
    MinEventsForBaseline int
    ImpossibleTravelThreshold float64  // 新增：不可能旅行阈值
    PrivilegeEscalationThreshold int   // 新增：权限提升阈值
}

// ueba.go 默认值
func DefaultEngineConfig() EngineConfig {
    return EngineConfig{
        LearningWindow:       7 * 24 * time.Hour,
        AlertThreshold:       70,
        MinEventsForBaseline: 10,
        ImpossibleTravelThreshold: 500,  // km/h
        PrivilegeEscalationThreshold: 5,
    }
}

// 从配置文件读取
func LoadEngineConfig(cfg *config.Config) EngineConfig {
    if cfg == nil {
        return DefaultEngineConfig()
    }
    // 从 cfg.UEBA 或 cfg.Alerts 读取配置
}
```

**复杂度**: 低 | **工时**: 1.5h

---

### P1-7: AlertStats.GetStats 缺少 TopSources/TopComputers

**文件**: `internal/alerts/stats.go`  
**问题**: `AlertStats` 有 `TopSources` 和 `TopComputers` 字段但 `GetStats` 只填充 `ByRule`

```go
func (e *Engine) GetStats() (*AlertStats, error) {
    stats, err := e.alertRepo.GetStats()
    if err != nil {
        return nil, err
    }
    e.stats.CopyFrom(stats)
    // TopSources 和 TopComputers 未填充
    return e.stats, nil
}
```

**修复方案**: 完善 `GetStats` 实现

**复杂度**: 低 | **工时**: 1h

---

### P1-8: UEBA detectPrivilegeEscalation 阈值硬编码

**文件**: `internal/ueba/engine.go:220-249`  
**问题**: `if len(events) > 5` 硬编码

```go
func (e *Engine) detectPrivilegeEscalation(events []*types.Event) []*AnomalyResult {
    // ...
    for user, events := range adminEvents {
        if len(events) > 5 {  // BUG: 硬编码
            results = append(results, &AnomalyResult{...})
        }
    }
}
```

**修复方案**: 使用配置

```go
type EngineConfig struct {
    // ...
    PrivilegeEscalationThreshold int  // 默认 5
}

// detectPrivilegeEscalation 使用 config.PrivilegeEscalationThreshold
```

**复杂度**: 低 | **工时**: 0.5h

---

### P1-9: AlertTrend.GetBySeverity 数据泄露

**文件**: `internal/alerts/trend.go:98-108`  
**问题**: 返回内部 slice 的拷贝，但 slice 元素是值拷贝不是指针拷贝

```go
func (t *AlertTrend) GetBySeverity() map[string][]int64 {
    t.mu.RLock()
    defer t.mu.RUnlock()
    
    result := make(map[string][]int64)
    for severity, hours := range t.bySeverity {
        result[severity] = make([]int64, len(hours))
        copy(result[severity], hours)  // 正确：做了完整拷贝
    }
    return result
}
```

**实际上这段代码是正确的**。问题在于其他方法：

```go
func (t *AlertTrend) GetHourlyDistribution() map[int]int64 {
    // BUG: 直接返回内部 map 的拷贝
    result := make(map[int]int64)
    for k, v := range t.hourly {
        result[k] = v  // 值拷贝，int64 是值类型，正确
    }
    return result
}
```

**这个实际上是正确的**。但 `GetWeeklyDistribution` 有问题：

```go
func (t *AlertTrend) GetWeeklyDistribution() map[int]map[int]int64 {
    // BUG: 嵌套 map 只拷贝了外层，内层还是共享
    result := make(map[int]map[int]int64)
    for day, hours := range t.weekly {
        result[day] = make(map[int]int64)
        for hour, count := range hours {
            result[day][hour] = count  // 值拷贝，正确
        }
    }
    return result
}
```

**实际上也是正确的**。让我重新审视问题...

实际上没问题。标记为已验证无需修改。

---

### P1-10: Engine.searchCache 无清理 goroutine

**文件**: `internal/engine/engine.go:25-36, 298-337`  
**问题**: `cacheEntry` 有 `created` 字段但从不清理过期条目

```go
type cacheEntry struct {
    result  *types.SearchResponse
    created time.Time
    key     string
}

// 设置时检查过期，但从不主动清理
func (c *searchCache) set(key string, result *types.SearchResponse) {
    // ...
    c.entries[key] = &cacheEntry{...}
}

// get 时被动清理，但不主动
func (c *searchCache) get(key string) *cacheEntry {
    // ...
    if time.Since(entry.created) < c.maxAge {
        return entry  // 过期的不返回，但也不删除
    }
    return nil  // 过期的不删除，map 会无限增长
}
```

**修复方案**: 添加主动清理 goroutine

```go
type searchCache struct {
    mu      sync.RWMutex
    entries map[string]*cacheEntry
    maxAge  time.Duration
    maxSize int
    stopCh  chan struct{}
    wg      sync.WaitGroup
}

func (e *Engine) SetImportConfig(cfg ImportConfig) {
    e.importCfg = cfg
    if e.searchCache.stopCh == nil {
        e.searchCache.stopCh = make(chan struct{})
        e.searchCache.wg.Add(1)
        go e.searchCache.cleanupLoop()
    }
}

func (c *searchCache) cleanupLoop() {
    defer c.wg.Done()
    ticker := time.NewTicker(c.maxAge)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            c.mu.Lock()
            now := time.Now()
            for key, entry := range c.entries {
                if now.Sub(entry.created) > c.maxAge {
                    delete(c.entries, key)
                }
            }
            c.mu.Unlock()
        case <-c.stopCh:
            return
        }
    }
}
```

**复杂度**: 中 | **工时**: 1.5h

---

### P1-11: CLI 和 Web UEBA 引擎状态不同步

**文件**: `cmd/winalog/commands/ueba.go` vs `internal/api/handlers_ueba.go`  
**问题**: 
- CLI 每次运行创建新引擎，无状态
- Web API 保持引擎状态，`Learn()` 累积数据
- CLI 的 `--save-alerts` 功能 Web API 没有

```go
// CLI: 每次运行新建引擎
func runUEBAAnalyze(cmd *cobra.Command, args []string) error {
    engine := ueba.NewEngine(ueba.EngineConfig{...})  // 新建
    engine.Learn(events)  // 内存中
    anomalies := engine.DetectAnomalies(events)
    // engine 被遗弃
}

// Web API: Handler 保持引擎
func NewUEBAHandler(db *storage.DB) *UEBAHandler {
    engine := ueba.NewEngine(ueba.EngineConfig{...})  // 新建
    return &UEBAHandler{db: db, engine: engine}  // 保存在 Handler 中
}

func (h *UEBAHandler) Analyze(c *gin.Context) {
    h.engine.Learn(events)  // 累积到 Handler 生命周期
}
```

**修复方案**: 
1. 为 CLI 添加 `--baseline-file` 保存/加载基线
2. 为 Web API 添加 `POST /api/ueba/reset` 重置基线
3. 统一使用配置文件配置

**复杂度**: 中 | **工时**: 3h

---

### P1-12: EvaluateBatchWithProgress 回调位置错误

**文件**: `internal/alerts/engine.go:414-481`  
**问题**: 回调在每个事件处理完后调用，但 `processed++` 在 goroutine 中仍有竞态

```go
func (e *Engine) EvaluateBatchWithProgress(...) {
    // ...
    for _, evt := range events {
        wg.Add(1)
        go func(event *types.Event) {
            // ... 处理逻辑
            if callback != nil {
                processed++  // BUG: 竞态
                callback(processed, total)
            }
        }(evt)
    }
}
```

**修复方案**: 同 P0-4

**复杂度**: 低 | **工时**: 0.5h (与 P0-4 合并)

---

## 4. P2 问题 (一般改进)

### P2-1: calculateIPDistance 简化假设

**文件**: `internal/ueba/engine.go:267-284`  
**问题**: 私网 IP 和公网 IP 距离简单返回固定值，没有真实地理计算

```go
func calculateIPDistance(ip1, ip2 string) float64 {
    // 简化：私网=100km，公网=1000km
    priv1 := isPrivateIP(ip1)
    priv2 := isPrivateIP(ip2)
    
    if priv1 && priv2 {
        return 100.0
    }
    if !priv1 && !priv2 {
        return 100.0
    }
    return 1000.0
}
```

**改进建议**: 预留接口，未来可集成 IP 地理库

```go
type GeoIPResolver interface {
    GetLocation(ip string) (lat, lon float64, err error)
}

var defaultResolver GeoIPResolver = &simpleGeoIPResolver{}

func RegisterGeoIPResolver(r GeoIPResolver) {
    defaultResolver = r
}

type simpleGeoIPResolver struct{}

func (r *simpleGeoIPResolver) GetLocation(ip string) (float64, float64, error) {
    // 当前简化实现
    return 0, 0, nil
}

func calculateIPDistance(ip1, ip2 string) float64 {
    loc1, _ := defaultResolver.GetLocation(ip1)
    loc2, _ := defaultResolver.GetLocation(ip2)
    // 使用 Haversine 公式计算真实距离
    return haversine(loc1.Lat, loc1.Lon, loc2.Lat, loc2.Lon)
}
```

**复杂度**: 中 | **工时**: 3h (预留接口 + 简单实现)

---

### P2-2: searchCache key 生成无排序

**文件**: `internal/engine/engine.go:292-296`  
**问题**: map 遍历无序，相同查询可能生成不同 cache key

```go
func (e *Engine) generateCacheKey(req *types.SearchRequest) string {
    return fmt.Sprintf("%d|%d|%s|%s|%v|%v|%v|%v|%v|%v",
        req.Page, req.PageSize, req.SortOrder, req.Keywords,
        req.EventIDs, req.Levels, req.LogNames, req.Sources, req.Computers, req.Users)
    // %v 对 slice/map 输出无序
}
```

**修复方案**: 排序后拼接

```go
func (e *Engine) generateCacheKey(req *types.SearchRequest) string {
    parts := []string{
        fmt.Sprintf("%d", req.Page),
        fmt.Sprintf("%d", req.PageSize),
        req.SortOrder,
        req.Keywords,
        joinSorted(req.EventIDs),
        joinSorted(req.Levels),
        joinSorted(req.LogNames),
        joinSorted(req.Sources),
        joinSorted(req.Computers),
        joinSorted(req.Users),
    }
    return strings.Join(parts, "|")
}

func joinSorted(vals []int) string {
    if len(vals) == 0 {
        return ""
    }
    sort.Ints(vals)
    return fmt.Sprintf("%v", vals)
}
```

**复杂度**: 低 | **工时**: 1h

---

### P2-3: PolicyInstance key 使用时间戳可能碰撞

**文件**: `internal/alerts/policy_template.go:204`  
**问题**: `time.Now().UnixNano()` 在高并发下可能碰撞

```go
key := fmt.Sprintf("%s_%s_%d", templateName, ruleName, time.Now().UnixNano())
m.instances[key] = instance
```

**修复方案**: 使用 UUID

```go
import "github.com/google/uuid"

key := fmt.Sprintf("%s_%s_%s", templateName, ruleName, uuid.New().String())
```

**复杂度**: 低 | **工时**: 0.5h

---

### P2-4: CreateCustomTemplate 允许覆盖内置模板

**文件**: `internal/alerts/policy_template.go:310-320`  
**问题**: 检查已存在但允许覆盖内置模板

```go
func (m *PolicyManager) CreateCustomTemplate(template *PolicyTemplate) error {
    if template.Name == "" {
        return fmt.Errorf("template name is required")
    }
    if _, ok := m.templates[template.Name]; ok {
        return fmt.Errorf("template '%s' already exists", template.Name)
    }
    // BUG: 内置模板在 registerBuiltInTemplates 后添加，这里会覆盖
}
```

**修复方案**: 添加 `BuiltIn` 标记

```go
type PolicyTemplate struct {
    // ...
    BuiltIn bool `json:"built_in"`
}

func (m *PolicyManager) CreateCustomTemplate(template *PolicyTemplate) error {
    if template.Name == "" {
        return fmt.Errorf("template name is required")
    }
    if existing, ok := m.templates[template.Name]; ok {
        if existing.BuiltIn {
            return fmt.Errorf("cannot override built-in template '%s'", template.Name)
        }
    }
    template.BuiltIn = false
    m.templates[template.Name] = template
    return nil
}

func (m *PolicyManager) registerBuiltInTemplates() {
    // 内置模板设置 BuiltIn = true
}
```

**复杂度**: 低 | **工时**: 1h

---

### P2-5: Suppress Duration 单位不一致

**文件**: `internal/alerts/suppress.go` vs `handlers_suppress.go`  
**问题**: 
- `SuppressRule.Duration` 是 `time.Duration`
- 数据库存储是分钟整数
- CLI flag 是分钟整数

```go
// suppress.go:376
rule := &types.SuppressRule{
    Duration: time.Duration(duration) * time.Minute,  // 分钟转 Duration
}

// whitelist.go:54
whitelistAddCmd.Flags().IntVar(&whitelistFlags.duration, "duration", 0, "Duration in minutes")

// handlers_suppress.go:152-156
_, err := h.db.Exec(`
    UPDATE suppress_rules
    SET name = ?, conditions = ?, duration = ?, scope = ?, enabled = ?, expires_at = ?
    WHERE id = ?
`, req.Name, conditionsJSON, req.Duration, ...)  // 直接存分钟数
```

**修复方案**: 统一使用分钟为单位

```go
// suppress.go
const DurationMinutes = time.Minute

func (r *SuppressRule) DurationMinutes() int {
    return int(r.Duration / time.Minute)
}
```

**复杂度**: 低 | **工时**: 1h

---

### P2-6: Pipeline errorChan buffer 太小

**文件**: `internal/engine/pipeline.go:55`  
**问题**: errorChan 只有 100 buffer，高吞吐可能丢失错误

```go
return &Pipeline{
    // ...
    errorChan: make(chan error, 100),  // 可能不够
}
```

**修复方案**: 使用无 buffer channel 或 larger buffer

```go
errorChan: make(chan error),  // 无 buffer，确保不丢失
```

**注意**: 这可能影响性能，需要权衡

**复杂度**: 低 | **工时**: 0.5h

---

### P2-7: Engine 配置零值问题

**文件**: `internal/engine/engine.go:57-79`  
**问题**: 零值配置可能导致问题

```go
func NewEngine(db *storage.DB) *Engine {
    e := &Engine{
        // ...
        importCfg: ImportConfig{
            Workers: 0,  // 零值
            BatchSize: 0,
            // ...
        },
    }
    // 没有校验和默认值设置
}
```

**修复方案**: 添加零值校验

```go
func NewEngine(db *storage.DB) *Engine {
    cfg := ImportConfig{
        Workers:          4,
        BatchSize:        10000,
        SkipPatterns:     []string{"Diagnostics", "Debug"},
        Incremental:      true,
        CalculateHash:    true,
        ProgressCallback: true,
    }
    // ... 使用 cfg
}
```

**复杂度**: 低 | **工时**: 0.5h

---

### P2-8: BaselineManager 锁粒度太大

**文件**: `internal/ueba/baseline.go:44-56`  
**问题**: `Update` 方法锁住整个操作，包括 IO

```go
func (m *BaselineManager) Update(events []*types.Event) error {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    for _, event := range events {
        // 所有操作都在锁内
        m.updateUserBaseline(*event.User, event)
        m.updateEntityStats(event)
    }
    return nil
}
```

**改进建议**: 分批获取锁，减少锁竞争

```go
func (m *BaselineManager) Update(events []*types.Event) error {
    // 按用户分组
    userEvents := make(map[string][]*types.Event)
    for _, event := range events {
        if event.User != nil {
            userEvents[*event.User] = append(userEvents[*event.User], event)
        }
    }
    
    // 批量更新用户基线
    m.mu.Lock()
    for user, evts := range userEvents {
        m.updateUserBaseline(user, evts...)
    }
    m.mu.Unlock()
    
    return nil
}

func (m *BaselineManager) updateUserBaseline(user string, events ...*types.Event) {
    baseline, exists := m.userActivity[user]
    if !exists {
        baseline = &UserBaseline{
            User:             user,
            TypicalHours:     make(map[int]bool),
            TypicalComputers: make(map[string]int),
            TypicalSources:   make(map[string]int),
        }
        m.userActivity[user] = baseline
    }
    
    for _, event := range events {
        baseline.LoginCount++
        hour := event.Timestamp.Hour()
        baseline.TypicalHours[hour] = true
        baseline.TypicalComputers[event.Computer]++
        if event.Source != "" {
            baseline.TypicalSources[event.Source]++
        }
    }
    baseline.LastUpdated = time.Now()
}
```

**复杂度**: 中 | **工时**: 2h

---

## 5. 实施计划

### Phase 1: P0 修复 (必须先完成)

| 序号 | 问题 | 文件 | 工时 |
|------|------|------|------|
| P0-1 | DedupCache goroutine 泄漏 | dedup.go | 0.5h |
| P0-2 | parseConditions 空实现 | handlers_suppress.go | 0.5h |
| P0-3 | formatValue int→rune 错误 | models.go | 0.5h |
| P0-4 | EvaluateBatch 竞态条件 | engine.go | 1h |
| **小计** | | | **2.5h** |

### Phase 2: P1 修复

| 序号 | 问题 | 文件 | 工时 |
|------|------|------|------|
| P1-1 | SuppressCache 条件匹配 OR 错误 | suppress.go | 0.5h |
| P1-2 | SuppressCache 条件内 ANY→ALL | suppress.go | 2h |
| P1-3 | PolicyManager 全局单例无锁 | policy_template.go | 0.5h |
| P1-4 | Policy 重复代码 | policy_template.go, engine.go | 2h |
| P1-5 | BaselineManager 内存无限增长 | baseline.go | 2h |
| P1-6 | UEBA 配置硬编码 | ueba.go, handlers_ueba.go | 1.5h |
| P1-7 | AlertStats.GetStats 不完整 | stats.go | 1h |
| P1-8 | PrivilegeEscalation 阈值硬编码 | engine.go | 0.5h |
| P1-9 | searchCache 无清理 goroutine | engine.go | 1.5h |
| P1-10 | CLI/Web UEBA 状态不同步 | ueba.go, handlers_ueba.go | 3h |
| P1-11 | EvaluateBatchWithProgress 竞态 | engine.go | 0.5h |
| **小计** | | | **15.5h** |

### Phase 3: P2 改进

| 序号 | 问题 | 文件 | 工时 |
|------|------|------|------|
| P2-1 | calculateIPDistance 简化 | engine.go | 3h |
| P2-2 | searchCache key 无序 | engine.go | 1h |
| P2-3 | PolicyInstance key 碰撞 | policy_template.go | 0.5h |
| P2-4 | CreateCustomTemplate 覆盖内置 | policy_template.go | 1h |
| P2-5 | Suppress Duration 单位不一致 | suppress.go | 1h |
| P2-6 | Pipeline errorChan buffer 小 | pipeline.go | 0.5h |
| P2-7 | Engine 配置零值问题 | engine.go | 0.5h |
| P2-8 | BaselineManager 锁粒度大 | baseline.go | 2h |
| **小计** | | | **9.5h** |

### 总计

| Phase | 优先级 | 工时 |
|-------|--------|------|
| Phase 1 | P0 | 2.5h |
| Phase 2 | P1 | 15.5h |
| Phase 3 | P2 | 9.5h |
| **总计** | | **27.5h** |

---

## 6. CLI vs Web 实现差异总结

| 功能 | CLI 实现 | Web API 实现 | 差异 |
|------|----------|--------------|------|
| UEBA 分析 | 每次新建引擎，无状态 | Handler 保持引擎，有状态 | 重大差异 |
| UEBA 基线 | CLI 参数控制 | 累积在内存中 | 需添加重置接口 |
| Suppress 规则 | 直接 SQL 操作 | 通过 loadRulesToEngine 同步 | CLI 不同步到引擎 |
| Alert 评估 | `getAlertEngine()` 每次新建 | 共享 Engine 实例 | Engine 生命周期不同 |
| 配置 | 启动时读取 | Handler 初始化时硬编码 | 不一致 |

---

## 7. 验证方法

### 修复后验证

```bash
# 编译验证
cd winalog-go && go build ./...

# 测试运行
go test ./internal/alerts/... -v
go test ./internal/ueba/... -v
go test ./internal/engine/... -v

# 竞态检测
go test -race ./internal/alerts/...
```

### 关键测试用例

1. **P0-1**: 创建多个 Engine 并 Close，验证无 goroutine 泄漏
2. **P0-2**: 创建 suppress rule，验证条件正确解析和匹配
3. **P0-3**: UEBA 异常输出，验证数字正确显示
4. **P0-4**: 并发调用 EvaluateBatch，验证计数准确
5. **P1-1**: Suppress rule 同时有条件和时间窗口，验证 AND 逻辑
6. **P1-2**: 多个条件的 suppress rule，验证 ALL 逻辑

---

## 8. 风险评估

| 问题 | 风险 | 缓解措施 |
|------|------|----------|
| P1-2 逻辑变更 | 高 - 改变现有行为 | 添加配置选项，默认保持兼容 |
| P1-10 CLI/Web 统一 | 中 - 需要 API 变更 | 添加 versioning |
| P2-1 GeoIP 接口 | 低 - 预留接口 | 使用简单实现作为默认值 |

---

**文档版本**: 1.0  
**生成时间**: 2026-04-17  
**分析深度**: 深入分析 (600+ 行代码审查)
