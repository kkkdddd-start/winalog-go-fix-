# WinLogAnalyzer-Go 告警模块问题报告

> 评估日期: 2026-04-17  
> 评估范围: `internal/alerts/` + API handlers + CLI alert commands

---

## 问题汇总

| ID | 问题 | 严重程度 | 修复复杂度 |
|----|------|---------|-----------|
| P01 | CLI 无法触发告警评估 | 高 | 低 |
| P02 | 无实时告警监控模式 | 高 | 中 |
| P03 | UpgradeCache 无并发保护 | 高 | 低 |
| P04 | EvaluateBatch 错误被静默忽略 | 中 | 低 |
| P05 | 导入时不支持自动触发告警 | 高 | 低 |
| P06 | GetTopRules 使用冒泡排序 O(n²) | 中 | 低 |
| P07 | DedupCache SHA256 性能开销 | 中 | 低 |
| P08 | 批量处理无进度反馈 | 中 | 低 |
| P09 | 无资源清理机制 | 中 | 中 |

---

## P01: CLI 无法触发告警评估

**严重程度: 高 | 修复复杂度: 低**

### 问题描述

CLI 的 `alert` 命令族（`list/show/resolve/delete/export/stats`）仅对数据库中已存在的告警进行 CRUD 操作，没有任何命令触发告警评估。

### 修复方案

新增 `winalog alert run` 命令：

```go
// cmd/winalog/commands/alert.go

var alertRunCmd = &cobra.Command{
    Use:   "run",
    Short: "Run alert analysis on stored events",
    Long:  `Evaluate alert rules against stored events and generate alerts`,
    RunE:  runAlertRun,
}

var alertRunFlags struct {
    batchSize  int
    rules      string
    clearDedup bool
}

func init() {
    alertCmd.AddCommand(alertRunCmd)
    alertRunCmd.Flags().IntVar(&alertRunFlags.batchSize, "batch-size", 1000, "Batch size")
    alertRunCmd.Flags().StringVar(&alertRunFlags.rules, "rules", "", "Comma-separated rule names")
    alertRunCmd.Flags().BoolVar(&alertRunFlags.clearDedup, "clear-dedup", false, "Clear dedup cache")
}

func runAlertRun(cmd *cobra.Command, args []string) error {
    engine := getAlertEngine()
    if engine == nil {
        return fmt.Errorf("failed to initialize alert engine")
    }

    builtinRules := builtin.GetAlertRules()
    enabledRules := make([]*rules.AlertRule, 0)
    for _, r := range builtinRules {
        if r.Enabled {
            if alertRunFlags.rules == "" {
                enabledRules = append(enabledRules, r)
            } else {
                for _, name := range strings.Split(alertRunFlags.rules, ",") {
                    if r.Name == strings.TrimSpace(name) {
                        enabledRules = append(enabledRules, r)
                        break
                    }
                }
            }
        }
    }

    if len(enabledRules) == 0 {
        fmt.Println("No rules to execute")
        return nil
    }

    engine.LoadRules(enabledRules)

    if alertRunFlags.clearDedup {
        engine.ClearDedup()
    }

    ctx := context.Background()
    batchSize := alertRunFlags.batchSize
    var totalEvents, totalAlerts int

    offset := 0
    for {
        events, _, err := engine.GetDB().ListEvents(&storage.EventFilter{
            Limit:  batchSize,
            Offset: offset,
        })
        if err != nil {
            return fmt.Errorf("failed to fetch events: %w", err)
        }

        if len(events) == 0 {
            break
        }

        alerts, err := engine.EvaluateBatch(ctx, events)
        if err != nil {
            fmt.Printf("Warning: evaluation error: %v\n", err)
        }

        if len(alerts) > 0 {
            if err := engine.SaveAlerts(alerts); err != nil {
                fmt.Printf("Warning: failed to save alerts: %v\n", err)
            } else {
                totalAlerts += len(alerts)
            }
        }

        totalEvents += len(events)
        offset += batchSize
        fmt.Printf("\rProcessed %d events, generated %d alerts...", totalEvents, totalAlerts)

        if len(events) < batchSize {
            break
        }
    }

    fmt.Printf("\nAnalysis complete: %d events analyzed, %d alerts generated\n", totalEvents, totalAlerts)
    return nil
}
```

**Engine 需要新增方法**：
```go
func (e *Engine) GetDB() *storage.DB {
    return e.db
}
```

---

## P02: 无实时告警监控模式

**严重程度: 高 | 修复复杂度: 中**

### 问题描述

系统采用"导入-存储-手动分析"模式，缺少实时监控模式，无法及时发现安全威胁。

### 修复方案

新增 `winalog alert monitor` 命令：

```go
// cmd/winalog/commands/alert.go

var alertMonitorCmd = &cobra.Command{
    Use:   "monitor",
    Short: "Run in continuous alert monitoring mode",
    Long:  `Continuously monitor events and generate alerts in real-time`,
    RunE:  runAlertMonitor,
}

var alertMonitorFlags struct {
    interval  time.Duration
    batchSize int
}

func init() {
    alertCmd.AddCommand(alertMonitorCmd)
    alertMonitorCmd.Flags().DurationVar(&alertMonitorFlags.interval, "interval", 30*time.Second, "Check interval")
    alertMonitorCmd.Flags().IntVar(&alertMonitorFlags.batchSize, "batch-size", 100, "Batch size per check")
}

func runAlertMonitor(cmd *cobra.Command, args []string) error {
    engine := getAlertEngine()
    if engine == nil {
        return fmt.Errorf("failed to initialize alert engine")
    }

    builtinRules := builtin.GetAlertRules()
    enabledRules := make([]*rules.AlertRule, 0)
    for _, r := range builtinRules {
        if r.Enabled {
            enabledRules = append(enabledRules, r)
        }
    }
    engine.LoadRules(enabledRules)

    ctx := context.Background()
    ticker := time.NewTicker(alertMonitorFlags.interval)
    defer ticker.Stop()

    lastCheckTime := time.Now().Add(-alertMonitorFlags.interval)

    fmt.Printf("Started monitoring (interval: %s, batch: %d)\n", 
        alertMonitorFlags.interval, alertMonitorFlags.batchSize)

    for {
        select {
        case <-ticker.C:
            events, _, err := engine.GetDB().ListEvents(&storage.EventFilter{
                Limit:     alertMonitorFlags.batchSize,
                StartTime: &lastCheckTime,
            })
            if err != nil {
                fmt.Printf("Error fetching events: %v\n", err)
                continue
            }

            if len(events) == 0 {
                continue
            }

            alerts, err := engine.EvaluateBatch(ctx, events)
            if err != nil {
                fmt.Printf("Error evaluating: %v\n", err)
                continue
            }

            if len(alerts) > 0 {
                if err := engine.SaveAlerts(alerts); err != nil {
                    fmt.Printf("Error saving alerts: %v\n", err)
                }
                fmt.Printf("[%s] Generated %d new alerts\n", time.Now().Format("15:04:05"), len(alerts))
            }

            lastCheckTime = time.Now()
        case <-cmd.Context().Done():
            fmt.Println("\nMonitoring stopped")
            return nil
        }
    }
}
```

---

## P03: UpgradeCache 无并发保护

**严重程度: 高 | 修复复杂度: 低**

### 问题描述

`AlertUpgradeCache` 的 `Add()` 和 `Check()` 方法无锁保护，在并发场景下存在竞态条件。

### 修复方案

添加读写锁：

```go
// internal/alerts/upgrade.go

type AlertUpgradeCache struct {
    mu    sync.RWMutex
    rules map[string]*types.AlertUpgradeRule
}

func NewAlertUpgradeCache() *AlertUpgradeCache {
    return &AlertUpgradeCache{
        rules: make(map[string]*types.AlertUpgradeRule),
    }
}

func (c *AlertUpgradeCache) Add(rule *types.AlertUpgradeRule) {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.rules[rule.Name] = rule
}

func (c *AlertUpgradeCache) Check(alert *types.Alert) (bool, *types.AlertUpgradeRule) {
    c.mu.RLock()
    defer c.mu.RUnlock()

    for _, rule := range c.rules {
        if c.matches(rule, alert) {
            return true, rule
        }
    }
    return false, nil
}

func (c *AlertUpgradeCache) Remove(ruleName string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    delete(c.rules, ruleName)
}

func (c *AlertUpgradeCache) Clear() {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.rules = make(map[string]*types.AlertUpgradeRule)
}

func (c *AlertUpgradeCache) List() []*types.AlertUpgradeRule {
    c.mu.RLock()
    defer c.mu.RUnlock()
    result := make([]*types.AlertUpgradeRule, 0, len(c.rules))
    for _, rule := range c.rules {
        result = append(result, rule)
    }
    return result
}
```

---

## P04: EvaluateBatch 错误被静默忽略

**严重程度: 中 | 修复复杂度: 低**

### 问题描述

规则评估过程中的错误被静默忽略，难以调试问题。

```go
// internal/alerts/engine.go
matched, err := e.evaluator.Evaluate(rule, evt)
if err != nil || !matched {
    continue  // 错误去哪了？没人知道
}
```

### 修复方案

添加错误日志：

```go
// internal/alerts/engine.go

for _, rule := range rules {
    select {
    case <-ctx.Done():
        return alerts, ctx.Err()
    default:
    }

    if e.suppressCache.IsSuppressed(rule, evt) {
        continue
    }

    matched, err := e.evaluator.Evaluate(rule, evt)
    if err != nil {
        log.Printf("evaluator error for rule %s: %v", rule.Name, err)
        continue
    }
    if !matched {
        continue
    }

    if e.dedup.IsDuplicate(rule.Name, evt) {
        continue
    }

    alert := e.createAlert(rule, evt)
    alertChan <- alert
    e.dedup.Mark(rule.Name, evt)
    e.trend.Record(alert)
}
```

---

## P05: 导入时不支持自动触发告警

**严重程度: 高 | 修复复杂度: 低**

### 问题描述

`ImportLogs` 只存储事件，不触发告警评估。用户导入日志后需要手动再调用一次分析。

### 修复方案

API 添加 `alert_on_import` 参数：

```go
// internal/api/handlers.go

type ImportRequest struct {
    Files         []string `json:"files" binding:"required"`
    AlertOnImport bool     `json:"alert_on_import"`
}

func (h *ImportHandler) ImportLogs(c *gin.Context) {
    var req ImportRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, ErrorResponse{Error: err.Error()})
        return
    }

    if len(req.Files) == 0 {
        c.JSON(400, ErrorResponse{Error: "no files provided"})
        return
    }

    eng := engine.NewEngine(h.db)
    importReq := &engine.ImportRequest{
        Paths:     req.Files,
        BatchSize: 1000,
    }

    ctx := c.Request.Context()
    result, err := eng.Import(ctx, importReq, nil)
    if err != nil {
        c.JSON(500, ErrorResponse{Error: err.Error()})
        return
    }

    // 如果启用，触发告警评估
    if req.AlertOnImport && h.alertEngine != nil {
        go func() {
            startTime := result.StartTime
            events, _, _ := h.db.ListEvents(&storage.EventFilter{
                Limit:     10000,
                StartTime: &startTime,
            })

            if len(events) > 0 {
                alerts, _ := h.alertEngine.EvaluateBatch(context.Background(), events)
                if len(alerts) > 0 {
                    h.alertEngine.SaveAlerts(alerts)
                }
            }
        }()
    }

    c.JSON(200, gin.H{
        "success":          result.TotalFiles > 0 && result.FilesFailed == 0,
        "total_files":      result.TotalFiles,
        "files_imported":   result.FilesImported,
        "files_failed":     result.FilesFailed,
        "events_imported":  result.EventsImported,
        "alert_on_import":  req.AlertOnImport,
        "duration":         fmt.Sprintf("%v", result.Duration),
        "errors":           result.Errors,
    })
}
```

CLI 添加 `--alert-on-import` 标志：

```go
// cmd/winalog/commands/import.go
var importFlags struct {
    // ... existing flags ...
    alertOnImport bool
}

func init() {
    importCmd.Flags().BoolVar(&importFlags.alertOnImport, "alert-on-import", false, "Trigger alert analysis after import")
}
```

---

## P06: GetTopRules 使用冒泡排序 O(n²)

**严重程度: 中 | 修复复杂度: 低**

### 问题描述

```go
// internal/alerts/stats.go - GetTopRules()
for i := 0; i < len(topRules)-1; i++ {
    for j := i + 1; j < len(topRules); j++ {
        if topRules[j].Count > topRules[i].Count {
            topRules[i], topRules[j] = topRules[j], topRules[i]
        }
    }
}
```

### 修复方案

使用 `sort.Slice()`：

```go
// internal/alerts/stats.go

import "sort"

func (s *AlertStats) GetTopRules(n int) []*RuleStat {
    s.mu.RLock()
    defer s.mu.RUnlock()

    topRules := make([]*RuleStat, 0, len(s.ByRule))
    for name, count := range s.ByRule {
        topRules = append(topRules, &RuleStat{
            RuleName: name,
            Count:    count,
        })
    }

    sort.Slice(topRules, func(i, j int) bool {
        return topRules[i].Count > topRules[j].Count
    })

    if n > 0 && len(topRules) > n {
        topRules = topRules[:n]
    }

    return topRules
}
```

### 作用

| 方面 | 说明 |
|------|------|
| **性能** | O(n²) → O(n log n)，100条规则: 10000次 → 665次 |
| **代码简洁** | 内置实现，减少嵌套循环 |
| **符合惯例** | Go 标准库用法 |

---

## P07: DedupCache SHA256 性能开销

**严重程度: 中 | 修复复杂度: 低**

### 问题描述

每次去重检查都计算 SHA256 哈希，高吞吐场景下可能成为瓶颈。

```go
// internal/alerts/dedup.go
func (c *DedupCache) generateKey(ruleName string, event *types.Event) string {
    keyData := fmt.Sprintf("%s|%d|%s|%s|%s|%s", ...)
    hash := sha256.Sum256([]byte(keyData))
    return hex.EncodeToString(hash[:])
}
```

### 修复方案

直接使用字符串拼接，Go 的 map 自动处理哈希：

```go
// internal/alerts/dedup.go

func (c *DedupCache) generateKey(ruleName string, event *types.Event) string {
    userStr := ""
    if event.UserSID != nil && *event.UserSID != "" {
        userStr = *event.UserSID
    } else if event.User != nil && *event.User != "" {
        userStr = *event.User
    }

    ipStr := ""
    if event.IPAddress != nil && *event.IPAddress != "" {
        ipStr = *event.IPAddress
    }

    return ruleName + "|" + 
           strconv.FormatInt(int64(event.EventID), 10) + "|" +
           event.Computer + "|" + 
           event.Source + "|" +
           userStr + "|" +
           ipStr
}
```

### 作用

| 方面 | 说明 |
|------|------|
| **性能** | 避免每次计算 SHA256 哈希 |
| **简化** | 减少 `crypto/sha256` 和 `encoding/hex` 依赖 |
| **可读性** | 调试时可直观看 key 内容 |

---

## P08: 批量处理无进度反馈

**严重程度: 中 | 修复复杂度: 低**

### 问题描述

`RunAnalysis` 一次性处理所有事件，大数据量时用户无法得知进度。

```go
// handlers.go RunAnalysis
for {
    events, _, err := h.db.ListEvents(&storage.EventFilter{...})
    // 处理...
    // 用户只能等待，不知道进度
}
```

### 修复方案

```go
// internal/alerts/engine.go

type ProgressCallback func(processed, total int)

func (e *Engine) EvaluateBatchWithProgress(ctx context.Context, events []*types.Event, 
    callback ProgressCallback) ([]*types.Alert, error) {
    
    total := len(events)
    processed := 0

    alertChan := make(chan *types.Alert, len(events))
    var wg sync.WaitGroup

    e.mu.RLock()
    rules := make([]*rules.AlertRule, 0, len(e.rules))
    for _, rule := range e.rules {
        rules = append(rules, rule)
    }
    e.mu.RUnlock()

    for _, event := range events {
        wg.Add(1)
        go func(evt *types.Event) {
            defer wg.Done()

            for _, rule := range rules {
                select {
                case <-ctx.Done():
                    return
                default:
                }

                if e.suppressCache.IsSuppressed(rule, evt) {
                    continue
                }

                matched, err := e.evaluator.Evaluate(rule, evt)
                if err != nil {
                    log.Printf("evaluator error for rule %s: %v", rule.Name, err)
                    continue
                }
                if !matched {
                    continue
                }

                if e.dedup.IsDuplicate(rule.Name, evt) {
                    continue
                }

                alert := e.createAlert(rule, evt)
                alertChan <- alert
                e.dedup.Mark(rule.Name, evt)
                e.trend.Record(alert)
            }

            if callback != nil {
                callback(processed, total)
            }
        }(event)
    }
    
    // ... 收集结果 ...
}
```

### CLI 显示进度

```go
// cmd/winalog/commands/alert.go - runAlertRun

progressCallback := func(processed, total int) {
    fmt.Printf("\rProcessed %d/%d events (%.1f%%)", 
        processed, total, float64(processed)/float64(total)*100)
}

alerts, err := engine.EvaluateBatchWithProgress(ctx, events, progressCallback)
```

### 作用

| 方面 | 说明 |
|------|------|
| **用户体验** | 大数据量时知道系统还在工作 |
| **可预期性** | 知道还要等多久 |
| **调试** | 知道处理到哪一行时出错 |

---

## P09: 无资源清理机制

**严重程度: 中 | 修复复杂度: 中**

### 问题描述

`DedupCache` 和 `Evaluator` 启动了后台 goroutine 进行清理，但没有提供停止机制。

```go
// 当前代码 - 无关闭机制
func NewDedupCache(window time.Duration) *DedupCache {
    c := &DedupCache{...}
    go c.cleanupLoop()  // 永远运行
    return c
}
```

### 修复方案

添加 `Close()` 方法：

```go
// internal/alerts/dedup.go

type DedupCache struct {
    mu      sync.RWMutex
    window  time.Duration
    entries map[string]*dedupEntry
    done    chan struct{}
}

func NewDedupCache(window time.Duration) *DedupCache {
    c := &DedupCache{
        window:  window,
        entries: make(map[string]*dedupEntry),
        done:    make(chan struct{}),
    }
    go c.cleanupLoop()
    return c
}

func (c *DedupCache) Close() {
    close(c.done)
}

func (c *DedupCache) cleanupLoop() {
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

func (c *DedupCache) cleanup() {
    c.mu.Lock()
    defer c.mu.Unlock()

    cutoff := time.Now().Add(-c.window)
    for key, entry := range c.entries {
        if entry.Timestamp.Before(cutoff) {
            delete(c.entries, key)
        }
    }
}
```

Engine 添加 Close：

```go
// internal/alerts/engine.go

func (e *Engine) Close() {
    if e.dedup != nil {
        e.dedup.Close()
    }
}
```

### 作用

| 方面 | 说明 |
|------|------|
| **资源管理** | 避免长期运行的内存/goroutine 泄漏 |
| **可测试性** | 测试中可以创建/销毁 Engine |
| **生产可用** | 服务重启时资源能正确释放 |

---

## 修复优先级

| 优先级 | 问题 | 工作量 |
|--------|------|--------|
| P1 | P03 UpgradeCache 并发保护 | 1小时 |
| P1 | P04 错误日志 | 10分钟 |
| P1 | P01 CLI alert run | 2小时 |
| P2 | P05 导入触发告警 | 2小时 |
| P2 | P02 alert monitor | 3小时 |
| P2 | P06 排序算法优化 | 30分钟 |
| P3 | P07 SHA256 优化 | 30分钟 |
| P3 | P08 进度反馈 | 1小时 |
| P3 | P09 资源清理 | 2小时 |
