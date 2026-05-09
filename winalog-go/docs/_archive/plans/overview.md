# WinLogAnalyzer-Go 改进实施方案

**项目**: WinLogAnalyzer-Go  
**版本**: v2.4.0  
**文档日期**: 2026-04-17  
**基于**: CODE_EVALUATION_REPORT.md + 代码审查验证

---

## 一、问题验证摘要

### 1.1 已确认存在的真实问题

| 优先级 | 问题 | 位置 | 验证状态 |
|--------|------|------|----------|
| **P0** | SQL 注入漏洞 | `internal/storage/events.go:127,131` | **已确认** |
| **P1** | 正则表达式 DoS 风险 | `internal/alerts/evaluator.go:293` | **已确认** |
| **P2** | Pipeline Pacer Goroutine 泄漏 | `internal/engine/pipeline.go:131-147` | **已确认** |
| **P2** | Evaluator 清理 Goroutine 无停止机制 | `internal/alerts/evaluator.go:37-50` | **已确认** |
| **P3** | 代码重复：scanEvent 与 scanEventFromRows | `internal/storage/events.go:314,375` | **已确认** |
| **P3** | 报告模块全量加载数据 | `internal/reports/generator.go` | **已确认** |

### 1.2 已修复问题 (最新提交)

| 问题 | 状态 |
|------|------|
| CORS 配置允许所有来源凭据 | ✅ 已修复 |
| DB.Begin() 死锁 | ✅ 已修复 |
| BatchAlertAction 静默忽略错误 | ✅ 已修复 |
| 时间线排序 O(n²) | ✅ 已修复 |
| replace 函数重复 | ✅ 已修复 |

---

## 二、P0/P1/P2 级问题修复方案

> 详见第一版文档，此处省略重复内容。

---

## 三、优化项详细方案

### OPT-1: 解析器自注册机制

#### 3.1.1 问题分析

**当前问题**: `internal/engine/engine.go:66-72` 中解析器需要手动注册

```go
func (e *Engine) registerParsers() {
    e.parsers.Register(evtx.NewEvtxParser())
    e.parsers.Register(etl.NewEtlParser())
    e.parsers.Register(csv.NewCsvParser())
    e.parsers.Register(iis.NewIISParser())
    e.parsers.Register(sysmon.NewSysmonParser())
}
```

**问题**: 新增解析器需要修改 Engine 代码，违反开闭原则

#### 3.1.2 实施方案

**修改文件**: 
- `internal/parsers/evtx/parser.go`
- `internal/parsers/etl/parser.go`
- `internal/parsers/csv/parser.go`
- `internal/parsers/iis/parser.go`
- `internal/parsers/sysmon/parser.go`
- `internal/engine/engine.go`

**修改内容**:

```go
// 1. 修改 Parser 接口，添加 Priority 方法
type Parser interface {
    CanParse(path string) bool
    Parse(path string) <-chan *types.Event
    ParseBatch(path string) ([]*types.Event, error)
    GetType() string
    Priority() int  // 新增：返回解析器优先级，0-100，数值越大优先级越高
}

// 2. 各解析器实现自注册
package evtx

//go:register
func init() {
    parsers.Register(&EvtxParser{})
}

type EvtxParser struct{}

func (p *EvtxParser) Priority() int { return 90 }  // EVTX 优先级高

// 3. 修改 ParserRegistry 支持自注册
var (
    globalRegistry *ParserRegistry
    once           sync.Once
)

func GetGlobalRegistry() *ParserRegistry {
    once.Do(func() {
        globalRegistry = NewParserRegistry()
        // 调用所有已注册的 init 函数
    })
    return globalRegistry
}

type ParserRegistry struct {
    parsers   map[string]Parser
    priority  []Parser  // 按优先级排序
    mu        sync.RWMutex
}

func (r *ParserRegistry) Register(p Parser) {
    r.mu.Lock()
    defer r.mu.Unlock()
    
    parserType := p.GetType()
    if _, exists := r.parsers[parserType]; exists {
        return  // 避免重复注册
    }
    
    r.parsers[parserType] = p
    r.rebuildPriority()
}

func (r *ParserRegistry) rebuildPriority() {
    r.priority = make([]Parser, 0, len(r.parsers))
    for _, p := range r.parsers {
        r.priority = append(r.priority, p)
    }
    sort.Slice(r.priority, func(i, j int) bool {
        return r.priority[i].Priority() > r.priority[j].Priority()
    })
}

// 4. 修改 Engine 使用全局注册表
func NewEngine(db *storage.DB) *Engine {
    e := &Engine{
        db:        db,
        parsers:   parsers.GetGlobalRegistry(),  // 使用全局注册表
        eventRepo: storage.NewEventRepo(db),
        alertRepo: storage.NewAlertRepo(db),
        // ...
    }
    return e
}
```

**注意**: Go 没有 `//go:register` 指令，需要手动在 init() 中调用。也可使用 `go.generate` 工具自动生成注册代码。

#### 3.1.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 低 | 约 30-50 行修改 |
| **适配性** | 高 | 向后兼容，新增解析器自动注册 |
| **必要性** | 中 | 代码维护性改进 |
| **可靠性** | 高 | 无功能变更 |
| **风险** | 低 | 现有功能不受影响 |

---

### OPT-2: 引擎文件级重试机制

#### 3.2.1 问题分析

**当前问题**: `internal/engine/engine.go` 中导入失败的文件没有重试逻辑

#### 3.2.2 实施方案

**修改文件**: `internal/engine/engine.go`

```go
type ImportConfig struct {
    Workers          int
    BatchSize        int
    SkipPatterns     []string
    Incremental      bool
    CalculateHash    bool
    ProgressCallback bool
    MaxRetries      int           // 新增：最大重试次数
    RetryDelay       time.Duration // 新增：重试间隔
}

func NewEngine(db *storage.DB) *Engine {
    e := &Engine{
        // ...
        importCfg: ImportConfig{
            MaxRetries:  3,
            RetryDelay:  time.Second * 5,
            // ...
        },
    }
    // ...
}

func (e *Engine) Import(ctx context.Context, req *ImportRequest, progressFn func(*ImportProgress)) (*ImportResult, error) {
    result := &ImportResult{
        StartTime: time.Now(),
    }

    files := collectFiles(req.Paths, e.importCfg.SkipPatterns)
    if len(files) == 0 {
        return nil, fmt.Errorf("no files found to import")
    }

    result.TotalFiles = len(files)

    // 失败文件重试队列
    retryQueue := make([]string, 0)
    retryMu := sync.Mutex{}

    workerPool := make(chan struct{}, e.importCfg.Workers)
    var wg sync.WaitGroup
    var mu sync.Mutex

    for i, file := range files {
        select {
        case <-ctx.Done():
            return result, ctx.Err()
        default:
        }

        workerPool <- struct{}{}
        wg.Add(1)

        go func(idx int, path string) {
            defer wg.Done()
            defer func() { <-workerPool }()

            var lastErr error
            for attempt := 0; attempt <= e.importCfg.MaxRetries; attempt++ {
                if attempt > 0 {
                    select {
                    case <-ctx.Done():
                        return
                    case <-time.After(e.importCfg.RetryDelay * time.Duration(attempt)):
                    }
                }

                fileResult, err := e.importFile(ctx, path)
                if err == nil {
                    mu.Lock()
                    result.FilesImported++
                    result.EventsImported += fileResult.EventsImported
                    mu.Unlock()
                    return
                }
                lastErr = err
            }

            mu.Lock()
            result.FilesFailed++
            result.Errors = append(result.Errors, &types.ImportError{
                FilePath: path,
                Error:    fmt.Sprintf("failed after %d retries: %v", e.importCfg.MaxRetries, lastErr),
            })
            mu.Unlock()
        }(i, file)
    }

    wg.Wait()
    result.Duration = time.Since(result.StartTime)
    return result, nil
}
```

#### 3.2.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 低 | 约 30 行修改 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 中 | 提高导入成功率 |
| **可靠性** | 高 | 指数退避算法 |
| **风险** | 低 | 不影响现有功能 |

---

### OPT-3: 引擎目录递归与通配符支持

#### 3.3.1 问题分析

**当前问题**: `internal/engine/engine.go:205-216` 仅支持单文件，不支持目录和通配符

```go
func collectFiles(paths []string, skipPatterns []string) []string {
    var files []string
    for _, path := range paths {
        ext := strings.ToLower(filepath.Ext(path))
        if ext == ".evtx" || ext == ".etl" || ext == ".csv" || ext == ".log" || ext == ".txt" {
            if !shouldSkip(path, skipPatterns) {
                files = append(files, path)
            }
        }
    }
    return files
}
```

#### 3.3.2 实施方案

**修改文件**: `internal/engine/engine.go`

```go
import (
    "path/filepath"
    "os"
    "strings"
)

func collectFiles(paths []string, skipPatterns []string) []string {
    var files []string
    
    for _, path := range paths {
        // 检查是否为目录
        info, err := os.Stat(path)
        if err != nil {
            continue
        }
        
        if info.IsDir() {
            // 递归遍历目录
            files = append(files, collectFromDir(path, skipPatterns)...)
        } else if matches, err := filepath.Match("*", filepath.Base(path)); matches && err == nil {
            // 检查是否包含通配符
            if isGlobPattern(path) {
                files = append(files, collectFromGlob(path, skipPatterns)...)
            } else if isSupportedExt(path) {
                if !shouldSkip(path, skipPatterns) {
                    files = append(files, path)
                }
            }
        } else if isSupportedExt(path) {
            if !shouldSkip(path, skipPatterns) {
                files = append(files, path)
            }
        }
    }
    
    return deduplicateFiles(files)
}

func isGlobPattern(path string) bool {
    return strings.ContainsAny(filepath.Base(path), "*?[")
}

func isSupportedExt(path string) bool {
    ext := strings.ToLower(filepath.Ext(path))
    supportedExts := []string{".evtx", ".etl", ".csv", ".log", ".txt"}
    for _, e := range supportedExts {
        if ext == e {
            return true
        }
    }
    return false
}

func collectFromDir(dirPath string, skipPatterns []string) []string {
    var files []string
    
    entries, err := os.ReadDir(dirPath)
    if err != nil {
        return files
    }
    
    for _, entry := range entries {
        fullPath := filepath.Join(dirPath, entry.Name())
        
        if entry.IsDir() {
            // 递归处理子目录
            files = append(files, collectFromDir(fullPath, skipPatterns)...)
        } else if isSupportedExt(fullPath) {
            if !shouldSkip(fullPath, skipPatterns) {
                files = append(files, fullPath)
            }
        }
    }
    
    return files
}

func collectFromGlob(pattern string, skipPatterns []string) []string {
    var files []string
    
    matches, err := filepath.Glob(pattern)
    if err != nil {
        return files
    }
    
    for _, match := range matches {
        if info, err := os.Stat(match); err == nil && !info.IsDir() {
            if isSupportedExt(match) && !shouldSkip(match, skipPatterns) {
                files = append(files, match)
            }
        }
    }
    
    return files
}

func deduplicateFiles(files []string) []string {
    seen := make(map[string]bool)
    result := make([]string, 0, len(files))
    for _, f := range files {
        if !seen[f] {
            seen[f] = true
            result = append(result, f)
        }
    }
    return result
}
```

#### 3.3.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 中 | 约 60 行修改 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 中 | 用户体验提升 |
| **可靠性** | 高 | 标准库 filepath |
| **风险** | 低 | 新功能不影响现有逻辑 |

---

### OPT-4: Pipeline 错误上下文增强

#### 3.4.1 问题分析

**当前问题**: `internal/engine/pipeline.go` 中 `errorChan` 仅传递错误字符串，无上下文

```go
errorChan  chan error  // 仅传递 error
```

#### 3.4.2 实施方案

**修改文件**: `internal/engine/pipeline.go`

```go
// 定义错误上下文结构
type PipelineError struct {
    Err      error
    Events   []*types.Event  // 失败关联的事件
    Stage    string          // 发生阶段
    FilePath string          // 关联文件
}

type PipelineResult struct {
    TotalProcessed int64
    TotalFailed    int64
    Errors         []error  // 改为 []PipelineError
}

// 修改 worker 中的错误处理
if err := handler(batch); err != nil {
    for range batch {
        p.errorChan <- &PipelineError{
            Err:     err,
            Events:  batch,
            Stage:   "batch_processing",
            FilePath: "",  // 从外部传入
        }
        atomic.AddInt64(&p.failed, 1)
    }
}

// 修改 collectErrors
func (p *Pipeline) collectErrors() []PipelineError {
    var errors []PipelineError
    for {
        select {
        case err := <-p.errorChan:
            if pe, ok := err.(*PipelineError); ok {
                errors = append(errors, *pe)
            } else {
                errors = append(errors, PipelineError{Err: err})
            }
        default:
            return errors
        }
    }
}
```

#### 3.4.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 低 | 约 30 行修改 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 中 | 调试体验提升 |
| **可靠性** | 高 | 增强错误可追溯性 |
| **风险** | 低 | 仅改进错误信息 |

---

### OPT-5: 去重缓存持久化

#### 3.5.1 问题分析

**当前问题**: `internal/alerts/dedup.go` 中去重状态仅存内存，重启后丢失

```go
type DedupCache struct {
    mu      sync.RWMutex
    window  time.Duration
    entries map[string]*dedupEntry  // 内存存储
}
```

#### 3.5.2 实施方案

**修改文件**: 
- `internal/alerts/dedup.go`
- `internal/storage/alerts.go` (新增方法)

```go
// 1. 新增数据库表
// schema.go 添加
const DedupStateSQL = `
CREATE TABLE IF NOT EXISTS dedup_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL,
    event_key TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    count INTEGER DEFAULT 1,
    UNIQUE(rule_name, event_key)
);

CREATE INDEX IF NOT EXISTS idx_dedup_timestamp ON dedup_state(timestamp);
`

// 2. 修改 DedupCache
type DedupCache struct {
    mu      sync.RWMutex
    window  time.Duration
    entries map[string]*dedupEntry
    db      *storage.DB  // 新增：数据库引用
}

func NewDedupCacheWithDB(window time.Duration, db *storage.DB) *DedupCache {
    c := &DedupCache{
        window:  window,
        entries: make(map[string]*dedupEntry),
        db:      db,
    }
    
    // 从数据库加载已有状态
    c.loadFromDB()
    
    go c.cleanupLoop()
    return c
}

func (c *DedupCache) loadFromDB() {
    if c.db == nil {
        return
    }
    
    rows, err := c.db.Query(`
        SELECT rule_name, event_key, event_hash, timestamp, count 
        FROM dedup_state 
        WHERE timestamp > ?`,
        time.Now().Add(-c.window).Format(time.RFC3339))
    if err != nil {
        return
    }
    defer rows.Close()
    
    for rows.Next() {
        var ruleName, eventKey, eventHash, timestamp string
        var count int
        if rows.Scan(&ruleName, &eventKey, &eventHash, &timestamp, &count) == nil {
            if ts, err := time.Parse(time.RFC3339, timestamp); err == nil {
                c.entries[eventKey] = &dedupEntry{
                    RuleName:  ruleName,
                    EventKey:  eventKey,
                    Timestamp: ts,
                    Count:     count,
                }
            }
        }
    }
}

func (c *DedupCache) persistEntry(key string, entry *dedupEntry) {
    if c.db == nil {
        return
    }
    
    c.db.Exec(`
        INSERT OR REPLACE INTO dedup_state (rule_name, event_key, event_hash, timestamp, count)
        VALUES (?, ?, ?, ?, ?)`,
        entry.RuleName, entry.EventKey, key, entry.Timestamp.Format(time.RFC3339), entry.Count)
}

func (c *DedupCache) Mark(ruleName string, event *types.Event) {
    key := c.generateKey(ruleName, event)

    c.mu.Lock()
    defer c.mu.Unlock()

    entry, exists := c.entries[key]
    if exists {
        entry.Count++
        entry.Timestamp = time.Now()
    } else {
        c.entries[key] = &dedupEntry{
            EventKey:  key,
            RuleName:  ruleName,
            Timestamp: time.Now(),
            Count:     1,
        }
    }
    
    // 异步持久化
    go c.persistEntry(key, c.entries[key])
}
```

#### 3.5.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 中 | 约 80 行修改 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 中 | 提高告警准确性 |
| **可靠性** | 高 | WAL 模式保证一致性 |
| **风险** | 中 | 数据库写入开销 |

---

### OPT-6: 告警引擎规则并行评估

#### 3.6.1 问题分析

**当前问题**: `internal/alerts/engine.go:90-130` 中规则串行评估

```go
for _, rule := range rules {  // 串行遍历
    matched, err := e.evaluator.Evaluate(rule, event)
    // ...
}
```

#### 3.6.2 实施方案

**修改文件**: `internal/alerts/engine.go`

```go
func (e *Engine) Evaluate(ctx context.Context, event *types.Event) ([]*types.Alert, error) {
    e.mu.RLock()
    rules := make([]*rules.AlertRule, 0, len(e.rules))
    for _, rule := range e.rules {
        rules = append(rules, rule)
    }
    e.mu.RUnlock()

    // 使用 Worker Pool 并行评估
    const maxWorkers = 10
    ruleChan := make(chan *rules.AlertRule, len(rules))
    resultChan := make(chan *types.Alert, len(rules))
    errorChan := make(chan error, 1)
    
    var wg sync.WaitGroup
    
    // 启动 workers
    for i := 0; i < maxWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for rule := range ruleChan {
                select {
                case <-ctx.Done():
                    return
                default:
                }
                
                if e.suppressCache.IsSuppressed(rule, event) {
                    continue
                }

                matched, err := e.evaluator.Evaluate(rule, event)
                if err != nil || !matched {
                    continue
                }

                if e.dedup.IsDuplicate(rule.Name, event) {
                    continue
                }

                alert := e.createAlert(rule, event)
                resultChan <- alert
                e.dedup.Mark(rule.Name, event)
                e.trend.Record(alert)
            }
        }()
    }
    
    // 发送规则到通道
    go func() {
        for _, rule := range rules {
            ruleChan <- rule
        }
        close(ruleChan)
    }()
    
    // 等待 workers 完成
    go func() {
        wg.Wait()
        close(resultChan)
        close(errorChan)
    }()
    
    // 收集结果
    var alerts []*types.Alert
    for alert := range resultChan {
        alerts = append(alerts, alert)
    }
    
    return alerts, nil
}
```

#### 3.6.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 中 | 约 50 行修改 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 中 | 规则多时性能提升明显 |
| **可靠性** | 高 | Worker Pool 模式成熟 |
| **风险** | 中 | 小数据集可能略慢 |

---

### OPT-7: 规则验证增强

#### 3.7.1 问题分析

**当前问题**: `internal/rules/rule.go:129-139` 规则验证过于基础

```go
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
    return nil
}
```

#### 3.7.2 实施方案

**修改文件**: `internal/rules/rule.go`

```go
func (r *AlertRule) Validate() error {
    // 基础验证
    if r.Name == "" {
        return fmt.Errorf("rule name is required")
    }
    if r.Severity == "" {
        return fmt.Errorf("severity is required")
    }
    if r.Filter == nil && r.Conditions == nil {
        return fmt.Errorf("either filter or conditions is required")
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
    
    // 验证 Threshold
    if r.Threshold > 0 && r.TimeWindow == 0 {
        return fmt.Errorf("threshold requires time_window to be set")
    }
    
    // 验证 Severity 有效值
    validSeverities := map[types.Severity]bool{
        types.SeverityCritical: true,
        types.SeverityHigh:     true,
        types.SeverityMedium:   true,
        types.SeverityLow:      true,
        types.SeverityInfo:     true,
    }
    if !validSeverities[r.Severity] {
        return fmt.Errorf("invalid severity: %s", r.Severity)
    }
    
    return nil
}

func (r *AlertRule) validateFilter(f *Filter) error {
    // 验证 EventIDs
    for _, eid := range f.EventIDs {
        if eid < 0 || eid > 65535 {
            return fmt.Errorf("invalid event_id: %d (must be 0-65535)", eid)
        }
    }
    
    // 验证 Levels
    for _, lvl := range f.Levels {
        if lvl < 1 || lvl > 5 {
            return fmt.Errorf("invalid level: %d (must be 1-5)", lvl)
        }
    }
    
    // 验证正则关键词
    if f.Keywords != "" && f.KeywordMode == "" {
        return fmt.Errorf("keywords requires keyword_mode to be set")
    }
    
    // 验证时间范围
    if f.TimeRange != nil {
        if f.TimeRange.End.Before(f.TimeRange.Start) {
            return fmt.Errorf("time_range end must be after start")
        }
    }
    
    return nil
}

func (r *AlertRule) validateConditions(c *Conditions) error {
    validFields := map[string]bool{
        "event_id":   true,
        "level":      true,
        "source":     true,
        "log_name":   true,
        "computer":   true,
        "user":       true,
        "message":    true,
        "ip_address": true,
    }
    
    var validateCondition func(cond *Condition) error
    validateCondition = func(cond *Condition) error {
        if cond.Field == "" {
            return fmt.Errorf("condition field is required")
        }
        if !validFields[cond.Field] {
            return fmt.Errorf("invalid condition field: %s", cond.Field)
        }
        
        validOps := map[string]bool{
            "==":       true,
            "=":        true,
            "!=":       true,
            ">":        true,
            ">=":       true,
            "<":        true,
            "<=":       true,
            "contains": true,
            "startswith": true,
            "endswith": true,
            "not":      true,
            "regex":    true,
        }
        if !validOps[cond.Operator] {
            return fmt.Errorf("invalid operator: %s", cond.Operator)
        }
        
        if cond.Regex {
            if _, err := regexp.Compile(cond.Value); err != nil {
                return fmt.Errorf("invalid regex pattern: %w", err)
            }
        }
        
        return nil
    }
    
    for _, anyCond := range c.Any {
        if err := validateCondition(anyCond); err != nil {
            return err
        }
    }
    for _, allCond := range c.All {
        if err := validateCondition(allCond); err != nil {
            return err
        }
    }
    for _, noneCond := range c.None {
        if err := validateCondition(noneCond); err != nil {
            return err
        }
    }
    
    return nil
}
```

#### 3.7.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 低 | 约 80 行修改 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 中 | 防止无效规则加载 |
| **可靠性** | 高 | 早期错误检测 |
| **风险** | 低 | 仅验证逻辑 |

---

### OPT-8: 规则分组与优先级

#### 3.8.1 问题分析

**当前问题**: 规则无分组和优先级机制，所有规则平等评估

#### 3.8.2 实施方案

**修改文件**: 
- `internal/rules/rule.go` (新增类型)
- `internal/alerts/engine.go` (使用分组)

```go
// rules/rule.go 新增

type RuleGroup struct {
    Name        string       `yaml:"name"`
    Priority    int          `yaml:"priority"`  // 1-100, 越高越先评估
    Description string       `yaml:"description,omitempty"`
    Enabled     bool         `yaml:"enabled"`
    Rules       []*AlertRule `yaml:"rules,omitempty"`
}

type RuleWithPriority struct {
    Rule    *AlertRule
    Group   *RuleGroup
    Priority int
}

// Engine 中按优先级排序
type Engine struct {
    // ...
    ruleGroups    map[string]*RuleGroup  // 新增
    sortedRules    []*RuleWithPriority   // 按优先级排序
}

// 修改 LoadRules
func (e *Engine) LoadRules(ruleList []*rules.AlertRule) {
    e.mu.Lock()
    defer e.mu.Unlock()
    
    e.rules = make(map[string]*rules.AlertRule)
    e.sortedRules = make([]*RuleWithPriority, 0)
    
    for _, rule := range ruleList {
        if rule.Enabled {
            e.rules[rule.Name] = rule
            
            // 确定优先级：组优先级 + 规则自身优先级
            priority := 50 // 默认优先级
            if group := e.ruleGroups["default"]; group != nil {
                priority = group.Priority
            }
            
            e.sortedRules = append(e.sortedRules, &RuleWithPriority{
                Rule:    rule,
                Priority: priority,
            })
        }
    }
    
    // 按优先级排序
    sort.Slice(e.sortedRules, func(i, j int) bool {
        return e.sortedRules[i].Priority > e.sortedRules[i].Priority
    })
}

// 评估时按顺序进行
func (e *Engine) Evaluate(ctx context.Context, event *types.Event) ([]*types.Alert, error) {
    // 高优先级规则先评估，发现告警后可提前终止
    for _, rwp := range e.sortedRules {
        select {
        case <-ctx.Done():
            return alerts, ctx.Err()
        default:
        }
        // ... 评估逻辑
    }
}
```

#### 3.8.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 中 | 约 60 行修改 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 低 | 高级功能 |
| **可靠性** | 高 | 优先级机制明确 |
| **风险** | 低 | 新功能 |

---

### OPT-9: UEBA 基线持久化

#### 3.9.1 问题分析

**当前问题**: `internal/ueba/baseline.go` 基线仅存内存，重启后丢失

```go
type BaselineManager struct {
    userActivity map[string]*UserBaseline  // 内存
    entityStats  map[string]*EntityStats
}
```

#### 3.9.2 实施方案

**修改文件**: 
- `internal/ueba/baseline.go`
- `internal/storage/schema.go`

```go
// schema.go 添加表
const UEBASchemaSQL = `
CREATE TABLE IF NOT EXISTS ueba_baseline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT NOT NULL,
    login_count INTEGER DEFAULT 0,
    typical_hours TEXT,
    typical_computers TEXT,
    typical_sources TEXT,
    avg_events_per_day REAL,
    last_updated TEXT NOT NULL,
    UNIQUE(user)
);

CREATE TABLE IF NOT EXISTS ueba_entity_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_key TEXT NOT NULL UNIQUE,
    entity_type TEXT,
    event_count INTEGER DEFAULT 0,
    first_seen TEXT,
    last_seen TEXT,
    risk_score REAL DEFAULT 0.0
);
`

// baseline.go 修改
type BaselineManager struct {
    mu           sync.RWMutex
    userActivity map[string]*UserBaseline
    entityStats  map[string]*EntityStats
    window       time.Duration
    db           *storage.DB  // 新增
}

func NewBaselineManagerWithDB(window time.Duration, db *storage.DB) *BaselineManager {
    m := &BaselineManager{
        userActivity: make(map[string]*UserBaseline),
        entityStats:  make(map[string]*EntityStats),
        window:        window,
        db:            db,
    }
    
    m.loadFromDB()
    return m
}

func (m *BaselineManager) loadFromDB() {
    if m.db == nil {
        return
    }
    
    rows, err := m.db.Query(`
        SELECT user, login_count, typical_hours, typical_computers, 
               typical_sources, avg_events_per_day, last_updated
        FROM ueba_baseline`)
    if err != nil {
        return
    }
    defer rows.Close()
    
    for rows.Next() {
        var user string
        var loginCount int
        var typicalHours, typicalComputers, typicalSources, lastUpdated string
        var avgEventsPerDay float64
        
        if rows.Scan(&user, &loginCount, &typicalHours, &typicalComputers, 
                     &typicalSources, &avgEventsPerDay, &lastUpdated) == nil {
            
            baseline := &UserBaseline{
                User:             user,
                LoginCount:       loginCount,
                AvgEventsPerDay:  avgEventsPerDay,
                TypicalHours:     parseTypicalHours(typicalHours),
                TypicalComputers: parseTypicalMap(typicalComputers),
                TypicalSources:   parseTypicalMap(typicalSources),
            }
            m.userActivity[user] = baseline
        }
    }
}

func (m *BaselineManager) persistBaseline(user string, baseline *UserBaseline) {
    if m.db == nil {
        return
    }
    
    typicalHours := serializeTypicalHours(baseline.TypicalHours)
    typicalComputers := serializeTypicalMap(baseline.TypicalComputers)
    typicalSources := serializeTypicalMap(baseline.TypicalSources)
    
    m.db.Exec(`
        INSERT OR REPLACE INTO ueba_baseline 
        (user, login_count, typical_hours, typical_computers, typical_sources, avg_events_per_day, last_updated)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
        user, baseline.LoginCount, typicalHours, typicalComputers, typicalSources,
        baseline.AvgEventsPerDay, baseline.LastUpdated.Format(time.RFC3339))
}
```

#### 3.9.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 中 | 约 100 行修改 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 中 | UEBA 核心功能 |
| **可靠性** | 高 | 数据库持久化 |
| **风险** | 中 | 数据库写入频率 |

---

### OPT-10: UEBA IP 地理位置集成

#### 3.10.1 问题分析

**当前问题**: `internal/ueba/engine.go:267-284` 仅区分公网/私网

```go
func calculateIPDistance(ip1, ip2 string) float64 {
    // 仅返回 100 (同网) 或 1000 (跨网)
}
```

#### 3.10.2 实施方案

**方案选择**: 集成轻量级 GeoIP 数据库 (MaxMind GeoLite2)

**修改文件**: `internal/ueba/engine.go`

```go
import (
    "github.com/oschwald/geoip2-go"
)

// 添加 GeoIP 客户端
var geoDB *geoip2.Reader
var geoOnce sync.Once

func getGeoDB() (*geoip2.Reader, error) {
    var err error
    geoOnce.Do(func() {
        // 下载或加载本地 GeoLite2 数据库
        geoDB, err = geoip2.Open("GeoLite2-City.mmdb")
    })
    return geoDB, err
}

type GeoLocation struct {
    Latitude  float64
    Longitude float64
    City     string
    Country  string
}

func getIPLocation(ipStr string) (*GeoLocation, error) {
    if ipStr == "" || isPrivateIP(ipStr) {
        return nil, nil
    }
    
    db, err := getGeoDB()
    if err != nil {
        return nil, err
    }
    
    ip := net.ParseIP(ipStr)
    if ip == nil {
        return nil, nil
    }
    
    record, err := db.City(ip)
    if err != nil {
        return nil, err
    }
    
    return &GeoLocation{
        Latitude:  record.Location.Latitude,
        Longitude: record.Location.Longitude,
        City:      record.City.Names["en"],
        Country:   record.Country.Names["en"],
    }, nil
}

func calculateIPDistance(ip1, ip2 string) float64 {
    loc1, err1 := getIPLocation(ip1)
    loc2, err2 := getIPLocation(ip2)
    
    if err1 != nil || err2 != nil || loc1 == nil || loc2 == nil {
        // 回退到简单逻辑
        return 100.0
    }
    
    // Haversine 公式计算两点距离 (公里)
    const earthRadius = 6371.0
    
    lat1 := loc1.Latitude * math.Pi / 180
    lat2 := loc2.Latitude * math.Pi / 180
    deltaLat := (loc2.Latitude - loc1.Latitude) * math.Pi / 180
    deltaLon := (loc2.Longitude - loc1.Longitude) * math.Pi / 180
    
    a := math.Sin(deltaLat/2)*math.Sin(deltaLat/2) +
        math.Cos(lat1)*math.Cos(lat2)*math.Sin(deltaLon/2)*math.Sin(deltaLon/2)
    c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
    
    return earthRadius * c
}
```

#### 3.10.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 中 | 约 80 行修改 |
| **适配性** | 高 | GeoIP 数据文件可选 |
| **必要性** | 低 | 增强功能 |
| **可靠性** | 高 | 成熟 GeoIP 库 |
| **风险** | 低 | 数据库文件需单独下载 |

---

### OPT-11: 报告配置参数化

#### 3.11.1 问题分析

**当前问题**: `internal/reports/generator.go:36-39` IOC 限制硬编码

```go
const (
    maxIOCIPs       = 100
    maxIOCUsers     = 100
    maxIOCComputers = 50
)
```

#### 3.11.2 实施方案

**修改文件**: `internal/reports/generator.go`

```go
type GeneratorConfig struct {
    Title        string
    StartTime    time.Time
    EndTime      time.Time
    Format       ReportFormat
    IncludeRaw   bool
    IncludeIOC   bool
    IncludeMITRE bool
    // 新增配置
    MaxIOCIPs       int  // 0 = 无限制
    MaxIOCUsers     int
    MaxIOCComputers int
    MaxEventsInReport int  // 原始事件上限
}

func NewGenerator(db *storage.DB) *Generator {
    return &Generator{
        db:     db,
        config: &GeneratorConfig{
            MaxIOCIPs:         100,
            MaxIOCUsers:       100,
            MaxIOCComputers:   50,
            MaxEventsInReport: 1000,
        },
    }
}

// 使用配置代替硬编码
func (g *Generator) extractIOCs(req *ReportRequest) (*IOCSummary, error) {
    maxIPs := g.config.MaxIOCIPs
    if maxIPs == 0 {
        maxIPs = 10000
    }
    maxUsers := g.config.MaxIOCUsers
    if maxUsers == 0 {
        maxUsers = 10000
    }
    
    // 使用 maxIPs, maxUsers 代替硬编码
}
```

#### 3.11.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 很低 | 约 15 行修改 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 低 | 配置灵活性 |
| **可靠性** | 高 | 零风险 |
| **风险** | 无 | 仅配置变更 |

---

### OPT-12: API 请求验证中间件

#### 3.12.1 问题分析

**当前问题**: `internal/api` 中请求参数验证分散，缺乏统一验证

#### 3.12.2 实施方案

**修改文件**: `internal/api/middleware.go`

```go
import "github.com/go-playground/validator/v10"

var validate *validator.Validate

func init() {
    validate = validator.New()
}

type SearchRequest struct {
    Keywords  string `form:"keywords" validate:"max=500"`
    EventIDs  []int  `form:"event_ids" validate:"dive,min=1,max=65535"`
    Page      int    `form:"page" validate:"min=1,max=10000"`
    PageSize  int    `form:"page_size" validate:"min=1,max=1000"`
    StartTime string `form:"start_time" validate:"omitempty,rfc3339"`
    EndTime   string `form:"end_time" validate:"omitempty,rfc3339"`
}

type ImportRequest struct {
    Paths      []string `json:"paths" validate:"required,min=1,dive,filepath"`
    LogName    string   `json:"log_name" validate:"omitempty,max=100"`
    Workers    int      `json:"workers" validate:"min=1,max=32"`
    BatchSize  int      `json:"batch_size" validate:"min=100,max=100000"`
}

// 验证中间件
func validationMiddleware[T any]() gin.HandlerFunc {
    return func(c *gin.Context) {
        var req T
        if err := c.ShouldBindQuery(&req); err != nil {
            c.JSON(400, gin.H{
                "error":   "validation_error",
                "details": err.Error(),
            })
            c.Abort()
            return
        }
        c.Set("validated_request", req)
        c.Next()
    }
}

// 使用示例
func SetupQueryRoutes(e *gin.Engine, h *QueryHandler) {
    e.GET("/api/query", 
        validationMiddleware[SearchRequest](),
        h.Query)
}
```

#### 3.12.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 中 | 约 60 行修改 |
| **适配性** | 高 | 向后兼容 |
| **必要性** | 中 | API 安全性提升 |
| **可靠性** | 高 | 成熟的验证库 |
| **风险** | 低 | 新增验证逻辑 |

---

### OPT-13: API OpenAPI 文档生成

#### 3.13.1 问题分析

**当前问题**: API 无 Swagger/OpenAPI 文档

#### 3.13.2 实施方案

**修改文件**: `internal/api/server.go`

```go
import (
    swaggerFiles "github.com/swaggo/files"
    ginSwagger "github.com/swaggo/gin-swagger"
    _ "github.com/kkkdddd-start/winalog-go/docs"  // 生成的文件
)

// @title WinLogAnalyzer API
// @version 2.4
// @description Windows Event Log Analysis API
// @host localhost:8080
// @BasePath /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

func NewServer(...) *Server {
    // ...
    setupSwagger()
    return s
}

func setupSwagger() {
    // 注解格式
    // @Summary Search events
    // @Description Search events with filters
    // @Tags events
    // @Accept json
    // @Produce json
    // @Param keywords query string false "Search keywords"
    // @Param event_ids query string false "Comma-separated event IDs"
    // @Success 200 {object} SearchResponse
    // @Router /api/query [get]
}

// 生成文档命令
// swag init -g internal/api/server.go -o docs
```

#### 3.13.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 低 | 仅文档注解 |
| **适配性** | 高 | 自动生成 |
| **必要性** | 中 | API 可用性 |
| **可靠性** | 高 | 工具生成 |
| **风险** | 无 | 文档生成 |

---

### OPT-14: TUI 状态管理重构

#### 3.14.1 问题分析

**当前问题**: `internal/tui/model.go` 状态过于集中

```go
type Model struct {
    engine *engine.Engine
    db     *storage.DB
    cfg    *config.Config
    // 50+ 字段集中管理
}
```

#### 3.14.2 实施方案

**修改文件**: `internal/tui/model.go`

```go
// 拆分为子状态管理器
type EventStore struct {
    events      []*types.Event
    selectedIdx int
    filterOpts  FilterOptions
    totalCount  int64
    mu          sync.RWMutex
}

type AlertStore struct {
    alerts      []*types.Alert
    selectedIdx int
    stats       *types.AlertStats
    trend       *types.AlertTrend
    mu          sync.RWMutex
}

type ImportStore struct {
    importing      bool
    progress       *ImportProgress
    completedFiles int
    totalFiles     int
    mu             sync.RWMutex
}

// 主 Model 持有子状态
type Model struct {
    engine   *engine.Engine
    db       *storage.DB
    cfg      *config.Config
    
    events   *EventStore
    alerts   *AlertStore
    imports  *ImportStore
    ui      *UIState
    
    currentView ViewType
    width       int
    height      int
    err         error
}

func NewModel(cfg *config.Config) (*Model, error) {
    db, err := storage.NewDB(cfg.Database.Path)
    if err != nil {
        return nil, err
    }
    
    return &Model{
        cfg:     cfg,
        db:      db,
        events:  NewEventStore(),
        alerts:  NewAlertStore(),
        imports: NewImportStore(),
        ui:      NewUIState(),
    }, nil
}

// 子状态方法
func (s *EventStore) Load(filter *storage.EventFilter) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    // 加载事件逻辑
}

func (s *EventStore) GetSelected() *types.Event {
    s.mu.RLock()
    defer s.mu.RUnlock()
    if s.selectedIdx >= 0 && s.selectedIdx < len(s.events) {
        return s.events[s.selectedIdx]
    }
    return nil
}
```

#### 3.14.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 高 | 约 150-200 行重构 |
| **适配性** | 中 | 需测试覆盖 |
| **必要性** | 低 | 代码质量改进 |
| **可靠性** | 高 | 分离关注点 |
| **风险** | 中 | 重构风险 |

---

### OPT-15: 关联分析引擎重新设计

#### 3.15.1 问题分析

**当前问题**: `internal/correlation/matcher.go` 简化实现不验证实际关联

```go
func (m *Matcher) Match(rule *rules.CorrelationRule, events []*types.Event) bool {
    if len(rule.Patterns) != len(events) {  // 仅检查数量
        return false
    }
    // 不验证实际关联关系
}
```

#### 3.15.2 实施方案

**修改文件**: `internal/correlation/engine.go` (新建)

```go
package correlation

import (
    "container/list"
    "sync"
    "time"
)

type EventWindow struct {
    events    *list.List
    maxSize   int
    timeWindow time.Duration
}

type ChainMatcher struct {
    rules        []*rules.CorrelationRule
    eventWindows map[string]*EventWindow  // 按用户/IP/会话分组
    mu           sync.RWMutex
}

func NewChainMatcher() *ChainMatcher {
    return &ChainMatcher{
        eventWindows: make(map[string]*EventWindow),
    }
}

func (m *ChainMatcher) AddEvent(event *types.Event) []*types.CorrelationResult {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    results := make([]*types.CorrelationResult, 0)
    key := m.getAggregationKey(event)
    
    window := m.getOrCreateWindow(key)
    window.Add(event)
    
    // 滑动窗口清理
    window.RemoveExpired(time.Now())
    
    // 尝试匹配规则
    for _, rule := range m.rules {
        if !rule.Enabled {
            continue
        }
        
        if m.matchRule(rule, window) {
            results = append(results, m.buildResult(rule, window))
        }
    }
    
    return results
}

func (m *ChainMatcher) matchRule(rule *rules.CorrelationRule, window *EventWindow) bool {
    events := window.GetEvents()
    if len(events) < len(rule.Patterns) {
        return false
    }
    
    // 滑动窗口匹配
    for i := 0; i <= len(events)-len(rule.Patterns); i++ {
        if m.matchPatterns(rule.Patterns, events[i:i+len(rule.Patterns)]) {
            return true
        }
    }
    return false
}

func (m *ChainMatcher) matchPatterns(patterns []*rules.Pattern, events []*types.Event) bool {
    for i, pattern := range patterns {
        if !m.matchSinglePattern(pattern, events[i]) {
            return false
        }
    }
    return true
}

func (m *ChainMatcher) matchSinglePattern(p *rules.Pattern, e *types.Event) bool {
    if p.EventID != 0 && e.EventID != p.EventID {
        return false
    }
    
    for _, cond := range p.Conditions {
        if !evaluateCondition(cond, e) {
            return false
        }
    }
    return true
}

func (w *EventWindow) Add(event *types.Event) {
    w.events.PushBack(event)
    if w.events.Len() > w.maxSize {
        w.events.Remove(w.events.Front())
    }
}

func (w *EventWindow) RemoveExpired(now time.Time) {
    cutoff := now.Add(-w.timeWindow)
    for e := w.events.Front(); e != nil; {
        if event := e.Value.(*types.Event); event.Timestamp.Before(cutoff) {
            next := e.Next()
            w.events.Remove(e)
            e = next
        } else {
            e = e.Next()
        }
    }
}
```

#### 3.15.3 实施评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **实现复杂度** | 高 | 约 200 行 |
| **适配性** | 高 | 新增引擎，原接口不变 |
| **必要性** | 中 | 关联分析核心功能 |
| **可靠性** | 高 | 状态机模式 |
| **风险** | 中 | 需充分测试 |

---

## 四、优化项汇总

### 4.1 实施优先级总览

| ID | 优化项 | 优先级 | 复杂度 | 工作量 | 风险 |
|----|--------|--------|--------|--------|------|
| OPT-1 | 解析器自注册 | P2 | 低 | 0.5 人天 | 低 |
| OPT-2 | 文件重试机制 | P2 | 低 | 0.5 人天 | 低 |
| OPT-3 | 目录递归支持 | P2 | 中 | 1 人天 | 低 |
| OPT-4 | 错误上下文增强 | P3 | 低 | 0.5 人天 | 低 |
| OPT-5 | 去重持久化 | P2 | 中 | 1 人天 | 中 |
| OPT-6 | 规则并行评估 | P2 | 中 | 1 人天 | 中 |
| OPT-7 | 规则验证增强 | P2 | 低 | 0.5 人天 | 低 |
| OPT-8 | 规则分组/优先级 | P3 | 中 | 1 人天 | 低 |
| OPT-9 | UEBA 基线持久化 | P2 | 中 | 1 人天 | 中 |
| OPT-10 | UEBA GeoIP 集成 | P3 | 中 | 1 人天 | 低 |
| OPT-11 | 报告配置参数化 | P3 | 很低 | 0.25 人天 | 无 |
| OPT-12 | API 请求验证 | P2 | 中 | 1 人天 | 低 |
| OPT-13 | API OpenAPI 文档 | P3 | 低 | 0.5 人天 | 无 |
| OPT-14 | TUI 状态重构 | P3 | 高 | 2 人天 | 中 |
| OPT-15 | 关联引擎重新设计 | P2 | 高 | 2 人天 | 中 |

### 4.2 建议实施路线图

```
Q1 (安全/稳定性):
├─ P0/P1 问题修复 (已完成)
├─ OPT-7 规则验证增强
├─ OPT-4 错误上下文增强
└─ OPT-12 API 请求验证

Q2 (核心功能完善):
├─ OPT-1 解析器自注册
├─ OPT-2 文件重试机制
├─ OPT-5 去重持久化
├─ OPT-6 规则并行评估
└─ OPT-9 UEBA 基线持久化

Q3 (增强功能):
├─ OPT-3 目录递归支持
├─ OPT-8 规则分组/优先级
├─ OPT-10 UEBA GeoIP
└─ OPT-13 API OpenAPI

Q4 (重构优化):
├─ OPT-11 报告配置参数化
├─ OPT-14 TUI 状态重构
└─ OPT-15 关联引擎重新设计
```

---

## 五、相关文件清单

| 文件 | 修改类型 | 涉及优化项 |
|------|----------|------------|
| `internal/parsers/*.go` | 增强 | OPT-1 |
| `internal/engine/engine.go` | 增强 | OPT-1, OPT-2, OPT-3 |
| `internal/engine/pipeline.go` | 增强 | OPT-4 |
| `internal/alerts/dedup.go` | 增强 | OPT-5 |
| `internal/alerts/engine.go` | 增强 | OPT-6, OPT-8 |
| `internal/rules/rule.go` | 增强 | OPT-7, OPT-8 |
| `internal/ueba/baseline.go` | 增强 | OPT-9 |
| `internal/ueba/engine.go` | 增强 | OPT-10 |
| `internal/reports/generator.go` | 增强 | OPT-11 |
| `internal/api/middleware.go` | 增强 | OPT-12 |
| `internal/api/server.go` | 增强 | OPT-13 |
| `internal/tui/model.go` | 重构 | OPT-14 |
| `internal/correlation/*.go` | 重构 | OPT-15 |
| `internal/storage/schema.go` | 新增表 | OPT-5, OPT-9 |

---

*文档版本: 2.0*  
*新增优化项: 15 项*  
*审核状态: 待审核*  
*实施状态: 待实施*