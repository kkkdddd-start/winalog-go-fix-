# Alerts 模块

**路径**: `internal/alerts/`

告警引擎，负责规则评估、去重、统计和告警管理。

## 核心组件

### Engine

```go
type Engine struct {
    db            *storage.DB
    alertRepo     *storage.AlertRepo
    dedup         *DedupCache
    evaluator     *Evaluator
    stats         *AlertStats
    trend         *AlertTrend
    upgradeRules  *AlertUpgradeCache
    suppressCache *SuppressCache
    mu            sync.RWMutex
    rules         map[string]*rules.AlertRule
}

type EngineConfig struct {
    DedupWindow time.Duration  // 默认 5 分钟
    StatsWindow time.Duration   // 默认 24 小时
}

func NewEngine(db *storage.DB, cfg EngineConfig) *Engine
```

## 评估流程

```
┌─────────────────────────────────────────────────────────┐
│                    Evaluate(event)                       │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│              1. 检查抑制 (SuppressCache)                 │
│                 IsSuppressed(rule, event)              │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│              2. 规则评估 (Evaluator)                    │
│                 Evaluate(rule, event)                   │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│              3. 去重检查 (DedupCache)                  │
│                 IsDuplicate(rule.Name, event)           │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│              4. 创建告警                                 │
│                 createAlert(rule, event)               │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│              5. 记录去重标记                            │
│                 dedup.Mark(rule.Name, event)           │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│              6. 记录趋势                                │
│                 trend.Record(alert)                     │
└─────────────────────────────────────────────────────────┘
```

## DedupCache (去重)

基于时间窗口的去重机制。

```go
type DedupCache struct {
    window time.Duration
    marks  map[string]map[string]time.Time  // ruleName -> eventKey -> timestamp
    mu     sync.RWMutex
}

func NewDedupCache(window time.Duration) *DedupCache

// 检查是否重复
func (c *DedupCache) IsDuplicate(ruleName string, event *types.Event) bool

// 标记已处理
func (c *DedupCache) Mark(ruleName string, event *types.Event)

// 清理过期条目
func (c *DedupCache) Clean()

// 清除所有
func (c *DedupCache) Clear()
```

**eventKey 生成**:
```go
func eventKey(event *types.Event) string {
    return fmt.Sprintf("%d:%s:%s:%s", 
        event.EventID, event.Computer, ptrStr(event.User), ptrStr(event.IPAddress))
}
```

## Evaluator (规则评估)

```go
type Evaluator struct{}

func NewEvaluator() *Evaluator

// 评估单个规则
func (e *Evaluator) Evaluate(rule *rules.AlertRule, event *types.Event) (bool, error)
```

**评估逻辑**:

```go
func (e *Evaluator) Evaluate(rule *rules.AlertRule, event *types.Event) (bool, error) {
    // 1. 检查 Filter
    if rule.Filter != nil {
        if !matchFilter(rule.Filter, event) {
            return false, nil
        }
    }
    
    // 2. 检查 Conditions
    if rule.Conditions != nil {
        if !evaluateConditions(rule.Conditions, event) {
            return false, nil
        }
    }
    
    return true, nil
}
```

## AlertStats (统计)

```go
type AlertStats struct {
    Total       int64
    BySeverity  map[string]int64
    ByRule      map[string]int64
    ByHour      map[int]int64
    LastUpdated time.Time
}

func NewAlertStats() *AlertStats
func (s *AlertStats) CopyFrom(other *AlertStats)
```

## AlertTrend (趋势)

```go
type AlertTrend struct {
    window  time.Duration
    entries []*TrendEntry  // 按时间排序
    mu      sync.RWMutex
}

type TrendEntry struct {
    Timestamp time.Time
    Count     int
    Severity  string
}

func NewAlertTrend(window time.Duration) *AlertTrend
func (t *AlertTrend) Record(alert *types.Alert)
func (t *AlertTrend) GetHourly() []HourlyCount
func (t *AlertTrend) GetDaily() []DailyCount
```

## AlertUpgradeCache (告警升级)

低频告警升级为高频告警时自动提升严重级别。

```go
type AlertUpgradeRule struct {
    RuleName         string
    Threshold        int       // 触发次数
    NewSeverity      string    // 新严重级别
    TimeWindow       time.Duration
}

type AlertUpgradeCache struct {
    rules    map[string]*AlertUpgradeRule
    counters map[string]*UpgradeCounter  // ruleName -> count
}

func (c *AlertUpgradeCache) Check(alert *types.Alert) (bool, *AlertUpgradeRule)
```

## SuppressCache (抑制)

满足条件的告警被抑制，不生成。

```go
type SuppressRule struct {
    RuleName   string
    Filter     *rules.Filter
    Until      time.Time
    Count      int
}

type SuppressCache struct {
    rules []SuppressRule
    mu    sync.RWMutex
}

func (c *SuppressCache) IsSuppressed(rule *rules.AlertRule, event *types.Event) bool
func (c *SuppressCache) Add(rule *SuppressRule)
func (c *SuppressCache) Clear()
```

## 规则管理

```go
// 加载规则列表
func (e *Engine) LoadRules(ruleList []*rules.AlertRule)

// 添加单个规则
func (e *Engine) AddRule(rule *rules.AlertRule)

// 移除规则
func (e *Engine) RemoveRule(name string)

// 获取所有规则
func (e *Engine) GetRules() []*rules.AlertRule
```

## 批量评估

```go
func (e *Engine) EvaluateBatch(ctx context.Context, events []*types.Event) ([]*types.Alert, error)
```

**实现**: 使用 goroutine 并行评估，结果通过 channel 收集。

```go
alertChan := make(chan *types.Alert, len(events))
errChan := make(chan error, 1)
var wg sync.WaitGroup

for _, event := range events {
    wg.Add(1)
    go func(evt *types.Event) {
        defer wg.Done()
        // 评估逻辑...
        if matched {
            alertChan <- alert
        }
    }(event)
}

go func() {
    wg.Wait()
    close(alertChan)
    close(errChan)
}()

var alerts []*types.Alert
for alert := range alertChan {
    alerts = append(alerts, alert)
}
```

## 告警管理

```go
// 保存告警
func (e *Engine) SaveAlert(alert *types.Alert) error
func (e *Engine) SaveAlerts(alerts []*types.Alert) error

// 获取告警
func (e *Engine) GetAlert(id int64) (*types.Alert, error)
func (e *Engine) GetAlerts(filter *storage.AlertFilter) ([]*types.Alert, error)

// 解决告警
func (e *Engine) ResolveAlert(id int64, notes string) error

// 删除告警
func (e *Engine) DeleteAlert(id int64) error

// 标记误报
func (e *Engine) MarkFalsePositive(id int64) error
```

## 使用示例

```go
// 创建告警引擎
alertEng := alerts.NewEngine(db, alerts.EngineConfig{
    DedupWindow: 5 * time.Minute,
    StatsWindow: 24 * time.Hour,
})

// 加载规则
alertEng.LoadRules([]*rules.AlertRule{
    rules.NewBruteForceRule(),
    rules.NewLoginFailureRule(),
})

// 评估事件
alerts, err := alertEng.Evaluate(ctx, event)
if err != nil {
    return err
}

for _, alert := range alerts {
    alertEng.SaveAlert(alert)
}

// 获取统计
stats, err := alertEng.GetStats()
fmt.Printf("Total alerts: %d\n", stats.Total)
```
