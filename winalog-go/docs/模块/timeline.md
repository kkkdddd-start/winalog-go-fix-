# Timeline 模块

**路径**: `internal/timeline/`

时间线构建与攻击链检测。

## 核心组件

### TimelineBuilder

```go
type TimelineBuilder struct {
    events       []*types.Event
    filter       *TimelineFilter
    attackChains []*AttackChain
    categories   map[string][]*types.Event
}

func NewTimelineBuilder() *TimelineBuilder
func (b *TimelineBuilder) SetEvents(events []*types.Event)
func (b *TimelineBuilder) SetFilter(filter *TimelineFilter)
func (b *TimelineBuilder) Build() (*Timeline, error)
func (b *TimelineBuilder) GetAttackChains() []*AttackChain
func (b *TimelineBuilder) GroupByComputer() map[string]*Timeline
func (b *TimelineBuilder) GroupByCategory() map[string]*Timeline
```

## TimelineFilter

```go
type TimelineFilter struct {
    StartTime  time.Time
    EndTime    time.Time
    EventIDs   map[int32]bool         // O(1) 查找
    Levels     map[EventLevel]bool
    LogNames   map[string]bool
    Sources    map[string]bool
    Computers  map[string]bool
    Users      map[string]bool
    Keywords   string
    MITREIDs   []string
    IncludeRaw bool
}
```

## Timeline

```go
type Timeline struct {
    Entries    []*TimelineEntry `json:"entries"`
    TotalCount int              `json:"total_count"`
    StartTime  time.Time        `json:"start_time"`
    EndTime    time.Time        `json:"end_time"`
    Duration   time.Duration    `json:"duration"`
}

type TimelineEntry struct {
    ID          int64     `json:"id"`
    Timestamp   time.Time `json:"timestamp"`
    EventID     int32     `json:"event_id"`
    Level       string    `json:"level"`
    Category    string    `json:"category"`
    Source      string    `json:"source"`
    LogName     string    `json:"log_name"`
    Computer    string    `json:"computer"`
    User        string    `json:"user,omitempty"`
    Message     string    `json:"message"`
    MITREAttack []string  `json:"mitre_attack,omitempty"`
    AttackChain string    `json:"attack_chain,omitempty"`
    RawXML      string    `json:"raw_xml,omitempty"`
}
```

## AttackChain

攻击链检测结果。

```go
type AttackChain struct {
    ID          string         `json:"id"`
    Name        string         `json:"name"`
    Description string         `json:"description"`
    Technique   string         `json:"technique"`   // MITRE ID
    Tactic      string         `json:"tactic"`
    Severity    string         `json:"severity"`
    Events      []*types.Event `json:"events"`
    StartTime   time.Time      `json:"start_time"`
    EndTime     time.Time      `json:"end_time"`
    Duration    time.Duration  `json:"duration"`
}
```

## 事件分类

```go
type Category string

const (
    CategoryAuthentication  Category = "Authentication"
    CategoryAuthorization   Category = "Authorization"
    CategoryProcess        Category = "Process"
    CategoryNetwork        Category = "Network"
    CategoryFile           Category = "File"
    CategoryRegistry       Category = "Registry"
    CategoryScheduledTask  Category = "Scheduled Task"
    CategoryService        Category = "Service"
    CategoryPowerShell     Category = "PowerShell"
    CategoryRemoteAccess   Category = "Remote Access"
    CategoryAccount        Category = "Account"
    CategoryUnknown        Category = "Unknown"
)
```

## 攻击链检测

### detectBruteForce

检测暴力破解攻击 (T1110)。

```go
func (b *TimelineBuilder) detectBruteForce(events []*types.Event) []*AttackChain
```

**检测逻辑**:
- 统计 Event ID 4625 (Failed Login)
- 如果失败次数 >= 10，触发告警

### detectLateralMovement

检测横向移动 (T1021)。

```go
func (b *TimelineBuilder) detectLateralMovement(events []*types.Event) []*AttackChain
```

**检测逻辑**:
- 统计 Event ID 4624 (Successful Login) 和 4648 (Explicit Credentials)
- 如果同一用户登录 >= 3 台不同机器，触发告警

### detectPersistence

检测持久化行为 (T1053)。

```go
func (b *TimelineBuilder) detectPersistence(events []*types.Event) []*AttackChain
```

**检测逻辑**:
- 统计 Event ID 4698 (Scheduled Task Created)
- 统计 Event ID 4702 (Scheduled Task Enabled)
- 检测到即触发

## TimelineVisualizer

```go
type TimelineVisualizer struct {
    timeline *Timeline
}

func NewTimelineVisualizer(timeline *Timeline) *TimelineVisualizer
func (v *TimelineVisualizer) RenderJSON() (string, error)
func (v *TimelineVisualizer) RenderHTML() (string, error)
func (v *TimelineVisualizer) GetStatistics() *TimelineStats
```

## 使用示例

```go
// 创建时间线构建器
builder := timeline.NewTimelineBuilder()
builder.SetEvents(events)

// 设置过滤器
filter := &timeline.TimelineFilter{
    StartTime: time.Now().Add(-24 * time.Hour),
    EndTime:   time.Now(),
    EventIDs: map[int32]bool{
        4624: true,  // Successful Login
        4625: true,  // Failed Login
        4672: true,  // Special Privilege
    },
}
builder.SetFilter(filter)

// 构建时间线
tl, err := builder.Build()
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Timeline: %d entries\n", tl.TotalCount)
fmt.Printf("Time range: %s to %s\n", tl.StartTime, tl.EndTime)

// 获取攻击链
chains := builder.GetAttackChains()
for _, chain := range chains {
    fmt.Printf("Attack chain: %s (%s)\n", chain.Name, chain.Technique)
    fmt.Printf("  Events: %d\n", len(chain.Events))
    fmt.Printf("  Severity: %s\n", chain.Severity)
}

// 按计算机分组
byComputer := builder.GroupByComputer()
for computer, tl := range byComputer {
    fmt.Printf("Computer %s: %d events\n", computer, tl.TotalCount)
}
```
