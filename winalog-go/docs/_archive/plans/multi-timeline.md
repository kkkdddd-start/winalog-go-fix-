# WinLogAnalyzer-Go Multi 与 Timeline 模块改进实施方案

> 文档日期: 2026-04-17
> 评估范围: Multi 多机关联分析模块 + Timeline 事件时间线模块

---

## 一、模块现状分析

### 1.1 Multi 多机关联分析模块

#### 文件结构

| 文件路径 | 功能 |
|---------|------|
| `cmd/winalog/commands/report.go:311-596` | CLI 命令入口 |
| `internal/multi/analyzer.go` | 多机分析器核心 |
| `internal/api/handlers_multi.go` | HTTP 处理器 |
| `internal/correlation/engine.go` | 事件关联引擎 |
| `internal/correlation/matcher.go` | 事件匹配器 |
| `internal/correlation/chain.go` | 攻击链构建器 |
| `internal/api/handlers_correlation.go` | 关联分析 HTTP 处理器 |

#### 核心功能

1. **多机分析** (`multi analyze`)
   - 从 `machine_context` 表获取机器信息
   - 分析用户登录跨机器活动（7天窗口）
   - 检测可疑的多机登录用户

2. **横向移动检测** (`multi lateral`)
   - 检测 Pass-the-Hash (4624 NTLM)
   - 检测 RDP 跳转 (4624 + 4648)
   - 检测管理员权限分配 (4672)
   - 检测远程账户创建 (4728, 4729, 4732, 4756, 4757)

3. **关联分析引擎**
   - 基于规则的模式匹配
   - 攻击链构建

#### CLI 与 Web 功能对比

| 功能 | CLI | Web API |
|------|-----|---------|
| 多机分析 | `multi analyze` | `POST /api/multi/analyze` |
| 横向移动检测 | `multi lateral` | `GET /api/multi/lateral` |
| 关联分析 | 无 | `POST /api/correlation/analyze` |

---

### 1.2 Timeline 事件时间线模块

#### 文件结构

| 文件路径 | 功能 |
|---------|------|
| `cmd/winalog/commands/report.go:211-309` | CLI 命令 |
| `internal/timeline/builder.go` | 时间线构建器 |
| `internal/timeline/visualizer.go` | 可视化器 (HTML/JSON/CSV) |
| `internal/api/handlers.go:697-1147` | HTTP 处理器 |
| `internal/exporters/timeline.go` | 导出器 |

#### 核心功能

1. **时间线构建**
   - 按时间排序事件
   - 事件分类（认证、授权、进程、网络等12类）
   - MITRE ATT&CK 映射

2. **攻击链检测**
   - 暴力破解检测 (T1110)
   - 横向移动检测 (T1021)
   - 持久化检测 (T1053)

3. **可视化**
   - HTML 交互式时间线
   - JSON 导出
   - CSV 导出

#### CLI 与 Web 功能对比

| 功能 | CLI | Web API |
|------|-----|---------|
| 构建时间线 | `timeline build` | `GET /api/timeline` |
| 时间线统计 | 无 | `GET /api/timeline/stats` |
| 攻击链 | 无 | `GET /api/timeline/attack-chains` |
| 查询过滤 | 无 | Query 参数 |

---

## 二、问题诊断

### 2.1 Multi 模块问题

#### 问题 M1: 数据源依赖 `machine_context` 表，但无主动填充机制

**位置**: `handlers_multi.go:111-136`

```go
func (h *MultiHandler) getMachineContexts() ([]MachineInfo, error) {
    rows, err := h.db.Query(`
        SELECT machine_id, machine_name, ip_address, domain, role, os_version, last_seen
        FROM machine_context
        ...
    `)
}
```

**问题**: 
- `machine_context` 表依赖事件导入时自动填充
- 如果导入的事件缺少机器标识，表中无数据
- Multi 分析功能在无数据时返回空，无法告知用户根因

**影响**: 用户运行 `multi analyze` 看到空结果，不知如何解决

---

#### 问题 M2: 横向移动检测逻辑过于简单

**位置**: `handlers_multi.go:210-288`

```go
func (h *MultiHandler) detectLateralMovement() ([]LateralMovement, error) {
    rows, err := h.db.Query(`
        SELECT computer, user, event_id, timestamp, ip_address, message
        FROM events
        WHERE event_id IN (4624, 4625, 4648, 4672, 4688, 4697, 4698)
        AND timestamp > datetime('now', '-24 hours')
        ...
    `)
    // 简单的事件列表返回，没有关联分析
}
```

**问题**:
- 只按单事件标记 severity，没有关联分析
- 24小时窗口硬编码，不可配置
- `SourceMachine` 和 `TargetMachine` 都设为同一个 `computer`（都是本机事件）
- 缺少真正的跨机器关联（如 RDP 连接源和目标）

**影响**: 检测结果误报率高，真实横向移动可能漏报

---

#### 问题 M3: CLI 与 Web 逻辑重复

**位置**: 
- `cmd/winalog/commands/report.go:330-449` (CLI)
- `internal/api/handlers_multi.go:138-208` (Web)

```go
// CLI 重复的 SQL 查询
authEvents, err := db.Query(`
    SELECT computer, user, event_id, timestamp, ip_address, message
    FROM events
    WHERE event_id IN (4624, 4625, 4648, 4672, 4728, 4729, 4732, 4756, 4757)
    ...
`)

// Web 重复的 SQL 查询
rows, err := h.db.Query(`
    SELECT computer, user, event_id, timestamp, ip_address, message
    FROM events
    WHERE event_id IN (4624, 4625, 4648, 4672, 4728, 4729, 4732, 4756, 4757)
    ...
`)
```

**问题**: CLI 和 Web API 各自实现了一套相同的 SQL 查询逻辑，违反 DRY 原则

---

#### 问题 M4: `itoa` 函数实现错误

**位置**: `handlers_multi.go:309-311`

```go
func itoa(i int) string {
    return string(rune('0'+i/10000%10)) + string(rune('0'+i/1000%10)) + 
           string(rune('0'+i/100%10)) + string(rune('0'+i/10%10)) + 
           string(rune('0'+i%10))
}
```

**问题**: 
- 只支持 0-99999 范围
- 负数和大于 99999 的数字会返回乱码
- 应该直接使用 `strconv.Itoa`

---

#### 问题 M5: 无分析结果缓存和历史记录

**位置**: `handlers_multi.go:60-96`

```go
func (h *MultiHandler) Analyze(c *gin.Context) {
    // 每次都执行完整分析，无缓存
    machines, err := h.getMachineContexts()
    crossMachine, err := h.analyzeCrossMachineActivity()
    lateral, err := h.detectLateralMovement()
    // 直接返回，无存储
}
```

**问题**:
- 每次 API 调用都执行完整 SQL 查询
- 分析结果不保存，无法查看历史
- 无法对比不同时间段的检测结果

---

### 2.2 Timeline 模块问题

#### 问题 T1: 事件分类映射不完整

**位置**: `timeline/builder.go:188-215`

```go
func (b *TimelineBuilder) categorizeEvent(event *types.Event) string {
    switch {
    case isAuthEvent(event.EventID):
        return string(CategoryAuthentication)
    case isAuthzEvent(event.EventID):
        return string(CategoryAuthorization)
    // ... 其他类别
    default:
        return string(CategoryUnknown)
    }
}
```

**问题**:
- 大多数 Windows 安全事件 ID 落在 `default` 分支，返回 `Unknown`
- 分类覆盖的事件 ID 有限（认证 9 个，进程 8 个等）
- 安全事件的 4600-4800 范围大量未覆盖

---

#### 问题 T2: 攻击链检测阈值硬编码

**位置**: `timeline/builder.go:356-368`

```go
if len(failedLogins) >= 10 {
    chains = append(chains, &AttackChain{
        Name: "Brute Force Attack Detected",
        ...
    })
}
```

**问题**:
- 暴力破解阈值固定 10 次，不可配置
- 横向移动阈值固定 3 次，不可配置
- 不同企业环境对"可疑"定义不同

---

#### 问题 T3: Timeline API 无分页

**位置**: `handlers.go:722-812`

```go
func (h *TimelineHandler) GetTimeline(c *gin.Context) {
    limitStr := c.DefaultQuery("limit", "200")
    limit, _ := strconv.Atoi(limitStr)
    // limit 最大 1000
    
    entries := make([]*TimelineEntry, 0)
    events, _, err := h.db.ListEvents(eventFilter)
    // 一次性加载所有事件到内存
}
```

**问题**:
- 大数据量时内存爆炸（10000+ 事件）
- 无 offset 分页，查看历史数据困难
- `limit` 参数名与 SQL 语义不符

---

#### 问题 T4: CLI 与 Web 时间线逻辑分离

**位置**: 
- CLI: `cmd/winalog/commands/report.go:241-309`
- Web: `internal/timeline/builder.go`

```go
// CLI 使用独立的 builder
builder := timeline.NewTimelineBuilder()
builder.SetEvents(events)
tl, err := builder.Build()
visualizer := timeline.NewTimelineVisualizer(tl)

// Web 使用 handlers.go 中的独立实现
entries := make([]*TimelineEntry, 0)
for _, e := range events {
    entries = append(entries, &TimelineEntry{...})
}
sortTimeline(entries)
```

**问题**:
- CLI 使用 `timeline/builder.go` 的 `TimelineBuilder`
- Web API 在 `handlers.go` 中独立实现了一套 `TimelineEntry` 和排序逻辑
- 代码重复，维护困难

---

#### 问题 T5: 可视化 HTML 模板硬编码

**位置**: `timeline/visualizer.go:40-258`

```go
const DefaultVisualizerConfig = `
<!DOCTYPE html>
...
<script>
    const timelineData = {{.JSON}};
    function initTimeline() { ... }
    ...
</script>
`
```

**问题**:
- HTML 模板 200+ 行硬编码在 Go 代码中
- 无法自定义样式或功能
- Bootstrap 5.3 依赖通过 CDN 加载（需网络）

---

#### 问题 T6: `GroupByComputer` 和 `GroupByCategory` 有 bug

**位置**: `timeline/builder.go:431-486`

```go
func (b *TimelineBuilder) GroupByComputer() map[string]*Timeline {
    result := make(map[string]*Timeline)

    for _, event := range b.events {
        // 直接修改 b.categories，但 b.categories 是指针
        if _, exists := b.categories[computer]; !exists {
            b.categories[computer] = make([]*types.Event, 0)
        }
        b.categories[computer] = append(b.categories[computer], event)
    }

    // 复用 b.categories 会导致下次调用时数据残留
}
```

**问题**:
- `b.categories` 被直接修改，未在开始时清空
- 连续调用 `GroupByComputer()` 和 `GroupByCategory()` 会混淆数据

---

## 三、改进实施方案

---

### M-M1: 增强 machine_context 数据质量与反馈

**优先级**: P1 | **工时**: 2h | **复杂度**: 中

#### 问题
`machine_context` 表依赖事件导入时自动填充，无主动管理机制。

#### 解决方案

**1.1 新增 API 端点查看数据质量**

```go
// internal/api/handlers_multi.go

type MachineContextStats struct {
    TotalMachines     int    `json:"total_machines"`
    MachinesWithEvents int   `json:"machines_with_events"`
    LastImportTime    string `json:"last_import_time"`
    MissingMachineIDs []string `json:"missing_machine_ids,omitempty"`
}

func (h *MultiHandler) GetMachineStats(c *gin.Context) {
    // 查询有多少 distinct computers 在 events 表中
    rows, err := h.db.Query(`
        SELECT COUNT(DISTINCT computer) FROM events
        WHERE timestamp > datetime('now', '-30 days')
    `)
    // 与 machine_context 表对比
    // 返回缺口数据
    
    c.JSON(http.StatusOK, MachineContextStats{...})
}
```

**1.2 新增 API 手动注册机器**

```go
type RegisterMachineRequest struct {
    MachineID   string `json:"machine_id"`
    MachineName string `json:"machine_name"`
    IPAddress   string `json:"ip_address"`
    Domain      string `json:"domain"`
    Role        string `json:"role"` // DC/Server/Workstation
}

func (h *MultiHandler) RegisterMachine(c *gin.Context) {
    var req RegisterMachineRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
        return
    }
    
    // 插入或更新 machine_context
    _, err := h.db.Exec(`
        INSERT OR REPLACE INTO machine_context 
        (machine_id, machine_name, ip_address, domain, role, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
    `, req.MachineID, req.MachineName, req.IPAddress, req.Domain, req.Role)
    
    c.JSON(http.StatusOK, SuccessResponse{Message: "Machine registered"})
}
```

**1.3 新增 CLI 命令**

```bash
# 查看机器上下文状态
winalog multi status

# 手动注册机器
winalog multi register --id "MACHINE-001" --name "DC01" --role "DC"
```

---

### M-M2: 改进横向移动检测算法

**优先级**: P0 | **工时**: 4h | **复杂度**: 高

#### 问题
当前检测只是单事件列表返回，缺少真正的跨机器关联。

#### 解决方案

**2.1 重构检测逻辑，支持跨机器关联**

```go
// internal/multi/analyzer.go

type LateralMovementDetector struct {
    db *storage.DB
}

func (d *LateralMovementDetector) Detect(ctx context.Context, window time.Duration) ([]*LateralMovement, error) {
    // 1. 获取所有 4624 (登录成功) 和 4648 (显式凭据登录) 事件
    rows, err := d.db.Query(`
        SELECT computer, user, event_id, timestamp, ip_address, 
               target_server, logon_type
        FROM events
        WHERE event_id IN (4624, 4648)
        AND timestamp > datetime('now', ?)
        ORDER BY timestamp ASC
    `, fmt.Sprintf("-%f hours", window.Hours()))
    
    // 2. 按用户分组，构建登录序列
    userLogins := d.buildLoginSequence(rows)
    
    // 3. 检测跨机器登录模式
    movements := d.detectCrossMachinePattern(userLogins)
    
    // 4. 检测特殊登录类型 (RDP, SMB, etc.)
    movements = append(movements, d.detectLogonTypePatterns(userLogins)...)
    
    return movements, nil
}

func (d *LateralMovementDetector) buildLoginSequence(rows *sql.Rows) map[string][]*LoginEvent {
    userLogins := make(map[string][]*LoginEvent)
    for rows.Next() {
        var e LoginEvent
        rows.Scan(&e.Computer, &e.User, &e.EventID, &e.Timestamp, &e.IPAddress, &e.TargetServer, &e.LogonType)
        userLogins[e.User] = append(userLogins[e.User], &e)
    }
    return userLogins
}

func (d *LateralMovementDetector) detectCrossMachinePattern(userLogins map[string][]*LoginEvent) []*LateralMovement {
    movements := make([]*LateralMovement, 0)
    
    for user, logins := range userLogins {
        // 按时间排序
        sort.Slice(logins, func(i, j int) bool {
            return logins[i].Timestamp.Before(logins[j].Timestamp)
        })
        
        // 检测用户在短时间内登录多台机器
        for i := 0; i < len(logins); i++ {
            source := logins[i]
            
            // 查找后续 1 小时内登录的其他机器
            cutoff := source.Timestamp.Add(1 * time.Hour)
            for j := i + 1; j < len(logins) && logins[j].Timestamp.Before(cutoff); j++ {
                target := logins[j]
                
                if source.Computer != target.Computer {
                    movements = append(movements, &LateralMovement{
                        SourceMachine: source.Computer,
                        TargetMachine: target.Computer,
                        User:          user,
                        Technique:     "T1021",
                        Time:          target.Timestamp,
                        Evidence:      []*types.Event{source.Event, target.Event},
                        Description:   fmt.Sprintf("User %s moved from %s to %s", 
                            user, source.Computer, target.Computer),
                    })
                }
            }
        }
    }
    return movements
}
```

**2.2 支持可配置的时间窗口**

```go
type LateralMovementRequest struct {
    Window string `json:"window"` // 如 "24h", "7d"
}

func (h *MultiHandler) Lateral(c *gin.Context) {
    windowStr := c.DefaultQuery("window", "24h")
    window, _ := time.ParseDuration(windowStr)
    
    detector := NewLateralMovementDetector(h.db)
    movements, err := detector.Detect(c.Request.Context(), window)
    // ...
}
```

---

### M-M3: 消除 CLI 与 Web 代码重复

**优先级**: P1 | **工时**: 2h | **复杂度**: 低

#### 问题
CLI 和 Web 各自实现相同的 SQL 查询逻辑。

#### 解决方案

**3.1 提取公共分析函数到 multi 包**

```go
// internal/multi/analyzer.go

type CrossMachineAnalyzer struct {
    db *storage.DB
}

func (a *CrossMachineAnalyzer) AnalyzeCrossMachineActivity(window time.Duration) ([]CrossMachineActivity, error) {
    // 统一的分析逻辑
}

func (a *CrossMachineAnalyzer) DetectLateralMovement(window time.Duration) ([]LateralMovement, error) {
    // 统一的检测逻辑
}
```

**3.2 CLI 调用公共函数**

```go
// cmd/winalog/commands/report.go

func runMultiAnalyze(cmd *cobra.Command, args []string) error {
    analyzer := multi.NewCrossMachineAnalyzer(db)
    
    activities, err := analyzer.AnalyzeCrossMachineActivity(7 * 24 * time.Hour)
    // 使用结果
}
```

**3.3 Web API 调用公共函数**

```go
// internal/api/handlers_multi.go

func (h *MultiHandler) Analyze(c *gin.Context) {
    analyzer := multi.NewCrossMachineAnalyzer(h.db)
    
    activities, err := analyzer.AnalyzeCrossMachineActivity(7 * 24 * time.Hour)
    // ...
}
```

---

### M-M4: 修复 itoa 函数

**优先级**: P0 | **工时**: 0.5h | **复杂度**: 低

#### 问题
错误的 itoa 实现会导致数字显示乱码。

#### 解决方案

```go
// internal/api/handlers_multi.go

import "strconv"

func itoa(i int) string {
    return strconv.Itoa(i)
}
```

---

### M-M5: 添加分析结果缓存与历史存储

**优先级**: P1 | **工时**: 3h | **复杂度**: 中

#### 问题
每次 API 调用都执行完整分析，无历史记录。

#### 解决方案

**5.1 新增存储表**

```go
// internal/storage/multi.go

func (s *DB) InitMultiSchema() error {
    schema := `
    CREATE TABLE IF NOT EXISTS multi_analysis_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id TEXT NOT NULL UNIQUE,
        analysis_type TEXT NOT NULL, -- "full", "lateral", "correlation"
        start_time TEXT NOT NULL,
        end_time TEXT,
        machine_count INTEGER,
        suspicious_count INTEGER,
        lateral_count INTEGER,
        result_json TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_multi_history_analysis_id 
        ON multi_analysis_history(analysis_id);
    `
    return s.db.Exec(schema).Error
}
```

**5.2 添加缓存层**

```go
type MultiHandler struct {
    db    *storage.DB
    cache *MultiAnalysisCache
    mu    sync.RWMutex
}

type MultiAnalysisCache struct {
    result    *MultiAnalyzeResponse
    timestamp time.Time
    ttl       time.Duration
}

func (h *MultiHandler) Analyze(c *gin.Context) {
    // 检查缓存 (TTL = 5 分钟)
    h.mu.RLock()
    if h.cache.result != nil && 
       time.Since(h.cache.timestamp) < h.cache.ttl {
        h.cache.result.Cached = true
        h.mu.RUnlock()
        c.JSON(http.StatusOK, h.cache.result)
        return
    }
    h.mu.RUnlock()
    
    // 执行分析...
    
    // 更新缓存
    h.mu.Lock()
    h.cache.result = response
    h.cache.timestamp = time.Now()
    h.mu.Unlock()
}
```

---

### T-T1: 完善事件分类映射

**优先级**: P1 | **工时**: 2h | **复杂度**: 低

#### 问题
大量 Windows 安全事件落在 `Unknown` 分类。

#### 解决方案

**扩展分类函数**

```go
// internal/timeline/builder.go

func categorizeEventID(eventID int32) string {
    switch {
    // 认证事件 (4624-4640)
    case eventID == 4624: return "Authentication"
    case eventID == 4625: return "Authentication"
    case eventID == 4626: return "Authentication"
    case eventID == 4627: return "Authentication"
    case eventID == 4628: return "Authentication"
    case eventID == 4629: return "Authentication"
    case eventID == 4630: return "Authentication"
    case eventID == 4631: return "Authentication"
    case eventID == 4632: return "Authentication"
    case eventID == 4633: return "Authentication"
    case eventID == 4634: return "Authentication"
    case eventID == 4635: return "Authentication"
    case eventID == 4640: return "Authentication"
    
    // 授权事件 (4648-4675)
    case eventID == 4648: return "Authorization"
    case eventID == 4649: return "Authorization"
    case eventID == 4650: return "Authorization"
    case eventID >= 4651 && eventID <= 4675: return "Authorization"
    
    // 账户事件 (4720-4760)
    case eventID >= 4720 && eventID <= 4760: return "Account"
    
    // 进程事件 (4688-4699)
    case eventID >= 4688 && eventID <= 4699: return "Process"
    
    // 服务事件 (4697-4702)
    case eventID >= 4697 && eventID <= 4702: return "Service"
    
    // 文件/注册表事件 (4656-4666)
    case eventID >= 4656 && eventID <= 4666: return "FileOperation"
    
    // 网络事件 (5156-5159, 40000-40099)
    case eventID >= 5156 && eventID <= 5159: return "Network"
    case eventID >= 40000 && eventID <= 40099: return "Network"
    
    // PowerShell 事件 (400-4104)
    case eventID >= 400 && eventID <= 403: return "PowerShell"
    case eventID >= 4100 && eventID <= 4104: return "PowerShell"
    
    // 系统事件 (4600-4800)
    case eventID >= 4600 && eventID <= 4800: return "System"
    
    default: return "Other"
    }
}
```

---

### T-T2: 攻击链检测阈值可配置化

**优先级**: P1 | **工时**: 1.5h | **复杂度**: 低

#### 问题
硬编码的阈值无法适应不同环境。

#### 解决方案

**新增配置结构**

```go
// internal/timeline/builder.go

type AttackChainConfig struct {
    BruteForceThreshold      int           // 默认 10
    LateralMovementThreshold int           // 默认 3
    TimeWindow              time.Duration // 默认 24h
}

func (b *TimelineBuilder) DetectBruteForce(events []*types.Event, config *AttackChainConfig) []*AttackChain {
    if config == nil {
        config = &AttackChainConfig{
            BruteForceThreshold: 10,
            TimeWindow: 24 * time.Hour,
        }
    }
    
    failedLogins := filterFailedLogins(events, config.TimeWindow)
    if len(failedLogins) >= config.BruteForceThreshold {
        // 构建攻击链
    }
}
```

**API 支持参数**

```go
// internal/api/handlers.go

type AttackChainRequest struct {
    BruteForceThreshold int    `json:"brute_force_threshold"`
    LateralThreshold    int    `json:"lateral_threshold"`
    Window              string `json:"window"`
}

func (h *TimelineHandler) GetAttackChains(c *gin.Context) {
    var req AttackChainRequest
    c.ShouldBindQuery(&req)
    
    config := &timeline.AttackChainConfig{
        BruteForceThreshold:      req.BruteForceThreshold,
        LateralMovementThreshold:  req.LateralThreshold,
    }
    if req.Window != "" {
        config.TimeWindow, _ = time.ParseDuration(req.Window)
    }
    
    chains := detectAttackChainsWithConfig(events, config)
}
```

---

### T-T3: Timeline API 分页支持

**优先级**: P0 | **工时**: 2h | **复杂度**: 中

#### 问题
大数据量时内存爆炸，无分页。

#### 解决方案

**3.1 修改 API 签名**

```go
// internal/api/handlers.go

type TimelineRequest struct {
    Limit    int    `form:"limit"`
    Offset   int    `form:"offset"`
    StartTime string `form:"start_time"`
    EndTime   string `form:"end_time"`
}

type TimelineResponse struct {
    Entries    []*TimelineEntry `json:"entries"`
    TotalCount int              `json:"total_count"`
    HasMore    bool             `json:"has_more"`
    NextOffset int              `json:"next_offset,omitempty"`
}

func (h *TimelineHandler) GetTimeline(c *gin.Context) {
    var req TimelineRequest
    if err := c.ShouldBindQuery(&req); err != nil {
        req.Limit = 200
    }
    if req.Limit <= 0 || req.Limit > 1000 {
        req.Limit = 200
    }
    
    // 先查询总数
    total, _ := h.db.CountEvents(eventFilter)
    
    // SQL 分页
    eventFilter.Limit = req.Limit
    eventFilter.Offset = req.Offset
    
    events, _, err := h.db.ListEvents(eventFilter)
    
    hasMore := req.Offset+len(events) < total
    nextOffset := 0
    if hasMore {
        nextOffset = req.Offset + len(events)
    }
    
    c.JSON(http.StatusOK, TimelineResponse{
        Entries:    entries,
        TotalCount: total,
        HasMore:    hasMore,
        NextOffset: nextOffset,
    })
}
```

---

### T-T4: 统一 CLI 和 Web 的 Timeline 构建逻辑

**优先级**: P2 | **工时**: 3h | **复杂度**: 中

#### 问题
CLI 使用 `timeline.Builder`，Web 使用 `handlers.go` 中的独立实现。

#### 解决方案

**4.1 Web API 使用 Builder**

```go
// internal/api/handlers.go

func (h *TimelineHandler) GetTimeline(c *gin.Context) {
    events, _, err := h.db.ListEvents(eventFilter)
    if err != nil {
        // error
    }
    
    builder := timeline.NewTimelineBuilder()
    builder.SetEvents(events)
    builder.SetFilter(timelineFilter)
    
    tl, err := builder.Build()
    // 直接使用 tl.Entries
}
```

**4.2 删除 handlers.go 中的重复代码**

将 handlers.go 中的 `TimelineEntry` 相关代码删除，统一使用 `timeline.Builder`。

---

### T-T5: 可视化模板外部化

**优先级**: P2 | **工时**: 3h | **复杂度**: 中

#### 问题
200+ 行 HTML 硬编码在 Go 代码中。

#### 解决方案

**5.1 分离模板文件**

```bash
# 目录结构
internal/
  timeline/
    templates/
      timeline.html
      timeline.js
```

**5.2 动态加载模板**

```go
// internal/timeline/visualizer.go

func LoadTemplate(name string) (*template.Template, error) {
    tmplPath := filepath.Join("internal/timeline/templates", name)
    return template.ParseFiles(tmplPath)
}

func (v *TimelineVisualizer) RenderHTML(w io.Writer) error {
    tmpl, err := LoadTemplate("timeline.html")
    if err != nil {
        return err
    }
    return tmpl.Execute(w, v.data())
}
```

---

### T-T6: 修复 GroupBy 函数的 bug

**优先级**: P0 | **工时**: 0.5h | **复杂度**: 低

#### 问题
`b.categories` 被直接修改导致数据残留。

#### 解决方案

```go
func (b *TimelineBuilder) GroupByComputer() map[string]*Timeline {
    result := make(map[string]*Timeline)
    
    // 使用独立的 map，不复用 b.categories
    computerEvents := make(map[string][]*types.Event)
    
    for _, event := range b.events {
        if !b.matchesFilter(event) {
            continue
        }
        
        computer := event.Computer
        if computer == "" {
            computer = "Unknown"
        }
        
        computerEvents[computer] = append(computerEvents[computer], event)
    }
    
    for computer, events := range computerEvents {
        builder := NewTimelineBuilder()
        builder.SetEvents(events)
        builder.SetFilter(b.filter)
        timeline, _ := builder.Build()
        result[computer] = timeline
    }
    
    return result
}
```

---

## 四、实施优先级矩阵

| 编号 | 问题 | 优先级 | 工时 | 复杂度 | 适配性 | 必要性 |
|------|------|--------|------|--------|--------|--------|
| M-M4 | 修复 itoa 函数 | P0 | 0.5h | 低 | 高 | 高 |
| T-T6 | 修复 GroupBy bug | P0 | 0.5h | 低 | 高 | 高 |
| M-M2 | 横向移动检测算法 | P0 | 4h | 高 | 高 | 高 |
| T-T3 | Timeline API 分页 | P0 | 2h | 中 | 高 | 高 |
| M-M1 | machine_context 数据质量 | P1 | 2h | 中 | 高 | 中 |
| M-M3 | CLI/Web 代码重复 | P1 | 2h | 低 | 高 | 中 |
| M-M5 | 分析结果缓存与历史 | P1 | 3h | 中 | 高 | 中 |
| T-T1 | 事件分类映射不完整 | P1 | 2h | 低 | 高 | 中 |
| T-T2 | 攻击链阈值可配置 | P1 | 1.5h | 低 | 高 | 中 |
| T-T4 | CLI/Web Timeline 逻辑统一 | P2 | 3h | 中 | 中 | 低 |
| T-T5 | 可视化模板外部化 | P2 | 3h | 中 | 中 | 低 |

---

## 五、总结

本方案针对 Multi 多机关联分析模块和 Timeline 事件时间线模块的 11 个问题提出了具体的改进建议：

### 高优先级 (P0)
1. **M-M4**: 修复 itoa 函数 - 数字显示 bug
2. **T-T6**: 修复 GroupBy bug - 数据残留问题
3. **M-M2**: 横向移动检测算法 - 核心功能改进
4. **T-T3**: Timeline API 分页 - 性能问题

### 中优先级 (P1)
5. **M-M1**: machine_context 数据质量
6. **M-M3**: CLI/Web 代码重复
7. **M-M5**: 分析结果缓存与历史
8. **T-T1**: 事件分类映射不完整
9. **T-T2**: 攻击链阈值可配置

### 低优先级 (P2)
10. **T-T4**: CLI/Web Timeline 逻辑统一
11. **T-T5**: 可视化模板外部化

**总工时**: ~26h

---

*文档版本: v1.0 | 更新日期: 2026-04-17*
