# WinLogAnalyzer-Go API、Config、Timeline 模块改进实施方案

> 文档日期: 2026-04-17
> 评估范围: `internal/api/` + `internal/config/` + `internal/timeline/` + CLI timeline 命令

---

## 一、模块现状分析

### 1.1 API 模块 (`internal/api/`)

#### 文件结构

| 文件 | 功能 |
|------|------|
| `server.go` | HTTP 服务器主入口，17 个 Handler 注册 |
| `routes.go` | 主路由注册（6 个路由组） |
| `middleware.go` | 中间件（日志、CORS、恢复） |
| `handlers.go` | 核心处理器（AlertHandler、ImportHandler、TimelineHandler） |
| `handlers_dashboard.go` | 仪表盘统计 |
| `handlers_multi.go` | 多机关联分析 |
| `handlers_correlation.go` | 关联分析引擎 |
| `handlers_persistence.go` | 持久化检测 |
| `handlers_persistence_stream.go` | 持久化 SSE 流式 |
| `handlers_live.go` | 实时事件流 |
| `handlers_rules.go` | 规则管理 CRUD |
| `handlers_reports.go` | 报告生成 |
| `handlers_query.go` | SQL 查询执行 |
| `handlers_system.go` | 系统信息 |
| `handlers_suppress.go` | 告警抑制 |
| `handlers_ueba.go` | UEBA 分析 |
| `handlers_analyze.go` | 分析引擎 |
| `handlers_policy.go` | 策略管理 |
| `handlers_settings.go` | 设置管理 |
| `handlers_ui.go` | UI 相关 |
| `handlers_forensics.go` | 取证分析 |
| `setup_persistence_stream.go` | Windows 条件编译流路由 |

#### 核心架构

**Server 结构体** (`server.go:18-46`):
```go
type Server struct {
    engine     *gin.Engine
    httpServer *http.Server
    db         *storage.DB
    cfg        *config.Config
    // 17 个 Handler - 职责过多
    alertEng       *AlertHandler
    importEng      *ImportHandler
    liveEng        *LiveHandler
    persistenceEng *PersistenceHandler
    timelineEng    *TimelineHandler
    systemEng      *SystemHandler
    rulesEng       *RulesHandler
    reportsEng     *ReportsHandler
    forensicsEng    *ForensicsHandler
    dashboardEng   *DashboardHandler
    settingsEng    *SettingsHandler
    analyzeEng     *AnalyzeHandler
    collectEng     *CollectHandler
    suppressEng    *SuppressHandler
    uebaEng        *UEBAHandler
    correlationEng *CorrelationHandler
    multiEng       *MultiHandler
    queryEng       *QueryHandler
    policyEng      *PolicyHandler
    uiEng          *UIHandler
}
```

**路由注册机制** (`routes.go`):
```go
func SetupRoutes(r *gin.Engine, alertHandler *AlertHandler, ...) {
    r.GET("/api/health", healthCheck)
    api := r.Group("/api")
    {
        events := api.Group("/events")      // 事件管理
        alerts := api.Group("/alerts")       // 告警管理
        timeline := api.Group("/timeline")   // 时间线
        importGroup := api.Group("/import")  // 导入
        live := api.Group("/live")           // 实时监控
        dashboard := api.Group("/dashboard")  // 仪表盘
    }
}
```

---

### 1.2 Config 模块 (`internal/config/`)

#### 文件结构

| 文件 | 功能 |
|------|------|
| `config.go` | 配置结构体定义（12 个配置块） |
| `loader.go` | Viper 配置加载器 |

#### 核心配置结构

```go
type Config struct {
    Database    DatabaseConfig    `yaml:"database"`
    Import      ImportConfig      `yaml:"import"`
    Parser      ParserConfig      `yaml:"parser"`
    Search      SearchConfig      `yaml:"search"`
    Alerts      AlertsConfig      `yaml:"alerts"`
    Correlation CorrelationConfig `yaml:"correlation"`
    Report      ReportConfig      `yaml:"report"`
    Forensics   ForensicsConfig   `yaml:"forensics"`
    API         APIConfig         `yaml:"api"`
    Auth        AuthConfig        `yaml:"auth"`
    Audit       AuditConfig       `yaml:"audit"`
    Log         LogConfig         `yaml:"log"`
    TUI         TUIConfig         `yaml:"tui"`
}
```

---

### 1.3 Timeline 模块 (`internal/timeline/`)

#### 文件结构

| 文件 | 功能 |
|------|------|
| `builder.go` | 时间线构建器（498 行） |
| `visualizer.go` | 可视化渲染器（459 行） |
| `cmd/winalog/commands/report.go:211-309` | CLI 命令 |

#### CLI vs Web 功能对比

| 功能 | CLI | Web API |
|------|-----|---------|
| 构建时间线 | `timeline build` | `GET /api/timeline` |
| 时间线统计 | 无 | `GET /api/timeline/stats` |
| 攻击链检测 | 无 | `GET /api/timeline/chains` |
| 导出 | 无 | `GET /api/timeline/export` |
| 按类别过滤 | `--category` | Query 参数 |
| 按计算机过滤 | `--computer` | Query 参数 |

---

## 二、问题诊断

### 2.1 API 模块问题

#### 问题 A1: Server 结构体职责过重 (God Object)

**位置**: `server.go:18-46`

```go
type Server struct {
    engine         *gin.Engine
    httpServer     *http.Server
    db             *storage.DB
    cfg            *config.Config
    // 17 个 Handler 字段 - 违反单一职责原则
    alertEng       *AlertHandler
    importEng      *ImportHandler
    // ...
}
```

**问题**:
- 单一结构体包含 17 个 Handler，违反单一职责原则
- 新增 Handler 需要修改 Server 结构体
- 测试困难，需要 mock 大量依赖

**影响**: 可维护性差，扩展困难

---

#### 问题 A2: CORS 硬编码白名单

**位置**: `middleware.go:37-40`

```go
var allowedOrigins = []string{
    "http://localhost:3000",
    "http://localhost:8080",
}
```

**问题**:
- `allowedOrigins` 硬编码，不读取配置
- `config.go` 中定义了 `CORSConfig` 但未使用
- 生产环境无法动态调整

---

#### 问题 A3: formatBytes 函数类型转换错误

**位置**: `handlers_dashboard.go:74-84`

```go
func formatBytes(bytes int64) string {
    const unit = 1024
    if bytes < unit {
        return "< 1 KB"
    }
    div, exp := int64(unit), 0
    for n := bytes / unit; n >= unit; n /= unit {
        div *= unit
        exp++
    }
    return string([]byte{"KMGTPE"[exp], 'B'})  // BUG: 返回如 "GB" 而非 "2GB"
}
```

**问题**:
- 返回值格式错误，如 `2GB` 返回 `"GB"`
- 缺少数值部分，只有单位
- `exp` 可能超出数组边界

---

#### 问题 A4: SQL 验证可被绕过

**位置**: `handlers_query.go`

```go
func validateSQL(sql string) error {
    forbidden := []string{"DROP", "DELETE"}
    // 大小写可被绕过，如 "DrOp"
}
```

**问题**:
- 简单的字符串过滤可被大小写混合绕过
- 允许 PRAGMA 可能导致信息泄露
- 无参数化查询

---

#### 问题 A5: Handler 初始化不一致

**位置**: `server.go:70-106`

```go
func (s *Server) setupHandlers() {
    // 部分用 NewXxxHandler() 初始化
    s.alertEng = &AlertHandler{...}           // 手动
    s.liveEng = NewLiveHandler(s.db)          // 工厂函数
    
    // 部分直接赋值
    s.timelineEng = &TimelineHandler{db: s.db}  // 直接
    
    // 不一致导致维护困难
}
```

---

### 2.2 Config 模块问题

#### 问题 C1: Validate 方法不完整

**位置**: `config/config.go`

```go
func (c *Config) Validate() error {
    if c.Database.Path == "" {
        return fmt.Errorf("database.path is required")
    }
    if c.Import.Workers <= 0 {
        c.Import.Workers = 1  // 自动修正
    }
    // 部分返回错误，部分自动修正
    // 行为不一致
}
```

**问题**:
- 部分字段验证失败时自动修正（如 Workers）
- 部分字段验证失败时返回错误
- 缺少完整的验证规则文档

---

#### 问题 C2: 配置热重载未实现

**位置**: `config/loader.go`

```go
func (l *Loader) Load(configPath string) (*Config, error) {
    // 有 WatchConfigChanges() 方法但未被调用
    l.viper.WatchConfig()
    // 实际未生效
}
```

---

#### 问题 C3: 默认值设置过于宽松

**位置**: `config.go:203-206`

```go
CORS: CORSConfig{
    AllowedOrigins: []string{"*"},  // 生产环境不应允许 *
    AllowedMethods: []string{"*"},
    AllowedHeaders: []string{"*"},
}
```

**问题**:
- 默认允许所有来源，生产环境安全隐患
- 应该默认关闭，需要显式配置

---

### 2.3 Timeline 模块问题

#### 问题 T1: GroupBy 方法状态泄露

**位置**: `builder.go:431-486`

```go
func (b *TimelineBuilder) GroupByComputer() map[string]*Timeline {
    result := make(map[string]*Timeline)
    
    // BUG: 直接使用 b.categories，未在开始时清空
    for _, event := range b.events {
        if _, exists := b.categories[computer]; !exists {
            b.categories[computer] = make([]*types.Event, 0)
        }
        b.categories[computer] = append(b.categories[computer], event)
    }
    
    // 连续调用 GroupByComputer() 和 GroupByCategory() 会混淆
}
```

---

#### 问题 T2: 事件分类 map 每次重建

**位置**: `builder.go:217-302`

```go
func isAuthEvent(eventID int32) bool {
    authEvents := map[int32]bool{  // 每次调用都创建新 map
        4624: true, 4625: true, 4634: true, ...
    }
    return authEvents[eventID]
}
```

**问题**:
- 每次调用都分配新 map，GC 压力大
- 11 个分类函数，每个都创建 map
- 应使用包级别常量 map

---

#### 问题 T3: detectAttackChains 多次遍历

**位置**: `builder.go:321-340`

```go
func (b *TimelineBuilder) detectAttackChains(events []*types.Event) []*AttackChain {
    chains := make([]*AttackChain, 0)
    
    bruteForce := b.detectBruteForce(events)     // 遍历 1
    lateralMovement := b.detectLateralMovement(events)  // 遍历 2
    persistence := b.detectPersistence(events)   // 遍历 3
    
    // 同一 events 被遍历 3 次
}
```

---

#### 问题 T4: Timeline API 无分页

**位置**: `handlers.go:722-812`

```go
func (h *TimelineHandler) GetTimeline(c *gin.Context) {
    limitStr := c.DefaultQuery("limit", "200")
    limit, _ := strconv.Atoi(limitStr)
    if limit <= 0 || limit > 1000 {
        limit = 200
    }
    
    // 只支持 limit，无 offset
    // 无法翻页查看历史数据
}
```

---

#### 问题 T5: CLI 和 Web 使用不同实现

**位置**:
- CLI: `cmd/winalog/commands/report.go:241-309`
- Web: `handlers.go:697-980`

```go
// CLI 使用 timeline.Builder
builder := timeline.NewTimelineBuilder()
builder.SetEvents(events)
tl, err := builder.Build()

// Web 独立实现，未使用 Builder
entries := make([]*TimelineEntry, 0)
for _, e := range events {
    entries = append(entries, &TimelineEntry{...})
}
sortTimeline(entries)
```

---

#### 问题 T6: 攻击链阈值硬编码

**位置**: `builder.go:356-368`

```go
if len(failedLogins) >= 10 {  // 硬编码 10 次
    chains = append(chains, &AttackChain{...})
}
```

---

## 三、改进实施方案

---

### A-M1: 重构 Server 结构体，使用 Handler 注册表

**优先级**: P1 | **工时**: 4h | **复杂度**: 高

#### 问题
17 个 Handler 在单一结构体中，违反单一职责原则。

#### 解决方案

**1.1 创建 Handler 接口和注册表**

```go
// internal/api/handler.go

type Handler interface {
    RegisterRoutes(r *gin.RouterGroup)
    Name() string
}

type HandlerRegistry struct {
    handlers map[string]Handler
    mu       sync.RWMutex
}

func NewHandlerRegistry() *HandlerRegistry {
    return &HandlerRegistry{
        handlers: make(map[string]Handler),
    }
}

func (r *HandlerRegistry) Register(h Handler) {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.handlers[h.Name()] = h
}

func (r *HandlerRegistry) Get(name string) (Handler, bool) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    h, ok := r.handlers[name]
    return h, ok
}

func (r *HandlerRegistry) RegisterAll(rg *HandlerRegistry) {
    for _, h := range rg.handlers {
        r.Register(h)
    }
}
```

**1.2 改造现有 Handler 实现接口**

```go
// internal/api/handlers.go

func (h *AlertHandler) Name() string {
    return "AlertHandler"
}

func (h *AlertHandler) RegisterRoutes(r *gin.RouterGroup) {
    r.GET("", h.ListAlerts)
    r.GET("/stats", h.GetAlertStats)
    r.GET("/trend", h.GetAlertTrend)
    r.POST("/run-analysis", h.RunAnalysis)
    r.GET("/:id", h.GetAlert)
    r.POST("/:id/resolve", h.ResolveAlert)
    r.POST("/:id/false-positive", h.MarkFalsePositive)
    r.DELETE("/:id", h.DeleteAlert)
    r.POST("/batch", h.BatchAlertAction)
}
```

**1.3 重构 Server**

```go
// internal/api/server.go

type Server struct {
    engine     *gin.Engine
    httpServer *http.Server
    db         *storage.DB
    cfg        *config.Config
    registry   *HandlerRegistry
}

func NewServer(db *storage.DB, cfg *config.Config, configPath, addr string) *Server {
    // ...
    registry := NewHandlerRegistry()
    
    registry.Register(NewAlertHandler(db, alertEngine))
    registry.Register(NewImportHandler(db, alertEngine))
    registry.Register(NewLiveHandler(db))
    registry.Register(NewTimelineHandler(db))
    registry.Register(NewDashboardHandler(db))
    // ... 其他 Handler
    
    server.setupRoutes(registry)
}

func (s *Server) setupRoutes(registry *HandlerRegistry) {
    r := s.engine.Group("/api")
    r.GET("/health", healthCheck)
    
    // 核心路由
    api := r.Group("/api")
    registry.Get("AlertHandler").RegisterRoutes(api.Group("/alerts"))
    registry.Get("TimelineHandler").RegisterRoutes(api.Group("/timeline"))
    // ...
}
```

---

### A-M2: CORS 配置化

**优先级**: P0 | **工时**: 1h | **复杂度**: 低

#### 问题
CORS 硬编码，未读取配置。

#### 解决方案

```go
// internal/api/middleware.go

func corsMiddleware(cfg *config.CORSConfig) gin.HandlerFunc {
    if cfg == nil {
        cfg = &config.CORSConfig{
            AllowedOrigins: []string{"http://localhost:3000", "http://localhost:8080"},
        }
    }
    
    return func(c *gin.Context) {
        origin := c.Request.Header.Get("Origin")
        
        // 检查是否在白名单
        allowedOrigin := ""
        for _, ao := range cfg.AllowedOrigins {
            if ao == "*" || origin == ao {
                allowedOrigin = ao
                break
            }
        }
        
        if allowedOrigin != "" {
            c.Writer.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
            c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
        }
        // ...
    }
}

// server.go
func NewServer(...) *Server {
    engine.Use(corsMiddleware(&cfg.API.CORS))
}
```

---

### A-M3: 修复 formatBytes 函数

**优先级**: P0 | **工时**: 0.5h | **复杂度**: 低

#### 问题
返回值格式错误，如 `2GB` 返回 `"GB"`。

#### 解决方案

```go
// internal/api/handlers_dashboard.go

func formatBytes(bytes int64) string {
    const unit = 1024
    if bytes < unit {
        return "< 1 KB"
    }
    
    exp := 0
    size := float64(bytes)
    for size >= unit {
        size /= unit
        exp++
    }
    
    if exp >= len("KMGTPE") {
        return "> 1 PB"
    }
    
    return fmt.Sprintf("%.1f%cB", size, "KMGTPE"[exp-1])
}
```

---

### A-M4: SQL 验证增强

**优先级**: P0 | **工时**: 2h | **复杂度**: 中

#### 问题
简单字符串过滤可被绕过。

#### 解决方案

```go
// internal/api/handlers_query.go

import (
    "regexp"
    "strings"
)

var sqlForbiddenPatterns = []*regexp.Regexp{
    regexp.MustCompile(`(?i)\b(DROP|DELETE|TRUNCATE|ALTER)\s+(TABLE|DATABASE)`),
    regexp.MustCompile(`(?i)\b(INSERT\s+INTO|REPLACE\s+INTO)\s+\w+\s+\(SELECT`),
    regexp.MustCompile(`(?i)\b(EXEC|EXECUTE)\s*\(`,),
    regexp.MustCompile(`(?i)\b(PRAGMA|SHELL)\s*\(`,),
    regexp.MustCompile(`(?i)--`),
    regexp.MustCompile(`(?i)/\*.*\*/`),
}

func validateSQL(sql string) error {
    sql = strings.TrimSpace(sql)
    
    if len(sql) > 10000 {
        return fmt.Errorf("SQL statement too long")
    }
    
    for _, pattern := range sqlForbiddenPatterns {
        if pattern.MatchString(sql) {
            return fmt.Errorf("forbidden SQL pattern detected")
        }
    }
    
    // 检查是否有不完整的字符串字面量
    if strings.Count(sql, "'")%2 != 0 || strings.Count(sql, "\"")%2 != 0 {
        return fmt.Errorf("unclosed string literal")
    }
    
    return nil
}
```

---

### C-M1: 配置验证增强

**优先级**: P1 | **工时**: 2h | **复杂度**: 中

#### 问题
验证行为不一致，部分修正部分报错。

#### 解决方案

```go
// internal/config/config.go

type ValidationResult struct {
    Field   string
    Value   interface{}
    Message string
    Fixed   bool  // 是否被自动修正
}

func (c *Config) Validate() ([]*ValidationResult, error) {
    results := make([]*ValidationResult, 0)
    
    // 数据库验证
    if c.Database.Path == "" {
        results = append(results, &ValidationResult{
            Field:   "database.path",
            Value:   c.Database.Path,
            Message: "database.path is required",
            Fixed:   false,
        })
    }
    
    // Workers 自动修正
    if c.Import.Workers <= 0 {
        results = append(results, &ValidationResult{
            Field:   "import.workers",
            Value:   c.Import.Workers,
            Message: "import.workers must be positive, auto-corrected to 1",
            Fixed:   true,
        })
        c.Import.Workers = 1
    }
    if c.Import.Workers > 32 {
        results = append(results, &ValidationResult{
            Field:   "import.workers",
            Value:   c.Import.Workers,
            Message: "import.workers exceeds max (32), auto-corrected",
            Fixed:   true,
        })
        c.Import.Workers = 32
    }
    
    // API Port 验证
    if c.API.Port <= 0 || c.API.Port > 65535 {
        results = append(results, &ValidationResult{
            Field:   "api.port",
            Value:   c.API.Port,
            Message: "invalid api.port, must be 1-65535",
            Fixed:   false,
        })
    }
    
    // CORS 生产环境警告
    for _, origin := range c.API.CORS.AllowedOrigins {
        if origin == "*" {
            results = append(results, &ValidationResult{
                Field:   "api.cors.allowed_origins",
                Value:   origin,
                Message: "WARNING: CORS allows all origins (*), not suitable for production",
                Fixed:   false,
            })
        }
    }
    
    hasErrors := false
    for _, r := range results {
        if !r.Fixed {
            hasErrors = true
            break
        }
    }
    
    if hasErrors {
        return results, fmt.Errorf("configuration validation failed")
    }
    
    return results, nil
}
```

---

### C-M2: 配置热重载

**优先级**: P2 | **工时**: 3h | **复杂度**: 中

#### 问题
WatchConfig 未生效。

#### 解决方案

```go
// internal/config/loader.go

type ConfigWatcher struct {
    loader *Loader
    cfg    *Config
    mu     sync.RWMutex
    done   chan struct{}
}

func (l *Loader) LoadWithWatcher(configPath string) (*Config, *ConfigWatcher, error) {
    cfg, err := l.Load(configPath)
    if err != nil {
        return nil, nil, err
    }
    
    watcher := &ConfigWatcher{
        loader: l,
        cfg:    cfg,
        done:   make(chan struct{}),
    }
    
    l.viper.WatchConfig()
    l.viper.OnConfigChange(func(e fsnotify.Event) {
        if e.Op == fsnotify.Write {
            log.Printf("[CONFIG] Configuration file changed, reloading...")
            if newCfg, err := l.Load(configPath); err == nil {
                watcher.mu.Lock()
                watcher.cfg = newCfg
                watcher.mu.Unlock()
                log.Printf("[CONFIG] Configuration reloaded successfully")
            }
        }
    })
    
    return cfg, watcher, nil
}

func (w *ConfigWatcher) Get() *Config {
    w.mu.RLock()
    defer w.mu.RUnlock()
    return w.cfg
}

func (w *ConfigWatcher) Stop() {
    close(w.done)
}
```

---

### T-M1: 修复 GroupBy 状态泄露

**优先级**: P0 | **工时**: 0.5h | **复杂度**: 低

#### 问题
`b.categories` 被直接修改，导致连续调用时数据残留。

#### 解决方案

```go
// internal/timeline/builder.go

func (b *TimelineBuilder) GroupByComputer() map[string]*Timeline {
    result := make(map[string]*Timeline)
    
    // 使用独立的局部变量，不复用 b.categories
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
        tl, _ := builder.Build()
        result[computer] = tl
    }
    
    return result
}

func (b *TimelineBuilder) GroupByCategory() map[string]*Timeline {
    result := make(map[string]*Timeline)
    
    // 使用独立的局部变量
    categoryEvents := make(map[string][]*types.Event)
    
    for _, event := range b.events {
        if !b.matchesFilter(event) {
            continue
        }
        
        category := b.categorizeEvent(event)
        categoryEvents[category] = append(categoryEvents[category], event)
    }
    
    for category, events := range categoryEvents {
        builder := NewTimelineBuilder()
        builder.SetEvents(events)
        builder.SetFilter(b.filter)
        tl, _ := builder.Build()
        result[category] = tl
    }
    
    return result
}
```

---

### T-M2: 预编译事件分类 Map

**优先级**: P1 | **工时**: 1h | **复杂度**: 低

#### 问题
每次调用都创建新 map。

#### 解决方案

```go
// internal/timeline/builder.go

// 包级别常量 map - 初始化一次
var (
    authEventsMap = map[int32]bool{
        4624: true, 4625: true, 4626: true, 4627: true,
        4634: true, 4640: true, 4768: true, 4769: true, 4776: true,
    }
    
    authzEventsMap = map[int32]bool{
        4672: true, 4673: true, 4674: true, 4702: true,
    }
    
    processEventsMap = map[int32]bool{
        4688: true, 4689: true, 4696: true, 4697: true,
        4698: true, 4699: true, 4700: true, 4701: true,
    }
    
    networkEventsMap = map[int32]bool{
        3: true, 4000: true, 4001: true, 4002: true,
        5156: true, 5157: true, 5158: true, 5159: true,
    }
    
    fileEventsMap = map[int32]bool{
        4656: true, 4657: true, 4658: true, 4660: true,
        4663: true, 4664: true, 4670: true,
    }
    
    registryEventsMap = map[int32]bool{
        4657: true, 4660: true,
    }
    
    scheduledTaskEventsMap = map[int32]bool{
        4698: true, 4699: true, 4700: true, 4701: true, 4702: true,
    }
    
    serviceEventsMap = map[int32]bool{
        4697: true, 4698: true, 4699: true,
        7000: true, 7001: true, 7002: true, 7009: true,
    }
    
    powershellEventsMap = map[int32]bool{
        400: true, 600: true, 800: true,
        4100: true, 4103: true, 4104: true,
    }
    
    remoteAccessEventsMap = map[int32]bool{
        4624: true, 4625: true, 4648: true, 4672: true,
    }
    
    accountEventsMap = map[int32]bool{
        4720: true, 4721: true, 4722: true, 4723: true,
        4724: true, 4725: true, 4726: true, 4738: true,
        4740: true, 4767: true, 4768: true, 4769: true,
    }
)

func isAuthEvent(eventID int32) bool {
    return authEventsMap[eventID]
}

func isAuthzEvent(eventID int32) bool {
    return authzEventsMap[eventID]
}

func isProcessEvent(eventID int32) bool {
    return processEventsMap[eventID]
}

func isNetworkEvent(eventID int32) bool {
    return networkEventsMap[eventID]
}

// ... 其他函数类似
```

---

### T-M3: Timeline API 分页支持

**优先级**: P0 | **工时**: 2h | **复杂度**: 中

#### 问题
无 offset 分页，大数据量时内存爆炸。

#### 解决方案

```go
// internal/api/handlers.go

type TimelineRequest struct {
    Limit      int    `form:"limit,default=200"`
    Offset     int    `form:"offset,default=0"`
    StartTime  string `form:"start_time"`
    EndTime    string `form:"end_time"`
    IncludeRaw bool   `form:"include_raw"`
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
    if req.Offset < 0 {
        req.Offset = 0
    }
    
    // 构建时间过滤
    var start, end *time.Time
    if req.StartTime != "" {
        if t, err := time.Parse(time.RFC3339, req.StartTime); err == nil {
            start = &t
        }
    }
    if req.EndTime != "" {
        if t, err := time.Parse(time.RFC3339, req.EndTime); err == nil {
            end = &t
        }
    }
    
    // 查询总数
    total, _ := h.db.CountEvents(&storage.EventFilter{
        StartTime: start,
        EndTime:   end,
    })
    
    // 分页查询
    events, _, err := h.db.ListEvents(&storage.EventFilter{
        Limit:     req.Limit,
        Offset:    req.Offset,
        StartTime: start,
        EndTime:   end,
    })
    
    // 构建 entries
    entries := make([]*TimelineEntry, 0, len(events))
    for _, e := range events {
        entries = append(entries, &TimelineEntry{...})
    }
    
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

// storage 增加 CountEvents 方法
func (db *DB) CountEvents(filter *EventFilter) (int, error) {
    // 实现计数查询
}
```

---

### T-M4: 统一 CLI 和 Web 时间线构建

**优先级**: P2 | **工时**: 3h | **复杂度**: 中

#### 问题
CLI 使用 `timeline.Builder`，Web 独立实现。

#### 解决方案

**1.1 Web API 使用 Builder**

```go
// internal/api/handlers.go

func (h *TimelineHandler) GetTimeline(c *gin.Context) {
    // ... 解析参数
    
    events, _, err := h.db.ListEvents(eventFilter)
    if err != nil {
        log.Printf("failed to fetch events for timeline: %v", err)
    }
    
    // 使用统一的 Builder
    builder := timeline.NewTimelineBuilder()
    builder.SetEvents(events)
    builder.SetFilter(&timeline.TimelineFilter{
        StartTime:  *start,
        EndTime:    *end,
        IncludeRaw: req.IncludeRaw,
    })
    
    tl, err := builder.Build()
    if err != nil {
        internalError(c, err)
        return
    }
    
    c.JSON(http.StatusOK, TimelineResponse{
        Entries:    tl.Entries,
        TotalCount: tl.TotalCount,
    })
}
```

**1.2 Web 也使用 Timeline 结构替代 TimelineEntry 切片**

```go
type TimelineHandler struct {
    db *storage.DB
}

type TimelineHandlerResponse struct {
    Entries    []*TimelineEntry `json:"entries"`
    TotalCount int              `json:"total_count"`
    StartTime  time.Time        `json:"start_time"`
    EndTime    time.Time        `json:"end_time"`
}
```

---

### T-M5: 攻击链阈值可配置

**优先级**: P1 | **工时**: 1.5h | **复杂度**: 低

#### 问题
硬编码阈值无法适应不同环境。

#### 解决方案

```go
// internal/timeline/builder.go

type AttackChainConfig struct {
    BruteForceThreshold      int
    LateralMovementThreshold int
    PersistenceThreshold     int
    TimeWindow               time.Duration
}

func DefaultAttackChainConfig() *AttackChainConfig {
    return &AttackChainConfig{
        BruteForceThreshold:      10,
        LateralMovementThreshold: 3,
        PersistenceThreshold:     1,
        TimeWindow:               24 * time.Hour,
    }
}

func (b *TimelineBuilder) DetectBruteForce(events []*types.Event, cfg *AttackChainConfig) []*AttackChain {
    if cfg == nil {
        cfg = DefaultAttackChainConfig()
    }
    
    // 使用 cfg.BruteForceThreshold
    if len(failedLogins) >= cfg.BruteForceThreshold {
        // ...
    }
}
```

---

## 四、实施优先级矩阵

| 编号 | 问题 | 优先级 | 工时 | 复杂度 | 适配性 | 必要性 |
|------|------|--------|------|--------|--------|--------|
| A-M3 | formatBytes 错误 | P0 | 0.5h | 低 | 高 | 高 |
| A-M4 | SQL 验证可绕过 | P0 | 2h | 中 | 高 | 高 |
| A-M2 | CORS 硬编码 | P0 | 1h | 低 | 高 | 高 |
| T-M1 | GroupBy 状态泄露 | P0 | 0.5h | 低 | 高 | 高 |
| T-M3 | Timeline API 无分页 | P0 | 2h | 中 | 高 | 高 |
| A-M1 | Server 结构体过重 | P1 | 4h | 高 | 中 | 中 |
| T-M2 | 事件分类 map 重复创建 | P1 | 1h | 低 | 高 | 中 |
| T-M5 | 攻击链阈值可配置 | P1 | 1.5h | 低 | 高 | 中 |
| C-M1 | Config 验证增强 | P1 | 2h | 中 | 高 | 中 |
| T-M4 | CLI/Web 时间线统一 | P2 | 3h | 中 | 中 | 低 |
| C-M2 | 配置热重载 | P2 | 3h | 中 | 中 | 低 |

---

## 五、总结

本方案针对 API、Config、Timeline 模块的 11 个问题提出了具体的改进建议：

### 高优先级 (P0)
1. **A-M3**: formatBytes 错误修复 - 仪表盘显示 bug
2. **A-M4**: SQL 验证增强 - 安全漏洞
3. **A-M2**: CORS 配置化 - 生产环境问题
4. **T-M1**: GroupBy 状态泄露 - 数据混乱 bug
5. **T-M3**: Timeline API 分页 - 性能问题

### 中优先级 (P1)
6. **A-M1**: Server 结构体重构 - 架构优化
7. **T-M2**: 事件分类 map 预编译 - GC 优化
8. **T-M5**: 攻击链阈值可配置 - 灵活性增强
9. **C-M1**: Config 验证增强 - 可靠性提升

### 低优先级 (P2)
10. **T-M4**: CLI/Web 时间线统一 - 代码质量
11. **C-M2**: 配置热重载 - 功能增强

**总工时**: ~24h

---

*文档版本: v1.0 | 更新日期: 2026-04-17*
