# WinLogAnalyzer-Go 持久化检测模块改进实施方案

> 文档日期: 2026-04-17
> 评估范围: `internal/persistence/` + `cmd/winalog/commands/persistence.go` + `internal/api/handlers_persistence.go`

---

## 一、问题验证报告

经过代码审查，以下问题已验证存在：

### 1.1 代码重复严重 ✅ 已确认

**位置**: `internal/persistence/detector.go:188-252`

三个函数中存在完全相同的 15 个检测器注册代码：
- `RunAllDetectors()` - 行 188-208
- `DetectByCategory()` - 行 210-230
- `DetectByTechnique()` - 行 232-252

```go
// 重复代码示例 (3 处完全相同)
engine.Register(NewRunKeyDetector())
engine.Register(NewUserInitDetector())
engine.Register(NewStartupFolderDetector())
// ... 共 15 次重复注册
```

**影响**: 可维护性差，新增检测器需要修改 3 处

---

### 1.2 白名单机制不完善 ✅ 已确认

**白名单统计**:

| 检测器 | 白名单数量 | 文件位置 |
|--------|-----------|---------|
| RunKeyDetector | 2 | registry.go:57-60 |
| ServicePersistenceDetector | 4 | service.go:57-62 |
| BootExecuteDetector | 有 | boot_execute.go |
| BHODetector | 有 | bho.go |
| LSAPersistenceDetector | 有 | lsa.go |
| PrintMonitorDetector | 有 | print_monitor.go |
| WinsockDetector | 有 | winsock.go |

**问题**: Windows 系统有数百个合法服务和注册表项，白名单覆盖严重不足。

---

### 1.3 缺乏缓存机制 ✅ 已确认

**位置**: `internal/api/handlers_persistence.go:50`

```go
ctx := context.Background()  // 无超时，无缓存
var result *persistence.DetectionResult
result = persistence.RunAllDetectors(ctx)  // 每次都完整执行
```

**问题**: 每次 API 调用都执行完整检测，无缓存。

---

### 1.4 缺乏超时控制 ✅ 已确认

```go
// handlers_persistence.go:50
ctx := context.Background()  // 无限时
```

**问题**: 检测可能耗时很长（数分钟），无超时控制。

---

### 1.5 检测结果无法持久化 ⚠️ 确认

`types.go` 中存在 `ToAlert()` 和 `ToAlertWithEvidence()` 方法，但：
- 无 API 将检测结果存储到 SQLite
- 无法查看历史检测记录
- 无法生成检测趋势报告

---

## 二、改进实施方案

---

### P0-1: 消除检测器注册代码重复

**严重程度**: 高 | **优先级**: P0 | **预估工时**: 1h

#### 问题

`detector.go` 中三个函数重复注册 15 个检测器。

#### 解决方案

提取公共注册函数：

```go
// detector.go 新增

// AllDetectors 返回所有检测器列表
func AllDetectors() []Detector {
    return []Detector{
        NewRunKeyDetector(),
        NewUserInitDetector(),
        NewStartupFolderDetector(),
        NewAccessibilityDetector(),
        NewCOMHijackDetector(),
        NewIFEODetector(),
        NewAppInitDetector(),
        NewWMIPersistenceDetector(),
        NewServicePersistenceDetector(),
        NewLSAPersistenceDetector(),
        NewWinsockDetector(),
        NewBHODetector(),
        NewPrintMonitorDetector(),
        NewBootExecuteDetector(),
        NewETWDetector(),
    }
}

// registerAllDetectors 注册所有检测器到引擎
func registerAllDetectors(engine *DetectionEngine) {
    for _, d := range AllDetectors() {
        engine.Register(d)
    }
}

// RunAllDetectors 重构后
func RunAllDetectors(ctx context.Context) *DetectionResult {
    engine := NewDetectionEngine()
    registerAllDetectors(engine)
    return engine.Detect(ctx)
}

// DetectByCategory 重构后
func DetectByCategory(ctx context.Context, category string) *DetectionResult {
    engine := NewDetectionEngine()
    registerAllDetectors(engine)
    return engine.DetectCategory(ctx, category)
}

// DetectByTechnique 重构后
func DetectByTechnique(ctx context.Context, technique Technique) *DetectionResult {
    engine := NewDetectionEngine()
    registerAllDetectors(engine)
    return engine.DetectTechnique(ctx, technique)
}
```

#### 架构适配性

- **适配**: 完全符合现有架构
- **风险**: 低，只做重构不做功能变更
- **可靠性**: 高，逻辑不变只是消除重复

#### 验证方法

```bash
go build ./internal/persistence/
go test ./internal/persistence/...
```

---

### P0-2: 扩展白名单数据库

**严重程度**: 高 | **优先级**: P0 | **预估工时**: 4h

#### 问题

白名单数量不足，导致大量误报。

#### 解决方案

**2.1 统一白名单存储位置**

创建 `internal/persistence/whitelist.go`:

```go
package persistence

type WhitelistType int

const (
    WhitelistTypeRunKey WhitelistType = iota
    WhitelistTypeService
    WhitelistTypeBHO
    WhitelistTypePrintMonitor
    WhitelistTypeWinsock
    WhitelistTypeLSA
    WhitelistTypeBootExecute
)

type WhitelistEntry struct {
    Key     string
    Type    WhitelistType
    Reason  string
    Source  string  // "microsoft", "common-software", "custom"
}

type Whitelist struct {
    entries map[string]*WhitelistEntry
}

var GlobalWhitelist = &Whitelist{
    entries: make(map[string]*WhitelistEntry),
}

func (w *Whitelist) Add(key string, wtype WhitelistType, reason, source string) {
    w.entries[key] = &WhitelistEntry{
        Key:    key,
        Type:   wtype,
        Reason: reason,
        Source: source,
    }
}

func (w *Whitelist) IsAllowed(key string) bool {
    _, exists := w.entries[key]
    return exists
}

func (w *Whitelist) LoadDefaults() {
    // Run Keys - Microsoft 组件
    w.Add(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\DiagTrack`, 
        WhitelistTypeRunKey, "Windows Telemetry", "microsoft")
    w.Add(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth`, 
        WhitelistTypeRunKey, "Windows Security Health", "microsoft")
    // ... 扩展至 100+ 项
    
    // Services - Windows 核心服务
    w.Add(`SecurityHealthService`, WhitelistTypeService, "Windows Security Center", "microsoft")
    w.Add(`WinDefend`, WhitelistTypeService, "Windows Defender", "microsoft")
    // ... 扩展至 50+ 项
    
    // ... 其他类型
}
```

**2.2 各检测器使用统一白名单**

修改 `registry.go`:

```go
func (d *RunKeyDetector) Detect(ctx context.Context) ([]*Detection, error) {
    // 初始化白名单（只执行一次）
    if len(GlobalWhitelist.entries) == 0 {
        GlobalWhitelist.LoadDefaults()
    }
    
    for _, keyPath := range RunKeyPaths {
        entries, err := d.enumerateRunKey(keyPath)
        if err != nil {
            continue
        }
        
        for _, entry := range entries {
            fullKey := keyPath + "\\" + entry.Name
            
            // 使用统一白名单检查
            if GlobalWhitelist.IsAllowed(fullKey) {
                continue
            }
            
            if d.isSuspicious(entry.Value) {
                // ... 现有检测逻辑
            }
        }
    }
    return detections, nil
}
```

**2.3 支持用户自定义白名单**

在 `types.go` 或新建 `storage/persistence_whitelist.go`:

```go
// 支持从配置文件加载用户白名单
func LoadUserWhitelist(path string) error {
    data, err := os.ReadFile(path)
    if err != nil {
        return err
    }
    // JSON/YAML 格式
    type UserWhitelistEntry struct {
        Key    string `json:"key"`
        Type   string `json:"type"`
        Reason string `json:"reason"`
    }
    var entries []UserWhitelistEntry
    json.Unmarshal(data, &entries)
    for _, e := range entries {
        wtype := WhitelistTypeFromString(e.Type)
        GlobalWhitelist.Add(e.Key, wtype, e.Reason, "custom")
    }
    return nil
}
```

#### 架构适配性

- **适配**: 新增 whitelist.go，不修改现有检测器接口
- **风险**: 中，白名单加载逻辑需要测试验证
- **可靠性**: 高，白名单只是跳过检测不影响告警准确性

#### 工时分解

| 任务 | 工时 |
|------|------|
| 创建 whitelist.go 结构 | 1h |
| 迁移现有白名单 | 0.5h |
| 扩展 Microsoft 白名单 | 1h |
| 扩展常见软件白名单 | 1h |
| 测试验证 | 0.5h |

---

### P1-1: 添加检测超时控制

**严重程度**: 中 | **优先级**: P1 | **预估工时**: 1h

#### 问题

检测无超时控制，可能长时间阻塞。

#### 解决方案

修改 `handlers_persistence.go`:

```go
const (
    defaultDetectTimeout = 5 * time.Minute
)

func (h *PersistenceHandler) Detect(c *gin.Context) {
    if runtime.GOOS != "windows" {
        // ... 非 Windows 处理
        return
    }
    
    var req DetectRequest
    if err := c.ShouldBindQuery(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    // 支持自定义超时参数
    timeoutStr := c.DefaultQuery("timeout", "5m")
    timeout, err := time.ParseDuration(timeoutStr)
    if err != nil || timeout < 0 {
        timeout = defaultDetectTimeout
    }
    if timeout > 10*time.Minute {
        timeout = 10 * time.Minute // 最大 10 分钟
    }
    
    // 使用带超时的 context
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    
    // ... 后续检测逻辑
}
```

修改 `detector.go` 的 `Detect` 方法，响应 ctx 取消：

```go
func (e *DetectionEngine) Detect(ctx context.Context) *DetectionResult {
    // ... 现有初始化代码
    
    for name, d := range e.detectors {
        wg.Add(1)
        go func(name string, d Detector) {
            defer wg.Done()
            
            // 检查 ctx 是否已取消
            select {
            case <-ctx.Done():
                errorChan <- fmt.Sprintf("%s: context cancelled", name)
                return
            default:
            }
            
            detections, err := d.Detect(ctx)
            // ... 后续逻辑
        }(name, d)
    }
    // ... 
}
```

#### 架构适配性

- **适配**: 完全符合 Go context 规范
- **风险**: 低，向后兼容
- **可靠性**: 高，超时机制成熟

---

### P1-2: 添加检测结果缓存

**严重程度**: 中 | **优先级**: P1 | **预估工时**: 2h

#### 问题

每次 API 调用都执行完整检测，效率低。

#### 解决方案

修改 `handlers_persistence.go`:

```go
type PersistenceHandler struct {
    cache      *DetectionCache
    cacheMutex sync.RWMutex
}

type DetectionCache struct {
    result    *persistence.DetectionResult
    timestamp time.Time
    params    string  // category|technique 的 hash
    ttl       time.Duration
}

const defaultCacheTTL = 30 * time.Second

func NewPersistenceHandler() *PersistenceHandler {
    return &PersistenceHandler{
        cache: &DetectionCache{
            ttl: defaultCacheTTL,
        },
    }
}

func (h *PersistenceHandler) Detect(c *gin.Context) {
    // ... 现有参数解析 ...
    
    // 生成缓存 key
    cacheParams := fmt.Sprintf("%s|%s", req.Category, req.Technique)
    
    // 检查缓存（仅对全量检测生效，筛选检测不使用缓存）
    if req.Category == "" && req.Technique == "" {
        h.cacheMutex.RLock()
        if h.cache.result != nil && 
           time.Since(h.cache.timestamp) < h.cache.ttl &&
           h.cache.params == cacheParams {
            response := DetectResponse{
                Detections: h.cache.result.Detections,
                Summary:    h.cache.result.Summary(),
                Duration:   h.cache.result.Duration.String(),
                TotalCount: h.cache.result.TotalCount,
                Cached:     true,
            }
            h.cacheMutex.RUnlock()
            c.JSON(http.StatusOK, response)
            return
        }
        h.cacheMutex.RUnlock()
    }
    
    // ... 执行检测 ...
    
    // 更新缓存（仅对全量检测生效）
    if req.Category == "" && req.Technique == "" {
        h.cacheMutex.Lock()
        h.cache.result = result
        h.cache.timestamp = time.Now()
        h.cache.params = cacheParams
        h.cacheMutex.Unlock()
    }
    
    // ... 返回结果 ...
}
```

修改 `DetectResponse` 添加缓存标记：

```go
type DetectResponse struct {
    Detections []*persistence.Detection `json:"detections"`
    Summary    map[string]interface{}   `json:"summary"`
    Duration   string                   `json:"duration"`
    TotalCount int                      `json:"total_count"`
    Cached     bool                     `json:"cached,omitempty"`  // 新增
}
```

#### 架构适配性

- **适配**: 完全符合现有架构，Handler 结构体扩展
- **风险**: 低，缓存只是优化不影响核心逻辑
- **可靠性**: 高，TTL 控制确保数据新鲜度

---

### P1-3: 添加检测结果持久化存储

**严重程度**: 中 | **优先级**: P1 | **预估工时**: 6h

#### 问题

检测结果无法存储，无法查看历史记录。

#### 解决方案

**3.1 扩展 Storage 层**

新建 `internal/storage/persistence.go`:

```go
package storage

import (
    "time"
    
    "github.com/kkkdddd-start/winalog-go/internal/persistence"
)

type PersistenceDetectionStore struct {
    db *DB
}

func NewPersistenceDetectionStore(db *DB) *PersistenceDetectionStore {
    return &PersistenceDetectionStore{db: db}
}

func (s *PersistenceDetectionStore) InitSchema() error {
    schema := `
    CREATE TABLE IF NOT EXISTS persistence_detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        detection_id TEXT NOT NULL UNIQUE,
        technique TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        evidence_type TEXT,
        evidence_path TEXT,
        evidence_key TEXT,
        evidence_value TEXT,
        evidence_file_path TEXT,
        evidence_command TEXT,
        mitre_ref TEXT,
        recommended_action TEXT,
        false_positive_risk TEXT,
        detected_at TIMESTAMP NOT NULL,
        is_true_positive INTEGER DEFAULT -1,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_persistence_detections_technique 
        ON persistence_detections(technique);
    CREATE INDEX IF NOT EXISTS idx_persistence_detections_severity 
        ON persistence_detections(severity);
    CREATE INDEX IF NOT EXISTS idx_persistence_detections_detected_at 
        ON persistence_detections(detected_at);
    `
    return s.db.Exec(schema).Error
}

func (s *PersistenceDetectionStore) SaveResult(result *persistence.DetectionResult) error {
    tx := s.db.Begin()
    
    for _, det := range result.Detections {
        detectionID := det.ID
        if detectionID == "" {
            detectionID = fmt.Sprintf("det_%d", time.Now().UnixNano())
        }
        
        evidence := det.Evidence
        mitreRef := ""
        if len(det.MITRERef) > 0 {
            mitreRef = strings.Join(det.MITRERef, ",")
        }
        
        record := &PersistenceDetectionRecord{
            DetectionID:        detectionID,
            Technique:         string(det.Technique),
            Category:          det.Category,
            Severity:          string(det.Severity),
            Title:             det.Title,
            Description:       det.Description,
            EvidenceType:      string(evidence.Type),
            EvidencePath:      evidence.Path,
            EvidenceKey:       evidence.Key,
            EvidenceValue:     evidence.Value,
            EvidenceFilePath:  evidence.FilePath,
            EvidenceCommand:   evidence.Command,
            MITRERef:         mitreRef,
            RecommendedAction: det.RecommendedAction,
            FalsePositiveRisk: det.FalsePositiveRisk,
            DetectedAt:        det.Time,
        }
        
        if err := tx.Create(record).Error; err != nil {
            tx.Rollback()
            return err
        }
    }
    
    return tx.Commit().Error
}

type PersistenceDetectionRecord struct {
    ID                  int64     `gorm:"primaryKey"`
    DetectionID         string    `gorm:"uniqueIndex"`
    Technique           string    `gorm:"index"`
    Category            string
    Severity            string    `gorm:"index"`
    Title              string
    Description        string
    EvidenceType       string
    EvidencePath       string
    EvidenceKey        string
    EvidenceValue      string
    EvidenceFilePath   string
    EvidenceCommand    string
    MITRERef           string
    RecommendedAction  string
    FalsePositiveRisk  string
    DetectedAt         time.Time `gorm:"index"`
    IsTruePositive     int       `gorm:"default:-1"`
    Notes              string
    CreatedAt          time.Time
}

func (s *PersistenceDetectionStore) Query(req *PersistenceQueryRequest) ([]*persistence.Detection, int64, error) {
    query := s.db.Model(&PersistenceDetectionRecord{})
    
    if req.Technique != "" {
        query = query.Where("technique = ?", req.Technique)
    }
    if req.Category != "" {
        query = query.Where("category = ?", req.Category)
    }
    if req.Severity != "" {
        query = query.Where("severity = ?", req.Severity)
    }
    if !req.StartTime.IsZero() {
        query = query.Where("detected_at >= ?", req.StartTime)
    }
    if !req.EndTime.IsZero() {
        query = query.Where("detected_at <= ?", req.EndTime)
    }
    if req.IsTruePositive != -1 {
        query = query.Where("is_true_positive = ?", req.IsTruePositive)
    }
    
    var total int64
    query.Count(&total)
    
    var records []PersistenceDetectionRecord
    query.Order("detected_at DESC").
        Limit(req.Limit).
        Offset(req.Offset).
        Find(&records)
    
    detections := make([]*persistence.Detection, len(records))
    for i, r := range records {
        detections[i] = s.recordToDetection(&r)
    }
    
    return detections, total, nil
}

type PersistenceQueryRequest struct {
    Technique     string
    Category      string
    Severity      string
    StartTime     time.Time
    EndTime       time.Time
    IsTruePositive int
    Limit         int
    Offset        int
}
```

**3.2 扩展 API Handler**

修改 `handlers_persistence.go`:

```go
type PersistenceHandler struct {
    db    *storage.PersistenceDetectionStore
    cache *DetectionCache
}

func NewPersistenceHandler(db *storage.DB) *PersistenceHandler {
    store := storage.NewPersistenceDetectionStore(db)
    store.InitSchema()  // 初始化表
    
    return &PersistenceHandler{
        db:    store,
        cache: &DetectionCache{ttl: defaultCacheTTL},
    }
}

// 新增 API: 保存检测结果
func (h *PersistenceHandler) SaveDetection(c *gin.Context) {
    var result persistence.DetectionResult
    if err := c.ShouldBindJSON(&result); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    if err := h.db.SaveResult(&result); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    
    c.JSON(http.StatusOK, gin.H{"status": "saved"})
}

// 新增 API: 查询历史检测
func (h *PersistenceHandler) QueryDetections(c *gin.Context) {
    var req storage.PersistenceQueryRequest
    if err := c.ShouldBindQuery(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    if req.Limit <= 0 || req.Limit > 1000 {
        req.Limit = 100
    }
    
    detections, total, err := h.db.Query(&req)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "detections": detections,
        "total":      total,
    })
}

// 新增 API: 标记真阳性/误报
func (h *PersistenceHandler) MarkDetection(c *gin.Context) {
    var req struct {
        DetectionID string `json:"detection_id"`
        IsTruePositive bool `json:"is_true_positive"`
        Notes string `json:"notes"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    // 更新数据库记录
    // ...
    
    c.JSON(http.StatusOK, gin.H{"status": "updated"})
}
```

**3.3 添加新路由**

```go
func SetupPersistenceRoutes(r *gin.Engine, h *PersistenceHandler, db *storage.DB) {
    // 重新初始化 handler（传入 db）
    persistenceHandler := NewPersistenceHandler(db)
    
    persistenceGroup := r.Group("/api/persistence")
    {
        persistenceGroup.GET("/detect", persistenceHandler.Detect)
        persistenceGroup.POST("/save", persistenceHandler.SaveDetection)      // 新增
        persistenceGroup.GET("/history", persistenceHandler.QueryDetections) // 新增
        persistenceGroup.POST("/mark", persistenceHandler.MarkDetection)    // 新增
        persistenceGroup.GET("/categories", persistenceHandler.ListCategories)
        persistenceGroup.GET("/techniques", persistenceHandler.ListTechniques)
    }
}
```

#### 架构适配性

- **适配**: 完全符合现有 storage 层架构
- **风险**: 中，需要数据库迁移
- **可靠性**: 高，使用 GORM 成熟 ORM

#### 工时分解

| 任务 | 工时 |
|------|------|
| 设计数据库 schema | 1h |
| 实现 storage 层 | 2h |
| 扩展 API Handler | 1h |
| 添加路由和初始化 | 0.5h |
| 测试验证 | 1.5h |

---

### P2-1: 添加检测进度反馈

**严重程度**: 低 | **优先级**: P2 | **预估工时**: 4h

#### 问题

长时间检测无进度反馈，用户体验差。

#### 解决方案

使用 SSE (Server-Sent Events) 流式返回进度：

**修改 `handlers_persistence.go`**:

```go
func (h *PersistenceHandler) DetectStream(c *gin.Context) {
    // 设置 SSE headers
    c.Header("Content-Type", "text/event-stream")
    c.Header("Cache-Control", "no-cache")
    c.Header("Connection", "keep-alive")
    
    // ... 解析参数 ...
    
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    // 使用 channel 收集进度更新
    progressChan := make(chan string, 10)
    doneChan := make(chan *persistence.DetectionResult, 1)
    
    go func() {
        result := persistence.RunAllDetectorsWithProgress(ctx, progressChan)
        doneChan <- result
    }()
    
    c.Stream(func(w io.Writer) bool {
        select {
        case progress, ok := <-progressChan:
            if ok {
                c.SSEvent("progress", progress)
                return true
            }
        case result, ok := <-doneChan:
            if ok {
                c.SSEvent("result", result)
            }
            return false
        case <-c.Request.Context().Done():
            cancel()
            return false
        }
        return false
    })
}
```

**修改 `detector.go`**:

```go
// RunAllDetectorsWithProgress 带进度回调的检测
func RunAllDetectorsWithProgress(ctx context.Context, progressChan chan<- string) *DetectionResult {
    engine := NewDetectionEngine()
    registerAllDetectors(engine)
    
    detectors := engine.ListDetectors()
    total := len(detectors)
    
    result := NewDetectionResult()
    var wg sync.WaitGroup
    resultChan := make(chan *Detection, 100)
    errorChan := make(chan string, 10)
    
    for i, d := range detectors {
        wg.Add(1)
        detectorName := d.Name
        go func(idx int, name string, detector Detector) {
            defer wg.Done()
            
            progressChan <- fmt.Sprintf("Running %s (%d/%d)", name, idx+1, total)
            
            detections, err := detector.Detect(ctx)
            if err != nil {
                errorChan <- fmt.Sprintf("%s: %v", name, err)
                return
            }
            
            for _, det := range detections {
                if det.ID == "" {
                    det.ID = uuid.New().String()
                }
                if det.Time.IsZero() {
                    det.Time = time.Now()
                }
                resultChan <- det
            }
        }(i, detectorName, d)
    }
    
    go func() {
        wg.Wait()
        close(resultChan)
        close(errorChan)
    }()
    
    for det := range resultChan {
        result.Add(det)
    }
    
    for errMsg := range errorChan {
        result.Errors = append(result.Errors, errMsg)
        result.ErrorCount++
    }
    
    progressChan <- "complete"
    return result
}
```

#### 架构适配性

- **适配**: 完全符合现有架构，复用 RunAllDetectors
- **风险**: 低，新增函数不影响现有逻辑
- **可靠性**: 高，进度反馈是可选优化

---

### P2-2: 改进 WMI 检测使用结构化数据

**严重程度**: 低 | **优先级**: P2 | **预估工时**: 6h

#### 问题

WMI 检测使用 PowerShell 字符串输出 + 手动 JSON 解析，脆弱。

#### 解决方案

使用 Go-OLE 库直接调用 COM：

```go
// wmi.go 使用 go-ole

import (
    "github.com/go-ole/go-ole"
    "github.com/go-ole/go-ole/oleutil"
)

func (d *WMIPersistenceDetector) enumerateConsumersCOM() ([]WMIEventConsumer, error) {
    consumers := make([]WMIEventConsumer, 0)
    
    ole.CoInitializeEx(nil, ole.COINIT_MULTITHREADED)
    defer ole.CoUninitialize()
    
    // 连接 WMI
    unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
    if err != nil {
        return consumers, err
    }
    defer unknown.Release()
    
    wmi, err := unknown.QueryInterface(ole.IID_IDispatch)
    if err != nil {
        return consumers, err
    }
    defer wmi.Release()
    
    // 连接 Root\Subscription 命名空间
    service, err := oleutil.CallMethod(wmi, "ConnectServer", nil, `Root\Subscription`)
    if err != nil {
        return consumers, err
    }
    defer service.Release()
    
    // 查询 CommandLineEventConsumer
    consumersRaw, err := oleutil.CallMethod(service, "InstancesOf", `CommandLineEventConsumer`)
    if err != nil {
        return consumers, err
    }
    
    // 遍历结果
    enumrator := consumersRaw.ToIUnknown().IEnumVARIANT()
    if enumrator != nil {
        defer enumrator.Release()
        for {
            var item ole.VARIANT
            hr, _ := enumrator.Next(1, &item)
            if hr != 0 {
                break
            }
            
            disp := item.ToIDispatch()
            name := oleutil.GetProperty(disp, "Name").ToString()
            cmdLine := oleutil.GetProperty(disp, "CommandLine").ToString()
            
            consumers = append(consumers, WMIEventConsumer{
                Name:        name,
                Type:        "CommandLineEventConsumer",
                CommandLine: cmdLine,
            })
            
            disp.Release()
            ole.ReleaseVariants(&item)
        }
    }
    
    return consumers, nil
}
```

**注意**: 需要添加 `go-ole` 依赖：

```bash
go get github.com/go-ole/go-ole
```

#### 架构适配性

- **适配**: 需要添加新依赖
- **风险**: 中，go-ole 是成熟库
- **可靠性**: 高，结构化数据更可靠

---

## 三、改进优先级矩阵

| 编号 | 问题 | 优先级 | 工时 | 复杂度 | 适配性 | 必要性 | 可靠性 |
|------|------|--------|------|--------|--------|--------|--------|
| P0-1 | 代码重复 | P0 | 1h | 低 | 高 | 高 | 高 |
| P0-2 | 白名单不足 | P0 | 4h | 中 | 高 | 高 | 高 |
| P1-1 | 超时控制 | P1 | 1h | 低 | 高 | 中 | 高 |
| P1-2 | 缓存机制 | P1 | 2h | 低 | 高 | 中 | 高 |
| P1-3 | 结果持久化 | P1 | 6h | 中 | 高 | 中 | 高 |
| P2-1 | 进度反馈 | P2 | 4h | 中 | 高 | 低 | 高 |
| P2-2 | WMI 字符串解析 | P2 | 6h | 高 | 中 | 低 | 中 |

---

## 四、实施计划

### 第一阶段: 核心修复 (P0)

**目标**: 消除代码重复，完善白名单

| 任务 | 工时 | 依赖 |
|------|------|------|
| P0-1: 消除代码重复 | 1h | 无 |
| P0-2: 扩展白名单 | 4h | P0-1 |

**里程碑**: 代码质量提升，误报率降低

---

### 第二阶段: 稳定性增强 (P1)

**目标**: 添加超时、缓存、持久化

| 任务 | 工时 | 依赖 |
|------|------|------|
| P1-1: 超时控制 | 1h | P0-1 |
| P1-2: 缓存机制 | 2h | P1-1 |
| P1-3: 结果持久化 | 6h | P1-2 |

**里程碑**: API 响应更稳定，支持历史记录

---

### 第三阶段: 用户体验优化 (P2)

**目标**: 进度反馈，WMI 改进

| 任务 | 工时 | 依赖 |
|------|------|------|
| P2-1: 进度反馈 | 4h | P1-1 |
| P2-2: WMI 改进 | 6h | P0-1 |

**里程碑**: 用户体验显著提升

---

## 五、验证方法

### 代码验证

```bash
cd winalog-go

# 编译检查
go build ./internal/persistence/...
go build ./cmd/winalog/...
go build ./internal/api/...

# 测试运行
go test ./internal/persistence/... -v

# 手动测试 CLI
winalog persistence detect --category registry

# API 测试
curl "http://localhost:8080/api/persistence/detect"
```

### 回归测试

```bash
# 确保现有功能不受影响
go test ./... -count=1

# 对比改进前后输出
winalog persistence detect -o before.json
# 实施改进后
winalog persistence detect -o after.json
diff before.json after.json
```

---

## 六、风险评估

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| 白名单扩展引入漏报 | 高 | 严格测试，只添加已验证的安全项 |
| 缓存导致数据过期 | 中 | 设置合理 TTL，提供手动刷新 |
| 数据库迁移失败 | 中 | 做好备份，支持 schema 自动升级 |
| go-ole 依赖兼容性问题 | 低 | 充分测试 Windows 版本 |

---

## 七、总结

本方案针对持久化检测模块的 7 个问题提出了具体实施方案：

1. **P0-1 代码重复**: 1h，消除 3 处完全重复的代码
2. **P0-2 白名单不足**: 4h，扩展白名单至 150+ 项
3. **P1-1 超时控制**: 1h，添加 context 超时
4. **P1-2 缓存机制**: 2h，添加 30s TTL 缓存
5. **P1-3 结果持久化**: 6h，支持历史检测记录
6. **P2-1 进度反馈**: 4h，SSE 流式进度
7. **P2-2 WMI 改进**: 6h，使用 go-ole 结构化调用

**总工时**: 24h

**预期效果**:
- 代码可维护性显著提升
- 误报率降低 50%+
- API 响应速度提升 3-5 倍（使用缓存）
- 支持历史检测和趋势分析

---

*文档版本: v1.0 | 更新日期: 2026-04-17*