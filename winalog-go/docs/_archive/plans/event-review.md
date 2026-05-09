# WinLogAnalyzer-Go 事件模块问题报告

> 评估日期: 2026-04-17
> 评估范围: `internal/engine/` + `internal/storage/events.go` + `internal/parsers/` + `internal/api/handlers.go` (事件相关) + CLI import 命令

---

## 一、事件模块架构概述

### 1.1 核心组件

```
事件模块
├── internal/types/event.go          # 事件数据结构
├── internal/storage/events.go       # SQLite 持久化层
├── internal/engine/
│   ├── engine.go                    # 核心引擎 (导入/搜索)
│   └── importer.go                  # 文件导入逻辑
├── internal/parsers/               # 解析器注册表
│   ├── parser.go                    # Parser 接口 + Registry
│   ├── evtx/parser.go               # Windows EVTX 解析
│   ├── etl/parser.go                # ETL 解析
│   ├── csv/parser.go                # CSV 解析
│   ├── iis/parser.go                # IIS 日志解析
│   └── sysmon/parser.go             # Sysmon 日志解析
├── internal/api/
│   ├── handlers.go                  # 事件 API handlers
│   └── handlers_live.go             # SSE 实时流
└── cmd/winalog/commands/
    └── import.go                    # CLI 导入命令
```

### 1.2 数据流

```
EVTX/ETL/CSV 文件
       ↓
ParserRegistry.Get(path)  ──→ 选择合适的 Parser
       ↓
Parser.Parse(path)  ──→ 返回 <-chan *types.Event
       ↓
Engine.Import() / Importer.ImportFile()
       ↓
EventRepo.InsertBatch()  ──→ SQLite WAL 模式
       ↓
存储完成
```

### 1.3 CLI vs Web 模式对比

| 功能 | CLI | Web API |
|------|-----|---------|
| 导入事件 | `winalog import <path>` | `POST /api/collect/import` |
| 列出事件 | 无直接命令 | `GET /api/events` |
| 搜索事件 | 无 | `POST /api/events/search` |
| 导出事件 | 无 | `POST /api/events/export` |
| 实时流 | 无 | `GET /api/live/events` (SSE) |

---

## 二、现有设计原理

### 2.1 解析器注册表模式

```go
// internal/parsers/parser.go
type Parser interface {
    CanParse(path string) bool
    Parse(path string) <-chan *types.Event  // 流式解析
    ParseBatch(path string) ([]*types.Event, error)
    GetType() string
    Priority() int
}
```

特点：
- 支持多种文件格式自动识别
- 流式解析避免内存溢出
- 优先级机制处理格式冲突（如 CSV vs Sysmon）

### 2.2 批量插入优化

```go
// internal/storage/events.go
func (r *EventRepo) InsertBatch(events []*types.Event) error {
    tx, unlock, err := r.db.Begin()
    stmt, err := tx.Prepare(`INSERT INTO events ...`)
    for _, event := range events {
        stmt.Exec(...)  // 复用 prepared statement
    }
    tx.Commit()
}
```

### 2.3 Worker Pool 并行导入

```go
// internal/engine/engine.go
workerPool := make(chan struct{}, e.importCfg.Workers)  // 并发控制
for i, file := range files {
    workerPool <- struct{}{}
    wg.Add(1)
    go func(idx int, path string) {
        defer wg.Done()
        defer func() { <-workerPool }()
        // 导入文件...
    }(i, file)
}
```

---

## 三、问题清单

| ID | 问题 | 严重程度 | 修复复杂度 |
|----|------|---------|-----------|
| E01 | Live Handler 重复发送相同事件 | 高 | 低 |
| E02 | 搜索无 Sources 过滤支持 | 中 | 低 |
| E03 | ImportBatch 错误处理不完整 | 中 | 低 |
| E04 | Timeline API 缺少 Alert 合并 | 中 | 中 |
| E05 | 事件聚合功能缺失 | 高 | 高 |
| E06 | Incremental Import 基于 mtime 不准确 | 中 | 中 |
| E07 | 缺少事件字段提取机制 | 中 | 高 |
| E08 | 导入进度估算不准确 | 低 | 低 |
| E09 | RawXML 未被利用 | 低 | 中 |
| E10 | 搜索结果无缓存 | 低 | 中 |
| E11 | 事件去重功能缺失 | 低 | 中 |

---

## 四、详细问题分析与修复方案

---

## E01: Live Handler 重复发送相同事件

**严重程度: 高 | 修复复杂度: 低**

### 问题描述

`handlers_live.go` 中 `StreamEventsSSE` 每 2 秒查询 `h.db.ListEvents(filter)`，但 filter 只有 `Limit: 50`，没有时间过滤或 ID 过滤：

```go
// internal/api/handlers_live.go:68-72
filter := &storage.EventFilter{
    Limit: 50,  // 只有 limit，没有时间过滤
}
events, _, err := h.db.ListEvents(filter)
if err == nil && len(events) > 0 {
    for _, event := range events {
        if event.ID > lastEventID {  // 这个判断无用，因为查询结果顺序不确定
            // 发送事件...
        }
    }
}
```

问题：
1. 每次查询返回的事件顺序不确定（取决于 SQLite 内部实现）
2. `lastEventID` 判断无法保证只发送新事件
3. 应该基于 `import_time` 或 `timestamp` 过滤

### 修复方案

```go
// internal/api/handlers_live.go

type LiveHandler struct {
    db         *storage.DB
    startTime  time.Time
    eventCount int64
    lastCount  int64
    mu         sync.RWMutex
    lastImportTime time.Time  // 新增：记录上次导入时间
}

func (h *LiveHandler) StreamEventsSSE(c *gin.Context) {
    // ... 现有代码 ...

    for {
        select {
        case <-ticker.C:
            if h.db != nil {
                // 每次查询自上次检查以来新导入的事件
                filter := &storage.EventFilter{
                    Limit:     100,
                    StartTime: &h.lastImportTime,  // 只查新的
                }
                events, _, err := h.db.ListEvents(filter)
                if err == nil && len(events) > 0 {
                    for _, event := range events {
                        msg := LiveEventMessage{
                            Type: "event",
                            Data: formatLiveEvent(event),
                        }
                        c.SSEvent("event", msg)
                    }
                    // 更新最后导入时间
                    h.lastImportTime = events[len(events)-1].ImportTime
                }
                // ...
            }
        // ...
        }
    }
}
```

---

## E02: 搜索无 Sources 过滤支持

**严重程度: 中 | 修复复杂度: 低**

### 问题描述

`SearchEventsRequest` 定义了 `Sources []string` 字段，但 handler 中未使用：

```go
// internal/api/handlers.go:129-145
type SearchEventsRequest struct {
    Keywords  string   `json:"keywords"`
    Regex     bool     `json:"regex"`
    EventIDs  []int32  `json:"event_ids"`
    Levels    []int    `json:"levels"`
    LogNames  []string `json:"log_names"`
    Sources   []string `json:"sources"`    // 定义了但没使用！
    Users     []string `json:"users"`
    Computers []string `json:"computers"`
    // ...
}
```

### 修复方案

1. 在 `handlers.go` 的 `SearchEvents` 函数中添加 Sources 过滤：

```go
// internal/api/handlers.go

func (h *AlertHandler) SearchEvents(c *gin.Context) {
    var req SearchEventsRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, ErrorResponse{Error: err.Error(), Code: types.ErrCodeInvalidRequest})
        return
    }

    // ... 现有验证代码 ...

    filter := &storage.EventFilter{
        Keywords:  req.Keywords,
        Regex:     req.Regex,
        Limit:     req.PageSize,
        Offset:    (req.Page - 1) * req.PageSize,
        EventIDs:  req.EventIDs,
        Levels:    req.Levels,
        LogNames:  req.LogNames,
        Sources:   req.Sources,    // 添加这行
        Users:     req.Users,
        Computers: req.Computers,
        StartTime: startTime,
        EndTime:   endTime,
    }

    events, total, err := h.db.SearchEvents(filter)
    // ...
}
```

2. 在 `storage/events.go` 的 `Search` 方法中添加 Sources 过滤：

```go
// internal/storage/events.go

func (r *EventRepo) Search(req *types.SearchRequest) ([]*types.Event, int64, error) {
    var conditions []string
    var args []interface{}

    // ... 现有 conditions ...

    if len(req.Sources) > 0 {
        placeholders := make([]string, len(req.Sources))
        for i, source := range req.Sources {
            placeholders[i] = "?"
            args = append(args, source)
        }
        conditions = append(conditions, fmt.Sprintf("source IN (%s)", strings.Join(placeholders, ",")))
    }

    // ... 其余代码 ...
}
```

3. 在 `types.SearchRequest` 中添加 Sources 字段（如果缺失）：

```go
// internal/types/search.go（如果存在）

type SearchRequest struct {
    // ... 现有字段 ...
    Sources []string `json:"sources"`
}
```

---

## E03: ImportBatch 错误处理不完整

**严重程度: 中 | 修复复杂度: 低**

### 问题描述

在 `engine.go` 的 `importFile` 中，错误处理不完整：

```go
// internal/engine/engine.go:144-150
for event := range events {
    batch = append(batch, event)
    if len(batch) >= e.importCfg.BatchSize {
        if err := e.eventRepo.InsertBatch(batch); err != nil {
            lastErr = err
            break  // 只 break，batch 没有清空，会导致重复插入
        }
        totalEvents += int64(len(batch))
        batch = batch[:0]
    }
}
```

问题：
1. `break` 后 `batch` 未清空，可能导致部分事件在 finally 中被重复处理
2. `lastErr` 只记录第一个错误，后续批次失败被忽略
3. 没有记录具体哪个批次失败

### 修复方案

```go
// internal/engine/engine.go

func (e *Engine) importFile(ctx context.Context, path string) (*ImportResult, error) {
    parser := e.parsers.Get(path)
    if parser == nil {
        return nil, fmt.Errorf("no parser found for %s", path)
    }

    startTime := time.Now()
    events := parser.Parse(path)

    var batch []*types.Event
    var totalEvents int64
    var lastErr error
    var batchNum int

    for event := range events {
        select {
        case <-ctx.Done():
            return &ImportResult{EventsImported: totalEvents}, ctx.Err()
        default:
        }

        batch = append(batch, event)
        if len(batch) >= e.importCfg.BatchSize {
            batchNum++
            if err := e.eventRepo.InsertBatch(batch); err != nil {
                lastErr = fmt.Errorf("batch %d failed: %w", batchNum, err)
                // 不 break，继续处理剩余事件但记录错误
            } else {
                totalEvents += int64(len(batch))
            }
            batch = batch[:0]  // 确保清空 batch
        }
    }

    // 处理剩余事件
    if len(batch) > 0 {
        batchNum++
        if err := e.eventRepo.InsertBatch(batch); err != nil {
            lastErr = fmt.Errorf("batch %d (final) failed: %w", batchNum, err)
        } else {
            totalEvents += int64(len(batch))
        }
        batch = batch[:0]
    }

    duration := time.Since(startTime)
    e.db.InsertImportLog(path, "", int(totalEvents), int(duration.Milliseconds()), "success", "")

    return &ImportResult{
        EventsImported: totalEvents,
        Duration:       duration,
    }, lastErr
}
```

---

## E04: Timeline API 缺少 Alert 合并

**严重程度: 中 | 修复复杂度: 中**

### 问题描述

`GetTimeline` 只返回事件，不返回告警。用户需要两个独立 API：
- `GET /api/timeline` - 只返回事件
- `GET /api/alerts` - 只返回告警

没有统一的时序视图。

### 问题分析

```go
// internal/api/handlers.go:721-768
func (h *TimelineHandler) GetTimeline(c *gin.Context) {
    // 只获取事件，不获取告警
    events, _, err := h.db.ListEvents(eventFilter)
    for _, e := range events {
        entries = append(entries, &TimelineEntry{
            ID:        e.ID,
            Timestamp: e.Timestamp,
            Type:      "event",
            // ...
        })
    }
    // 没有合并 alerts
}
```

### 修复方案

```go
// internal/api/handlers.go

func (h *TimelineHandler) GetTimeline(c *gin.Context) {
    limitStr := c.DefaultQuery("limit", "200")
    limit, _ := strconv.Atoi(limitStr)
    if limit <= 0 || limit > 1000 {
        limit = 200
    }

    startTime := c.Query("start_time")
    endTime := c.Query("end_time")
    includeAlertsStr := c.DefaultQuery("include_alerts", "true")

    var start, end *time.Time
    // ... 时间解析 ...

    entries := make([]*TimelineEntry, 0)
    var eventCount, alertCount int

    // 获取事件
    eventFilter := &storage.EventFilter{
        Limit: limit,
    }
    if start != nil {
        eventFilter.StartTime = start
    }
    if end != nil {
        eventFilter.EndTime = end
    }
    events, _, err := h.db.ListEvents(eventFilter)
    if err != nil {
        log.Printf("failed to fetch events for timeline: %v", err)
    }
    for _, e := range events {
        entries = append(entries, &TimelineEntry{
            ID:        e.ID,
            Timestamp: e.Timestamp,
            Type:      "event",
            EventID:   e.EventID,
            Level:     e.Level.String(),
            Source:    e.Source,
            Message:   e.Message,
        })
        eventCount++
    }

    // 合并告警（如果启用）
    includeAlerts := includeAlertsStr != "false"
    if includeAlerts {
        alertFilter := &storage.AlertFilter{
            Limit: limit,
        }
        if start != nil {
            alertFilter.StartTime = start
        }
        if end != nil {
            alertFilter.EndTime = end
        }
        alerts, _, err := h.db.ListAlerts(alertFilter)
        if err != nil {
            log.Printf("failed to fetch alerts for timeline: %v", err)
        }
        for _, a := range alerts {
            entries = append(entries, &TimelineEntry{
                ID:       a.ID,
                Timestamp: a.FirstSeen,
                Type:     "alert",
                AlertID:  &a.ID,
                Severity: string(a.Severity),
                Message:  a.Message,
                RuleName: a.RuleName,
            })
            alertCount++
        }
    }

    // 按时间排序并限制数量
    sort.Slice(entries, func(i, j int) bool {
        return entries[i].Timestamp.After(entries[j].Timestamp)
    })
    if len(entries) > limit {
        entries = entries[:limit]
    }

    c.JSON(200, TimelineResponse{
        Entries:    entries,
        TotalCount: len(entries),
        EventCount: eventCount,
        AlertCount: alertCount,
    })
}
```

---

## E05: 事件聚合功能缺失

**严重程度: 高 | 修复复杂度: 高**

### 问题描述

系统缺乏基于时间窗口的事件聚合能力，无法检测：
- 同一用户 N 分钟内登录失败次数
- 同一主机 N 分钟内错误事件数量
- 特定事件 ID 的突增

### 修复方案

新增聚合分析模块：

```go
// internal/analyzers/aggregation.go

package analyzers

import (
    "time"
    
    "github.com/kkkdddd-start/winalog-go/internal/types"
)

type AggregationRule struct {
    Name          string
    EventID      int32
    Window       time.Duration
    Threshold    int
    GroupBy      string  // "user", "computer", "source"
    AlertMessage string
}

type AggregationResult struct {
    RuleName   string
    GroupKey   string
    Count      int
    WindowStart time.Time
    WindowEnd   time.Time
    Events     []*types.Event
}

type AggregationAnalyzer struct {
    rules []AggregationRule
}

func NewAggregationAnalyzer() *AggregationAnalyzer {
    return &AggregationAnalyzer{
        rules: []AggregationRule{
            {
                Name:          "failed-login-aggregation",
                EventID:       4625,  // Windows 登录失败
                Window:        5 * time.Minute,
                Threshold:     10,
                GroupBy:       "user",
                AlertMessage:  "用户在 5 分钟内登录失败超过 10 次",
            },
            {
                Name:          "error-spike",
                EventID:       0,  // 所有错误级别
                Window:        1 * time.Minute,
                Threshold:     50,
                GroupBy:       "computer",
                AlertMessage:  "主机在 1 分钟内产生超过 50 个错误事件",
            },
        },
    }
}

func (a *AggregationAnalyzer) Analyze(events []*types.Event) ([]*AggregationResult, error) {
    results := make([]*AggregationResult, 0)
    
    // 按规则分组处理
    for _, rule := range a.rules {
        windowEvents := a.groupEventsByWindow(events, rule)
        for groupKey, groupEvents := range windowEvents {
            if len(groupEvents) >= rule.Threshold {
                results = append(results, &AggregationResult{
                    RuleName:   rule.Name,
                    GroupKey:   groupKey,
                    Count:      len(groupEvents),
                    WindowStart: groupEvents[0].Timestamp,
                    WindowEnd:   groupEvents[len(groupEvents)-1].Timestamp,
                    Events:     groupEvents,
                })
            }
        }
    }
    
    return results, nil
}

func (a *AggregationAnalyzer) groupEventsByWindow(events []*types.Event, rule AggregationRule) map[string][]*types.Event {
    groups := make(map[string][]*types.Event)
    
    for _, e := range events {
        if rule.EventID != 0 && e.EventID != rule.EventID {
            continue
        }
        
        var groupKey string
        switch rule.GroupBy {
        case "user":
            if e.User != nil {
                groupKey = *e.User
            }
        case "computer":
            groupKey = e.Computer
        case "source":
            groupKey = e.Source
        default:
            groupKey = "global"
        }
        
        groups[groupKey] = append(groups[groupKey], e)
    }
    
    return groups
}
```

---

## E06: Incremental Import 基于 mtime 不准确

**严重程度: 中 | 修复复杂度: 中**

### 问题描述

当前增量导入只检查文件修改时间：

```go
// internal/engine/importer.go:194-207
if im.incremental {
    lastImport := im.db.GetLastImportTime(path)
    if lastImport != nil {
        info.LastImport = lastImport
        if info.ModTime.Before(*lastImport) || info.ModTime.Equal(*lastImport) {
            info.NeedsImport = false  // 只看 mtime
        }
    }
}
```

问题：
1. 文件追加新事件但 mtime 不变 → 漏导入
2. 文件复制后 mtime 变化 → 重复导入

### 修复方案

使用文件 hash + mtime 双重检测：

```go
// internal/engine/importer.go

type FileInfo struct {
    Path        string
    Size        int64
    ModTime     time.Time
    Hash        string
    FileType    string
    IsLocked    bool
    NeedsImport bool
    LastImport  *time.Time
    LastHash    string  // 新增：上次导入时的 hash
}

func (im *Importer) GetFileInfo(path string, calcHash bool) (*FileInfo, error) {
    fi, err := os.Stat(path)
    // ...
    
    if im.incremental {
        lastImport := im.db.GetLastImportTime(path)
        if lastImport != nil {
            info.LastImport = lastImport
            
            // 计算当前 hash
            currentHash, _ := im.CalculateFileHash(path)
            lastLog := im.db.GetImportLog(path)
            
            if lastLog != nil && lastLog.FileHash != "" {
                info.LastHash = lastLog.FileHash
                
                // 双重检查：hash 变了才需要导入
                if currentHash == lastLog.FileHash && 
                   (info.ModTime.Before(*lastImport) || info.ModTime.Equal(*lastImport)) {
                    info.NeedsImport = false
                } else {
                    info.NeedsImport = true
                }
            } else {
                // 旧记录没有 hash，降级到 mtime 检查
                if info.ModTime.Before(*lastImport) || info.ModTime.Equal(*lastImport) {
                    info.NeedsImport = false
                }
            }
        }
    }
    
    return info, nil
}
```

---

## E07: 缺少事件字段提取机制

**严重程度: 中 | 修复复杂度: 高**

### 问题描述

`Event.ExtractedFields` 被定义但从未填充。解析器只提取基本字段，Message 中的关键信息（如 `TargetUserName`, `LogonType`）未被提取。

### 修复方案

在解析器中添加字段提取：

```go
// internal/parsers/evtx/parser.go

func (p *EvtxParser) parseEvtxFile(path string) ([]*types.Event, error) {
    // ... 现有解析逻辑 ...
    
    for _, record := range records {
        event := &types.Event{
            // ... 基本字段 ...
        }
        
        // 提取字段
        event.ExtractedFields = p.extractFields(event.Message)
        
        events = append(events, event)
    }
    
    return events, nil
}

func (p *EvtxParser) extractFields(message string) map[string]interface{} {
    fields := make(map[string]interface{})
    
    // 简单的键值对提取
    patterns := []struct {
        key   string
        regex string
    }{
        {"TargetUserName", `Target User:\s*Name:\s*(\S+)`},
        {"LogonType", `Logon Type:\s*(\d+)`},
        {"IpAddress", `IpAddress:\s*(\S+)`},
        {"ProcessName", `Process Name:\s*(\S+)`},
        {"CommandLine", `Command Line:\s*(.+?)(?:\n|$)`},
    }
    
    for _, pattern := range patterns {
        if re := regexp.MustCompile(pattern.regex); re.MatchString(message) {
            if matches := re.FindStringSubmatch(message); len(matches) > 1 {
                fields[pattern.key] = matches[1]
            }
        }
    }
    
    return fields
}
```

---

## E08: 导入进度估算不准确

**严重程度: 低 | 修复复杂度: 低**

### 问题描述

进度回调只显示已处理文件数和事件数，无法估算剩余时间。

### 修复方案

添加速率计算和 ETA 估算：

```go
// internal/engine/engine.go

type ImportProgress struct {
    TotalFiles      int
    CurrentFile     int
    CurrentFileName string
    EventsImported  int64
    BytesProcessed  int64
    TotalBytes     int64  // 新增
    EventsPerSec   float64  // 新增
    EstimatedLeft   time.Duration  // 新增
}

func (e *Engine) Import(ctx context.Context, req *ImportRequest, progressFn func(*ImportProgress)) (*ImportResult, error) {
    // ...
    
    var totalBytes int64
    var startTime = time.Now()
    var lastUpdateTime = startTime
    var lastEvents int64
    
    for i, file := range files {
        // ...
        go func(idx int, path string) {
            // ...
            mu.Lock()
            result.EventsImported += fileResult.EventsImported
            
            // 计算速率和 ETA
            elapsed := time.Since(startTime)
            if elapsed > 0 {
                eventsPerSec := float64(result.EventsImported) / elapsed.Seconds()
                remainingEvents := estimateRemainingEvents(files, idx, result.EventsImported)
                eta := time.Duration(0)
                if eventsPerSec > 0 {
                    eta = time.Duration(float64(remainingEvents) / eventsPerSec * float64(time.Second))
                }
                
                if progressFn != nil {
                    progressFn(&ImportProgress{
                        TotalFiles:      result.TotalFiles,
                        CurrentFile:     idx + 1,
                        CurrentFileName: filepath.Base(path),
                        EventsImported:  result.EventsImported,
                        EventsPerSec:    eventsPerSec,
                        EstimatedLeft:   eta,
                    })
                }
            }
            mu.Unlock()
        }(i, file)
    }
    // ...
}

func estimateRemainingEvents(files []string, currentIdx int, imported int64) int64 {
    if currentIdx == 0 {
        return 0
    }
    avgPerFile := float64(imported) / float64(currentIdx+1)
    return int64(avgPerFile * float64(len(files)-currentIdx-1))
}
```

---

## E09: RawXML 未被利用

**严重程度: 低 | 修复复杂度: 中**

### 问题描述

`Event.RawXML` 字段存储但从未解析，无法利用 XML 中的丰富信息。

### 修复方案

添加 XML 解析选项：

```go
// internal/types/event.go

type Event struct {
    // ... 现有字段 ...
    ExtractedFields map[string]interface{} `json:"extracted_fields,omitempty" db:"-"`
    ParseXML        bool                   `json:"-"`  // 是否解析 XML
}

func (e *Event) ParseRawXML() error {
    if e.RawXML == nil || *e.RawXML == "" {
        return nil
    }
    
    // 简单 XML 解析
    decoder := xml.NewDecoder(strings.NewReader(*e.RawXML))
    for {
        token, err := decoder.Token()
        if err == io.EOF {
            break
        }
        if err != nil {
            return err
        }
        
        switch elem := token.(type) {
        case xml.StartElement:
            var data string
            if err := decoder.DecodeElement(&data, &elem); err == nil {
                e.SetExtractedField(elem.Name.Local, data)
            }
        }
    }
    return nil
}
```

---

## E10: 搜索结果无缓存

**严重程度: 低 | 修复复杂度: 中**

### 问题描述

高频搜索（如 Dashboard 刷新）每次都查询数据库。

### 修复方案

添加简单的内存缓存：

```go
// internal/engine/engine.go

type Engine struct {
    db        *storage.DB
    parsers   *parsers.ParserRegistry
    eventRepo *storage.EventRepo
    alertRepo *storage.AlertRepo
    importCfg ImportConfig
    
    // 新增缓存
    searchCache    *searchCache
}

type searchCache struct {
    mu          sync.RWMutex
    entries     map[string]*cacheEntry
    maxAge      time.Duration
    maxSize     int
}

type cacheEntry struct {
    result   *types.SearchResponse
    created  time.Time
    key      string
}

func NewEngine(db *storage.DB) *Engine {
    e := &Engine{
        // ...
        searchCache: &searchCache{
            entries:  make(map[string]*cacheEntry),
            maxAge:   30 * time.Second,
            maxSize:  100,
        },
    }
    return e
}

func (e *Engine) Search(req *types.SearchRequest) (*types.SearchResponse, error) {
    // 生成缓存 key
    cacheKey := e.generateCacheKey(req)
    
    // 尝试从缓存获取
    if entry := e.searchCache.get(cacheKey); entry != nil {
        return entry.result, nil
    }
    
    // 执行查询
    result, err := e.eventRepo.Search(req)
    if err != nil {
        return nil, err
    }
    
    // 存入缓存
    e.searchCache.set(cacheKey, result)
    
    return result, nil
}

func (c *searchCache) get(key string) *cacheEntry {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    if entry, ok := c.entries[key]; ok {
        if time.Since(entry.created) < c.maxAge {
            return entry
        }
    }
    return nil
}
```

---

## E11: 事件去重功能缺失

**严重程度: 低 | 修复复杂度: 中**

### 问题描述

导入时没有基于事件内容去重，可能产生重复事件。

### 修复方案

在 `InsertBatch` 中添加去重：

```go
// internal/storage/events.go

func (r *EventRepo) InsertBatch(events []*types.Event) error {
    if len(events) == 0 {
        return nil
    }
    
    // 导入前先去重
    uniqueEvents := r.deduplicate(events)
    
    tx, unlock, err := r.db.Begin()
    // ...
}

func (r *EventRepo) deduplicate(events []*types.Event) []*types.Event {
    seen := make(map[string]bool)
    unique := make([]*types.Event, 0, len(events))
    
    for _, e := range events {
        key := r.generateEventKey(e)
        if !seen[key] {
            seen[key] = true
            unique = append(unique, e)
        }
    }
    
    return unique
}

func (r *EventRepo) generateEventKey(e *types.Event) string {
    return fmt.Sprintf("%d|%s|%s|%s|%s",
        e.EventID,
        e.Timestamp.Format(time.RFC3339Nano),
        e.Computer,
        e.Message,
        e.getUserKey())
}

func (e *Event) getUserKey() string {
    if e.UserSID != nil {
        return *e.UserSID
    }
    if e.User != nil {
        return *e.User
    }
    return ""
}
```

---

## 五、修复优先级

| 优先级 | 问题 | 工作量 | 风险 |
|--------|------|--------|------|
| P1 | E01 Live Handler 重复发送 | 2h | 低 |
| P1 | E03 ImportBatch 错误处理 | 1h | 低 |
| P2 | E02 搜索 Sources 过滤 | 1h | 低 |
| P2 | E04 Timeline 合并 Alert | 3h | 中 |
| P2 | E06 Incremental Import 改进 | 3h | 中 |
| P3 | E05 事件聚合 | 8h+ | 高 |
| P3 | E08 进度估算 | 2h | 低 |
| P3 | E07 字段提取 | 6h | 高 |
| P4 | E09 RawXML 解析 | 4h | 中 |
| P4 | E10 搜索缓存 | 3h | 中 |
| P4 | E11 事件去重 | 3h | 低 |

---

## 六、总结

事件模块整体架构合理，采用了：
- 解析器注册表模式支持多格式
- 流式解析避免内存溢出
- WAL 模式 SQLite 支持高并发
- Worker pool 并行导入

主要问题集中在：
1. **Live Handler 的查询逻辑缺陷** - 每次返回相同事件
2. **搜索过滤不完整** - Sources 字段未实现
3. **错误处理不健壮** - 批量导入失败后可能重复
4. **缺乏高级分析** - 无聚合、去重等能力

建议按优先级逐步修复 P1 问题，再考虑 P2/P3 的增强功能。
