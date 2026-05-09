# Engine 模块

**路径**: `internal/engine/`

核心导入引擎，负责日志文件的解析和入库。

## 核心组件

### Engine

```go
type Engine struct {
    db        *storage.DB
    parsers   *parsers.ParserRegistry
    eventRepo *storage.EventRepo
    alertRepo *storage.AlertRepo
    importCfg ImportConfig
}
```

Engine 是整个系统的核心，协调解析器、存储和告警引擎。

### ImportConfig

```go
type ImportConfig struct {
    Workers          int      // 并发 Worker 数量，默认 4
    BatchSize        int      // 批量插入大小，默认 10000
    SkipPatterns     []string // 跳过文件模式，默认 ["Diagnostics", "Debug"]
    Incremental      bool     // 增量导入，默认 true
    CalculateHash    bool     // 计算文件哈希，默认 true
    ProgressCallback bool     // 进度回调，默认 true
}
```

## 导入流程

```
┌─────────────┐
│ collectFiles │ 收集待导入文件
└──────┬──────┘
       ▼
┌─────────────┐
│ Worker Pool │ 创建 Worker 池
└──────┬──────┘
       ▼
┌─────────────┐
│  并发解析   │ ◄── 每个文件一个 goroutine
└──────┬──────┘
       ▼
┌─────────────┐
│  批量入库   │ ◄── BatchSize 为单位
└──────┬──────┘
       ▼
┌─────────────┐
│  记录日志   │ ◄── ImportLog
└─────────────┘
```

## 主要方法

### NewEngine

```go
func NewEngine(db *storage.DB) *Engine
```

创建引擎实例。

### Import

```go
func (e *Engine) Import(
    ctx context.Context,
    req *ImportRequest,
    progressFn func(*ImportProgress)
) (*ImportResult, error)
```

导入日志文件。

**参数**:
- `ctx`: 上下文，用于取消
- `req`: 导入请求
- `progressFn`: 进度回调函数

**返回**:
- `ImportResult`: 导入结果统计

**示例**:

```go
result, err := engine.Import(ctx, &ImportRequest{
    Paths:   []string{"security.evtx", "system.evtx"},
    Workers: 4,
    BatchSize: 10000,
}, func(progress *ImportProgress) {
    fmt.Printf("Progress: %d/%d files, %d events\r",
        progress.CurrentFile, progress.TotalFiles, progress.EventsImported)
})
```

### Search

```go
func (e *Engine) Search(req *types.SearchRequest) (*types.SearchResponse, error)
```

搜索事件。

### GetStats

```go
func (e *Engine) GetStats() (*storage.DBStats, error)
```

获取数据库统计信息。

## 内部实现

### Worker Pool

使用信号量模式控制并发:

```go
workerPool := make(chan struct{}, e.importCfg.Workers)
var wg sync.WaitGroup

for i, file := range files {
    workerPool <- struct{}{}  // 获取令牌
    wg.Add(1)
    go func(idx int, path string) {
        defer wg.Done()
        defer func() { <-workerPool }()  // 释放令牌
        // 处理文件...
    }(i, file)
}
wg.Wait()
```

### Batch Insert

事件累积到 BatchSize 后批量入库:

```go
var batch []*types.Event
for event := range events {
    batch = append(batch, event)
    if len(batch) >= e.importCfg.BatchSize {
        if err := e.eventRepo.InsertBatch(batch); err != nil {
            // 处理错误
        }
        batch = batch[:0]  // 清空批次
    }
}
// 处理剩余事件
if len(batch) > 0 {
    e.eventRepo.InsertBatch(batch)
}
```

## 文件过滤

```go
func collectFiles(paths []string, skipPatterns []string) []string

func shouldSkip(path string, patterns []string) bool
```

支持的扩展名: `.evtx`, `.etl`, `.csv`, `.log`, `.txt`
