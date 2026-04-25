# LiveCollector 模块

Windows 事件日志实时采集模块，使用 Windows Event Log API (`wevtapi.dll`) 实现推送式订阅。

## 核心组件

### 1. EvtLiveCollector (`evt_collector.go`)

Windows Event Log 实时采集器，使用 `EvtSubscribe` API 实现事件推送。

**关键特性**:
- 使用 `CreateEvent` + `WaitForSingleObject` 实现真正的推送通知（非轮询）
- 支持书签续传（Bookmark），重启后可从上次位置继续
- 支持 XPath 查询过滤
- 线程安全

**架构流程**:
```
Start()
  ├─ CreateEvent() → signalEvent
  ├─ loadBookmark() → EvtCreateBookmark(XML)
  └─ EvtSubscribe(channel, bookmark, signalEvent)

runLoop()
  └─ WaitForSingleObject(signalEvent, INFINITE)
       └─ EvtNext() → fetch events
          └─ channel <- events
          └─ ResetEvent(signalEvent)

Stop()
  ├─ saveBookmark()
  └─ CloseHandle(signalEvent/session/bookmark)
```

**API 调用**:
| 函数 | Windows API | 作用 |
|------|-------------|------|
| `EvtSubscribe` | `wevtapi.dll!EvtSubscribe` | 订阅事件通道 |
| `EvtNext` | `wevtapi.dll!EvtNext` | 获取下一个事件 |
| `EvtRender` | `wevtapi.dll!EvtRender` | 渲染事件为 XML |
| `EvtCreateBookmark` | `wevtapi.dll!EvtCreateBookmark` | 创建书签 |
| `EvtUpdateBookmark` | `wevtapi.dll!EvtUpdateBookmark` | 更新书签 |

### 2. Event Render (`evt_render.go`)

将 Windows Event XML 解析为 `types.Event` 结构。

**解析内容**:
- `Provider Name` → `event.Source`
- `EventID` → `event.EventID`
- `Level` → `event.Level`
- `Channel` → `event.LogName`
- `Computer` → `event.Computer`
- `TimeCreated SystemTime` → `event.Timestamp`
- `EventRecordID` → `event.RecordID`
- `ProcessID/ThreadID` → `event.ProcessID/event.ThreadID`
- `UserID` → `event.User`
- `Data` → `event.Message`

### 3. Bookmark (`bookmark.go`, `evt_bookmark.go`)

事件书签管理，支持采集断点续传。

**Bookmark 结构**:
```go
type Bookmark struct {
    lastTime time.Time  // 最后事件时间
    lastID   int64      // 最后事件 ID
    path     string     // 持久化路径
}
```

**持久化格式**:
```xml
Channel="Security"
RecordID="12345"
TimeCreated="2026-04-17T10:30:00Z"
```

### 4. EventFilter (`filtered.go`)

7 种事件过滤器，均实现 `EventFilter` 接口。

**过滤器类型**:

| 过滤器 | 结构 | 匹配方式 |
|--------|------|----------|
| LevelFilter | 事件级别 | 精确匹配 |
| EventIDFilter | 事件 ID | 精确匹配 |
| SourceFilter | 提供者名称 | 精确匹配 |
| LogNameFilter | 日志名称 | 精确匹配 |
| TimeRangeFilter | 时间范围 | startTime ≤ timestamp ≤ endTime |
| KeywordFilter | 关键词 | 消息内容包含 |
| CompositeFilter | 组合过滤器 | AND 逻辑 |

**使用示例**:
```go
filter := NewCompositeFilter(
    NewLevelFilter(1, 2),                    // Critical/Error
    NewEventIDFilter(4624, 4625),            // 登录事件
    NewTimeRangeFilter(start.Unix(), end.Unix()),
)
```

### 5. CollectStats (`stats.go`)

采集统计和自适应轮询。

**CollectStats**:
```go
type CollectStats struct {
    totalCollected  uint64
    totalErrors     uint64
    lastCollectTime time.Time
    collectors      map[string]*CollectorStats
}
```

**AdaptivePoller**:
- 根据负载动态调整轮询间隔
- 负载 > 80%：间隔 × 1.5（最大 `maxInterval`）
- 负载 < 20%：间隔 ÷ 1.5（最小 `minInterval`）

## LiveCollector 框架 (`collector.go`)

主采集框架，管理多个 Collector 和过滤器。

```go
type LiveCollector struct {
    bookmark   *Bookmark
    filters    []EventFilter
    stats      *CollectStats
    collectors []Collector
}
```

**Collector 接口**:
```go
type Collector interface {
    Name() string
    Collect(ctx context.Context) ([]interface{}, error)
}
```

## 文件结构

```
internal/collectors/live/
├── collector.go        # LiveCollector 框架
├── evt_collector.go     # EvtLiveCollector 实现 (windows)
├── evt_render.go        # XML → Event 解析 (windows)
├── evt_bookmark.go      # Windows Bookmark API (windows)
├── bookmark.go          # Bookmark 持久化
├── filtered.go          # 7 种过滤器
├── stats.go             # 采集统计
└── *_test.go           # 测试文件
```

## 测试覆盖

| 测试文件 | 覆盖内容 |
|----------|----------|
| `collector_test.go` | LiveCollector, mockCollector |
| `bookmark_test.go` | Bookmark, BookmarkManager |
| `filtered_test.go` | 7 种 Filter |
| `stats_test.go` | CollectStats, AdaptivePoller |
| `evt_render_test.go` | ParseEventXML (Windows only) |

**测试结果**:
```
ok  github.com/kkkdddd-start/winalog-go/internal/collectors/live  0.157s
coverage: 98.2% of statements
```

## 使用示例

```go
// 创建采集器
collector := NewEvtLiveCollector("Security", "")
collector.SetBookmarkFile("security.bookmark")

// 启动采集
ctx := context.Background()
if err := collector.Start(ctx); err != nil {
    log.Fatal(err)
}

// 获取事件
results, _ := collector.Collect(ctx)
for _, r := range results {
    if event, ok := r.(*types.Event); ok {
        fmt.Printf("Event: %d from %s\n", event.EventID, event.Source)
    }
}

// 停止采集
collector.Stop()
```

## 构建要求

- 使用 `//go:build windows` 标签，Linux 上不编译
- 依赖 `golang.org/x/sys/windows`
- 需要 Windows Vista+ 或 Windows Server 2008+
