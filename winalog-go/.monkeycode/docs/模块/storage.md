# SQLite 数据存储层 (storage)

存储层基于 SQLite 提供事件、告警、导入日志等数据的持久化能力。

## 目录

- [文件结构](#文件结构)
- [数据库连接](#数据库连接)
- [数据库表一览](#数据库表一览)
- [EventRepo 核心方法](#eventrepo-核心方法)
- [AlertRepo 核心方法](#alertrepo-核心方法)
- [Repository 接口](#repository-接口)

## 文件结构

| 文件 | 说明 |
|------|------|
| `db.go` | DB 结构体、连接管理、事务、导入日志、实时事件 |
| `schema.go` | SchemaSQL 常量（完整建表语句）、表定义元数据 |
| `events.go` | EventRepo：事件 CRUD、搜索、FTS5 全文索引 |
| `alerts.go` | AlertRepo：告警 CRUD、统计、趋势分析 |
| `repository.go` | 接口定义：EventRepository、AlertRepository 等 |
| `persistence.go` | 持久化检测存储 |
| `rule_state.go` | 规则启用/禁用状态 |
| `system.go` | 系统信息、进程、网络快照 |
| `storage_test.go` | 存储层测试 |

## 数据库连接

### NewDB 连接流程

```go
func NewDB(path string) (*DB, error) {
    // 1. 解析绝对路径
    absPath, _ := filepath.Abs(path)
    os.MkdirAll(dir, 0755)

    // 2. DSN 配置（WAL 模式、超时、同步策略）
    dsn := absPath + "?_journal_mode=WAL&_busy_timeout=120000&_synchronous=NORMAL&_cache_size=-64000"
    conn, _ := sql.Open("sqlite", dsn)

    // 3. 连接池配置
    conn.SetMaxOpenConns(10)
    conn.SetMaxIdleConns(2)
    conn.SetConnMaxLifetime(time.Hour)

    // 4. 外键约束
    conn.Exec("PRAGMA foreign_keys = ON")

    // 5. 自动建表 + 迁移
    db.createTables()
}
```

### DB 结构体

```go
type DB struct {
    conn *sql.DB
    path string
    rwMu sync.RWMutex
}
```

- **WAL 模式**：Write-Ahead Logging，提升并发读写性能
- **连接池**：MaxOpen=10, MaxIdle=2, MaxLifetime=1h
- **读写锁**：`sync.RWMutex` 保护并发访问
- **Busy Timeout**：120 秒，避免并发写入冲突

### 数据库迁移

系统通过 `runMigrations()` 执行增量迁移，检测表结构变化：

| 迁移名 | 变更内容 |
|--------|----------|
| `add_event_db_ids_to_alerts` | alerts 表新增 `event_db_ids TEXT` 列 |
| `add_explanation_to_alerts` | alerts 表新增 `explanation TEXT` 列 |
| `add_recommendation_to_alerts` | alerts 表新增 `recommendation TEXT` 列 |
| `add_real_case_to_alerts` | alerts 表新增 `real_case TEXT` 列 |
| `create_persistence_detections_table` | 创建持久化检测表 |

## 数据库表一览

系统共有 **23 张表**，涵盖事件存储、告警管理、资产追踪、系统监控等：

| 表名 | 用途 | 索引 |
|------|------|------|
| `events` | 导入的 Windows 事件日志 | timestamp, event_id, level, log_name, computer, user, import_time |
| `events_fts` | FTS5 全文搜索虚拟表 | 自动索引 |
| `alerts` | 规则触发的告警记录 | rule_name, first_seen, severity, resolved |
| `import_log` | 文件导入历史记录 | import_time |
| `machine_context` | 机器上下文信息 | machine_id (唯一) |
| `machine_assets` | 混合资产管理 | role, importance |
| `multi_machine_analysis` | 多机分析结果 | analysis_id |
| `global_timeline` | 全局时间线 | event_id, timestamp |
| `sessions` | 会话追踪 | session_id (唯一) |
| `live_channels` | 实时监控频道配置 | name (主键) |
| `live_events` | 实时事件流 | id, timestamp, log_name, level |
| `evidence_chain` | 证据链哈希追踪 | evidence_id (唯一) |
| `evidence_file` | 证据文件记录 | file_hash |
| `processes` | 系统进程快照 | pid, name, collected_at |
| `network_connections` | 网络连接快照 | protocol, local_port, collected_at |
| `users` | 本地用户快照 | name, sid, collected_at |
| `drivers` | 系统驱动快照 | name, collected_at |
| `registry_persistence` | 注册表持久化点 | path, collected_at |
| `scheduled_tasks` | 计划任务快照 | task_name, collected_at |
| `system_info` | 系统信息快照 | hostname, collected_at |
| `reports` | 报告生成记录 | status, generated_at |
| `suppress_rules` | 告警抑制规则 | name, enabled |
| `rule_states` | 规则启用/禁用状态 | rule_name (唯一) |
| `ueba_baselines` | UEBA 学习基线 | user (主键) |

## EventRepo 核心方法

```go
type EventRepo struct {
    db              *DB
    ftsReady        bool
    pendingImportIDs []int64
    pendingMu       sync.Mutex
}
```

### 主要方法

| 方法 | 功能 | 说明 |
|------|------|------|
| `Insert(event)` | 插入单条事件 | 同时写入 FTS 索引 |
| `InsertBatch(events)` | 批量插入 | 去重 + 事务 + 分批（500条/批） |
| `GetByID(id)` | 按 ID 查询 | - |
| `GetByIDs(ids)` | 按 ID 列表查询 | - |
| `GetByEventIDs(eventIDs)` | 按 Windows EventID 查询 | 限 1000 条 |
| `Search(req)` | 高级搜索 | 支持 FTS5、关键词、多条件过滤、分页排序 |
| `SearchWithContext(ctx, req)` | 带超时的搜索 | 支持 context 取消 |
| `DeleteByImportID(importID)` | 按导入 ID 删除 | 同时清理 FTS 索引 |
| `DeleteOldEvents(age)` | 清理过期事件 | 按时间范围 |
| `GetByTimeRange(start, end)` | 时间范围查询 | - |
| `FlushFTS()` | 刷写 FTS 索引 | 批量导入后调用 |
| `RebuildFTS()` | 重建 FTS 索引 | 全量重建 |

### 搜索功能

支持多维度过滤：

- **关键词搜索**：FTS5 全文索引（AND/OR 模式）或 LIKE 回退
- **EventID 过滤**：支持多 EventID IN 查询
- **级别过滤**：Critical/Error/Warning/Info
- **日志名过滤**：Security/System/Application 等
- **计算机/用户过滤**：支持多值
- **时间范围**：StartTime / EndTime
- **排序**：按 timestamp/event_id/level 等字段，支持 ASC/DESC
- **分页**：Page + PageSize

### 去重机制

批量插入前通过 FNV 哈希去重：

```go
func (r *EventRepo) generateEventKey(e *types.Event) string {
    msgHash := fnvHash(e.Message)
    return fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s",
        e.EventID, e.Timestamp, e.Computer, e.LogName, e.Source, userKey, msgHash)
}
```

### 机器上下文自动发现

导入事件时自动从 XML 中提取 IP 地址并更新 `machine_assets` 表：

```go
var xmlExtractors = map[int32]map[string]string{
    4624: {
        "//Data[@Name='IpAddress']":     "ip_address",
        "//Data[@Name='TargetUserName']": "username",
    },
    4625: {"//Data[@Name='IpAddress']": "ip_address"},
    5140: {"//Data[@Name='IpAddress']": "ip_address"},
}
```

## AlertRepo 核心方法

```go
type AlertRepo struct {
    db *DB
}
```

### 主要方法

| 方法 | 功能 |
|------|------|
| `Insert(alert)` | 插入单条告警 |
| `Update(alert)` | 更新告警 |
| `InsertBatch(alerts)` | 批量插入（事务） |
| `GetByID(id)` | 按 ID 查询 |
| `List(query)` | 分页列表查询 |
| `Query(filter)` | 条件过滤查询 |
| `Resolve(id, notes)` | 标记已解决 |
| `Delete(id)` | 删除告警 |
| `MarkFalsePositive(id, reason)` | 标记误报 |
| `GetUnresolved()` | 查询未解决告警 |
| `GetByRuleName(ruleName)` | 按规则名查询 |
| `GetStats()` | 统计（按严重级别/状态/规则） |
| `GetTrend(days)` | 趋势分析（日/周/小时/星期） |
| `CountAlerts()` | 总告警数 |
| `CountBySeverity()` | 按严重级别计数 |
| `CountByStatus()` | 按状态计数 |
| `CountByRule()` | 按规则计数（含百分比） |

## Repository 接口

存储层定义了一组接口，便于测试和扩展：

```go
type EventRepository interface {
    Insert(*types.Event) error
    InsertBatch([]*types.Event) error
    GetByID(int64) (*types.Event, error)
    Search(*types.SearchRequest) ([]*types.Event, int64, error)
    DeleteByImportID(int64) error
    DeleteOldEvents(age string) (int64, error)
    GetByTimeRange(start, end string) ([]*types.Event, error)
    GetEventIDsByImportID(importID int64) ([]int64, error)
}

type AlertRepository interface {
    Insert(*types.Alert) error
    Update(*types.Alert) error
    GetByID(int64) (*types.Alert, error)
    List(query *AlertQuery) ([]*types.Alert, int64, error)
    Resolve(id int64, notes string) error
    Delete(int64) error
    MarkFalsePositive(id int64, reason string) error
    GetUnresolved() ([]*types.Alert, error)
    GetByRuleName(ruleName string) ([]*types.Alert, error)
    CountBySeverity() (map[string]int64, error)
    CountByStatus() (map[string]int64, error)
    CountByRule() ([]*types.RuleCount, error)
}
```
