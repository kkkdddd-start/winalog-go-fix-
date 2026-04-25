# Storage 模块

**路径**: `internal/storage/`

SQLite 存储层，使用 `modernc.org/sqlite` (Pure Go，无需 CGO)。

## 数据库配置

```go
dsn := absPath + "?_journal_mode=WAL&_busy_timeout=30000&_synchronous=NORMAL"
```

- **WAL 模式**: 提高并发读写性能
- **busy_timeout=30000**: 30秒锁等待
- **synchronous=NORMAL**: 平衡性能与安全

## DB 结构

```go
type DB struct {
    conn    *sql.DB
    path    string
    writeMu sync.Mutex  // 写锁
}
```

## 数据库 Schema

### events 表

存储所有日志事件。

```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_id INTEGER NOT NULL,
    level INTEGER NOT NULL,
    source TEXT,
    log_name TEXT NOT NULL,
    computer TEXT,
    user TEXT,
    user_sid TEXT,
    message TEXT,
    raw_xml TEXT,
    session_id TEXT,
    ip_address TEXT,
    import_time TEXT NOT NULL,
    import_id INTEGER DEFAULT 0
);
-- 索引
INDEX idx_timestamp (timestamp)
INDEX idx_event_id (event_id)
INDEX idx_level (level)
INDEX idx_log_name (log_name)
INDEX idx_import_id (import_id)
```

### alerts 表

存储告警。

```sql
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    event_ids TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    count INTEGER DEFAULT 1,
    mitre_attack TEXT,
    resolved INTEGER DEFAULT 0,
    resolved_time TEXT,
    notes TEXT,
    false_positive INTEGER DEFAULT 0,
    log_name TEXT,
    rule_score REAL DEFAULT 0.0
);
-- 索引
INDEX idx_severity (severity)
INDEX idx_resolved (resolved)
INDEX idx_rule_name (rule_name)
INDEX idx_first_seen (first_seen)
```

### 其他表

| 表名 | 用途 |
|------|------|
| `import_log` | 导入历史记录 |
| `machine_context` | 多机分析机器信息 |
| `multi_machine_analysis` | 多机分析结果 |
| `global_timeline` | 全局时间线 |
| `sessions` | 会话信息 |
| `evidence_chain` | 取证证据链 |
| `evidence_file` | 取证文件信息 |

## Repository 模式

### EventRepo

```go
type EventRepo struct {
    db *DB
}

func NewEventRepo(db *DB) *EventRepo

// 插入单条事件
func (r *EventRepo) Insert(event *types.Event) error

// 批量插入事件
func (r *EventRepo) InsertBatch(events []*types.Event) error

// 根据 ID 获取
func (r *EventRepo) GetByID(id int64) (*types.Event, error)

// 搜索事件
func (r *EventRepo) Search(req *types.SearchRequest) ([]*types.Event, int64, error)

// 统计事件数
func (r *EventRepo) Count() (int64, error)

// 删除旧事件
func (r *EventRepo) DeleteOlderThan(t time.Time) error
```

### AlertRepo

```go
type AlertRepo struct {
    db *DB
}

func NewAlertRepo(db *DB) *AlertRepo

// 插入告警
func (r *AlertRepo) Insert(alert *types.Alert) error

// 批量插入
func (r *AlertRepo) InsertBatch(alerts []*types.Alert) error

// 更新告警
func (r *AlertRepo) Update(alert *types.Alert) error

// 删除告警
func (r *AlertRepo) Delete(id int64) error

// 根据 ID 获取
func (r *AlertRepo) GetByID(id int64) (*types.Alert, error)

// 查询告警
func (r *AlertRepo) Query(filter *AlertFilter) ([]*types.Alert, error)

// 获取统计
func (r *AlertRepo) GetStats() (*AlertStats, error)
```

### AlertFilter

```go
type AlertFilter struct {
    StartTime *time.Time
    EndTime   *time.Time
    Severity  []string
    RuleName  string
    Resolved  *bool  // nil 表示所有
    Limit     int
    Offset    int
}
```

## 事务支持

```go
// 开始事务
func (d *DB) Begin() (*sql.Tx, error)

// 开始事务并返回回滚函数
func (d *DB) BeginTx() (*sql.Tx, func(), error)

// 使用示例
tx, rollback, err := db.BeginTx()
if err != nil {
    return err
}
defer rollback()

// 执行操作...
if err := execTx(tx); err != nil {
    rollback()
    return err
}
tx.Commit()
```

## 数据库维护

```go
// VACUUM - 清理空白空间
func (d *DB) Vacuum() error

// ANALYZE - 更新统计信息，帮助查询优化
func (d *DB) Analyze() error

// 获取统计
func (d *DB) GetStats() (*DBStats, error)

type DBStats struct {
    EventCount   int64  // 事件总数
    AlertCount   int64  // 告警总数
    ImportCount  int64  // 导入次数
    DatabaseSize int64  // 数据库大小(字节)
}
```

## 事件过滤

```go
type EventFilter struct {
    Limit     int
    Offset    int
    EventIDs  []int32
    Levels    []int
    LogNames  []string
    Computers []string
    StartTime *time.Time
    EndTime   *time.Time
}

func (d *DB) ListEvents(filter *EventFilter) ([]*types.Event, int64, error)
func (d *DB) ListEventsFiltered(filter *EventFilter) ([]*types.Event, error)
```

## 导入日志

```go
// 记录导入
func (d *DB) InsertImportLog(...) (int64, error)

// 更新导入记录
func (d *DB) UpdateImportLog(...)

// 获取最后导入时间
func (d *DB) GetLastImportTime(filePath string) *time.Time

// 获取导入日志
func (d *DB) GetImportLog(filePath string) (*ImportLogEntry, error)
```
