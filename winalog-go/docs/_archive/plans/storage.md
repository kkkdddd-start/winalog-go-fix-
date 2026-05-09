# Storage 模块改进方案

**模块**: Storage (internal/storage)  
**分析时间**: 2026-04-17  
**问题数量**: 14 个（3 个严重，6 个中等，5 个优化）

---

## 问题汇总

| ID | 问题 | 严重性 | 优先级 | 复杂度 |
|----|------|--------|--------|--------|
| S1 | validateAlert/CorrelationRuleExists 空实现 | 严重 | P0 | 低 |
| S2 | reports 表使用保留关键字 `type` | 严重 | P0 | 低 |
| S3 | DeleteOldEvents 静默失败风险 | 严重 | P1 | 中 |
| S4 | BeginWithUnlock 命名与实现不符 | 中等 | P2 | 低 |
| S5 | GetStats 忽略 Scan 错误 | 中等 | P2 | 低 |
| S6 | Vacuum/Analyze 未使用写锁 | 中等 | P2 | 低 |
| S7 | InsertBatch 去重逻辑可能不准确 | 中等 | P1 | 中 |
| S8 | 缺少外键约束 | 中等 | P2 | 高 |
| S9 | 缺少 Repository 实现 | 中等 | P2 | 高 |
| S10 | json.Unmarshal 错误被忽略 | 中等 | P2 | 低 |
| S11 | repository.go 重复定义类型 | 优化 | P3 | 低 |
| S12 | Repository 接口未使用 | 优化 | P3 | 低 |
| S13 | 缺少数据库迁移机制 | 优化 | P3 | 高 |
| S14 | 事务处理不一致 | 优化 | P3 | 中 |

---

## 严重问题 (P0)

### S1: validateAlert/CorrelationRuleExists 空实现

**文件**: `internal/storage/rule_state.go`  
**行号**: 114-119

**问题描述**:  
`validateAlertRuleExists` 和 `validateCorrelationRuleExists` 函数是空实现，始终返回 `true, nil`，不执行任何验证。

```go
func (d *DB) validateAlertRuleExists(ruleName string) (bool, error) {
    return true, nil  // <-- 空实现
}

func (d *DB) validateCorrelationRuleExists(ruleName string) (bool, error) {
    return true, nil  // <-- 空实现
}
```

**影响**: 
- `ValidateRuleExists` 无法正确验证规则是否存在
- 可能导致无效的规则状态更新

**修复方案**:  
实现真正的规则验证逻辑：

```go
func (d *DB) validateAlertRuleExists(ruleName string) (bool, error) {
    var count int
    err := d.QueryRow("SELECT COUNT(*) FROM alerts WHERE rule_name = ?", ruleName).Scan(&count)
    if err != nil {
        return false, err
    }
    return count > 0, nil
}

func (d *DB) validateCorrelationRuleExists(ruleName string) (bool, error) {
    var count int
    err := d.QueryRow("SELECT COUNT(*) FROM correlation_results WHERE rule_name = ?", ruleName).Scan(&count)
    if err != nil {
        return false, err
    }
    return count > 0, nil
}
```

**评估**:
- 实现复杂度: 低
- 优先级: P0
- 适配性: 完全适配
- 必要性: 必须修复（功能完全失效）
- 可靠性: 简单 SQL 查询

---

### S2: reports 表使用保留关键字 `type`

**文件**: `internal/storage/schema.go`  
**行号**: 183

**问题描述**:  
`reports` 表使用 `type` 作为列名，这是 SQL 的保留关键字，可能导致查询语法问题。

```go
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,  // <-- 'type' 是保留关键字
    format TEXT NOT NULL,
    ...
);
```

**影响**: 
- 使用 `SELECT * FROM reports` 或其他涉及 `type` 列的查询可能出错
- 需要用引号或避免使用该列

**修复方案**:  
将列名改为非保留关键字，如 `report_type`：

```go
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    report_type TEXT NOT NULL,
    format TEXT NOT NULL,
    ...
);
```

同时更新所有引用该列的代码。

**评估**:
- 实现复杂度: 低
- 优先级: P0
- 适配性: 完全适配
- 必要性: 必须修复（可能导致查询失败）
- 可靠性: 简单列名修改

---

## 高优先级问题 (P1)

### S3: DeleteOldEvents 静默失败风险

**文件**: `internal/storage/events.go`  
**行号**: 271-283

**问题描述**:  
`DeleteOldEvents` 方法解析时间字符串，如果解析失败会删除所有事件。

```go
func (r *EventRepo) DeleteOldEvents(age string) (int64, error) {
    t, err := time.ParseDuration(age)
    if err != nil {
        // <-- 解析失败时，cutoff 为零值
        return 0, err  // <-- 错误被忽略，导致 cutoff = 0
    }

    cutoff := time.Now().Add(-t)
    result, err := r.db.Exec("DELETE FROM events WHERE timestamp < ?", cutoff)
    // 如果 t = 0，cutoff = now，所有事件都会被删除！
}
```

**影响**: 如果传入无效的 age 参数（如空字符串、错误格式），所有事件可能被删除。

**修复方案**:  
添加参数验证：

```go
func (r *EventRepo) DeleteOldEvents(age string) (int64, error) {
    if age == "" {
        return 0, fmt.Errorf("age parameter cannot be empty")
    }

    t, err := time.ParseDuration(age)
    if err != nil {
        return 0, fmt.Errorf("invalid duration format: %w", err)
    }

    if t < 0 {
        return 0, fmt.Errorf("duration must be positive")
    }

    cutoff := time.Now().Add(-t)
    result, err := r.db.Exec("DELETE FROM events WHERE timestamp < ?", cutoff)
    if err != nil {
        return 0, err
    }
    return result.RowsAffected()
}
```

**评估**:
- 实现复杂度: 中
- 优先级: P1
- 适配性: 完全适配
- 必要性: 必须修复（可能导致数据丢失）
- 可靠性: 需要明确验证所有输入

---

### S7: InsertBatch 去重逻辑可能不准确

**文件**: `internal/storage/events.go`  
**行号**: 423-445

**问题描述**:  
`generateEventKey` 函数生成的去重键可能产生冲突或漏掉重复事件。

```go
func (r *EventRepo) generateEventKey(e *types.Event) string {
    return fmt.Sprintf("%d|%s|%s|%s|%s",
        e.EventID,
        e.Timestamp.Format(time.RFC3339Nano),
        e.Computer,
        e.Message,
        getUserKey(e))  // <-- 依赖 Message 字段可能不准确
}
```

**问题**:
1. `Message` 字段可能为空或变化
2. 同一事件在不同导入中可能有微小的时间差异
3. 没有考虑事件源（Source）字段

**影响**: 去重可能不准确，导致重复事件或误删。

**修复方案**:  
改进去重键的生成逻辑，使用更可靠的字段组合：

```go
func (r *EventRepo) generateEventKey(e *types.Event) string {
    // 使用更可靠的去重键
    return fmt.Sprintf("%d|%s|%s|%s|%s|%s",
        e.EventID,
        e.Timestamp.Format(time.RFC3339Nano),
        e.Computer,
        e.LogName,
        e.Source,
        getUserKey(e))
}
```

或者使用原始 XML 的哈希作为更稳定的标识符（如果可用）。

**评估**:
- 实现复杂度: 中
- 优先级: P1
- 适配性: 完全适配
- 必要性: 建议修复
- 可靠性: 需要仔细评估对现有数据的影响

---

## 中等优先级问题 (P2)

### S4: BeginWithUnlock 命名与实现不符

**文件**: `internal/storage/db.go`  
**行号**: 100-103

**问题描述**:  
`BeginWithUnlock` 方法名具有误导性：它不开始事务，也不返回事务。

```go
func (d *DB) BeginWithUnlock() (*sql.Tx, func()) {
    d.writeMu.Lock()
    return nil, func() { d.writeMu.Unlock() }  // <-- 返回 nil 事务
}
```

**影响**: 代码可读性差，容易误用。

**修复方案**:  
重命名为 `LockAndReturnUnlocker` 或删除该方法：

```go
func (d *DB) LockAndReturnUnlocker() func() {
    d.writeMu.Lock()
    return d.writeMu.Unlock
}
```

**评估**:
- 实现复杂度: 低
- 优先级: P2
- 适配性: 完全适配
- 必要性: 建议修复
- 可靠性: 简单重命名

---

### S5: GetStats 忽略 Scan 错误

**文件**: `internal/storage/db.go`  
**行号**: 139-156

**问题描述**:  
`GetStats` 方法忽略 `QueryRow.Scan` 的错误，可能掩盖数据库问题。

```go
func (d *DB) GetStats() (*DBStats, error) {
    var eventCount, alertCount, importCount int64

    d.conn.QueryRow("SELECT COUNT(*) FROM events").Scan(&eventCount)  // <-- 忽略错误
    d.conn.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&alertCount)  // <-- 忽略错误
    d.conn.QueryRow("SELECT COUNT(*) FROM import_log").Scan(&importCount)  // <-- 忽略错误
    // ...
}
```

**影响**: 统计数据可能不准确，但不会报错。

**修复方案**:  
正确处理错误：

```go
func (d *DB) GetStats() (*DBStats, error) {
    stats := &DBStats{}

    if err := d.conn.QueryRow("SELECT COUNT(*) FROM events").Scan(&stats.EventCount); err != nil {
        return nil, fmt.Errorf("failed to get event count: %w", err)
    }

    if err := d.conn.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&stats.AlertCount); err != nil {
        return nil, fmt.Errorf("failed to get alert count: %w", err)
    }

    if err := d.conn.QueryRow("SELECT COUNT(*) FROM import_log").Scan(&stats.ImportCount); err != nil {
        return nil, fmt.Errorf("failed to get import count: %w", err)
    }

    var dbSize int64
    if fi, err := os.Stat(d.path); err == nil {
        dbSize = fi.Size()
    }
    stats.DatabaseSize = dbSize

    return stats, nil
}
```

**评估**:
- 实现复杂度: 低
- 优先级: P2
- 适配性: 完全适配
- 必要性: 建议修复
- 可靠性: 简单错误处理

---

### S6: Vacuum/Analyze 未使用写锁

**文件**: `internal/storage/db.go`  
**行号**: 124-136

**问题描述**:  
`Vacuum` 和 `Analyze` 方法没有使用 `writeMu` 锁，与其他写操作不一致。

```go
func (d *DB) Vacuum() error {
    d.writeMu.Lock()
    defer d.writeMu.Unlock()
    _, err := d.conn.Exec("VACUUM")  // <-- 有锁
    return err
}

func (d *DB) Analyze() error {
    d.writeMu.Lock()
    defer d.writeMu.Unlock()
    _, err := d.conn.Exec("ANALYZE")  // <-- 有锁
    return err
}
```

实际上这两个方法是有锁的，但问题在于它们使用的是 `d.conn.Exec` 而不是 `d.Exec`，后者会再次尝试获取锁导致死锁。

**影响**: 可能导致死锁或锁冲突。

**修复方案**:  
使用 `d.Exec` 而不是直接使用 `d.conn.Exec`：

```go
func (d *DB) Vacuum() error {
    _, err := d.Exec("VACUUM")
    return err
}

func (d *DB) Analyze() error {
    _, err := d.Exec("ANALYZE")
    return err
}
```

**评估**:
- 实现复杂度: 低
- 优先级: P2
- 适配性: 完全适配
- 必要性: 建议修复
- 可靠性: 简单修改

---

### S8: 缺少外键约束

**文件**: `internal/storage/schema.go`

**问题描述**:  
数据库表之间存在隐式关系（如 `events.import_id` 引用 `import_log.id`），但没有定义外键约束。

**影响**: 
- 可能产生孤立记录
- 数据完整性无法保证
- 级联删除不可用

**修复方案**:  
在 schema 中添加外键约束：

```sql
CREATE TABLE IF NOT EXISTS events (
    ...
    import_id INTEGER DEFAULT 0,
    FOREIGN KEY (import_id) REFERENCES import_log(id) ON DELETE SET DEFAULT
);
```

注意：SQLite 外键需要 `PRAGMA foreign_keys = ON` 才能生效。

**评估**:
- 实现复杂度: 高
- 优先级: P2
- 适配性: 需要评估对现有代码的影响
- 必要性: 建议实现
- 可靠性: 需要仔细测试

---

### S9: 缺少 Repository 实现

**文件**: `internal/storage/repository.go`

**问题描述**:  
`repository.go` 定义了多个 Repository 接口，但只有部分被实现：

| 接口 | 状态 |
|------|------|
| EventRepository | 已实现 (EventRepo) |
| AlertRepository | 部分实现 (AlertRepo 缺少某些方法) |
| ImportLogRepository | 未实现 |
| MachineContextRepository | 未实现 |
| CorrelationResultRepository | 未实现 |
| TimelineRepository | 未实现 |
| EvidenceChainRepository | 未实现 |
| EvidenceFileRepository | 未实现 |

**影响**: Repository 接口无法用于依赖注入，测试困难。

**修复方案**:  
实现缺失的 Repository，或删除未使用的接口定义。

**评估**:
- 实现复杂度: 高
- 优先级: P2
- 适配性: 完全适配
- 必要性: 可选（取决于是否需要依赖注入）
- 可靠性: 需要全面测试

---

### S10: json.Unmarshal 错误被忽略

**文件**: `internal/storage/alerts.go`  
**行号**: 639

**问题描述**:  
解析 `event_ids` JSON 时忽略错误。

```go
if eventIDsJSON.Valid {
    json.Unmarshal([]byte(eventIDsJSON.String), &a.EventIDs)  // <-- 忽略错误
}
```

**影响**: JSON 格式损坏的告警记录无法正确加载。

**修复方案**:  
处理错误：

```go
if eventIDsJSON.Valid {
    if err := json.Unmarshal([]byte(eventIDsJSON.String), &a.EventIDs); err != nil {
        return nil, fmt.Errorf("failed to parse event_ids for alert %d: %w", a.ID, err)
    }
}
```

**评估**:
- 实现复杂度: 低
- 优先级: P2
- 适配性: 完全适配
- 必要性: 建议修复
- 可靠性: 简单错误处理

---

## 优化建议 (P3)

### S11: repository.go 重复定义类型

**文件**: `internal/storage/repository.go`

**问题描述**:  
`repository.go` 中定义的 `ImportLog` 结构体与 `db.go` 中的 `ImportLogEntry` 重复。

**优化建议**:  
删除重复定义，统一使用一个结构体。

---

### S12: Repository 接口未使用

**文件**: `internal/storage/repository.go`

**问题描述**:  
虽然定义了 Repository 接口，但实际代码直接使用具体类型 `*EventRepo`、`*AlertRepo`，没有通过接口进行依赖注入。

**优化建议**:  
如果不需要 mock 测试或替换实现，可以删除接口定义以减少维护负担。

---

### S13: 缺少数据库迁移机制

**问题描述**:  
当 schema 发生变化时，没有版本管理和迁移机制。

**优化建议**:  
添加简单的 migration 机制：

```go
type Migration struct {
    Version int
    SQL     string
}

var migrations = []Migration{
    {1, "ALTER TABLE events ADD COLUMN new_field TEXT"},
    // ...
}

func (d *DB) Migrate() error {
    // 检查当前版本并应用未完成的迁移
}
```

---

### S14: 事务处理不一致

**文件**: `internal/storage/*.go`

**问题描述**:  
事务处理方式不一致：
- `db.go:83-94` - `Begin()` 返回 rollback 函数
- `db.go:184-193` - `BeginTx()` 再次封装 `Begin()`
- `alerts.go:176-226` - `InsertBatch` 使用 `Begin()` + `defer unlock()`

**优化建议**:  
统一事务处理模式，使用统一的 helper：

```go
func (d *DB) WithTransaction(fn func(*sql.Tx) error) error {
    tx, rollback, err := d.Begin()
    if err != nil {
        return err
    }

    if err := fn(tx); err != nil {
        rollback()
        return err
    }

    return tx.Commit()
}
```

---

## 修复优先级总结

### 立即修复 (P0)
1. **S1**: validateAlert/CorrelationRuleExists 空实现
2. **S2**: reports 表使用保留关键字 `type`

### 尽快修复 (P1)
3. **S3**: DeleteOldEvents 静默失败风险
4. **S7**: InsertBatch 去重逻辑可能不准确

### 计划修复 (P2)
5. **S4**: BeginWithUnlock 命名与实现不符
6. **S5**: GetStats 忽略 Scan 错误
7. **S6**: Vacuum/Analyze 未使用写锁
8. **S8**: 缺少外键约束
9. **S9**: 缺少 Repository 实现
10. **S10**: json.Unmarshal 错误被忽略

### 后续优化 (P3)
11. **S11**: repository.go 重复定义类型
12. **S12**: Repository 接口未使用
13. **S13**: 缺少数据库迁移机制
14. **S14**: 事务处理不一致

---

## 依赖关系

```
S2 (type 关键字) ──> S10 (json.Unmarshal)
S3 (DeleteOldEvents) ──> S14 (事务处理)
S9 (Repository 实现) ──> S12 (接口未使用)
```

---

## 附录：测试建议

### 编译测试
```bash
cd winalog-go
go build ./...
```

### 单元测试
```bash
go test ./internal/storage/... -v
```

### 集成测试
```bash
# 测试数据库操作
winalog import test.evtx

# 测试 stats
winalog stats

# 测试事件查询
winalog query --limit 10
```
