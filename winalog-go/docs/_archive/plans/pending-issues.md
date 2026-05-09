# 待实施问题精简方案

> 文档日期: 2026-04-17
> 问题数量: 0 个
> 状态: **全部已实施完成**

---

## 实施状态

所有 5 个待实施问题已全部完成实施：

| 问题编号 | 问题描述 | 状态 | 提交 |
|----------|----------|------|------|
| L3 | findNextEvents 实时查询 | ✅ 已完成 | ecfec07 |
| R4 | 高误报规则条件过滤 | ✅ 已完成 | ecfec07 |
| S1 | FTS5 全文索引 | ✅ 已完成 | ecfec07 |
| S4 | EventIndex 分层存储 | ✅ 已完成 | ecfec07 |
| O1 | BeginWithUnlock | ✅ 不存在问题 | - |

---

## 实施详情

### L3: ChainBuilder 注入 EventRepo

- 新增 `eventRepo` 字段到 ChainBuilder 结构体
- `findNextEvents` 方法现在从数据库实时查询真实后续事件
- 保留 `findNextEventsFallback` 用于无 eventRepo 的测试场景

### R4: 扩展 matchCondition + 规则条件

- 扩展 `matchCondition` 支持 ip_address, destination_port, logon_type, process_name, command_line 等字段
- `admin-login-unusual` 规则添加 Conditions 过滤管理员账户
- `sysmon-network-suspicious-port` 规则添加 Conditions 过滤高位端口

### S1: FTS5 全文索引

- 在 schema.go 中添加 FTS5 虚拟表 `events_fts`
- `EventRepo.Insert` 同步 FTS5 索引
- `EventRepo.Search` 使用 FTS5 MATCH 查询

### S4: EventIndex 分层存储

- `EventIndex` 添加 `eventRepo` 和 `eventsCache` 字段
- 内存索引只存储 ID 和 Timestamp 元数据
- 查询时从数据库或内存缓存获取完整事件

---

**文档版本**: v3.0
**更新内容**: 所有问题已实施完成
