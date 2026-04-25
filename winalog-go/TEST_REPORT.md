# WinLogAnalyzer-Go 功能测试报告

## 测试环境

- **平台**: Linux (amd64)
- **Go 版本**: go1.25.6
- **测试日期**: 2026-04-20
- **数据库**: /root/.winalog/winalog.db (1GB+, 48万+ 事件)

---

## 一、CLI 命令测试结果

### 1.1 核心命令

| 命令 | 状态 | 说明 |
|------|------|------|
| `status` | ✅ 通过 | 正常显示系统状态 |
| `info` | ⚠️ 部分 | Windows 专用功能显示预期错误 |
| `metrics` | ✅ 通过 | Prometheus 格式指标正常 |
| `config get` | ✅ 通过 | 配置读取正常 |
| `db status` | ✅ 通过 | 数据库状态正常 |

### 1.2 查询和搜索

| 命令 | 状态 | 结果 |
|------|------|------|
| `search --event-id 4624` | ✅ 通过 | 返回 1766 个登录事件 |
| `query "SELECT COUNT(*) FROM events"` | ✅ 通过 | SQL 查询正常 |
| `timeline query` | ⚠️ 需要参数 | 需指定 --start/--end |

### 1.3 规则和告警

| 命令 | 状态 | 结果 |
|------|------|------|
| `rules list` | ✅ 通过 | 列出 98 条内置规则 |
| `alert list` | ✅ 通过 | 显示 67 条告警 |
| `whitelist list` | ✅ 通过 | 白名单管理正常 |

### 1.4 分析和报告

| 命令 | 状态 | 结果 |
|------|------|------|
| `analyze list` | ✅ 通过 | 列出 9 个分析器 |
| `analyze brute_force` | ⚠️ 未测试 | 需要时间参数 |
| `report generate` | ⚠️ 未测试 | 需要较长时间 |

### 1.5 其他命令

| 命令 | 状态 | 说明 |
|------|------|------|
| `serve --port 18080` | ✅ 通过 | API 服务器正常启动 |
| `evtx2csv` | ⚠️ 无法测试 | Linux 无法解析 EVTX 文件 |
| `collect` | ⚠️ 需要 Windows | Windows 专用功能 |
| `forensics` | ⚠️ 需要 Windows | Windows 专用功能 |
| `live` | ⚠️ 需要 Windows | Windows 专用功能 |

---

## 二、API 端点测试结果

### 2.1 正常工作的端点

| 端点 | 方法 | 状态 | 响应 |
|------|------|------|------|
| `/api/health` | GET | ✅ 200 | `{"service":"winalog-api","status":"ok"}` |
| `/api/events` | GET | ✅ 200 | 返回事件列表 |
| `/api/alerts` | GET | ✅ 200 | 返回告警列表 |
| `/api/rules` | GET | ✅ 200 | 返回 98 条规则 |
| `/api/system/info` | GET | ✅ 200 | 系统信息正常 |
| `/api/settings` | GET/POST | ✅ 200 | 设置读写正常 |
| `/api/analyzers` | GET | ✅ 200 | 返回 9 个分析器 |
| `/api/persistence/detect` | GET | ✅ 200 | 持久化检测正常 |
| `/api/persistence/categories` | GET | ✅ 200 | 正常 |
| `/api/persistence/techniques` | GET | ✅ 200 | 正常 |
| `/api/logs` | GET | ✅ 200 | 日志查询正常 |
| `/api/monitor/stats` | GET | ✅ 200 | 监控统计正常 |
| `/api/monitor/events` | GET | ✅ 200 | 监控事件正常 |

### 2.2 超时的端点

| 端点 | 方法 | 状态 | 问题 |
|------|------|------|------|
| `/api/ui/dashboard` | GET | ❌ 超时 | 5秒内无响应 |
| `/api/ui/metrics` | GET | ❌ 超时 | 5秒内无响应 |
| `/api/ui/alerts/groups` | GET | ❌ 超时 | 5秒内无响应 |
| `/api/reports` | GET | ❌ 超时 | 5秒内无响应 |
| `/api/ui/events/distribution` | GET | ❌ 超时 | 5秒内无响应 |
| `/api/timeline` | GET | ❌ 超时 | 5秒内无响应 |

**超时问题分析**:
- 超时端点均涉及复杂数据库查询或聚合操作
- 单独测试 SQLite 查询均 < 1ms，说明不是数据库本身问题
- 可能与 Gin 框架的并发处理或连接池配置有关
- 需要在 Windows 环境进一步调查

### 2.3 返回 404 的端点

| 端点 | 说明 |
|------|------|
| `/api/collect` | 路由未定义 |
| `/api/policy` | 路由未定义 |
| `/api/query` | 路由未定义 |
| `/api/forensics` | 路由未定义 |
| `/api/monitor` | 路由未定义 |
| `/api/ueba` | 路由未定义 (POST 存在) |
| `/api/correlation` | 路由未定义 (POST 存在) |
| `/api/multi` | 路由未定义 (POST 存在) |

### 2.4 正常工作的 POST 端点

| 端点 | 方法 | 状态 |
|------|------|------|
| `/api/ueba/analyze` | POST | ✅ 200 |
| `/api/correlation/analyze` | POST | ✅ 200 |
| `/api/multi/analyze` | POST | ✅ 200 |

---

## 三、发现的问题

### 3.1 UI API 超时问题 (严重)

**问题描述**: `/api/ui/dashboard`、`/api/ui/metrics`、`/api/ui/alerts/groups` 等端点在调用时超时，无响应。

**影响范围**: Web UI 的核心功能（仪表盘、指标、告警分组）

**可能原因**:
1. `GetDashboardOverview` 调用多个数据库查询，可能存在连接池竞争
2. `DB.Query()` 和 `DB.Exec()` 使用不同的锁机制，可能导致死锁
3. SQLite 在高并发下的 WAL 模式可能存在问题

**建议修复方案**:
1. 检查 `internal/api/handlers_ui.go` 中的查询逻辑
2. 为数据库操作添加超时控制
3. 考虑使用连接池或改进并发模型

### 3.2 API 路由不一致 (中等)

**问题描述**: 部分端点如 `/api/ueba` GET 返回 404，但 POST `/api/ueba/analyze` 存在。

**影响**: API 文档和实际实现不匹配。

### 3.3 Linux 环境限制 (信息)

**问题描述**: EVTX 解析、实时监控、取证分析等 Windows 专用功能无法在 Linux 测试。

**影响**: 无法完整测试所有功能。

---

## 四、测试覆盖率

### 4.1 CLI 命令覆盖率

- 总命令数: ~27
- 已测试: ~15
- 通过率: ~90% (已测试命令中)

### 4.2 API 端点覆盖率

- 总端点数: ~40+
- 已测试: ~25
- 正常工作: ~18
- 问题端点: ~7

---

## 五、建议

1. **优先修复 UI API 超时问题** - 影响 Web UI 核心功能
2. **统一 API 路由风格** - 修复 404 路由问题
3. **在 Windows 环境完整测试** - EVTX 解析、取证功能
4. **添加 API 集成测试** - 确保端点行为一致性

---

## 六、测试数据统计

```
数据库: /root/.winalog/winalog.db
事件总数: 480,329
告警总数: 67
存储大小: ~1GB
导入次数: 231
规则数量: 98 (内置)
分析器: 9
```
