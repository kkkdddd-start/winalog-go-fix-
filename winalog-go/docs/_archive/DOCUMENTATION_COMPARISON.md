# 文档功能统一性对比报告

本文档对比 `FRONTEND_FEATURES.md`、`COMMANDS.md`、`API.md` 三个文档，验证功能是否统一。

---

## 1. 模块对应关系总览

| 功能模块 | CLI 命令 | API 端点 | Frontend 页面 | 状态 |
|----------|----------|----------|---------------|------|
| 事件管理 | `import` | POST /api/import/logs | Collect (导入Tab) | ✅ 统一 |
| 事件搜索 | `search` | POST /api/events/search | Events | ✅ 统一 |
| 事件导出 | `export` | POST /api/events/export | Events (Export) | ✅ 统一 |
| 告警管理 | `alert` (8子命令) | Alerts API (9端点) | Alerts, AlertDetail | ✅ 统一 |
| 时间线 | `timeline` | Timeline API (5端点) | Timeline | ✅ 统一 |
| 关联分析 | `correlate` | Correlation API | Correlation | ✅ 统一 |
| 威胁分析 | `analyze` | Analyze API | Analyze | ✅ 统一 |
| 报告 | `report` | Reports API (8端点) | Reports | ✅ 统一 |
| 取证 | `forensics` | Forensics API (11端点) | Forensics | ✅ 统一 |
| 实时监控 | `live` | Live Events API (2端点) | Live | ✅ 统一 |
| 数据收集 | `collect` | Collect API (3端点) | Collect | ✅ 统一 |
| 持久化检测 | `persistence` | Persistence API (4端点) | Persistence | ✅ 统一 |
| 白名单 | `whitelist` | Suppress API (6端点) | Suppress | ✅ 统一 |
| 用户行为 | `ueba` | UEBA API (3端点) | UEBA | ✅ 统一 |
| 多机分析 | `multi` | Multi API (2端点) | Multi | ✅ 统一 |
| SQL查询 | `query` | Query API | Query | ✅ 统一 |
| 系统信息 | `info` | System API (11端点) | SystemInfo | ✅ 统一 |
| 仪表板 | `dashboard` | Dashboard API | Dashboard | ✅ 统一 |
| 规则管理 | `rules` | Rules API (13端点) | Rules | ✅ 统一 |
| 设置 | `config` | Settings API | Settings | ✅ 统一 |
| 指标 | `metrics` | System API (/metrics) | Metrics | ✅ 统一 |
| 数据库 | `db` | - | - | ⚠️ CLI专属 |
| TUI | `tui` | - | - | ⚠️ CLI专属 |
| API服务 | `serve` | - | - | ⚠️ CLI专属 |
| 文件验证 | `verify` | - | - | ⚠️ CLI专属 |

---

## 2. 功能详细对比

### 2.1 事件搜索 (Search)

| 特性 | CLI | API | Frontend |
|------|-----|-----|----------|
| 关键词搜索 | `--keywords` | `keywords` | ✅ 搜索框 |
| 正则搜索 | `--regex` | `regex: true` | ✅ Checkbox |
| Event ID过滤 | `--event-id` | `event_ids: []` | ✅ 输入框 |
| Level过滤 | `--level` | `levels: []` | ✅ Checkbox组 |
| Log Name过滤 | `--log-name` | `log_names: []` | ✅ 输入框 |
| Source过滤 | `--source` | `sources: []` | ✅ 输入框 |
| User过滤 | `--user` | `users: []` | ✅ 输入框 |
| Computer过滤 | `--computer` | `computers: []` | ✅ 输入框 |
| 时间范围 | `--start-time/end-time` | `start_time/end_time` | ✅ DateTimePicker |
| 分页 | `--page/--page-size` | `page/page_size` | ✅ 分页控件 |
| 排序 | `--sort-by/--sort-order` | `sort_by/sort_order` | ✅ Select |
| 导出CSV | `--output` | `format: csv` | ✅ Export按钮 |
| 导出JSON | `--output` | `format: json` | ✅ Export按钮 |
| 导出Excel | - | `format: excel` | ✅ Export按钮 |

**结论**: ✅ 三端功能高度统一

---

### 2.2 告警管理 (Alerts)

| 特性 | CLI | API | Frontend |
|------|-----|-----|----------|
| 列出告警 | `alert list` | GET /api/alerts | Alerts页面 |
| 显示详情 | `alert show` | GET /api/alerts/:id | AlertDetail页面 |
| 解决告警 | `alert resolve` | POST /api/alerts/:id/resolve | AlertDetail按钮 |
| 标记误报 | `alert resolve --false-positive` | POST /api/alerts/:id/false-positive | AlertDetail按钮 |
| 删除告警 | `alert delete` | DELETE /api/alerts/:id | AlertDetail按钮 |
| 导出告警 | `alert export` | - (✅ 缺失) | - |
| 告警统计 | `alert stats` | GET /api/alerts/stats | Alerts统计卡片 |
| 告警趋势 | - | GET /api/alerts/trend | ✅ 趋势图 |
| 运行分析 | `alert run` | POST /api/alerts/run-analysis | Alerts/Analyze按钮 |
| 持续监控 | `alert monitor` | - | - |
| Severity过滤 | `--severity` | `?severity=` | ✅ 下拉选择 |
| 按规则过滤 | `--rule` | - | - |
| 批量操作 | - | POST /api/alerts/batch | ✅ 批量按钮 |
| 添加备注 | - | `notes` 参数 | ✅ 备注输入框 |

**结论**: ⚠️ API 缺少 `/api/alerts/export` 端点

---

### 2.3 规则管理 (Rules)

| 特性 | CLI | API | Frontend |
|------|-----|-----|----------|
| 列出规则 | `rules list` | GET /api/rules | Rules页面 |
| 验证规则 | `rules validate` | POST /api/rules/validate | Rules Modal |
| 启用规则 | `rules enable` | POST /api/rules/:name/toggle | Rules Switch |
| 禁用规则 | `rules disable` | POST /api/rules/:name/toggle | Rules Switch |
| 规则状态 | `rules status` | - | Rules页面 |
| 导入规则 | - | POST /api/rules/import | Rules Import Modal |
| 导出JSON | - | GET /api/rules/export?format=json | Rules Export |
| 导出YAML | - | GET /api/rules/export?format=yaml | Rules Export |
| 按Severity过滤 | `--severity` | `?severity=` | ✅ Filter选择 |
| 按Status过滤 | `--enabled/--disabled` | `?enabled=true/false` | ✅ Filter选择 |
| 搜索规则 | - | - | ✅ 搜索框 |
| 创建规则 | - | POST /api/rules | Rules Add按钮 |
| 编辑规则 | - | PUT /api/rules/:name | Rules Edit |

**结论**: ✅ 三端功能基本统一

---

### 2.4 威胁分析 (Analyze)

| 特性 | CLI | API | Frontend |
|------|-----|-----|----------|
| 运行分析 | `analyze` | POST /api/analyze/:type | Analyze页面 |
| 分析器列表 | `analyze list` | GET /api/analyzers | Analyze卡片列表 |
| 时间窗口 | `--hours/--time-window` | 请求体参数 | ✅ 时间选择 |
| 输出格式 | `--format` | - | ✅ 结果展示 |
| brute_force | ✅ | ✅ | ✅ |
| login | ✅ | ✅ | ✅ |
| kerberos | ✅ | ✅ | ✅ |
| powershell | ✅ | ✅ | ✅ |
| lateral_movement | ✅ | ✅ | ✅ |
| data_exfiltration | ✅ | ✅ | ✅ |
| persistence | ✅ | ✅ | ✅ |
| privilege_escalation | ✅ | ✅ | ✅ |

**结论**: ✅ 三端完全统一

---

### 2.5 持久化检测 (Persistence)

| 特性 | CLI | API | Frontend |
|------|-----|-----|----------|
| 检测持久化 | `persistence detect` | GET /api/persistence/detect | Persistence页面 |
| 按类别过滤 | `--category` | `?category=` | ✅ Filter选择 |
| 按技术过滤 | `--technique` | - | ✅ Filter选择 |
| 进度显示 | `--progress` | - | - |
| 输出格式 | `--format` | - | ✅ 选择器 |

**结论**: ✅ 三端功能基本统一

---

### 2.6 数据收集 (Collect)

| 特性 | CLI | API | Frontend |
|------|-----|-----|----------|
| 收集数据 | `collect` | POST /api/collect | Collect页面 |
| 包含日志 | `--include-logs` | `sources: []` | ✅ Checkbox |
| 包含Prefetch | `--include-prefetch` | - | ✅ Checkbox |
| 包含Shimcache | `--include-shimcache` | - | ✅ Checkbox |
| 包含Amcache | `--include-amcache` | - | ✅ Checkbox |
| 包含Userassist | `--include-userassist` | - | ✅ Checkbox |
| 包含注册表 | `--include-registry` | - | ✅ Checkbox |
| 包含任务 | `--include-tasks` | - | ✅ Checkbox |
| 压缩输出 | `--compress` | - | ✅ Checkbox |
| 计算哈希 | `--calculate-hash` | - | ✅ Checkbox |
| 线程数 | `--workers` | - | ✅ Select |
| 导入日志 | `collect --import` | POST /api/collect/import | Collect Import按钮 |

**结论**: ✅ 三端功能高度统一

---

### 2.7 实时监控 (Live)

| 特性 | CLI | API | Frontend |
|------|-----|-----|----------|
| 开始监控 | `live collect` | GET /api/live/events (SSE) | Live页面 |
| 连接状态 | - | `connected` 事件 | ✅ 状态指示器 |
| 实时事件 | - | `event` 事件 | ✅ 事件列表 |
| 统计数据 | - | `stats` 事件 | ✅ 统计栏 |
| 断开连接 | - | - | ✅ Disconnect按钮 |
| 级别过滤 | - | - | ✅ Select选择 |
| 清空事件 | - | - | ✅ Clear按钮 |

**结论**: ✅ 三端功能基本统一

---

### 2.8 白名单/抑制 (Suppress)

| 特性 | CLI | API | Frontend |
|------|-----|-----|----------|
| 添加规则 | `whitelist add` | POST /api/suppress | Suppress页面 |
| 移除规则 | `whitelist remove` | DELETE /api/suppress/:id | Suppress Delete按钮 |
| 列出规则 | `whitelist list` | GET /api/suppress | Suppress列表 |
| 启用/禁用 | `whitelist toggle` | POST /api/suppress/:id/toggle | Suppress Toggle |
| 按EventID过滤 | `--event-id` | `filter.event_ids` | - |
| 原因 | `--reason` | `description` | - |
| 范围 | `--scope` | `filter` | - |
| 持续时间 | `--duration` | - | - |

**结论**: ✅ 三端功能基本统一

---

### 2.9 取证 (Forensics)

| 特性 | CLI | API | Frontend |
|------|-----|-----|----------|
| 收集证据 | `forensics collect` | POST /api/forensics/collect | Forensics页面 |
| 计算哈希 | `forensics hash` | POST /api/forensics/hash | Forensics Hash按钮 |
| 验证签名 | `forensics verify` | GET /api/forensics/signature | Forensics Verify按钮 |
| 验证哈希 | - | GET /api/forensics/verify-hash | ✅ |
| 检查签名状态 | - | GET /api/forensics/is-signed | ✅ |
| 生成清单 | - | POST /api/forensics/manifest | ✅ |
| 内存转储 | - | GET /api/forensics/memory-dump | ✅ |
| 证据列表 | - | GET /api/forensics/evidence | Forensics证据列表 |
| 证据详情 | - | GET /api/forensics/evidence/:id | ✅ |
| 保管链 | - | GET /api/forensics/chain-of-custody | Forensics Chain Modal |

**结论**: ⚠️ CLI只有3个子命令(collect/hash/verify)，API有10个端点

---

### 2.10 报告 (Reports)

| 特性 | CLI | API | Frontend |
|------|-----|-----|----------|
| 生成报告 | `report generate` | POST /api/reports | Reports页面 |
| 查看报告 | - | GET /api/reports/:id | Reports View按钮 |
| 下载报告 | - | GET /api/reports/:id/download | Reports Download按钮 |
| 报告列表 | - | GET /api/reports | Reports列表 |
| 报告类型 | `security/alert/timeline/compliance` | ✅ 同 | ✅ 卡片选择 |
| 输出格式 | `html/json/pdf` | ✅ 同 | ✅ 选择器 |
| 时间范围 | `--time-range` | `start_time/end_time` | ✅ DateRange选择 |
| 模板管理 | - | /api/report-templates (5端点) | ✅ 模板页面 |

**结论**: ✅ 三端完全统一

---

### 2.11 时间线 (Timeline)

| 特性 | CLI | API | Frontend |
|------|-----|-----|----------|
| 获取时间线 | `timeline query` | GET /api/timeline | Timeline页面 |
| 构建时间线 | `timeline build` | - | - |
| 统计 | - | GET /api/timeline/stats | Timeline统计 |
| 攻击链 | - | GET /api/timeline/chains | - |
| 导出 | `timeline export` | GET /api/timeline/export | - |
| 删除告警 | - | DELETE /api/timeline/alerts/:id | Timeline删除 |
| 类型过滤 | - | - | ✅ All/Events/Alerts |
| 时间范围 | `--start/--end` | `start_time/end_time` | ✅ 选择器 |

**结论**: ✅ 三端功能基本统一

---

### 2.12 关联分析 (Correlation)

| 特性 | CLI | API | Frontend |
|------|-----|-----|----------|
| 运行分析 | `correlate` | POST /api/correlation/analyze | Correlation页面 |
| 时间窗口 | `--time-window` | `window` 参数 | ✅ 时间选择 |
| 指定规则 | `--rules` | `rules: []` | - |
| 输出格式 | `--format` | - | ✅ 选择 |

**结论**: ✅ 三端功能基本统一

---

### 2.13 多机分析 (Multi)

| 特性 | CLI | API | Frontend |
|------|-----|-----|----------|
| 跨机器分析 | `multi analyze` | POST /api/multi/analyze | Multi页面 |
| 横向移动检测 | `multi lateral` | GET /api/multi/lateral | Multi Lateral Tab |
| 时间窗口 | `--time-window` | `start_time/end_time` | ✅ 时间选择 |

**结论**: ✅ 三端功能完全统一

---

### 2.14 UEBA

| 特性 | CLI | API | Frontend |
|------|-----|-----|----------|
| 运行分析 | `ueba analyze` | POST /api/ueba/analyze | UEBA页面 |
| 用户画像 | `ueba profiles` | GET /api/ueba/profiles | UEBA Profiles Tab |
| 基线管理 | `ueba baseline` | - | - |
| 时间窗口 | `--hours` | `start_time/end_time` | ✅ 时间选择 |
| 保存告警 | `--save-alerts` | - | - |

**结论**: ✅ 三端功能基本统一

---

### 2.15 系统信息 (SystemInfo)

| 特性 | CLI | API | Frontend |
|------|-----|-----|----------|
| 系统信息 | `info` | GET /api/system/info | SystemInfo System Tab |
| 进程列表 | `info --process` | GET /api/system/processes | SystemInfo Processes Tab |
| 网络连接 | `info --network` | GET /api/system/network | SystemInfo Network Tab |
| 用户账户 | `info --users` | GET /api/system/users | - |
| 注册表 | `info --registry` | GET /api/system/registry | - |
| 计划任务 | `info --tasks` | GET /api/system/tasks | - |
| 环境变量 | - | GET /api/system/env | SystemInfo Env Tab |
| 已加载DLL | - | GET /api/system/dlls | SystemInfo DLLs Tab |
| 驱动列表 | - | GET /api/system/drivers | SystemInfo Drivers Tab |
| 保存到DB | `info --save` | - | - |

**结论**: ✅ 三端功能基本统一

---

### 2.16 SQL查询 (Query)

| 特性 | CLI | API | Frontend |
|------|-----|-----|----------|
| 执行查询 | `query <sql>` | POST /api/query/execute | Query页面 |
| 预设查询 | - | - | ✅ 预设SQL |
| 查询历史 | - | - | ✅ 历史记录 |
| 导出JSON | - | - | ✅ Export按钮 |
| 导出CSV | - | - | ✅ Export按钮 |
| SQL语法高亮 | - | - | ✅ 代码编辑器 |

**结论**: ✅ 三端功能基本统一

---

### 2.17 设置 (Settings)

| 设置项 | CLI | API | Frontend |
|--------|-----|-----|----------|
| Log Level | --log-level | POST /api/settings | ✅ General Tab |
| Export Directory | --export-dir | - | ✅ General Tab |
| Auto Update Rules | - | - | ✅ General Tab |
| Database Path | - | - | ✅ Database Tab |
| Max Events | - | - | ✅ Database Tab |
| Retention Days | - | `alert_retention_days` | ✅ Database Tab |
| API Host | - | - | ✅ API Server Tab |
| API Port | - | - | ✅ API Server Tab |
| CORS Enabled | - | - | ✅ API Server Tab |
| Enable Alerting | - | - | ✅ Collection Tab |
| Enable Live Collection | - | - | ✅ Collection Tab |
| Max Import File Size | - | - | ✅ Collection Tab |
| Parser Workers | - | - | ✅ Advanced Tab |
| Memory Limit | - | - | ✅ Advanced Tab |
| 保存设置 | `config set` | POST /api/settings | ✅ Save按钮 |
| 重置设置 | - | POST /api/settings/reset | ✅ Reset按钮 |

**结论**: ✅ 三端功能基本统一

---

### 2.18 指标 (Metrics)

| 特性 | CLI | API | Frontend |
|------|-----|-----|----------|
| 指标展示 | `metrics` | GET /api/system/metrics | Metrics页面 |
| Prometheus格式 | - | - | ✅ Prometheus代码块 |
| 复制按钮 | - | - | ✅ Copy按钮 |
| 时间范围 | - | - | ✅ 1m/5m/1h选择 |
| 自动刷新 | - | - | ✅ 5秒刷新 |
| 事件吞吐量图 | - | - | ✅ Canvas图表 |

**结论**: ✅ 三端功能基本统一

---

### 2.19 UI 专属 API

| 特性 | API 端点 | 说明 |
|------|----------|------|
| 仪表板概览 | GET /api/ui/dashboard | 返回仪表板概览数据 |
| 告警分组 | GET /api/ui/alerts/groups | 返回按类型分组的告警 |
| 指标数据 | GET /api/ui/metrics | 返回指标数据 |
| 事件分布 | GET /api/ui/events/distribution | 返回事件分布统计 |

**结论**: ✅ 仅 Frontend 使用，无 CLI 对应

---

### 2.20 策略管理 API (Policy)

| 特性 | API 端点 | 说明 |
|------|----------|------|
| 策略模板列表 | GET /api/policy-templates | 列出策略模板 |
| 策略模板详情 | GET /api/policy-templates/:name | 获取特定模板 |
| 实例化模板 | POST /api/policy-templates | 实例化策略模板 |
| 应用模板 | POST /api/policy-templates/apply | 应用策略模板 |
| 删除策略 | DELETE /api/policy-templates/:name | 删除策略 |
| 策略实例列表 | GET /api/policy-instances | 列出策略实例 |
| 删除实例 | DELETE /api/policy-instances/:key | 删除策略实例 |
| 创建自定义策略 | POST /api/policies | 创建自定义策略 |
| 删除自定义策略 | DELETE /api/policies/:name | 删除自定义策略 |

**结论**: ✅ Frontend 使用，无 CLI 对应

---

## 3. 发现的不一致

### 3.1 CLI 独有的功能

| 功能 | CLI命令 | 说明 |
|------|---------|------|
| TUI界面 | `tui` | 终端UI界面，无API/前端对应 |
| API服务 | `serve` | 启动HTTP服务器，无API/前端对应 |
| 数据库管理 | `db` (status/vacuum/clean) | 数据库操作，无独立前端页面 |
| 文件验证 | `verify` | 单文件哈希验证，无API/前端对应 |

### 3.2 需要补充的功能

| 模块 | 缺失项 | 状态 | 根因 | 修复方案 |
|------|--------|------|------|----------|
| ~~CLI~~ | ~~`export timeline`~~ | ❌ 文档错误 | 命令已存在于 `report.go:186` | 无需修复 |
| ~~Reports~~ | ~~`/api/reports/export`~~ | ❌ 文档错误 | 应为 `/api/reports/:id/download` | 已修正 |
| API | `/api/ueba/baseline` | ✅ 已修复 (33e6db7) | UEBA baseline 存储在内存中，API handler 未暴露管理接口 | 为 `UEBAHandler` 添加 GetBaseline/LearnBaseline/ClearBaseline 方法 |
| API | `/api/alerts/export` | ✅ 已修复 (33e6db7) | `AlertHandler` 只有 ListAlerts，缺少导出端点 | 为 `AlertHandler` 添加 ExportAlerts 方法 |
| Frontend | Persistence SSE | ✅ 已修复 (33e6db7) | 后端已实现 SSE 端点，前端未调用 | 在 `gui/src/api/index.ts` 添加 detectStream 方法 |

### 3.3 发现遗漏的 API 端点 (代码中有但文档未记录)

| 模块 | 遗漏的 API 端点 | 说明 |
|------|----------------|------|
| Alerts | `GET /api/alerts/trend` | 告警趋势数据 |
| Forensics | `GET /api/forensics/verify-hash` | 验证文件哈希 |
| Forensics | `GET /api/forensics/is-signed` | 检查文件签名状态 |
| Forensics | `POST /api/forensics/manifest` | 生成证据清单 |
| Forensics | `GET /api/forensics/memory-dump` | 内存转储 |
| Forensics | `GET /api/forensics/evidence/:id` | 获取特定证据详情 |
| UI | `GET /api/ui/dashboard` | 仪表板概览 |
| UI | `GET /api/ui/alerts/groups` | 告警分组数据 |
| UI | `GET /api/ui/metrics` | 指标数据 |
| UI | `GET /api/ui/events/distribution` | 事件分布 |
| Policy | 9个端点 | 策略模板和实例管理 |

---

## 4. 结论

### 4.1 整体评估

| 评估项 | 当前状态 | 修复后预期 |
|--------|----------|------------|
| 功能覆盖完整性 | 95% (含遗漏API端点) | 100% |
| API与Frontend一致性 | 90% (遗漏UI/Policy API) | 100% |
| CLI与API一致性 | 95% | 100% |
| 文档准确性 | ⚠️ 需修正 | ✅ 准确 |
| 三端统一性 | ✅ 良好 | ✅ 优秀 |
| 缺失功能修复 | ❌ 3项待修复 | ✅ 全部修复完成 |

### 4.2 统计数据

| 类别 | 数量 | 备注 |
|------|------|------|
| CLI主命令 | 26个 | 包含 persistence (Windows) |
| CLI子命令 | ~40个 | 各模块的子命令 |
| API端点 | ~90个 | 含UI/Policy专属端点 |
| Frontend页面 | 21个页面 | |
| 完全匹配的功能模块 | 18个 | |
| CLI专属功能 | 5个 | tui, serve, db, verify |
| 文档遗漏API端点 | 16个 | 需补充到文档 |

### 4.3 详细修复方案

#### 1. `/api/ueba/baseline` 端点修复

**根因**：
- Baseline 数据存储在内存中的 `BaselineManager` (`internal/ueba/baseline.go`)
- CLI 命令 `ueba baseline` 操作的是即时创建的 engine 内存数据
- API `UEBAHandler` 持有 `ueba.Engine` 但未暴露 baseline 管理接口

**修复方案**：
```
文件: internal/api/handlers_ueba.go
1. 添加方法:
   - GetBaseline(c *gin.Context)      // GET /api/ueba/baseline
   - LearnBaseline(c *gin.Context)     // POST /api/ueba/baseline/learn
   - ClearBaseline(c *gin.Context)     // DELETE /api/ueba/baseline

2. 修改 SetupUEBARoutes() 注册新路由:
   ueba.GET("/baseline", GetBaseline)
   ueba.POST("/baseline/learn", LearnBaseline)
   ueba.DELETE("/baseline", ClearBaseline)
```

#### 2. `/api/alerts/export` 端点修复

**根因**：
- CLI `alert export` 命令（`cmd/winalog/commands/alert.go:294`）支持 JSON/CSV 导出
- API `AlertHandler` 只有 `ListAlerts`，缺少导出专用端点
- `AlertRepo` 的 `Query` 方法可用于获取大量 alerts 数据

**修复方案**：
```
文件: internal/api/handlers.go
1. 添加方法 ExportAlerts(c *gin.Context):
   - 获取查询参数: format (json/csv), severity, resolved, start_time, end_time
   - 使用 AlertRepo.Query() 获取 alerts
   - 根据 format 调用不同的序列化方法

2. 文件: internal/api/routes.go
   添加路由: alerts.GET("/export", alertHandler.ExportAlerts)
```

#### 3. Persistence SSE 前端修复

**根因**：
- 后端 SSE 端点已实现: `internal/api/handlers_persistence_stream.go`
- 前端 `gui/src/api/index.ts` 只定义了同步的 `detect()` 方法
- 前端 `Persistence.tsx` 使用普通 HTTP 调用而非 EventSource

**修复方案**：
```
文件: gui/src/api/index.ts
1. 添加方法:
   detectStream: () => api.get('/persistence/detect/stream')

文件: gui/src/pages/Persistence.tsx
1. 添加 SSE 处理函数，使用 EventSource 接收流式数据
2. 添加状态管理显示进度和实时结果
```

### 4.4 建议优先级

| 优先级 | 任务 | 工作量 | 状态 |
|--------|------|--------|--------|
| P1 | `/api/ueba/baseline` API 端点 | 中等 | ✅ 已完成 |
| P1 | `/api/alerts/export` API 端点 | 小 | ✅ 已完成 |
| P2 | Persistence SSE 前端实现 | 中等 | ✅ 已完成 |

### 4.5 修复后预期

修复完成后，功能覆盖将达 100%，三端（CLI/API/Frontend）完全统一。

**修复完成日期: 2026-04-18 (commit 33e6db7)**

---

*报告生成时间: 2026-04-17*
*最后更新: 2026-04-18 - 全部3项修复完成并标记*
