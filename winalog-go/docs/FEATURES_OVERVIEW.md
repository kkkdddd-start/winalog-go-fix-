# WinLogAnalyzer-Go 功能概览

**版本**: v2.4.0  
**更新日期**: 2026-04-17

本文档按用户使用方式归纳 WinLogAnalyzer-Go 各模块的可用功能。

---

## 目录

1. [CLI 命令](#1-cli-命令)
2. [API 端点](#2-api-端点)
3. [TUI 界面](#3-tui-界面)
4. [Web UI 页面](#4-web-ui-页面)
5. [快速参考](#5-快速参考)

---

## 1. CLI 命令

### 1.1 数据导入

| 命令 | 功能 | 关键选项 |
|------|------|----------|
| `import` | 导入 EVTX/ETL/CSV/IIS/Sysmon/LOG 文件 | `--workers`, `--batch-size`, `--incremental`, `--alert-on-import`, `--skip-patterns`, `--format` |

### 1.2 事件搜索

| 命令 | 功能 | 关键选项 |
|------|------|----------|
| `search` | 全文搜索事件 | `--keywords`, `--regex`, `--event-id`, `--level`, `--user`, `--computer`, `--start-time`, `--end-time` |
| `query` | 执行 SQL 查询 | 直接输入 SQL 语句 |

### 1.3 数据导出

| 命令 | 功能 | 关键选项 |
|------|------|----------|
| `export` | 导出数据 | `--format json\|csv\|timeline`, `--include-events`, `--include-alerts` |

### 1.4 告警管理

| 命令 | 子命令 | 功能 |
|------|--------|------|
| `alert` | `list` | 列出告警 |
| `alert` | `show <id>` | 显示告警详情 |
| `alert` | `resolve <id>` | 标记已解决 |
| `alert` | `delete <id>` | 删除告警 |
| `alert` | `export` | 导出告警 |
| `alert` | `stats` | 告警统计 |
| `alert` | `run` | 运行告警分析 |
| `alert` | `monitor` | 持续监控模式 |
| `alert` | `upgrade` | 告警升级（高危告警自动提升） |
| `alert` | `suppress` | 告警抑制（误报过滤） |

### 1.5 威胁分析

| 命令 | 功能 |
|------|------|
| `analyze [type]` | 运行分析器（brute_force, login, kerberos, powershell, lateral_movement, privilege_escalation, persistence, data_exfiltration, file_analysis, anomaly_detection） |
| `correlate` | 关联分析 |

### 1.6 取证与持久化

| 命令 | 功能 | 关键选项 |
|------|------|----------|
| `collect` | 一键采集取证数据 | `--include-prefetch`, `--include-registry`, `--compress` |
| `forensics` | 取证功能 | `collect`, `hash`, `verify` |
| `persistence detect` | 持久化检测 | `--category`, `--technique`, `--format` |

### 1.7 报告

| 命令 | 功能 |
|------|------|
| `report generate` | 生成报告（security, summary, threat, compliance） |
| `report templates` | 报告模板管理 |

### 1.8 白名单管理

| 命令 | 功能 |
|------|------|
| `whitelist` | 白名单查看/添加/删除 |

### 1.9 其他命令

| 命令 | 功能 |
|------|------|
| `dashboard` | 统计仪表板 |
| `info` | 系统信息（`--process`, `--network`, `--registry`, `--tasks`） |
| `config get/set` | 配置管理 |
| `db` | 数据库管理（status, vacuum, clean） |
| `rules` | 规则管理（list, validate, enable, disable） |
| `whitelist` | 白名单管理 |
| `ueba` | 用户行为分析 |
| `multi` | 多机分析 |
| `live collect` | 实时监控 |
| `tui` | 启动 TUI 界面 |
| `serve` | 启动 API 服务 |
| `profile` | 性能分析（--output, --type cpu\|mem\|block） |

---

## 2. API 端点

### 2.0 通用参数

| 参数 | 类型 | 说明 |
|------|------|------|
| `page` | int | 页码（默认 1） |
| `page_size` | int | 每页数量（默认 50，最大 1000） |
| `start_time` | string | 开始时间（ISO 8601） |
| `end_time` | string | 结束时间（ISO 8601） |
| `level` | string | 过滤级别（info/warning/error/critical） |
| `keyword` | string | 关键词搜索 |

### 2.1 事件 API

| 方法 | 端点 | 功能 |
|------|------|------|
| GET | `/api/events` | 获取事件列表 |
| GET | `/api/events/:id` | 获取单个事件 |
| POST | `/api/events/search` | 搜索事件 |
| POST | `/api/events/export` | 导出事件 |

### 2.2 告警 API

| 方法 | 端点 | 功能 |
|------|------|------|
| GET | `/api/alerts` | 获取告警列表 |
| GET | `/api/alerts/stats` | 获取告警统计 |
| GET | `/api/alerts/trend` | 获取告警趋势 |
| POST | `/api/alerts/run-analysis` | 运行告警分析 |
| GET | `/api/alerts/:id` | 获取告警详情 |
| POST | `/api/alerts/:id/resolve` | 解决告警 |
| POST | `/api/alerts/:id/false-positive` | 标记误报 |
| DELETE | `/api/alerts/:id` | 删除告警 |
| POST | `/api/alerts/batch` | 批量操作 |

### 2.3 分析 API

| 方法 | 端点 | 功能 |
|------|------|------|
| GET | `/api/analyzers` | 获取分析器列表 |
| GET | `/api/analyzers/:type` | 获取分析器详情 |
| POST | `/api/analyze/:type` | 运行分析 |
| POST | `/api/correlation/analyze` | 关联分析 |

### 2.4 报告 API

| 方法 | 端点 | 功能 |
|------|------|------|
| GET | `/api/reports` | 获取报告列表 |
| POST | `/api/reports` | 生成报告 |
| GET | `/api/reports/:id` | 获取报告详情 |
| GET | `/api/report-templates` | 获取报告模板 |
| POST | `/api/report-templates` | 创建模板 |
| PUT | `/api/report-templates/:name` | 更新模板 |
| DELETE | `/api/report-templates/:name` | 删除模板 |

### 2.5 系统信息 API

| 方法 | 端点 | 功能 |
|------|------|------|
| GET | `/api/system/info` | 系统信息 |
| GET | `/api/system/metrics` | 系统指标 |
| GET | `/api/system/processes` | 进程列表 |
| GET | `/api/system/process/:pid/dlls` | 进程 DLL |
| GET | `/api/system/network` | 网络连接 |
| GET | `/api/system/users` | 用户列表 |
| GET | `/api/system/registry` | 注册表信息 |
| GET | `/api/system/tasks` | 计划任务 |
| GET | `/api/system/dlls` | DLL 列表 |
| GET | `/api/system/drivers` | 驱动列表 |

### 2.6 规则 API

| 方法 | 端点 | 功能 |
|------|------|------|
| GET | `/api/rules` | 获取规则列表 |
| GET | `/api/rules/:name` | 获取规则详情 |
| POST | `/api/rules` | 创建规则 |
| PUT | `/api/rules/:name` | 更新规则 |
| DELETE | `/api/rules/:name` | 删除规则 |
| POST | `/api/rules/:name/toggle` | 切换启用状态 |
| POST | `/api/rules/validate` | 验证规则 |
| POST | `/api/rules/import` | 导入规则 |
| GET | `/api/rules/export` | 导出规则 |
| GET | `/api/rules/templates` | 获取规则模板 |
| POST | `/api/rules/templates/:name/instantiate` | 实例化模板 |

### 2.7 持久化检测 API

| 方法 | 端点 | 功能 |
|------|------|------|
| GET | `/api/persistence/detect` | 执行检测 |
| GET | `/api/persistence/detect/stream` | 流式检测 |
| GET | `/api/persistence/categories` | 获取类别 |
| GET | `/api/persistence/techniques` | 获取技术列表 |

### 2.8 取证 API

| 方法 | 端点 | 功能 |
|------|------|------|
| POST | `/api/forensics/hash` | 计算哈希 |
| GET | `/api/forensics/signature` | 签名验证 |
| GET | `/api/forensics/is-signed` | 检查签名状态 |
| POST | `/api/forensics/collect` | 收集证据 |
| GET | `/api/forensics/evidence` | 获取证据列表 |
| GET | `/api/forensics/chain-of-custody` | 监管链 |
| POST | `/api/forensics/manifest` | 生成清单 |
| GET | `/api/forensics/memory-dump` | 内存转储 |

### 2.9 UEBA API

| 方法 | 端点 | 功能 |
|------|------|------|
| POST | `/api/ueba/analyze` | 运行分析 |
| GET | `/api/ueba/profiles` | 获取用户画像 |
| GET | `/api/ueba/anomaly/:type` | 获取异常类型 |

### 2.10 其他 API

| 方法 | 端点 | 功能 |
|------|------|------|
| GET | `/api/dashboard/collection-stats` | 仪表板统计 |
| GET | `/api/timeline` | 时间线 |
| GET | `/api/timeline/stats` | 时间线统计 |
| GET | `/api/timeline/chains` | 攻击链 |
| POST | `/api/import/logs` | 导入日志 |
| GET | `/api/import/status` | 导入状态 |
| GET | `/api/live/events` | 实时事件流 |
| GET | `/api/live/stats` | 实时统计 |
| POST | `/api/collect` | 开始收集 |
| POST | `/api/collect/import` | 导入收集的日志 |
| GET | `/api/collect/status` | 收集状态 |
| POST | `/api/multi/analyze` | 多机分析 |
| GET | `/api/multi/lateral` | 横向移动 |
| POST | `/api/query/execute` | SQL 查询 |
| GET | `/api/suppress` | 抑制规则列表 |
| POST | `/api/suppress` | 创建抑制规则 |
| PUT | `/api/suppress/:id` | 更新抑制规则 |
| DELETE | `/api/suppress/:id` | 删除抑制规则 |
| POST | `/api/suppress/:id/toggle` | 切换启用状态 |
| GET | `/api/settings` | 获取设置 |
| POST | `/api/settings` | 保存设置 |
| POST | `/api/settings/reset` | 重置设置 |
| GET | `/api/ui/dashboard` | UI 仪表板 |
| GET | `/api/ui/alerts/groups` | 告警分组 |
| GET | `/api/ui/metrics` | UI 指标 |
| GET | `/api/ui/events/distribution` | 事件分布 |
| GET | `/api/policy-templates` | 策略模板 |
| POST | `/api/policy-templates` | 创建策略模板 |
| POST | `/api/policy-templates/apply` | 应用策略模板 |
| DELETE | `/api/policy-templates/:name` | 删除策略模板 |
| GET | `/api/policy-instances` | 策略实例 |
| DELETE | `/api/policy-instances/:key` | 删除策略实例 |
| POST | `/api/policies` | 创建策略 |
| DELETE | `/api/policies/:name` | 删除策略 |
| GET | `/api/health` | 健康检查 |

---

## 3. TUI 界面

启动命令: `winalog tui`

### 3.1 视图列表（11个）

| 视图 | 快捷键 | 功能 |
|------|--------|------|
| Dashboard | `d` | 统计概览 |
| Events | `e` | 事件列表 |
| Event Detail | `Enter` | 事件详情 |
| Alerts | `a` | 告警列表 |
| Alert Detail | `Enter` | 告警详情 |
| Search | `/` | 搜索界面 |
| Timeline | `t` | 时间线 |
| Collect | `c` | 一键采集 |
| Live Monitor | `l` | 实时监控 |
| Persistence | `p` | 持久化检测 |
| Help | `?` | 帮助 |

### 3.2 全局快捷键

| 键 | 功能 |
|----|------|
| `q` | 退出 |
| `?` | 帮助 |
| `/` | 搜索 |
| `j` | 下移 |
| `k` | 上移 |
| `g` | 跳转到顶部 |
| `G` | 跳转到底部 |
| `Enter` | 选择/确认 |
| `Esc` | 返回 |

---

## 4. Web UI 页面

启动命令: `winalog serve`（默认端口 8080）

### 4.1 页面列表

| 路由 | 页面 | 功能 |
|------|------|------|
| `/` | Dashboard | 统计图表、告警概览 |
| `/events` | Events | 事件列表、筛选、分页 |
| `/events/:id` | Event Detail | 事件详情、XML |
| `/alerts` | Alerts | 告警列表、管理 |
| `/alerts/:id` | Alert Detail | 告警详情、处置 |
| `/timeline` | Timeline | 攻击链可视化 |
| `/reports` | Reports | 报告生成 |
| `/forensics` | Forensics | 取证采集、Hash 验证 |
| `/system-info` | SystemInfo | 系统信息采集 |
| `/rules` | Rules | 规则管理、编辑器 |
| `/settings` | Settings | 配置管理 |
| `/metrics` | Metrics | Prometheus 指标 |
| `/collect` | Collect | 一键采集 |
| `/live` | Live | 实时监控 |
| `/multi` | Multi | 多机分析 |
| `/query` | Query | SQL 查询 |
| `/persistence` | Persistence | 持久化检测 |
| `/suppress` | Suppress | 白名单管理 |
| `/correlation` | Correlation | 关联分析 |
| `/ueba` | UEBA | 用户行为分析 |
| `/analyze` | Analyze | 分析器执行 |

---

## 5. 快速参考

### 5.1 常用命令

| 任务 | 命令 |
|------|------|
| 导入日志文件 | `winalog import <file>` |
| 搜索事件 | `winalog search --event-id <id>` |
| 查看告警 | `winalog alert list` |
| 运行分析 | `winalog analyze` |
| 生成报告 | `winalog report generate` |
| 检测持久化 | `winalog persistence detect` |
| 启动 Web UI | `winalog serve` |
| 启动 TUI | `winalog tui` |
| 实时监控 | `winalog live collect` |
| 收集取证数据 | `winalog collect` |

### 5.2 常用 API

| 任务 | API 端点 |
|------|----------|
| 获取事件 | `GET /api/events` |
| 搜索事件 | `POST /api/events/search` |
| 获取告警 | `GET /api/alerts` |
| 运行分析 | `POST /api/alerts/run-analysis` |
| 获取统计 | `GET /api/dashboard/collection-stats` |
| SQL 查询 | `POST /api/query/execute` |

### 5.3 分析器类型

| 类型 | 检测内容 |
|------|----------|
| `brute_force` | 暴力破解攻击 |
| `login` | 登录行为分析 |
| `kerberos` | Kerberos 协议异常 |
| `powershell` | PowerShell 恶意使用 |
| `data_exfiltration` | 数据外泄 |
| `lateral_movement` | 横向移动 |
| `privilege_escalation` | 权限提升 |
| `persistence` | 持久化机制 |
| `file_analysis` | 文件分析（哈希、签名、熵值） |
| `anomaly_detection` | 异常行为检测 |

### 5.4 内置规则（60+ 规则，MITRE ATT&CK 映射）

| 类别 | 示例规则 |
|------|----------|
| 凭证访问 | T1110 暴力破解、T1003 凭证转储 |
| 持久化 | T1547 注册表Run键、T1053 计划任务 |
| 横向移动 | T1021 远程服务、T1550 替代凭证 |
| 权限提升 | T1068 特权提升、T1548 滥用权限 |
| 命令与控制 | T1059 命令执行、T1105 外部远程服务 |
| 数据外泄 | T1041 编码数据、T1567 加密外泄 |

### 5.5 持久化技术

| 技术 ID | 技术名称 | 类别 |
|---------|----------|------|
| T1546.001 | Accessibility Features | Registry |
| T1546.003 | WMI Event Subscription | WMI |
| T1546.010 | AppInit_DLLs | Registry |
| T1546.012 | IFEO Debugger | Registry |
| T1546.015 | COM Hijacking | COM |
| T1546.016 | Startup Folder | File |
| T1547.001 | Registry Run Keys | Registry |
| T1053.005 | Scheduled Task | Tasks |
| T1543.003 | Windows Service | Service |

### 5.6 常用事件 ID

| 事件 ID | 描述 | 日志源 |
|---------|------|--------|
| 4624 | 账户登录成功 | Security |
| 4625 | 账户登录失败 | Security |
| 4672 | 特殊权限分配 | Security |
| 4688 | 进程创建 | Security |
| 4697 | 服务创建 | Security |
| 4698 | 计划任务创建 | Security |
| 7045 | 服务创建 | System |
| 4103 | PowerShell 模块日志 | PowerShell |
| 4104 | PowerShell 脚本块日志 | PowerShell |

---

**文档版本**: v2.5.0  
**最后更新**: 2026-04-17
