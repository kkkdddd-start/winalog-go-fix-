# WinLogAnalyzer-Go CLI 命令参考

本文档列出 WinLogAnalyzer-Go 所有实际实现的 CLI 命令及其详细说明。

## 目录

- [全局选项](#全局选项)
- [1. import - 导入日志文件](#1-import---导入日志文件)
- [2. search - 搜索事件日志](#2-search---搜索事件日志)
- [3. collect - 收集取证数据](#3-collect---收集取证数据)
- [4. alert - 告警管理](#4-alert---告警管理)
- [5. correlate - 关联分析](#5-correlate---关联分析)
- [6. analyze - 威胁分析](#6-analyze---威胁分析)
- [7. report - 生成报告](#7-report---生成报告)
- [8. export - 导出数据](#8-export---导出数据)
- [9. timeline - 时间线分析](#9-timeline---时间线分析)
- [10. multi - 多机分析](#10-multi---多机分析)
- [11. live - 实时监控](#11-live---实时监控)
- [12. status - 系统状态](#12-status---系统状态)
- [13. info - 系统信息](#13-info---系统信息)
- [14. verify - 文件验证](#14-verify---文件验证)
- [15. rules - 规则管理](#15-rules---规则管理)
- [16. db - 数据库管理](#16-db---数据库管理)
- [17. config - 配置管理](#17-config---配置管理)
- [18. metrics - 指标展示](#18-metrics---指标展示)
- [19. query - SQL 查询](#19-query---sql-查询)
- [20. tui - 终端界面](#20-tui---终端界面)
- [21. serve - 启动 API 服务](#21-serve---启动-api-服务)
- [22. forensics - 取证功能](#22-forensics---取证功能)
- [23. dashboard - 统计仪表板](#23-dashboard---统计仪表板)
- [24. whitelist - 白名单管理](#24-whitelist---白名单管理)
- [25. ueba - 用户行为分析](#25-ueba---用户行为分析)
- [26. persistence - 持久化检测](#26-persistence---持久化检测)
- [27. evtx2csv - EVTX 转 CSV](#27-evtx2csv---evtx-转-csv)

---

## 全局选项

所有命令支持以下全局选项：

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--db <path>` | 数据库路径 | `winalog.db` |
| `--log-level <level>` | 日志级别 (debug/info/warn/error) | `info` |
| `--config <path>` | 配置文件路径 | - |

---

## 1. import - 导入日志文件

将 EVTX、ETL、LOG、CSV 格式的 Windows 事件日志文件导入数据库。

### 用法

```bash
winalog import <file> [file2] [file3] ... [flags]
```

### 参数

| 参数 | 描述 |
|------|------|
| `<file>` | 要导入的日志文件路径 (支持多个文件) |

### 选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--log-name <name>` | 日志名称/来源标识 | 自动检测 |
| `--incremental` | 增量导入模式（跳过已导入事件） | `true` |
| `--workers <n>` | 并行导入的工作线程数 | `4` |
| `--batch-size <n>` | 每批次插入的事件数 | `10000` |
| `--alert-on-import` | 导入后立即触发告警分析 | `false` |
| `--skip-patterns <patterns>` | 跳过匹配模式的文件（逗号分隔） | - |

### 示例

```bash
# 导入单个 EVTX 文件
winalog import Security.evtx

# 导入多个文件
winalog import System.evtx Application.evtx Security.evtx

# 指定日志名称
winalog import Security.evtx --log-name "WindowsSecurity"

# 禁用增量模式（强制重新导入）
winalog import Security.evtx --incremental=false

# 使用 8 个工作线程加速导入
winalog import large_log.evtx --workers 8

# 导入后触发告警分析
winalog import Security.evtx --alert-on-import
```

### 支持的格式

- `.evtx` - Windows 事件日志文件
- `.etl` - 事件跟踪日志 (ETW)
- `.log` - 通用日志格式
- `.csv` - CSV 格式日志

---

## 2. search - 搜索事件日志

在已导入数据库中搜索 Windows 事件日志。

### 用法

```bash
winalog search [flags]
```

### 选项

| 选项 | 描述 |
|------|------|
| `--keywords <text>` | 搜索关键词 |
| `--keyword-mode <mode>` | 关键词匹配模式：`AND` 或 `OR` |
| `--regex` | 启用正则表达式匹配 |
| `--event-id <id>` | 按事件 ID 过滤 (支持逗号分隔多 ID) |
| `--level <level>` | 按事件级别过滤 (1=Critical, 2=Error, 3=Warning, 4=Information) |
| `--log-name <name>` | 按日志名称过滤 (Security, System, Application 等) |
| `--user <username>` | 按用户名过滤 |
| `--computer <name>` | 按计算机名过滤 |
| `--source <name>` | 按事件源过滤 |
| `--start-time <time>` | 开始时间 (RFC3339 格式) |
| `--end-time <time>` | 结束时间 (RFC3339 格式) |
| `--sort-by <field>` | 排序字段 (timestamp, event_id, level) |
| `--sort-order <order>` | 排序顺序：`asc` 或 `desc` |
| `--highlight` | 高亮显示匹配关键词 |
| `--page <n>` | 页码 |
| `--page-size <n>` | 每页事件数 |
| `--output <file>` | 输出到文件 |

### 示例

```bash
# 基本关键词搜索
winalog search --keywords "登录失败"

# 正则表达式搜索
winalog search --regex --keywords "NTLM.*失败|Kerberos.*错误"

# 搜索指定事件 ID
winalog search --event-id 4625

# 搜索多个事件 ID
winalog search --event-id 4624,4625,4672

# 按级别过滤
winalog search --level 2

# 组合过滤
winalog search --event-id 4625 --level 2 --computer DC01

# 时间范围搜索
winalog search --start-time "2024-01-01T00:00:00Z" --end-time "2024-01-02T00:00:00Z"

# 输出到文件
winalog search --event-id 4625 --output failed_logins.json
```

---

## 3. collect - 收集取证数据

一键收集 Windows 系统各类取证数据。

### 用法

```bash
winalog collect [flags]
```

### 选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--output, -o <file>` | 输出文件路径 | `winalog_collect_<timestamp>.zip` |
| `--include-logs` | 包含 Windows 事件日志 | `true` |
| `--include-prefetch` | 包含 Prefetch 文件 | `false` |
| `--include-shimcache` | 包含 ShimCache 数据 | `false` |
| `--include-amcache` | 包含 Amcache 数据 | `false` |
| `--include-userassist` | 包含 UserAssist 数据 | `false` |
| `--include-registry` | 包含注册表持久化点 | `false` |
| `--include-tasks` | 包含计划任务 | `false` |
| `--include-system-info` | 包含系统信息 | `true` |
| `--compress` | 压缩输出 | `true` |
| `--compress-level <n>` | 压缩级别 (0-9) | `6` |
| `--workers <n>` | 并行工作线程数 | `4` |
| `--calculate-hash` | 计算 SHA256 哈希 | `false` |
| `--password <pwd>` | ZIP 密码保护 | - |
| `--exclude <patterns>` | 排除匹配模式的文件（逗号分隔） | - |

### 示例

```bash
# 基本收集
winalog collect

# 指定输出文件
winalog collect -o forensic_data.zip

# 收集所有取证数据
winalog collect --include-prefetch --include-shimcache --include-amcache --include-registry --include-tasks

# 高压缩比收集
winalog collect --compress-level 9

# 使用 8 个工作线程
winalog collect --workers 8
```

---

## 4. alert - 告警管理

告警管理命令组，包括查看、解决、删除告警等操作。

### 用法

```bash
winalog alert <subcommand> [flags]
```

### 子命令

#### 4.1 alert list - 列出告警

列出所有匹配的告警。

```bash
winalog alert list [flags]
```

| 选项 | 描述 |
|------|------|
| `--severity <level>` | 按严重级别过滤 (1=Critical, 2=High, 3=Medium, 4=Low) |
| `--resolved` | 仅显示已解决的告警 |
| `--rule <name>` | 按规则名称过滤 |
| `--limit <n>` | 最大显示数量 |
| `--page <n>` | 页码 |
| `--format <type>` | 输出格式：`table`、`json`、`csv` |

#### 4.2 alert show - 显示告警详情

显示指定告警的详细信息。

```bash
winalog alert show <id> [flags]
```

| 选项 | 描述 |
|------|------|
| `--json` | JSON 格式输出 |

#### 4.3 alert resolve - 标记告警已解决

标记指定告警为已解决状态。

```bash
winalog alert resolve <id> [flags]
```

| 选项 | 描述 |
|------|------|
| `--comment <text>` | 添加解决备注 |

#### 4.4 alert delete - 删除告警

删除指定告警。

```bash
winalog alert delete <id>
```

#### 4.5 alert export - 导出告警

将告警导出为 JSON 格式。

```bash
winalog alert export [output-file] [flags]
```

| 选项 | 描述 |
|------|------|
| `--format <type>` | 导出格式：`json`、`csv` |

#### 4.6 alert stats - 告警统计

显示告警统计信息。

```bash
winalog alert stats [flags]
```

| 选项 | 描述 |
|------|------|
| `--hours <n>` | 统计时间窗口（小时） |

#### 4.7 alert run - 运行告警分析

对已存储的事件运行告警分析引擎。

```bash
winalog alert run [flags]
```

| 选项 | 描述 |
|------|------|
| `--rules <names>` | 指定要运行的规则（逗号分隔） |
| `--batch-size <n>` | 处理批次大小 |
| `--clear-dedup` | 清除去重缓存后重新分析 |

#### 4.8 alert monitor - 持续监控

启动持续监控模式，实时检测新事件并触发告警。

```bash
winalog alert monitor [flags]
```

| 选项 | 描述 |
|------|------|
| `--interval <seconds>` | 检查间隔（秒） |
| `--batch-size <n>` | 每次检查的批次大小 |

### 示例

```bash
# 列出所有告警
winalog alert list

# 列出高严重级别告警
winalog alert list --severity 1 --severity 2

# 显示告警详情
winalog alert show 123

# 标记告警为已解决
winalog alert resolve 123 --comment "确认为正常操作"

# 删除告警
winalog alert delete 123

# 导出告警到文件
winalog alert export alerts.json

# 查看告警统计
winalog alert stats

# 运行告警分析
winalog alert run

# 启动实时监控
winalog alert monitor --interval 10
```

---

## 5. correlate - 关联分析

运行关联分析引擎，检测复杂攻击链。

### 用法

```bash
winalog correlate [flags]
```

### 选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--time-window <duration>` | 关联分析的时间窗口 | `24h` |
| `--rules <names>` | 指定运行的规则（逗号分隔） | 全部规则 |
| `--format <type>` | 输出格式：`table`、`json` | `table` |
| `--output, -o <file>` | 输出到文件 | - |

### 示例

```bash
# 基本关联分析
winalog correlate

# 指定 48 小时时间窗口
winalog correlate --time-window 48h

# 指定特定规则
winalog correlate --rules "LateralMovement,BruteForce"

# 输出为 JSON
winalog correlate --format json

# 保存结果
winalog correlate -o correlation_results.json
```

---

## 6. analyze - 威胁分析

运行威胁分析器检测各类攻击行为。

### 用法

```bash
winalog analyze [type] [flags]
```

### 参数

| 参数 | 描述 |
|------|------|
| `[type]` | 分析器类型（可选，不指定时列出所有分析器） |

### 选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--hours <n>` | 分析时间窗口（小时） | `24` |
| `--time-window <duration>` | 时间窗口（覆盖 --hours） | - |
| `--format <type>` | 输出格式：`table`、`json` | `table` |
| `--output, -o <file>` | 输出到文件 | - |

### 列出可用分析器

```bash
winalog analyze
winalog analyze list
```

显示所有可用的威胁分析器及其描述（两种写法等价）。

### 内置分析器

| 分析器 | 检测内容 |
|--------|----------|
| `brute_force` | 暴力破解攻击 |
| `login` | 登录行为分析 |
| `kerberos` | Kerberos 协议异常 |
| `powershell` | PowerShell 恶意使用 |
| `data_exfiltration` | 数据外泄 |
| `lateral_movement` | 横向移动 |
| `privilege_escalation` | 权限提升 |
| `persistence` | 持久化机制 |

### 示例

```bash
# 列出所有分析器
winalog analyze list

# 运行分析（过去 24 小时）
winalog analyze

# 分析过去 48 小时
winalog analyze --hours 48

# 指定时间窗口
winalog analyze --time-window 72h

# JSON 格式输出
winalog analyze --format json
```

---

## 7. report - 生成报告

生成安全分析报告。

### 用法

```bash
winalog report <subcommand> [flags]
```

### 子命令

#### report generate - 生成报告

```bash
winalog report generate [type] [flags]
```

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--format <type>` | 报告格式：`html`、`json` | `html` |
| `--output, -o <file>` | 输出文件路径 | - |
| `--time-range <duration>` | 报告时间范围 | `24h` |

### 报告类型

| 类型 | 描述 |
|------|------|
| `security` | 安全事件摘要报告 |
| `summary` | 综合分析摘要 |
| `threat` | 威胁检测报告 |
| `compliance` | 合规性报告 |

### 示例

```bash
# 生成安全报告
winalog report generate security

# 生成 JSON 格式报告
winalog report generate summary --format json

# 指定时间范围
winalog report generate threat --time-range 7d

# 指定输出文件
winalog report generate security -o security_report.html
```

---

## 8. export - 导出数据

导出事件数据为多种格式。

### 用法

```bash
winalog export <subcommand> [file] [flags]
```

### 子命令

#### export json - 导出为 JSON

```bash
winalog export json [file] [flags]
```

#### export csv - 导出为 CSV

```bash
winalog export csv [file] [flags]
```

#### export timeline - 导出时间线

```bash
winalog export timeline [file] [flags]
```

### 选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--format <type>` | 导出格式：`csv`、`json`、`excel` | `csv` |
| `--limit <n>` | 最大导出事件数 | `10000` |

### 示例

```bash
# 导出为 CSV
winalog export csv export.csv

# 导出为 JSON
winalog export json events.json

# 导出时间线
winalog export timeline timeline.csv

# 限制导出数量
winalog export csv --limit 50000
```

---

## 9. timeline - 时间线分析

构建和查询全局事件时间线。

### 用法

```bash
winalog timeline <subcommand> [flags]
```

### 子命令

#### timeline build - 构建时间线

从已存储的事件构建全局时间线索引。

```bash
winalog timeline build [flags]
```

#### timeline query - 查询时间线

查询时间线中的事件。

```bash
winalog timeline query [flags]
```

| 选项 | 描述 |
|------|------|
| `--start <time>` | 开始时间 (RFC3339) |
| `--end <time>` | 结束时间 (RFC3339) |
| `--category <name>` | 按类别过滤 |
| `--computer <name>` | 按计算机名过滤 |

### 示例

```bash
# 构建全局时间线
winalog timeline build

# 查询时间线
winalog timeline query --start "2024-01-01T00:00:00Z" --end "2024-01-02T00:00:00Z"

# 按计算机过滤
winalog timeline query --computer DC01
```

---

## 10. multi - 多机分析

跨多台机器进行关联分析和横向移动检测。

### 用法

```bash
winalog multi <subcommand> [flags]
```

### 子命令

#### multi analyze - 跨机器关联分析

```bash
winalog multi analyze
```

#### multi lateral - 横向移动检测

```bash
winalog multi lateral [flags]
```

### 检测的攻击模式

- **Pass-the-Hash** - 使用哈希传递的攻击
- **远程桌面跳转** - RDP 跳跃攻击
- **管理员到管理员登录** - 横向移动
- **远程账户创建** - 在远程机器创建账户

### 示例

```bash
# 运行多机关联分析
winalog multi analyze

# 检测横向移动
winalog multi lateral

# 指定时间窗口
winalog multi analyze --time-window 48h
```

---

## 11. live - 实时监控

实时监控 Windows 事件日志。

### 用法

```bash
winalog live <subcommand> [flags]
```

### 子命令

#### live collect - 开始实时收集

```bash
winalog live collect
```

启动实时监控模式，持续监控数据库中的新事件并通过 SSE 流输出。

### 示例

```bash
# 开始实时收集
./winalog live collect
```

| 选项 | 描述 |
|------|------|
| `--log-name <name>` | 监控的日志名称 |
| `--event-id <id>` | 监控特定事件 ID |
| `--rules <names>` | 触发告警的规则 |

### 示例

```bash
# 开始实时收集
winalog live collect

# 监控特定日志
winalog live collect --log-name Security

# 监控特定事件
winalog live collect --event-id 4625 --event-id 4672
```

---

## 12. status - 系统状态

显示 WinLogAnalyzer 系统状态。

### 用法

```bash
winalog status [flags]
```

### 显示信息

- 数据库连接状态
- 事件统计
- 告警摘要
- 存储使用情况
- 最后分析时间

### 示例

```bash
winalog status
```

---

## 13. info - 系统信息

收集和显示 Windows 系统信息。

### 用法

```bash
winalog info [flags]
```

### 选项

| 选项 | 描述 |
|------|------|
| `--process` | 显示进程信息 |
| `--network` | 显示网络连接 |
| `--registry` | 显示注册表持久化点 |
| `--tasks` | 显示计划任务 |
| `--save` | 保存到数据库 |

### 示例

```bash
# 显示所有系统信息
./winalog info

# 仅显示进程
./winalog info --process

# 显示网络连接
./winalog info --network

# 显示注册表持久化点
./winalog info --registry

# 显示计划任务
./winalog info --tasks

# 保存信息到数据库
./winalog info --save
```

---

## 14. verify - 文件验证

计算并显示文件的 SHA256 哈希值。

### 用法

```bash
winalog verify <file>
```

### 参数

| 参数 | 描述 |
|------|------|
| `<file>` | 要验证的文件路径 |

### 示例

```bash
# 验证文件哈希
winalog verify suspicious.exe

# 批量验证
winalog verify file1.dll file2.dll
```

---

## 15. rules - 规则管理

管理告警和关联规则。

### 用法

```bash
winalog rules <subcommand> [flags]
```

### 子命令

#### rules list - 列出所有规则

```bash
winalog rules list
```

#### rules validate - 验证规则文件

```bash
winalog rules validate <file>
```

#### rules enable - 启用规则

```bash
winalog rules enable <name>
```

#### rules disable - 禁用规则

```bash
winalog rules disable <name>
```

#### rules status - 显示规则状态

```bash
winalog rules status [name]
```

### 示例

```bash
# 列出所有规则
winalog rules list

# 仅显示已启用规则
winalog rules list --enabled

# 验证自定义规则文件
winalog rules validate custom_rules.yaml

# 启用规则
winalog rules enable BruteForce

# 禁用规则
winalog rules disable SuspiciousPowerShell

# 查看规则状态
winalog rules status
```

---

## 16. db - 数据库管理

管理 SQLite 数据库。

### 用法

```bash
winalog db <subcommand> [flags]
```

### 子命令

#### db status - 显示数据库状态

```bash
winalog db status
```

显示数据库大小、表数量、索引状态等。

#### db vacuum - 优化数据库

```bash
winalog db vacuum
```

执行 VACUUM 命令回收空间并优化数据库。

#### db clean - 清理旧数据

```bash
winalog db clean
```

清理超过 90 天的旧事件数据。

### 示例

```bash
# 查看数据库状态
./winalog db status

# 优化数据库
./winalog db vacuum

# 清理旧数据（保留最近 90 天）
./winalog db clean
```

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--days <n>` | 保留天数 | `90` |

### 示例

```bash
# 查看数据库状态
winalog db status

# 优化数据库
winalog db vacuum

# 清理 30 天前的数据
winalog db clean --days 30

# 清理所有超过 180 天的数据
winalog db clean --days 180
```

---

## 17. config - 配置管理

查看和修改 WinLogAnalyzer 配置。

### 用法

```bash
winalog config <subcommand> [flags]
```

### 子命令

#### config get - 获取配置值

```bash
winalog config get [key]
```

#### config set - 设置配置值

```bash
winalog config set <key> <value>
```

### 示例

```bash
# 获取所有配置
winalog config get

# 获取特定配置
winalog config get alert.retention_days

# 设置配置值
winalog config set alert.retention_days 180
```

---

## 18. metrics - 指标展示

显示 Prometheus 格式的监控指标。

### 用法

```bash
winalog metrics
```

### 显示的指标

- `winalog_events_total` - 事件总数
- `winalog_alerts_total` - 告警总数
- `winalog_import_duration_seconds` - 导入耗时
- `winalog_search_duration_seconds` - 搜索耗时
- `winalog_db_size_bytes` - 数据库大小

### 示例

```bash
winalog metrics
```

---

## 19. query - SQL 查询

执行原始 SQL 查询。

### 用法

```bash
winalog query <sql>
```

### 参数

| 参数 | 描述 |
|------|------|
| `<sql>` | SQL 查询语句 |

### 安全限制

仅允许 `SELECT` 和 `PRAGMA` 查询语句。

### 示例

```bash
# 基本查询
winalog query "SELECT COUNT(*) FROM events"

# 查看事件统计
winalog query "SELECT event_id, COUNT(*) as count FROM events GROUP BY event_id ORDER BY count DESC LIMIT 10"

# 查看数据库表结构
winalog query "PRAGMA table_info(events)"
```

---

## 20. tui - 终端界面

启动基于 Bubble Tea 的交互式终端用户界面。

### 用法

```bash
winalog tui
```

### TUI 视图

| 视图 | 描述 |
|------|------|
| Dashboard | 总览仪表板 |
| Events | 事件列表 |
| EventDetail | 事件详情 |
| Alerts | 告警列表 |
| AlertDetail | 告警详情 |
| Search | 搜索界面 |
| Timeline | 时间线视图 |
| Reports | 报告管理 |
| Analyze | 威胁分析 |
| SystemInfo | 系统信息 |
| Persistence | 持久化检测 |
| Forensics | 取证工具 |
| Collect | 数据收集 |
| Help | 帮助信息 |
| Settings | 设置 |
| Metrics | 指标展示 |

### 示例

```bash
# 启动 TUI
winalog tui
```

---

## 21. serve - 启动 API 服务

启动 Gin HTTP API 服务器和 Web UI。

### 用法

```bash
winalog serve [flags]
```

### 选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--host <addr>` | API 监听地址 | `127.0.0.1` |
| `--port <port>` | API 监听端口 | `8080` |
| `--config <path>` | 配置文件路径 | - |

### 示例

```bash
# 默认启动
winalog serve

# 指定端口
winalog serve --port 9000

# 监听所有接口
winalog serve --host 0.0.0.0 --port 8080
```

---

## 22. forensics - 取证功能

Windows 取证操作工具集。

### 用法

```bash
winalog forensics <subcommand> [flags]
```

### 子命令

#### forensics collect - 收集取证数据

```bash
winalog forensics collect [flags]
```

#### forensics hash - 计算文件哈希

```bash
winalog forensics hash <file>
```

#### forensics verify - 验证文件签名

```bash
winalog forensics verify <file>
```

### 示例

```bash
# 收集取证数据
winalog forensics collect -o evidence.zip

# 计算文件哈希
winalog forensics hash suspicious.exe

# 验证文件签名
winalog forensics verify malware.dll
```

---

## 23. dashboard - 统计仪表板

显示安全事件统计仪表板。

### 用法

```bash
winalog dashboard [flags]
```

### 选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--format <type>` | 输出格式：`table`、`json` | `table` |

### 显示内容

- 事件统计摘要
- 登录事件摘要
- 事件级别分布
- Top 10 事件 ID
- 计算机列表

### 示例

```bash
# 基本显示
winalog dashboard

# JSON 格式
winalog dashboard --format json
```

---

## 24. whitelist - 白名单管理

管理告警白名单/抑制规则。

### 用法

```bash
winalog whitelist <subcommand> [flags]
```

### 子命令

#### whitelist add - 添加白名单规则

```bash
winalog whitelist add <name> [flags]
```

| 选项 | 描述 |
|------|------|
| `--event-id <id>` | 按事件 ID 过滤 |
| `--reason <text>` | 白名单原因 |
| `--scope <scope>` | 范围：`global`、`user`、`computer` |
| `--duration <minutes>` | 持续时间（分钟，0=永久） |
| `--enabled` | 立即启用 |

#### whitelist remove - 移除白名单规则

```bash
winalog whitelist remove <name>
```

#### whitelist list - 列出白名单规则

```bash
winalog whitelist list
```

### 示例

```bash
# 添加白名单规则
winalog whitelist add trusted_event --event-id 4624 --reason "IT 管理员正常登录" --scope global --duration 0

# 列出所有白名单
winalog whitelist list

# 移除白名单
winalog whitelist remove trusted_event
```

---

## 25. ueba - 用户行为分析

用户实体行为分析 (UEBA) 功能。

### 用法

```bash
winalog ueba <subcommand> [flags]
```

### 子命令

#### ueba analyze - 运行 UEBA 分析

```bash
winalog ueba analyze [flags]
```

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--hours, -H <n>` | 分析时间窗口（小时） | `24` |
| `--save-alerts` | 将异常保存为告警 | `false` |

#### ueba profiles - 显示用户行为画像

```bash
winalog ueba profiles [flags]
```

| 选项 | 描述 |
|------|------|
| `--user <name>` | 指定用户 |

#### ueba baseline - 管理用户基线

```bash
winalog ueba baseline [flags]
```

| 选项 | 描述 |
|------|------|
| `--action <type>` | 操作：`learn`、`clear`、`show` |

### 检测的异常类型

- **不可能旅行** - 用户在不可能的时间间隔内从不同地理位置登录
- **异常行为** - 偏离正常用户行为模式
- **权限提升** - 异常的管理员权限获取

### 示例

```bash
# 运行 UEBA 分析
winalog ueba analyze

# 分析过去 7 天
winalog ueba analyze -H 168

# 保存异常为告警
winalog ueba analyze --save-alerts

# 显示用户画像
winalog ueba profiles

# 显示特定用户画像
winalog ueba profiles --user administrator

# 学习用户基线
winalog ueba baseline --action learn

# 显示当前基线
winalog ueba baseline --action show
```

---

## 26. persistence - 持久化检测

检测 Windows 系统中的持久化机制（仅 Windows）。

### 用法

```bash
winalog persistence <subcommand> [flags]
```

### 子命令

#### persistence detect - 检测持久化

```bash
winalog persistence detect [flags]
```

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--category <name>` | 按类别过滤 | - |
| `--technique <id>` | 按 MITRE ATT&CK 技术 ID 过滤 | - |
| `--output, -o <file>` | 输出到文件 | - |
| `--format <type>` | 输出格式：`json`、`csv`、`text` | `json` |
| `--progress` | 显示检测进度 | `false` |

### 持久化类别

| 类别 | 描述 |
|------|------|
| `Registry` | 注册表持久化点 |
| `WMI` | WMI 事件订阅 |
| `COM` | COM 劫持 |
| `Service` | Windows 服务 |
| `ScheduledTask` | 计划任务 |

### 支持的 MITRE ATT&CK 技术

| 技术 ID | 技术名称 |
|---------|----------|
| T1546.001 | Accessibility Features |
| T1546.003 | WMI Event Subscription |
| T1546.010 | AppInit_DLLs |
| T1546.012 | IFEO Debugger |
| T1546.015 | COM Hijacking |
| T1546.016 | Startup Folder |
| T1547.001 | Registry Run Keys |
| T1547.016 | Winlogon Helper |
| T1053.005 | Scheduled Task |
| T1543.003 | Windows Service |

### 示例

```bash
# 检测所有持久化机制
winalog persistence detect

# 仅检测注册表持久化
winalog persistence detect --category Registry

# 检测特定 MITRE 技术
winalog persistence detect --technique T1546.003

# 文本格式输出
winalog persistence detect --format text

# 保存结果
winalog persistence detect -o persistence_results.json

# 显示检测进度
winalog persistence detect --progress
```

---

## 27. evtx2csv - EVTX 转 CSV

将 Windows 事件日志 (EVTX) 文件转换为 CSV 格式，无需存储到数据库。

### 用法

```bash
winalog evtx2csv <input.evtx> [output.csv] [flags]
```

### 参数

| 参数 | 描述 |
|------|------|
| `<input.evtx>` | 要转换的 EVTX 文件路径 |
| `[output.csv]` | 输出 CSV 文件路径（可选，默认与输入文件同名） |

### 选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--limit, -l <n>` | 限制转换的事件数量（0 = 不限制） | `0` |

### 示例

```bash
# 基本转换
winalog evtx2csv security.evtx security.csv

# 使用默认输出文件名
winalog evtx2csv security.evtx

# 限制事件数量
winalog evtx2csv -l 1000 security.evtx security.csv

# 使用管道输出
winalog evtx2csv -l 1000 security.evtx > security.csv
```

---

## 快速参考

### 常用命令速查

| 任务 | 命令 |
|------|------|
| 导入日志文件 | `winalog import <file>` |
| 搜索事件 | `winalog search --event-id <id>` |
| 查看告警 | `winalog alert list` |
| 运行分析 | `winalog analyze` |
| 生成报告 | `winalog report generate` |
| 启动 Web UI | `winalog serve` |
| 启动 TUI | `winalog tui` |
| 实时监控 | `winalog live collect` |
| 检测持久化 | `winalog persistence detect` |
| 收集取证数据 | `winalog collect` |

### 事件 ID 速查

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
