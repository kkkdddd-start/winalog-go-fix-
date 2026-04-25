# WinLogAnalyzer 模块功能对比文档

**项目**: WinLogAnalyzer  
**版本**: Python v1.4.7 vs Go v2.2.0  
**日期**: 2026-04-13  

---

## 一、模块总览

| 模块类别 | Python 模块数 | Go 模块数 | 覆盖状态 |
|----------|--------------|-----------|----------|
| CLI 命令 | 19 | 19 | ✅ 100% |
| Core 核心 | 7 | 7 | ✅ 100% |
| Parsers 解析器 | 6 | 6 | ✅ 100% |
| Collectors 采集器 | 13 | 13 | ✅ 100% |
| Alerts 告警 | 1 | 3 | ✅ 增强 |
| Correlation 关联 | 1 | 3 | ✅ 增强 |
| Rules 规则 | 2 | 4 | ✅ 增强 |
| Analyzers 分析器 | 5 | 5 | ✅ 100% |
| Reports 报告 | 2 | 4 | ✅ 增强 |
| Exporters 导出器 | 1 | 4 | ✅ 增强 |
| Storage 存储 | 1 | 4 | ✅ 增强 |
| Timeline 时间线 | 1 | 2 | ✅ 增强 |
| Multi-machine 多机 | 1 | 1 | ✅ 简化 |
| Observability 可观测性 | 3 | 3 | ✅ 100% |
| Utils 工具 | 4 | 4 | ✅ 100% |
| Forensics 取证 | 0 | 5 | 🆕 新增 |
| GUI 界面 | 11 | Web UI | ✅ 重构 |

---

## 二、CLI 命令模块 (`cli/` → `cmd/winalog/commands/`)

### 2.1 功能对比表

| Python 命令 | Go 命令 | 功能 | 状态 |
|-------------|---------|------|------|
| `import_cmd.py` | `import.go` | EVTX/ETL 文件批量导入 | ✅ |
| `search.py` | `search.go` | 全文搜索事件 | ✅ |
| `collect.py` | `collect.go` | 一键采集 | ✅ |
| `alert_cmd.py` | `alert.go` | 告警查看/解决 | ✅ |
| `correlate.py` | `correlate.go` | 关联分析 | ✅ |
| `report.py` | `report.go` | HTML/JSON/CSV 报告 | ✅ |
| `export_cmd.py` | `export.go` | JSON/CSV/HTML 导出 | ✅ |
| `rules_cmd.py` | `rules_cmd.go` | 规则查看/验证 | ✅ |
| `db.py` | `db.go` | 数据库状态/维护 | ✅ |
| `timeline_cmd.py` | `timeline.go` | 全局时间线构建 | ✅ |
| `multi_cmd.py` | `multi.go` | 跨机器关联分析 | ✅ |
| `gui_cmd.py` | `gui.go` | 启动 GUI | ✅ |
| `live_cmd.py` | `live.go` | 实时日志监控 | ✅ |
| `status.py` | `status.go` | 显示系统状态 | ✅ |
| `info.py` | `info.go` | 显示机器信息 | ✅ |
| `verify_cmd.py` | `verify.go` | 验证数据完整性 | ✅ |
| `config_cmd.py` | `config.go` | 查看/设置配置 | ✅ |
| `observability.py` | `observability.go` | Prometheus 指标 | ✅ |
| `query.py` | `query.go` | 结构化查询 | ✅ |

### 2.2 Python CLI 详细功能

| 模块 | 文件 | 主要功能 |
|------|------|----------|
| `import_cmd.py` | 批量导入 EVTX/ETL，支持并行、增量、异步 |
| `search.py` | 全文搜索、正则、时间范围、事件ID过滤 |
| `collect.py` | 触发一键采集，生成压缩包 |
| `alert_cmd.py` | `alert list`/`show`/`resolve` 告警管理 |
| `correlate.py` | 执行关联规则分析 |
| `report.py` | 生成 HTML/JSON/CSV 综合报告 |
| `export_cmd.py` | 导出事件为 JSON/CSV/HTML |
| `rules_cmd.py` | `rules list`/`validate`/`export` 规则管理 |
| `db.py` | `db status`/`vacuum` 数据库维护 |
| `timeline_cmd.py` | `timeline build` 全局时间线构建 |
| `multi_cmd.py` | `multi analyze` 跨机器关联分析 |
| `gui_cmd.py` | 启动 PyQt6 GUI 界面 |
| `live_cmd.py` | `live collect` 启动实时监控 |
| `status.py` | 显示系统状态统计 |
| `info.py` | 显示机器信息 |
| `verify_cmd.py` | `verify` 验证导入数据完整性 |
| `config_cmd.py` | `config get`/`set` 配置管理 |
| `observability.py` | `metrics` Prometheus 指标端点 |
| `query.py` | 结构化 SQL 查询接口 |

### 2.3 Go CLI 详细功能

| 模块 | 主要功能 |
|------|----------|
| `import.go` | EVTX/ETL/LOG 文件导入，支持并行 workers、批量插入 |
| `search.go` | 事件搜索，支持关键词、时间范围、事件ID、用户、计算机过滤 |
| `collect.go` | 一键采集所有日志源，生成 ZIP 包 |
| `alert.go` | 告警列表、详情、解决、导出 |
| `correlate.go` | 执行关联分析，返回攻击链 |
| `report.go` | 生成 HTML/JSON 报告 |
| `export.go` | JSON/CSV/HTML 事件导出 |
| `rules_cmd.go` | 规则列表、验证、启用/禁用 |
| `db.go` | 数据库状态、优化、清理 |
| `timeline.go` | 全局时间线构建和查询 |
| `multi.go` | 多机分析、横向移动检测 |
| `gui.go` | 启动 Web UI (React) |
| `live.go` | 实时日志监控、状态显示 |
| `status.go` | 系统统计、事件数量、告警统计 |
| `info.go` | 系统信息、进程、网络、用户 |
| `verify.go` | 文件哈希校验、完整性验证 |
| `config.go` | 配置查看/设置 |
| `observability.go` | Prometheus 指标、运行时状态 |
| `query.go` | 直接 SQL 查询接口 |

---

## 三、Core 核心模块 (`core/` → `internal/core/`)

### 3.1 功能对比表

| Python 模块 | Go 模块 | 功能 | 状态 |
|------------|---------|------|------|
| `types.py` | `types/event.go` | 事件/告警类型定义 | ✅ |
| `constants.py` | `core/constants.go` | 事件ID/MITRE 常量 | ✅ |
| `config.py` | `config/` | 配置加载 | ✅ |
| `exceptions.py` | `types/errors.go` | 异常类型 | ✅ |
| `logger.py` | `core/logger.go` | 日志配置 | ✅ |
| `search.py` | `core/search.go` | 搜索索引/查询 | ✅ |
| `analyzer.py` | `engine/` | 分析引擎 | ✅ |

### 3.2 Python Core 详细功能

| 模块 | 主要功能 | 关键类型 |
|------|----------|----------|
| `types.py` | 事件、告警、查询、关联结果数据类型 | `Event`, `Alert`, `SearchQuery`, `CorrelationResult` |
| `constants.py` | Windows 日志路径、事件ID映射、MITRE ATT&CK | `WINDOWS_LOG_PATHS`, `MITRE_ATTACK_MAPPING` |
| `config.py` | TOML 配置加载、环境变量覆盖 | `Config.load()`, `get_config()` |
| `exceptions.py` | 基础异常及子异常类型 | `WinalogException`, `ParseException` |
| `logger.py` | 错误日志、审计日志、资源监控 | `ErrorLogger`, `AuditLogger` |
| `search.py` | Whoosh 全文索引和搜索 | `SearchEngine`, `FullTextSearcher` |
| `analyzer.py` | EVTX 导入引擎、并行/增量/异步 | `Analyzer.import_evtx()` |

### 3.3 Go Core 详细功能

| 模块 | 主要功能 | 关键类型 |
|------|----------|----------|
| `types/event.go` | 事件、告警级别、查询结构 | `Event`, `EventLevel`, `Severity` |
| `types/alert.go` | 告警、关联结果结构 | `Alert`, `CorrelationResult` |
| `core/constants.go` | Windows 事件ID、MITRE 映射 | `EventIDLogonSuccess = 4624` |
| `core/logger.go` | Zap 日志配置、Lumberjack 轮转 | `InitLogger()` |
| `core/search.go` | 搜索构建器、SQL 生成 | `SearchBuilder` |
| `engine/engine.go` | 分析引擎、导入管道 | `Engine`, `ImportRequest` |
| `engine/pipeline.go` | Worker Pool、流式处理 | `EventPipeline` |

---

## 四、Parsers 解析器 (`parsers/` → `internal/parsers/`)

### 4.1 功能对比表

| Python 解析器 | Go 解析器 | 功能 | 状态 |
|---------------|-----------|------|------|
| `evtx_parser.py` | `evtx/` | Windows EVTX 事件日志 | ✅ |
| `etl_parser.py` | `etl/` | Windows ETW 跟踪日志 | ✅ |
| `log_parser.py` | `csv/` | 文本/CSV 日志 | ✅ |
| `iis_parser.py` | `iis/` | IIS W3C/NCSA 日志 | ✅ |
| `sysmon_parser.py` | `sysmon/` | Sysmon 事件 | ✅ |
| `base.py` | `parser.go` | 解析器接口 | ✅ |

### 4.2 Python Parsers 详细功能

| 模块 | 主要功能 | 关键类/函数 |
|------|----------|-------------|
| `base.py` | 流式解析器接口 | `BaseParser`, `StreamingParser`, `ParseResult` |
| `evtx_parser.py` | EVTX 二进制解析、python-evtx 和 wevtutil 双引擎 | `EvtxParser`, `StreamingEvtxParser`, `EvtxChunkReader` |
| `etl_parser.py` | ETW 跟踪解析、traceprocessing 库、二进制解析 | `EtlParser`, `EtlSecurityAnalyzer` |
| `log_parser.py` | 通用文本日志、CSV 格式解析 | `LogParser`, `CsvParser` |
| `iis_parser.py` | W3C/NCSA/JSON/二进制 IIS 日志、安全分析 | `IisParser`, `IisSecurityFinding` |
| `sysmon_parser.py` | Sysmon 事件 ID 1-22 结构化解析 | `SysmonParser`, `SysmonEvent` |

### 4.3 Go Parsers 详细功能

| 模块 | 主要功能 | 关键接口/类型 |
|------|----------|---------------|
| `parser.go` | 统一解析器接口、文件类型识别 | `Parser` interface |
| `evtx/parser.go` | EVTX 二进制解析、XML 提取 | `EvtxParser` |
| `evtx/xml.go` | XML 事件解析 | XML 解析函数 |
| `evtx/wevtutil.go` | wevtutil 备用解析 | `ParseViaWevtutil()` |
| `etl/` | ETL 文件解析 | `EtlParser` |
| `csv/` | CSV/文本日志解析 | `CsvParser` |
| `iis/` | IIS 日志解析 | `IisParser` |
| `sysmon/` | Sysmon 事件解析 | `SysmonParser` |

---

## 五、Collectors 采集器 (`collectors/` → `internal/collectors/`)

### 5.1 功能对比表

| Python 采集器 | Go 采集器 | 功能 | 状态 |
|---------------|-----------|------|------|
| `base.py` | `collector.go` | 采集器接口 | ✅ |
| `one_click.py` | `one_click.go` | 一键采集 | ✅ |
| `live_collector.py` | `live/` | 实时日志监控 | ✅ 完整 |
| `system_info.py` | `system_info.go` | 系统信息 | ✅ |
| `process_info.py` | `process_info.go` | 进程列表 | ✅ |
| `network_info.py` | `network_info.go` | 网络连接 | ✅ |
| `user_info.py` | `user_info.go` | 用户账户 | ✅ |
| `registry_info.py` | `registry_info.go` | 注册表 | ✅ |
| `persistence.py` | `persistence/` | 持久化痕迹 | ✅ 完整 |
| `task_info.py` | `task_info.go` | 计划任务 | ✅ |
| `wmi_subscription.py` | `wmi_subscription.go` | WMI 订阅 | ✅ |
| `driver_info.py` | `driver_info.go` | 驱动信息 | ✅ |
| `env_info.py` | `env_info.go` | 环境变量 | ✅ |

### 5.2 Python Collectors 详细功能

| 模块 | 主要功能 |
|------|----------|
| `base.py` | `BaseCollector` 接口、`CollectorResult` 数据结构、权限检查 |
| `one_click.py` | 自动发现日志源、采集到 ZIP、密码保护、可选哈希校验 |
| `live_collector.py` | Windows Event Log API 订阅、自适应轮询 (0.2s-5s)、书签支持、过滤采集、背压控制、状态回调 |
| `system_info.py` | 主机名/OS/域/进程/网络/注册表综合信息 |
| `process_info.py` | 进程列表、文件签名、哈希计算、路径验证 |
| `network_info.py` | TCP/UDP 连接、ARP 表、路由表、NetBIOS 名称 |
| `user_info.py` | 本地用户/组、RDP 设置、空密码检测、凭证管理器 |
| `registry_info.py` | Run 键、服务、共享、持久化位置 |
| `persistence.py` | Prefetch、ShimCache、Amcache、UserAssist、SRUM、RecentApps |
| `task_info.py` | Windows 计划任务 COM/PowerShell 双接口、历史记录 |
| `wmi_subscription.py` | WMI 永久事件订阅、恶意监听器检测 |
| `driver_info.py` | 驱动列表、签名状态、已加载模块 |
| `env_info.py` | 环境变量、系统代理配置 |

### 5.3 Go Collectors 详细功能

| 模块 | 主要功能 |
|------|----------|
| `collector.go` | `Collector` 接口、`RequiresAdmin()` 方法 |
| `one_click.go` | 自动发现、并行采集、ZIP 打包、SHA256 校验 |
| `live/collector.go` | 自适应轮询 (0.2s-5s)、背压控制、状态回调、去重 |
| `live/bookmark.go` | 书签保存/加载、断点续采 |
| `live/filtered.go` | 事件ID/级别/关键词过滤 |
| `live/stats.go` | 采集统计 (队列大小、会话状态) |
| `system_info.go` | 主机名/OS/域/架构/时区 |
| `process_info.go` | 进程列表、PPID、路径、签名状态 |
| `network_info.go` | TCP/UDP 连接、远程地址、状态 |
| `user_info.go` | 本地用户、SID、最后登录、账户状态 |
| `registry_info.go` | Run 键、服务、共享 |
| `persistence/collector.go` | `CollectAll()` 统一入口 |
| `persistence/prefetch.go` | .pf 文件列表、时间戳、大小 |
| `persistence/shimcache.go` | AppCompatCache 注册表 |
| `persistence/amcache.go` | Amcache.hve 信息 |
| `persistence/userassist.go` | UserAssist 注册表项 |
| `persistence/usnjournal.go` | USN Journal 查询 |
| `task_info.go` | 计划任务列表、触发器 |
| `wmi_subscription.go` | WMI 永久订阅、事件过滤器 |
| `driver_info.go` | 已加载驱动、签名状态 |
| `env_info.go` | 系统/用户环境变量 |

---

## 六、Storage 存储 (`storage/` → `internal/storage/`)

### 6.1 功能对比表

| Python 模块 | Go 模块 | 功能 | 状态 |
|------------|---------|------|------|
| `database.py` | `db.go` | SQLite 操作 | ✅ |
| - | `schema.go` | 完整 Schema 定义 | ✅ 增强 |
| - | `repository.go` | Repository 模式 | ✅ 新增 |

### 6.2 Python Storage 详细功能

| 模块 | 主要功能 |
|------|----------|
| `database.py` | SQLite WAL 模式、批量导入优化、事件/告警 CRUD、搜索、历史记录 |

### 6.3 Go Storage 详细功能

| 模块 | 主要功能 |
|------|----------|
| `db.go` | Pure Go SQLite (modernc.org/sqlite)、WAL 模式、批量插入、线程安全写入锁 |
| `schema.go` | 完整 9 张表: events, alerts, import_log, machine_context, multi_machine_analysis, global_timeline, sessions, evidence_chain, evidence_file |
| `repository.go` | Repository 接口模式 (EventRepository, AlertRepository) |

---

## 七、Alerts 告警 (`alerts/` → `internal/alerts/`)

### 7.1 功能对比表

| Python 模块 | Go 模块 | 功能 | 状态 |
|------------|---------|------|------|
| `engine.py` | `engine.go` | 告警引擎核心 | ✅ |
| - | `evaluator.go` | 规则评估 | ✅ 新增 |
| - | `dedup.go` | 去重机制 | ✅ 新增 |
| - | `stats.go` | Top Rules 统计 | ✅ 新增 |
| - | `trend.go` | 告警趋势分析 | ✅ 新增 |
| - | `upgrade.go` | 告警升级机制 | ✅ 新增 |

### 7.2 Python Alerts 详细功能

| 模块 | 主要功能 |
|------|----------|
| `engine.py` | `AlertEngine.evaluate()` 规则匹配、去重、全局静默、阈值检测、MITRE 映射 |

### 7.3 Go Alerts 详细功能

| 模块 | 主要功能 |
|------|----------|
| `engine.go` | `Engine.Evaluate()` 规则评估、线程安全去重缓存、批量评估 (goroutine 并发) |
| `evaluator.go` | 规则条件匹配、阈值检测、时间窗口聚合 |
| `dedup.go` | `DedupCache` 线程安全去重、基于时间窗口 |
| `stats.go` | Top Rules 统计、每日趋势、RuleScore 计算 |
| `trend.go` | 告警趋势分析、事件率计算 |
| `upgrade.go` | 告警升级机制、时间/计数阈值触发 |
| `suppress.go` | 告警抑制/静默规则 |

---

## 八、Correlation 关联 (`correlation/` → `internal/correlation/`)

### 8.1 功能对比表

| Python 模块 | Go 模块 | 功能 | 状态 |
|------------|---------|------|------|
| `engine.py` | `engine.go` | 关联分析核心 | ✅ |
| - | `matcher.go` | 模式匹配 | ✅ 新增 |
| - | `chain.go` | 事件链 | ✅ 新增 |

### 8.2 Python Correlation 详细功能

| 模块 | 主要功能 |
|------|----------|
| `engine.py` | 时间窗口关联、跨桶关联、事件链检测、多条件回溯 |

### 8.3 Go Correlation 详细功能

| 模块 | 主要功能 |
|------|----------|
| `engine.go` | `Engine.Analyze()` 事件索引 (event_id/time)、回溯查找攻击链 |
| `matcher.go` | 关联条件匹配、Join 字段匹配 |
| `chain.go` | 事件链构建、攻击时序分析 |

---

## 九、Rules 规则 (`rules/` → `internal/rules/`)

### 9.1 功能对比表

| Python 模块 | Go 模块 | 功能 | 状态 |
|------------|---------|------|------|
| `builtin.py` | `builtin/` | 内置规则 | ✅ 完整 |
| `loader.py` | `loader.go` | 规则加载 | ✅ |

### 9.2 Python Rules 详细功能

| 模块 | 主要功能 |
|------|----------|
| `builtin.py` | 30+ 内置关联规则、`get_builtin_rules()`、`get_rule_explanation()` 规则解释 |
| `loader.py` | YAML/JSON 规则加载、规则验证、规则导出 |

### 9.3 Go Rules 详细功能

| 模块 | 主要功能 |
|------|----------|
| `rule.go` | 统一 `Rule` 接口、`BaseRule`、`AlertRule`、`CorrelationRule` 结构 |
| `loader.go` | YAML 规则加载、规则验证 |
| `builtin/registry.go` | 规则注册表 |
| `builtin/definitions.go` | 60+ 条规则完整定义 |
| `builtin/explanations.go` | 规则 attack explanation, examples, recommendations |
| `builtin/mitre.go` | MITRE ATT&CK 技术映射 |

**规则分类 (60+)**:
- 凭据访问: 5+
- 暴力破解: 3+
- 横向移动: 5+
- 权限维持: 8+
- Kerberos: 4+
- PowerShell: 5+
- WinRM: 10+
- UEBA: 3+
- 防御规避: 6+
- 其他攻击: 5+

---

## 十、Analyzers 分析器 (`analyzers/` → `internal/analyzers/`)

### 10.1 功能对比表

| Python 分析器 | Go 分析器 | 功能 | 状态 |
|---------------|-----------|------|------|
| `base.py` | `analyzer.go` | 分析器接口 | ✅ |
| `brute_force.py` | `brute_force.go` | 暴力破解检测 | ✅ |
| `login_analyzer.py` | `login.go` | 登录分析 | ✅ |
| `kerberos_analyzer.py` | `kerberos.go` | Kerberos 分析 | ✅ |
| `powershell_analyzer.py` | `powershell.go` | PowerShell 分析 | ✅ |

### 10.2 Python Analyzers 详细功能

| 模块 | 主要功能 |
|------|----------|
| `base.py` | `BaseAnalyzer` 接口、`AnalysisResult` 数据结构 |
| `brute_force.py` | IP 聚合、账户聚合、时间密度分析、IPv4/IPv6 提取 |
| `login_analyzer.py` | 成功/失败/可疑登录分析、登录类型映射 |
| `kerberos_analyzer.py` | TGT/服务票据、黄金票据 (异常生命周期)、白银票据检测 |
| `powershell_analyzer.py` | 可疑脚本检测、编码命令解码、混淆检测、风险评估 |

### 10.3 Go Analyzers 详细功能

| 模块 | 主要功能 |
|------|----------|
| `analyzer.go` | `Analyzer` 接口、`Result` 结构 |
| `brute_force.go` | IP 聚合、账户聚合、时间密度分析、正则提取 IP/账户 |
| `login.go` | 登录事件分析、登录类型分类 |
| `kerberos.go` | Kerberos 票据分析、黄金/白银票据检测 |
| `powershell.go` | PowerShell 命令分析、编码检测 |

---

## 十一、Reports 报告 (`reports/` → `internal/reports/`)

### 11.1 功能对比表

| Python 模块 | Go 模块 | 功能 | 状态 |
|------------|---------|------|------|
| `report_generator.py` | `generator.go` | 报告生成器 | ✅ |
| `comprehensive_report.py` | `html.go` | HTML 综合报告 | ✅ 增强 |
| - | `security_stats.go` | 安全事件统计 | ✅ 新增 |
| - | `json.go` | JSON 报告 | ✅ 新增 |

### 11.2 Python Reports 详细功能

| 模块 | 主要功能 |
|------|----------|
| `report_generator.py` | HTML/JSON/CSV 报告、IOC 提取、攻击链分析 |
| `comprehensive_report.py` | Bootstrap HTML 报告、统计图表、告警列表、时间线 |

### 11.3 Go Reports 详细功能

| 模块 | 主要功能 |
|------|----------|
| `generator.go` | `Generator` 报告生成器、模板渲染 |
| `security_stats.go` | 25+ 种安全事件统计、MITRE 分布、IOC 提取 |
| `html.go` | Bootstrap HTML 报告、Chart.js 可视化 |
| `json.go` | 结构化 JSON 报告 |

---

## 十二、Exporters 导出器 (`exporters/` → `internal/exporters/`)

### 12.1 功能对比表

| Python 模块 | Go 模块 | 功能 | 状态 |
|------------|---------|------|------|
| `exporter.py` | `exporter.go` | 导出器接口 | ✅ |
| - | `json.go` | JSON 导出 | ✅ 新增 |
| - | `csv.go` | CSV 导出 | ✅ 新增 |
| - | `timeline.go` | 时间线导出 | ✅ 新增 |

### 12.2 Python Exporters 详细功能

| 模块 | 主要功能 |
|------|----------|
| `exporter.py` | `JsonExporter`, `CsvExporter`, `HtmlExporter`, `AlertReporter`, `ExporterFactory` |

### 12.3 Go Exporters 详细功能

| 模块 | 主要功能 |
|------|----------|
| `exporter.go` | `Exporter` 接口 |
| `json.go` | JSON 格式事件导出 |
| `csv.go` | CSV 格式事件导出 |
| `timeline.go` | 时间线格式导出 |

---

## 十三、Timeline 时间线 (`global_timeline.py` → `internal/timeline/`)

### 13.1 功能对比表

| Python 模块 | Go 模块 | 功能 | 状态 |
|------------|---------|------|------|
| `global_timeline.py` | `builder.go` | 时间线构建 | ✅ |
| - | `visualizer.go` | 可视化 | ✅ 新增 |

### 13.2 Python Timeline 详细功能

| 模块 | 主要功能 |
|------|----------|
| `global_timeline.py` | `GlobalTimelineBuilder` 多机器事件全局时间线、事件关联、攻击链检测 |

### 13.3 Go Timeline 详细功能

| 模块 | 主要功能 |
|------|----------|
| `builder.go` | `TimelineBuilder` 全局时间线构建、多源事件聚合 |
| `visualizer.go` | 时间线可视化、攻击链展示 |

---

## 十四、Multi-machine 多机 (`multi_machine/` → `internal/multi/`)

### 14.1 功能对比表

| Python 模块 | Go 模块 | 功能 | 状态 |
|------------|---------|------|------|
| `analyzer.py` | `analyzer.go` | 多机分析 | ✅ 简化 |

### 14.2 Python Multi-machine 详细功能

| 模块 | 主要功能 |
|------|----------|
| `analyzer.py` | `MultiMachineAnalyzer` 机器上下文管理、角色检测 (DC/Server/Workstation)、横向移动链、跨机器关联 |

### 14.3 Go Multi-machine 详细功能

| 模块 | 主要功能 |
|------|----------|
| `analyzer.go` | 跨机器关联分析、分布式事件聚合 (简化版) |

---

## 十五、Observability 可观测性 (`observability/` → `internal/observability/`)

### 15.1 功能对比表

| Python 模块 | Go 模块 | 功能 | 状态 |
|------------|---------|------|------|
| `metrics.py` | `metrics.go` | 指标收集 | ✅ |
| `logging.py` | `logging.go` | 日志配置 | ✅ |
| `system.py` | `system.go` | 系统监控 | ✅ |

### 15.2 Python Observability 详细功能

| 模块 | 主要功能 |
|------|----------|
| `metrics.py` | Prometheus 指标、事件计数、导入耗时、告警触发 |
| `logging.py` | JSON/Plain 日志格式化、上下文管理 |
| `system.py` | 系统资源监控 |

### 15.3 Go Observability 详细功能

| 模块 | 主要功能 |
|------|----------|
| `metrics.go` | `MetricsCollector` Prometheus 导出、Counter/Gauge 指标 |
| `logging.go` | 日志级别/格式配置 |
| `system.go` | CPU/内存/Goroutine 统计 |

---

## 十六、Utils 工具 (`utils/` → `internal/utils/`)

### 16.1 功能对比表

| Python 模块 | Go 模块 | 功能 | 状态 |
|------------|---------|------|------|
| `windows.py` | `windows.go` | Windows API | ✅ |
| `powershell.py` | `powershell.go` | PowerShell | ✅ |
| `registry.py` | (集成到 collectors) | 注册表 | ✅ |
| `geoip.py` | `geoip.go` | GeoIP 定位 | ✅ |

### 16.2 Python Utils 详细功能

| 模块 | 主要功能 |
|------|----------|
| `windows.py` | Windows API 封装、版本检测、管理员检查 |
| `powershell.py` | PowerShell 脚本分析/解码/混淆检测、风险评估 |
| `registry.py` | 注册表读写/枚举、持久化位置获取 |
| `geoip.py` | IP 地理位置查询、缓存 |

### 16.3 Go Utils 详细功能

| 模块 | 主要功能 |
|------|----------|
| `windows.go` | `GetComputerName()`, `GetDomain()`, `IsAdmin()`, `GetProcessList()` |
| `powershell.go` | `PowerShellExecutor` 命令执行、Base64 解码执行 |
| `geoip.go` | `GeoIPLookup` IP 定位、本地缓存、API 查询 |

---

## 十七、Forensics 取证 (🆕 新增)

### 17.1 Go Forensics 模块

| Python | Go 模块 | 功能 | 状态 |
|--------|---------|------|------|
| - | `hash.go` | SHA256/MD5 哈希 | 🆕 新增 |
| - | `signature.go` | PE 文件签名验证 | 🆕 新增 |
| - | `chain.go` | 区块链式证据链 | 🆕 新增 |
| - | `memory.go` | 内存采集接口 | 🆕 新增 |
| - | `timestamp.go` | RFC 3161 时间戳 | 🆕 新增 |

### 17.2 Go Forensics 详细功能

| 模块 | 主要功能 |
|------|----------|
| `hash.go` | `HashResult` SHA256/MD5 计算、文件完整性校验 |
| `signature.go` | Authenticode 签名验证、PE 文件签名检查 |
| `chain.go` | `EvidenceChain` 区块链式证据追溯、`EvidenceManifest` 证据清单 |
| `memory.go` | 进程内存转储、内存采集接口 |
| `timestamp.go` | RFC 3161 时间戳签名、证据时间认证 |

---

## 十八、前端界面 (TUI + Web UI)

### 18.1 双前端策略

WinLogAnalyzer-Go 采用 **TUI + Web UI** 双前端策略：

| 优先级 | 界面 | 技术 | 适用场景 |
|--------|------|------|----------|
| **P0** | TUI | Bubble Tea | 快速启动、服务器/远程、离线环境 |
| **P1** | Web UI | React + Vite | 团队协作、图表展示、报告生成 |

### 18.2 Python GUI vs Go 前端对比

| Python GUI | Go TUI | Go Web UI | 功能 | 状态 |
|------------|---------|-----------|------|------|
| PyQt6 主窗口 | Bubble Tea | React + Vite | 交互式界面 | ✅ 重构 |
| 11 个 Python 文件 | 10+ Go 文件 | TypeScript/React | 组件/页面 | ✅ 重构 |

### 18.3 Python GUI 详细功能

| 模块 | 主要功能 |
|------|----------|
| `app.py` | PyQt6 应用入口 |
| `main_window.py` | 主窗口、7862 行、33 个视图方法 |
| `widgets.py` | 虚拟滚动表格、分页表格 |
| `widgets/search_widget.py` | 搜索组件 |
| `widgets/event_table.py` | 事件表格 |
| `widgets/metrics_widget.py` | 指标显示 |
| `widgets/timeline_widget.py` | 时间线组件 |
| `widgets/alert_table.py` | 告警表格 |
| `widgets/detail_panel.py` | 详情面板 |
| `models/models.py` | 数据模型 |
| `dialogs/dialogs.py` | 对话框 |

### 18.4 Go TUI 详细功能 (P0)

| 模块 | 主要功能 |
|------|----------|
| `internal/tui/model.go` | 全局模型，Elm 架构 |
| `internal/tui/views/` | 视图 (Dashboard/Events/Alerts/Timeline/Search) |
| `internal/tui/components/` | 组件 (Table/Progress/Spinner/StatusBar) |
| `internal/tui/styles/theme.go` | 主题定义 (lipgloss) |
| `internal/tui/keys.go` | 键位映射 (vi 风格) |

**TUI 界面示例**:
```
┌────────────────────────────────────────────────────────────────┐
│  WinLogAnalyzer v2.0                                           │
├────────────────────────────────────────────────────────────────┤
│  Events: 123,456    Alerts: 89    Session: live_1234567890   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ #   TIMESTAMP            ID    LEVEL    MESSAGE           │  │
│  │ ────────────────────────────────────────────────────────│  │
│  │   1  2024-01-15 10:23:45  4624  INFO     Login Success   │  │
│  │ >  2  2024-01-15 10:23:46  4672  WARN     Special Priv   │  │
│  │   3  2024-01-15 10:23:47  4688  INFO     Process Create   │  │
│  └──────────────────────────────────────────────────────────┘  │
├────────────────────────────────────────────────────────────────┤
│ ↑↓ Navigate | Enter Select | / Search | i Import | q Quit   │
└────────────────────────────────────────────────────────────────┘
```

### 18.5 Go Web UI 详细功能 (P1)

| 模块 | 主要功能 |
|------|----------|
| React + Vite + TypeScript | 单页应用 |
| `internal/gui/src/App.tsx` | 主应用组件 |
| `internal/gui/src/components/` | 通用组件 (Table/Badge/Chart/Modal) |
| `internal/gui/src/pages/` | 页面 (Dashboard/Events/Alerts/Timeline/Reports) |
| `internal/gui/src/hooks/` | 自定义 React Hooks |
| `internal/gui/src/api/` | API 调用封装 |

**Web UI 页面示例**:
```
┌──────────────────────────────────────────────────────────────────────────┐
│  🛡️ WinLogAnalyzer                                    [User] [Settings] │
├──────────┬───────────────────────────────────────────────────────────────┤
│          │  Dashboard                                            2024-01 │
│ Dashboard│  ─────────────────────────────────────────────────────────── │
│          │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│ Events   │  │   Events    │ │   Alerts    │ │   Critical   │           │
│  > List  │  │   123,456   │ │     89      │ │      12     │           │
│  > Search│  └─────────────┘ └─────────────┘ └─────────────┘           │
│          │                                                             │
│ Alerts   │  Event Distribution                    Recent Alerts         │
│  > List  │  ┌────────────────────────────┐  ┌───────────────────────┐  │
│  > Rules │  │  ████████████████████     │  │ [!] Suspicious Login  │  │
│          │  │  ████████                │  │ [!] Brute Force       │  │
│ Timeline │  │  ████████████████        │  │ [!!] Golden Ticket   │  │
│          │  │                            │  │                       │  │
│ Reports  │  │  Security  System  App    │  └───────────────────────┘  │
│          │  └────────────────────────────┘                             │
└──────────┴───────────────────────────────────────────────────────────────┘
```

### 18.6 技术指标对比

| 指标 | TUI (Bubble Tea) | Web UI (React) |
|------|-------------------|-----------------|
| 启动时间 | <50ms | 2-3s |
| 内存占用 | 5-20MB | 100-300MB |
| 依赖 | 零 | Node.js (构建时) |
| 离线支持 | ✅ | ❌ |
| 远程访问 | SSH | HTTP |
| 图表支持 | ❌ ASCII | ✅ Chart.js |
| 命令 | `winalog tui` | `winalog serve` |

---

## 十九、配置对比

### 19.1 Python 配置

```python
# core/config.py
config = {
    "db_path": "~/.winalog/winalog.db",
    "verbose": False,
    "workers": 4,
    "batch_size": 10000,
}
```

### 19.2 Go 配置

```yaml
# config.yaml
database:
  path: "~/.winalog/winalog.db"
  wal_mode: true

import:
  workers: 4
  batch_size: 10000

alerts:
  dedup_window: 5m
  enabled: true

forensics:
  hash_algorithm: "sha256"
  sign_reports: true

api:
  host: "127.0.0.1"
  port: 8080
```

---

## 二十、技术栈对比

| 组件 | Python 版本 | Go 版本 |
|------|------------|---------|
| 语言 | Python 3.10+ | Go 1.22 |
| CLI | Click 8.0+ | Cobra |
| GUI | PyQt6 | React + Vite |
| HTTP | - | Gin |
| 数据库 | SQLite (python-sqlite3) | SQLite (modernc.org/sqlite) |
| 日志解析 | python-evtx, wevtutil | 原生实现 + wevtutil |
| 配置 | TOML, 环境变量 | YAML, Viper |
| 日志 | logging | Zap + Lumberjack |
| 全文搜索 | Whoosh | 内置 SQL LIKE |

---

## 二十一、总结

### 21.1 Python 版本优势

- PyQt6 原生 GUI 体验
- Whoosh 全文搜索
- 丰富的 Python 生态

### 21.2 Go 版本优势

- 单二进制部署，无依赖
- 原生并发性能 (goroutine)
- 精确内存管理，低内存占用
- 强类型系统
- 现代 Web UI (React)

### 21.3 新增功能

- Pure Go SQLite (真正的单文件)
- 区块链式证据链
- 数字签名验证
- RFC 3161 时间戳
- Web UI + HTTP API
- 告警 Top Rules 统计
- 告警趋势分析
- 告警升级机制

### 21.4 功能采纳状态

| 类别 | Python 功能数 | Go 已采纳 | 未采纳 |
|------|-------------|----------|--------|
| 系统信息采集 | 10 | 10 | 0 |
| 一键采集 | 9 | 9 | 0 |
| 日志分析 | 12 | 12 | 0 |
| 实时监控 | 10 | 10 | 0 |
| 事件表格 | 9 | 9 | 0 |
| 时间线 | 12 | 12 | 0 |
| 搜索功能 | 11 | 11 | 0 |
| 告警管理 | 12 | 11 | 1 |
| 报告生成 | 8 | 8 | 0 |
| 取证模块 | 5 | 5 | 0 |
| **总计** | **98** | **97** | **1** |

**未采纳功能**: 告警 WebSocket 实时通知

---

*文档版本: v2.0 | 更新日期: 2026-04-13*
