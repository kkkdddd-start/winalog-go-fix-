# WinLogAnalyzer-Go 需求文档

**项目名称**: WinLogAnalyzer-Go
**版本**: v2.4.0
**日期**: 2026-04-17

---

## 1. 简介

### 1.1 项目背景

WinLogAnalyzer Python 版本已实现完整功能，但在架构上存在以下问题需要通过 Go 语言重写来解决：

| Python 版本问题 | Go 版本解决方案 |
|----------------|----------------|
| main_window.py 7862 行过于庞大 | Web UI 分离，Go 只负责后端 |
| 4 个规则类类型不统一 | 统一 Rule 接口 |
| GIL 限制并发性能 | Go goroutine 天生并发 |
| 内存占用高 (GC) | Go 精确内存管理 |
| 依赖 Python 环境 | 单二进制静态编译 |

### 1.2 目标

使用 Go 语言重写 WinLogAnalyzer，实现：
- 保持 Python 版本全部功能
- 性能提升 3-5 倍
- 单文件分发，零依赖
- 更强的取证能力

### 1.3 技术栈

| 组件 | 技术 |
|------|------|
| 语言 | Go 1.25.6 |
| CLI 框架 | Cobra |
| HTTP 框架 | Gin |
| TUI 框架 | Bubble Tea |
| 前端 | React + Vite + TypeScript |
| 数据库 | SQLite (modernc.org/sqlite, Pure Go) |
| 日志 | Zap |
| 配置 | Viper |

---

## 2. 功能需求

### 2.1 日志采集 (6 个解析器)

| 功能 | 描述 | 优先级 |
|------|------|--------|
| EVTX 解析 | Windows 事件日志双解析 (go-evtx + wevtutil) | P0 |
| ETL 解析 | Windows ETW 跟踪文件解析 | P1 |
| IIS 日志 | IIS W3C 扩展日志格式解析 | P1 |
| CSV/文本 | 自定义格式日志解析 | P2 |
| Sysmon 日志 | Sysmon 事件解析 | P1 |
| 实时采集 | Windows Event Log API 订阅 | P1 |

### 2.2 数据存储 (16 张表)

| 功能 | 描述 | 优先级 |
|------|------|--------|
| SQLite 存储 | WAL 模式，支持高并发读 | P0 |
| 批量导入 | 10000 条/批事务优化 | P0 |
| 增量导入 | 基于文件 hash + 时间戳 | P0 |
| 事件去重 | 基于 event_id + timestamp | P1 |
| FTS5 全文搜索 | events_fts 虚拟表 | P1 |

**存储表结构：**

| 表名 | 用途 |
|------|------|
| events | 事件主表 |
| events_fts | 全文搜索虚拟表 |
| alerts | 告警表 |
| import_log | 导入日志 |
| machine_context | 机器上下文 |
| multi_machine_analysis | 多机分析 |
| global_timeline | 全局时间线 |
| sessions | 会话表 |
| evidence_chain | 证据链 |
| evidence_file | 证据文件 |
| processes | 进程快照 |
| network_connections | 网络连接 |
| system_info | 系统信息 |
| reports | 报告表 |
| suppress_rules | 抑制规则 |
| rule_states | 规则状态 |

### 2.3 分析引擎 (8 个分析器)

| 功能 | 描述 | 优先级 |
|------|------|--------|
| 暴力破解检测 | BruteForceAnalyzer | P0 |
| 登录分析 | LoginAnalyzer | P0 |
| Kerberos 分析 | KerberosAnalyzer | P1 |
| PowerShell 分析 | PowerShellAnalyzer | P0 |
| 数据外泄检测 | DataExfiltrationAnalyzer | P1 |
| 横向移动检测 | LateralMovementAnalyzer | P0 |
| 权限提升检测 | PrivilegeEscalationAnalyzer | P0 |
| 持久化检测 | PersistenceAnalyzer | P0 |

### 2.4 规则系统

| 功能 | 描述 | 数量/优先级 |
|------|------|------------|
| 统一规则接口 | AlertRule + CorrelationRule 实现同一接口 | P0 |
| YAML 规则加载 | 自定义规则文件 | P0 |
| 内置告警规则 | 104 条规则 | P0 |
| 内置关联规则 | 6 条规则 | P0 |
| MITRE ATT&CK 映射 | 规则关联 MITRE ID | P1 |
| 规则评分 | 规则质量评分机制 | P2 |
| 规则详情 | 每条规则包含解释、建议、真实案例 | P1 |

**规则分类：**

| MITRE ID | 战术 |
|----------|------|
| T1110 | 暴力破解 |
| T1078 | 有效账户 |
| T1059.001 | PowerShell |
| T1070.001 | 日志清除 |
| T1558.003 | Kerberoasting |
| T1558.001 | 黄金票据 |
| T1547.001 | 注册表 Run 键 |
| T1569.002 | 服务创建 |
| T1053.005 | 计划任务 |
| T1003 | 凭据访问 |
| T1490 | 勒索准备 |
| T1218 | LOLBAS |
| T1560 | 压缩归档 |

### 2.5 告警与抑制

| 功能 | 描述 | 优先级 |
|------|------|--------|
| 告警检测 | 阈值 + 时间窗口 + 分组 | P0 |
| 告警抑制 | SuppressRules 抑制误报 | P1 |
| 告警去重 | 基于事件特征的智能去重 | P1 |
| 告警升级 | AlertUpgradeRule 动态调整级别 | P2 |
| 告警统计 | 趋势分析、Top 规则统计 | P1 |
| UEBA 引擎 | 用户行为基线分析 | P1 |

### 2.6 报告生成

| 功能 | 描述 | 优先级 |
|------|------|--------|
| HTML 报告 | Bootstrap 响应式报告 | P0 |
| JSON 导出 | 结构化数据导出 | P1 |
| CSV 导出 | 事件数据批量导出 | P1 |
| 综合报告 | 告警 + 事件 + 系统信息 + IOC | P0 |
| 安全统计 | 安全事件多维度统计 | P1 |
| 报告模板 | 可定制的报告模板系统 | P2 |

### 2.7 取证功能

| 功能 | 描述 | 优先级 |
|------|------|--------|
| 文件哈希 | SHA256/MD5 计算 | P0 |
| 证据清单 | JSON 格式证据清单 | P0 |
| 证据链 | 区块链式证据追溯 | P1 |
| 时间戳取证 | 事件时间线重建 | P1 |
| 内存取证 | 进程内存分析 (Linux) | P2 |
| 签名分析 | 文件签名验证 | P1 |

### 2.8 持久化检测

| 功能 | 描述 | 优先级 |
|------|------|--------|
| 注册表检测 | Run键、IFEO、AppInit 等 | P0 |
| 服务检测 | Windows 服务创建/修改 | P0 |
| 计划任务检测 | Scheduled Task 创建 | P0 |
| WMI 检测 | WMI 持久化 | P1 |
| 引导执行检测 | Boot Execute | P1 |
| LSA 插件检测 | LSA 认证包 | P1 |
| 网络相关检测 | Winsock LSP、BHO | P2 |
| COM 检测 | COM 对象劫持 | P2 |
| 访问权限检测 | Accessibility Features | P1 |

### 2.9 用户界面

| 功能 | 描述 | 优先级 |
|------|------|--------|
| CLI | 26 个 Cobra 命令 | P0 |
| TUI | 16 个视图 (Bubble Tea) | P1 |
| Web UI | 21 个页面 (React + Vite) | P1 |
| HTTP API | 100+ REST 端点 (Gin) | P1 |

**CLI 命令列表（26 个顶层命令）：**

| 命令 | 功能 | 子命令 |
|------|------|--------|
| import | 导入 EVTX/ETL/CSV/IIS 日志 | - |
| search | 搜索事件 | - |
| collect | 一键采集系统日志 | - |
| alert | 告警管理 | list, show, resolve, delete, export, stats, run, monitor |
| correlate | 关联分析 | - |
| report | 生成报告 | - |
| export | 导出报告 | html, json, csv |
| timeline | 时间线 | view, export |
| multi | 多机分析 | view, analyze |
| live | 实时监控 | view, start |
| status | 系统状态 | - |
| info | 系统信息 | - |
| verify | 验证数据 | - |
| rules | 规则管理 | - |
| db | 数据库工具 | - |
| config | 配置管理 | - |
| metrics | 指标统计 | - |
| query | 高级查询 | - |
| tui | 启动 TUI 界面 | - |
| serve | 启动 API 服务 | - |
| analyze | 运行分析 | - |
| forensics | 取证分析 | - |
| persistence | 持久化检测 | detect |
| dashboard | 仪表板 | - |
| whitelist | 白名单管理 | add, list, remove |
| ueba | UEBA 分析 | - |

**TUI 视图列表：**

| 视图 | 功能 |
|------|------|
| Dashboard | 仪表板概览 |
| Events | 事件列表 |
| EventDetail | 事件详情 |
| Alerts | 告警列表 |
| AlertDetail | 告警详情 |
| Search | 搜索界面 |
| Timeline | 时间线 |
| Reports | 报告管理 |
| Analyze | 分析界面 |
| SystemInfo | 系统信息 |
| Persistence | 持久化检测 |
| Forensics | 取证界面 |
| Collect | 采集界面 |
| Help | 帮助信息 |
| Settings | 设置 |
| Metrics | 指标统计 |

**GUI 页面列表：**

| 页面 | 功能 |
|------|------|
| Dashboard | 仪表板 |
| Events | 事件列表 |
| EventDetail | 事件详情 |
| Alerts | 告警列表 |
| AlertDetail | 告警详情 |
| Timeline | 时间线视图 |
| Reports | 报告管理 |
| Forensics | 取证分析 |
| SystemInfo | 系统信息 |
| Rules | 规则管理 |
| Settings | 系统设置 |
| Metrics | 指标统计 |
| Collect | 日志采集 |
| Live | 实时监控 |
| Multi | 多机分析 |
| Query | 高级查询 |
| Persistence | 持久化检测 |
| Suppress | 抑制规则 |
| Correlation | 关联分析 |
| UEBA | 用户行为分析 |
| Analyze | 分析引擎 |

---

## 3. 非功能需求

### 3.1 性能

| 指标 | 目标 |
|------|------|
| EVTX 解析速度 | >= 150 万条/分钟 |
| 内存占用 (1GB EVTX) | <= 200MB |
| 启动时间 | <= 100ms |
| 批量插入速度 | >= 10 万条/秒 |

### 3.2 可用性

- 编译为单个可执行文件
- Windows x64 原生支持
- 配置文件 YAML 格式
- 详细的错误提示
- 跨平台支持 (Windows/Linux)

### 3.3 可维护性

- 模块化架构 (internal/ 包划分)
- 统一错误处理
- 结构化日志 (Zap)
- 完整单元测试覆盖率

---

## 4. 数据模型

### 4.1 事件

```go
type Event struct {
    ID         int64
    Timestamp  time.Time
    EventID    int32
    Level      EventLevel
    Source     string
    LogName    string
    Computer   string
    User       *string
    UserSID    *string
    Message    string
    RawXML     *string
    SessionID  *string
    IPAddress  *string
    ImportTime time.Time
    ImportID   *int64
}
```

### 4.2 告警

```go
type Alert struct {
    ID           int64
    RuleName     string
    Severity     Severity
    Message      string
    EventIDs     []int32
    FirstSeen    time.Time
    LastSeen     time.Time
    Count        int
    MITREAttack  []string
    Resolved     bool
    ResolvedTime *time.Time
    Notes        string
    LogName      string
    RuleScore    float64
    FalsePositive bool
}
```

### 4.3 统一规则

```go
type AlertRule struct {
    BaseRule
    EventIDs     []int32
    Filters      []Filter
    ConditionOp  LogicalOp
    GroupBy      string
    Threshold    int
    TimeWindow   time.Duration
    RuleScore    float64
}

type CorrelationRule struct {
    BaseRule
    TimeWindow time.Duration
    Conditions []Condition
    JoinField  string
    Patterns   []*Pattern
}

type BaseRule struct {
    Name        string
    Description string
    Enabled     bool
    Severity    Severity
    MITREAttack string
    Tags        []string
}
```

---

## 5. API 端点

### 5.1 主要 API 分组

| 分组 | 端点数量 | 功能 |
|------|---------|------|
| /api/events | 4 | 事件查询、搜索、导出 |
| /api/alerts | 8 | 告警列表、统计、处置 |
| /api/timeline | 5 | 时间线、攻击链 |
| /api/import | 2 | 日志导入 |
| /api/live | 2 | 实时事件流 |
| /api/dashboard | 1 | 仪表板统计 |

### 5.2 处理器文件

| 文件 | 功能 |
|------|------|
| handlers.go | 通用处理器 |
| handlers_alerts.go | 告警管理 |
| handlers_collect.go | 日志采集 |
| handlers_correlation.go | 关联分析 |
| handlers_dashboard.go | 仪表板 |
| handlers_forensics.go | 取证 |
| handlers_live.go | 实时监控 |
| handlers_multi.go | 多机分析 |
| handlers_persistence.go | 持久化检测 |
| handlers_policy.go | 策略管理 |
| handlers_query.go | 查询 |
| handlers_reports.go | 报告 |
| handlers_rules.go | 规则管理 |
| handlers_settings.go | 设置 |
| handlers_suppress.go | 抑制规则 |
| handlers_system.go | 系统信息 |
| handlers_timeline.go | 时间线 |
| handlers_ueba.go | UEBA |
| handlers_ui.go | UI 数据 |
| handlers_analyze.go | 分析 |

---

## 6. 验收标准

### 6.1 功能验收

- [ ] 能够导入 Security.evtx、System.evtx 等标准 Windows 日志
- [ ] 搜索命令能够按事件 ID、时间范围、关键词筛选
- [ ] 告警规则能够检测暴力破解、异常登录等行为
- [ ] 关联分析能够发现攻击链模式
- [ ] 报告能够生成包含统计和详情的 HTML 文件
- [ ] 一键采集能够打包所有日志到 ZIP 文件
- [ ] TUI 界面能够显示事件、告警、时间线
- [ ] Web UI 能够展示 21 个页面的完整功能
- [ ] API 服务能够提供 100+ 端点

### 6.2 性能验收

- [ ] 导入 100 万条事件的 EVTX 文件不超过 10 分钟
- [ ] 内存峰值不超过 500MB
- [ ] 启动到显示帮助信息不超过 200ms

### 6.3 质量验收

- [ ] 所有模块有单元测试
- [ ] 代码通过 golangci-lint 检查
- [ ] 无运行时 panic
- [ ] 错误消息清晰可读

---

## 7. 依赖关系

### 7.1 Go 模块

> **注意**: 为确保单二进制部署，使用 Pure Go SQLite 驱动，无需 CGO 编译。

```
github.com/spf13/cobra      - CLI 框架
github.com/spf13/viper      - 配置管理
github.com/gin-gonic/gin    - HTTP 框架
modernc.org/sqlite          - SQLite 驱动 (Pure Go，无需 CGO)
github.com/natefinch/lumberjack - 日志轮转
go.uber.org/zap            - 高性能日志
golang.org/x/crypto         - 加密
github.com/google/uuid      - UUID 生成
github.com/charmbracelet/bubbletea - TUI 框架
github.com/charmbracelet/lipgloss - 终端样式
github.com/muesli/termenv  - 终端环境
```

---

## 8. 附录

### 8.1 事件 ID 参考

| 事件 ID | 名称 | 说明 |
|---------|------|------|
| 4624 | 登录成功 | 登录成功 |
| 4625 | 登录失败 | 登录失败 |
| 4672 | 特殊权限 | 管理员权限分配 |
| 4688 | 进程创建 | 新进程创建 |
| 4697 | 服务创建 | Windows 服务创建 |
| 4698 | 计划任务 | 计划任务创建 |
| 4720 | 账户创建 | 新用户账户 |
| 4722 | 账户启用 | 账户启用 |
| 4732 | 添加组成员 | 用户加入组 |
| 4768 | TGT 请求 | Kerberos TGT |
| 4769 | TGS 请求 | Kerberos TGS |
| 1102 | 日志清除 | 安全日志被清除 |
| 4104 | PowerShell | PowerShell 脚本执行 |

### 8.2 MITRE ATT&CK 战术

| 战术 | 战术 ID |
|------|---------|
| 初始访问 | TA0001 |
| 执行 | TA0002 |
| 持久化 | TA0003 |
| 权限提升 | TA0004 |
| 防御规避 | TA0005 |
| 凭据访问 | TA0006 |
| 发现 | TA0007 |
| 横向移动 | TA0008 |
| 收集 | TA0009 |
| 外泄 | TA0010 |
| 命令与控制 | TA0011 |

---

*本需求文档遵循 EARS 规范，验收标准可测试可验证。*
