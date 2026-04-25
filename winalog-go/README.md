# WinLogAnalyzer-Go

**版本**: v2.4.0  
**日期**: 2026-04-17

Windows 安全取证与日志分析工具，使用 Go 语言重写。

## 特性

| 特性 | 说明 |
|------|------|
| 高性能 | Go 并发模型处理大文件日志 |
| 单二进制 | 编译为单个可执行文件，无依赖 |
| 内存安全 | Go 天然内存安全 |
| 取证合规 | 内置证据完整性校验 |
| 实时监控 | Windows Event Log 实时采集 |
| 持久化检测 | 15+ Windows 持久化技术检测 |

## 性能目标

| 指标 | 目标 |
|------|------|
| EVTX 解析速度 | ≥150万条/分钟 |
| 内存占用 (1GB EVTX) | ≤200MB |
| 启动时间 | ≤100ms |

## 支持的格式

- EVTX (Windows Event Log)
- ETL (Event Trace Log)
- CSV/LOG (自定义格式)
- IIS (W3C Extended Log)
- Sysmon (Event ID 1-22)

## 快速开始

### 安装

```bash
go install github.com/kkkdddd-start/winalog-go@latest
```

或者从源码编译：

```bash
git clone https://github.com/kkkdddd-start/winalog-go.git
cd winalog-go
make build
```

### 使用

```bash
# 导入日志文件
winalog import security.evtx

# 搜索事件
winalog search --event-id 4624

# 一键采集
winalog collect --output evidence.zip

# 告警管理
winalog alert list

# 启动 TUI
winalog tui

# 启动 API 服务器
winalog serve --port 8080
```

## CLI 命令

| 命令 | 说明 |
|------|------|
| `import` | 批量导入日志文件 |
| `search` | 全文搜索事件 |
| `collect` | 一键采集所有日志源 |
| `alert` | 告警管理 |
| `analyze` | 专用分析器 (暴力破解/登录/Kerberos等) |
| `report` | 报告生成 (HTML/JSON/PDF) |
| `dashboard` | 仪表板统计 |
| `config` | 配置管理 |
| `persistence` | Windows 持久化技术检测 |
| `system` | 系统信息 (进程/网络/用户/注册表) |
| `ueba` | 用户行为异常分析 |
| `whitelist` | 白名单规则管理 |
| `db` | 数据库管理 |
| `tui` | 终端界面 (Bubble Tea) |
| `serve` | HTTP API 服务器 + Web UI | |

## 开发

### 环境要求

- Go 1.22+
- Windows (用于实际运行)

### 构建

```bash
# 构建当前平台
make build

# 构建所有平台
make build-all

# 运行测试
make test

# 运行 lint
make lint
```

### 项目结构

```
winalog-go/
├── cmd/winalog/           # CLI 命令
│   └── commands/         # 子命令 (15个)
├── internal/              # 内部包
│   ├── engine/           # 核心引擎
│   ├── parsers/          # 日志解析器 (evtx/etl/csv/iis/sysmon)
│   ├── storage/           # 数据存储 (SQLite WAL)
│   ├── alerts/            # 告警引擎 (7模块)
│   ├── rules/             # 规则系统 (90+规则)
│   ├── analyzers/         # 分析器 (8个)
│   ├── collectors/        # 采集器 (live/persistence)
│   ├── forensics/         # 取证
│   ├── reports/           # 报告生成
│   ├── exporters/         # 导出器 (csv/excel/json/evtx)
│   ├── timeline/          # 时间线
│   ├── multi/             # 多机分析
│   ├── ueba/             # 用户行为分析
│   ├── persistence/       # 持久化检测 (15检测器)
│   ├── api/               # HTTP API (20+ handlers)
│   ├── tui/               # 终端界面 (12视图)
│   ├── observability/     # 可观测性
│   ├── types/             # 类型定义
│   └── version/           # 版本信息
├── internal/gui/          # React Web UI (21页面)
└── pkg/                   # 公共包
    ├── evtx/              # EVTX 解析库
    └── mitre/             # MITRE ATT&CK 映射
```

## 依赖

| 依赖 | 版本 | 说明 |
|------|------|------|
| cobra | v1.7+ | CLI 框架 |
| viper | v1.18+ | 配置管理 |
| gin | v1.9+ | HTTP 框架 |
| modernc.org/sqlite | v1.23+ | SQLite 驱动 (Pure Go, 无 CGO) |
| zap | v1.26+ | 日志 |
| bubbletea | v1.12+ | TUI 框架 |
| excelize | v2+ | Excel 导出 |

## 文档

详细设计文档位于 `dev-pkg/` 和 `.monkeycode/docs/` 目录：

**设计文档** (`dev-pkg/`):
- `design.md` - 核心架构设计 (~100KB)
- `FEATURES.md` - 功能详细清单 (~500+)
- `MODULES_COMPARISON.md` - Python→Go 模块对比
- `requirements.md` - 需求文档

**用户文档** (`.monkeycode/docs/`):
- `USER_MANUAL.md` - 完整用户手册
- `API.md` - API 文档 (~30+ 端点)
- `ARCHITECTURE.md` - 架构文档

## License

MIT
