# WinLogAnalyzer-Go 项目文档索引

> 版本: v2.5.0 | 最后更新: 2026-05-09

## 项目概览

WinLogAnalyzer-Go 是一个高性能的 Windows 安全取证与日志分析工具，使用 Go 语言开发。支持 EVTX/ETL/CSV/IIS 等多种日志格式解析，内置 60+ 安全检测规则，提供实时告警、关联分析、取证导出等完整功能。

- **仓库**: https://github.com/kkkdddd-start/winalog-go-fix-
- **许可证**: MIT
- **Go 版本**: 1.25.0

## 文档目录

### 架构文档
| 文档 | 说明 |
|------|------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | 系统整体架构设计 |
| [INTERFACES.md](INTERFACES.md) | API 接口与 CLI 命令文档 |
| [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) | 开发者指南 |

### 核心概念
| 文档 | 说明 |
|------|------|
| [事件模型](核心概念/事件模型.md) | Event 数据结构与生命周期 |
| [规则引擎](核心概念/规则引擎.md) | 安全规则与 MITRE ATT&CK 映射 |
| [告警系统](核心概念/告警系统.md) | 告警生成、去重、抑制与升级 |
| [关联分析](核心概念/关联分析.md) | 多事件关联与攻击链检测 |
| [数据流](核心概念/数据流.md) | 从日志导入到告警生成的完整数据流 |

### 模块文档
| 模块 | 说明 |
|------|------|
| [config](模块/config.md) | 配置管理模块 |
| [storage](模块/storage.md) | SQLite 数据存储层 |
| [engine](模块/engine.md) | 核心处理引擎 |
| [api](模块/api.md) | REST API 服务 |
| [gui](模块/gui.md) | Web UI 前端 |
| [alerts](模块/alerts.md) | 告警引擎 |
| [analyzers](模块/analyzers.md) | 专项分析器 |
| [rules](模块/rules.md) | 规则引擎与内置规则 |
| [parsers](模块/parsers.md) | 日志解析器 |
| [collectors](模块/collectors.md) | 日志收集器 |
| [exporters](模块/exporters.md) | 数据导出器 |
| [reports](模块/reports.md) | 报告生成模块 |
| [correlation](模块/correlation.md) | 关联分析引擎 |
| [timeline](模块/timeline.md) | 时间线模块 |
| [ueba](模块/ueba.md) | 用户行为分析 |
| [forensics](模块/forensics.md) | 取证模块 |
| [persistence](模块/persistence.md) | 持久化检测 |
| [monitor](模块/monitor.md) | 实时监控 |
| [multi](模块/multi.md) | 多机分析 |
| [types](模块/types.md) | 核心类型定义 |

## 快速导航

- **快速开始**: `docs/user/QUICKSTART.md`
- **用户指南**: `docs/user/USER_GUIDE.md`
- **功能清单**: `docs/reference/FEATURES.md`
- **更新日志**: `CHANGELOG.md`
- **安全策略**: `SECURITY.md`
- **贡献指南**: `CONTRIBUTING.md`
