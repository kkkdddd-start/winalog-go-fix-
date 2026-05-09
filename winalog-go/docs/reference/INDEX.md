# WinLogAnalyzer-Go 项目文档

**版本**: v2.4.0  
**更新日期**: 2026-04-17

---

## 用户手册章节预览

### 快速开始
- [安装与配置](./USER_MANUAL.md#2-安装与配置)
- [日志导入](./USER_MANUAL.md#4-日志导入)
- [事件搜索](./USER_MANUAL.md#5-事件搜索)
- [告警管理](./USER_MANUAL.md#6-告警管理)

### 高级功能
- [威胁分析](./USER_MANUAL.md#7-威胁分析)
- [实时监控](./USER_MANUAL.md#8-实时监控)
- [取证功能](./USER_MANUAL.md#9-取证功能)
- [持久化检测](./USER_MANUAL.md#10-持久化检测)
- [UEBA 用户行为分析](./USER_MANUAL.md#14-ueba用户行为分析)

### API 使用
- [事件 API](./API.md#2-events-api)
- [告警 API](./API.md#3-alerts-api)
- [时间线 API](./API.md#4-timeline-api)
- [报告 API](./API.md#7-reports-api)

---



## 文档索引

### 用户手册
| 文档 | 说明 |
|------|------|
| [USER_MANUAL](./USER_MANUAL.md) | 完整用户使用手册，包含所有 CLI 命令和实际案例 |
| [API_DOCUMENTATION](./API.md) | 完整 API 文档，包含所有端点和请求/响应示例 |

### [架构文档](./ARCHITECTURE.md)
- 系统架构概述
- 核心模块设计
- 数据流与处理管道
- 并发模型

### [接口文档](./INTERFACES.md)
- Parser 接口
- Collector 接口
- Exporter 接口
- Rule 接口
- Storage 接口

### [开发者指南](./DEVELOPER_GUIDE.md)
- 环境搭建
- 构建与测试
- 代码规范
- 提交规范

### 模块文档

#### 核心引擎
| 模块 | 说明 |
|------|------|
| [engine](./模块/engine.md) | 核心导入引擎，Worker Pool 模式 |
| [parsers](./模块/parsers.md) | 日志解析器注册表与实现 |
| [storage](./模块/storage.md) | SQLite 存储层 |

#### 安全分析
| 模块 | 说明 |
|------|------|
| [alerts](./模块/alerts.md) | 告警引擎，去重/评估/统计 |
| [correlation](./模块/correlation.md) | 关联分析引擎 |
| [rules](./模块/rules.md) | 规则系统 (AlertRule/CorrelationRule) |
| [persistence](./模块/persistence.md) | Windows 持久化检测 (T1546 系列) |
| [analyzers](./模块/analyzers.md) | 专用分析器 (暴力破解/登录/Kerberos) |

#### 数据采集
| 模块 | 说明 |
|------|------|
| [collectors](./模块/collectors.md) | 采集器接口与实现 |
| [collectors/live](./模块/collectors_live.md) | Windows Event Log 实时采集 |
| [collectors/persistence](./模块/collectors_persistence.md) | 取证持久化数据采集 |

#### 报告与导出
| 模块 | 说明 |
|------|------|
| [reports](./模块/reports.md) | 报告生成器（统一服务层） |
| [exporters](./模块/exporters.md) | 数据导出器 |
| [timeline](./模块/timeline.md) | 时间线构建与可视化 |

#### 取证
| 模块 | 说明 |
|------|------|
| [forensics](./模块/forensics.md) | 取证模块 (哈希/签名/证据链) |

#### 多机分析
| 模块 | 说明 |
|------|------|
| [multi](./模块/multi.md) | 多机关联分析 |

#### 可观测性
| 模块 | 说明 |
|------|------|
| [observability](./模块/observability.md) | Prometheus 指标/日志/系统监控 |

#### 用户界面
| 模块 | 说明 |
|------|------|
| [api](./模块/api.md) | Gin HTTP API 服务器 |
| [tui](./模块/tui.md) | Bubble Tea 终端界面 |

#### 工具库
| 模块 | 说明 |
|------|------|
| [types](./模块/types.md) | 核心类型定义 |
| [config](./模块/config.md) | 配置管理 |
| [mitre](./模块/mitre.md) | MITRE ATT&CK 映射库 |

---

## 快速导航

### 按功能领域

**日志解析**: `parsers/` → `engine/` → `storage/`  
**告警检测**: `rules/` → `alerts/` → `analyzers/`  
**报告导出**: `reports/` → `exporters/` → `timeline/`  
**取证分析**: `forensics/` → `collectors/persistence/`  
**多机关联**: `multi/`  
**实时监控**: `collectors/live/` → `api/` → `tui/`  

### 按开发阶段

| Phase | 内容 | 状态 |
|-------|------|------|
| Phase 1 | parsers, storage, collectors, CLI | ✅ 完成 |
| Phase 2 | alerts, correlation, rules, analyzers | ✅ 完成 |
| Phase 3 | TUI, API, Web UI | ✅ 完成 |
| Phase 4 | forensics, reports, timeline, exporters, MITRE ATT&CK | ✅ 完成 |
