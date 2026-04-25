# WinLogAnalyzer-Go 开发文档包

**版本**: v2.4.0  
**更新日期**: 2026-04-13

---

## 文档清单

| 文件 | 大小 | 用途 |
|------|------|------|
| `design.md` | ~90KB | **核心设计文档** - 架构设计、目录结构、核心类型、CLI、API、TUI、Web UI、告警引擎详细设计 |
| `FEATURES.md` | 43KB | **功能详细清单** - 所有模块的详细功能设计需求 (~450+ 功能) |
| `MODULES_COMPARISON.md` | 33KB | **模块对比** - Python vs Go 功能对照表 |
| `requirements.md` | 7KB | **需求文档** - 产品需求、用户故事 |
| `INDEX.md` | 5KB | **索引目录** - 文档导航索引 |
| `ISSUES_FIX.md` | 25KB | **问题修复清单** - 设计问题及修复方案 (v2.3.0 → v2.4.0) |

---

## 使用指南

### 1. 设计阶段
- 先阅读 `INDEX.md` 了解文档结构
- 阅读 `design.md` 了解整体架构
- 阅读 `MODULES_COMPARISON.md` 了解 Python 到 Go 的映射
- 参考 `ISSUES_FIX.md` 了解已知问题和修复方案

### 2. 开发阶段
- 参考 `FEATURES.md` 实现各模块功能
- 每个功能包含：
  - 功能需求代码示例
  - 数据结构定义
  - API 接口设计
  - 处理流程说明

### 3. 对照参考
- `MODULES_COMPARISON.md` 可快速查找 Python 原型
- `requirements.md` 确保需求完整性

---

## 目录结构参考

根据 design.md v2.4.0，Go 项目结构为：

```
winalog-go/
├── cmd/winalog/           # CLI 命令
│   └── commands/          # 19 个子命令
├── internal/
│   ├── engine/           # 核心引擎
│   ├── parsers/          # 解析器 (EVTX/ETL/CSV/IIS/Sysmon)
│   ├── collectors/       # 采集器
│   │   ├── live/         # 实时采集 (4 个文件)
│   │   └── persistence/  # 持久化检测 (6 个文件)
│   ├── alerts/           # 告警引擎 (7 个模块) ✅ 完整
│   ├── correlation/       # 关联引擎
│   ├── rules/            # 规则系统 (60+ 规则)
│   ├── analyzers/        # 分析器
│   ├── storage/          # 存储 (5 个文件) ✅ 完整
│   ├── reports/          # 报告 (4 个文件) ✅ 完整
│   ├── exporters/        # 导出器
│   ├── timeline/         # 时间线
│   ├── multi/            # 多机分析
│   ├── forensics/        # 取证
│   ├── observability/     # 可观测性
│   ├── api/              # HTTP API (详细设计) ✅ 完整
│   ├── tui/              # TUI 界面
│   └── gui/              # Web UI
└── pkg/                  # 公共包
```

---

## 开发优先级建议

### Phase 1: 核心模块 (MVP)
1. **解析器** (`parsers/`) - EVTX 解析是基础
2. **存储** (`storage/`) - SQLite 数据库
3. **采集器** (`collectors/`) - 一键采集
4. **CLI** (`cmd/winalog/`) - 命令行接口

### Phase 2: 分析功能
5. **告警引擎** (`alerts/`) - 规则评估、去重、统计、趋势、升级、抑制 ✅ 7 个模块完整
6. **关联引擎** (`correlation/`) - 事件链
7. **规则系统** (`rules/`) - 60+ 规则
8. **分析器** (`analyzers/`) - 暴力破解、登录分析

### Phase 3: UI 界面
9. **TUI** (`tui/`) - Bubble Tea 终端界面
10. **API** (`api/`) - HTTP API ✅ 详细设计
11. **Web UI** (`gui/`) - React 前端

### Phase 4: 增强功能
12. **取证** (`forensics/`)
13. **报告** (`reports/`)
14. **多机分析** (`multi/`)
15. **可选功能** (`OPTIONAL_FEATURES.md`)

---

## 关键设计决策

### 1. 类型系统
统一使用 `types/` 下的类型定义，避免 Python 中的类型混乱问题

### 2. 并发模型
使用 Go goroutine + channel 实现事件管道，避免 Python GIL 问题

### 3. 数据库
使用 Pure Go SQLite (modernc.org/sqlite)，无 CGO 依赖，单二进制部署

### 4. 前端策略
- TUI: Bubble Tea (P0 - 必做)
- Web UI: React + Vite + Gin API (P1)

---

## v2.4.0 更新内容

| 问题 | 修复 |
|------|------|
| 目录结构不完整 | 补充缺失文件 (dll_info.go, user_info.go, stats.go 等) |
| 告警引擎不完整 | 添加 evaluator/stats/trend/upgrade/suppress 5 个模块 |
| API Handler 缺失 | 添加详细 Handler 设计 |
| 数据类型不一致 | 统一 Alert 结构，添加 FalsePositive 字段 |
| 章节编号错误 | 重编号 9-19 章 |
| 错误码缺失 | 扩展错误码定义 |
| 配置结构不完整 | 添加 AlertConfig, SearchConfig 等 |
| 依赖选择不一致 | 更新 requirements.md 使用 modernc.org/sqlite |

---

## 文档更新记录

| 版本 | 日期 | 更新内容 |
|------|------|----------|
| v1.0 | 2026-04-13 | 初始打包 |
| v2.4.0 | 2026-04-13 | 修复设计问题：目录结构、告警引擎、API Handler、数据类型等 |
