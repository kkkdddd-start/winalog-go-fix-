# 系统架构文档

> 版本: v2.5.0 | 最后更新: 2026-05-09

## 1. 架构概览

WinLogAnalyzer-Go 采用分层模块化架构，通过清晰的接口和共享类型实现模块间解耦。整体架构遵循 DDD 分层模式：

```
┌─────────────────────────────────────────────────────────────────┐
│                        交互层 (Interfaces)                       │
├─────────────────────┬─────────────────────┬─────────────────────┤
│     CLI (cobra)     │   REST API (gin)    │     Web UI (React)  │
│   cmd/winalog/      │   internal/api/     │   internal/gui/     │
│   commands/         │                     │                     │
└─────────┬───────────┴──────────┬──────────┴──────────┬──────────┘
          │                      │                     │
          ▼                      ▼                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                        业务层 (Application)                      │
├──────────┬──────────┬──────────┬──────────┬──────────┬──────────┤
│ engine/  │ alerts/  │analyzers │correlat/ │ timeline │ reports/ │
│ 导入搜索  │ 告警引擎  │专项分析   │关联分析   │ 时间线    │ 报告生成  │
└────┬─────┴────┬─────┴────┬─────┴────┬─────┴────┬─────┴────┬─────┘
     │          │          │          │          │          │
     ▼          ▼          ▼          ▼          ▼          ▼
┌─────────────────────────────────────────────────────────────────┐
│                        领域层 (Domain)                           │
├──────────┬──────────┬──────────┬──────────┬──────────┬──────────┤
│ rules/   │ ueba/    │forensics │persist/  │ multi/   │ monitor/ │
│ 规则引擎  │行为分析   │取证模块   │持久化检测  │多机分析   │实时监控   │
└────┬─────┴────┬─────┴────┬─────┴────┬─────┴────┬─────┴────┬─────┘
     │          │          │          │          │          │
     ▼          ▼          ▼          ▼          ▼          ▼
┌─────────────────────────────────────────────────────────────────┐
│                        基础设施层 (Infrastructure)               │
├──────────┬──────────┬──────────┬──────────┬──────────┬──────────┤
│ storage/ │ parsers/ │collectors│exporters │  config/  │observab/ │
│ SQLite   │日志解析   │数据采集   │数据导出   │ 配置管理   │日志/指标  │
└──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘
                              ▲
                              │
                    ┌─────────┴─────────┐
                    │    types/          │
                    │  (共享类型定义)     │
                    └───────────────────┘
```

## 2. 核心数据流

### 2.1 日志导入流程

```
[EVTX/ETL/CSV/IIS/Sysmon 文件]
           │
           ▼
    ┌──────────────┐
    │  ParserRegistry │ 按文件类型选择解析器
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │   Engine.Import() │ 并发导入 (可配置 worker 数)
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │  Parser.Parse() │ 解析为 Event 流 (channel)
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │  storage.DB.InsertBatch() │ 批量插入 (默认 10000 条/批)
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │  events 表 + events_fts (FTS5 全文索引)
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │  alerts.Engine.Evaluate() │ 触发告警评估
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │  alerts 表 + import_log 表
    └──────────────┘
```

### 2.2 实时监控流程

```
[Windows Event Log / ETW]
           │
           ▼
    ┌──────────────┐
    │  monitor/    │ WMI 事件订阅 / 轮询
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │  live_events 表 │ 实时事件写入
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │  WebSocket 推送 │ 前端实时更新
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │  alerts.Engine.Evaluate() │ 实时告警评估
    └──────────────┘
```

### 2.3 搜索与查询流程

```
[用户搜索请求]
           │
           ▼
    ┌──────────────┐
    │  api/handlers │ 解析搜索参数
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │  engine.Search() │ 带缓存的搜索
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │  storage.EventRepo │ SQL 查询 / FTS5 全文搜索
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │  events 表 (主查询)
    │  events_fts (全文搜索)
    └──────────────┘
```

## 3. 模块依赖关系

```
                    cmd/winalog (CLI 入口)
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
    engine/           api/            collectors/
    (导入/搜索)        (HTTP 服务)      (数据采集)
        │                 │                 │
        ▼                 ▼                 ▼
    parsers/    ←→   alerts/     ←→   storage/
    (日志解析)        (告警引擎)        (SQLite 存储)
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
     rules/          analyzers/       exporters/
    (规则引擎)        (专项分析)        (数据导出)
          │               │
          ▼               ▼
    correlation/     timeline/
    (关联分析)        (时间线)
          │               │
          ▼               ▼
      ueba/           reports/
    (行为分析)        (报告生成)
          │               │
          ▼               ▼
    persistence/    forensics/
    (持久化检测)     (取证模块)
```

## 4. 技术栈

### 4.1 后端 (Go)

| 组件 | 技术 | 用途 |
|------|------|------|
| HTTP 框架 | gin-gonic/gin v1.12.0 | REST API 服务 |
| CLI 框架 | spf13/cobra v1.10.2 | 命令行界面 |
| 配置管理 | spf13/viper v1.21.0 | YAML 配置加载 |
| 数据库 | mattn/go-sqlite3 v1.14.44 | SQLite 存储 |
| EVTX 解析 | 0xrawsec/golang-evtx v1.2.9 | Windows 事件日志解析 |
| WebSocket | gorilla/websocket v1.5.3 | 实时通信 |
| 日志 | uber-go/zap v1.27.1 | 结构化日志 |
| 指标 | prometheus/client_golang v1.23.2 | Prometheus 指标 |
| Excel 导出 | xuri/excelize/v2 v2.10.1 | Excel 文件生成 |
| PDF 生成 | jung-kurt/gofpdf v1.16.2 | PDF 报告生成 |
| API 文档 | swaggo/swag v1.16.6 | Swagger 文档生成 |

### 4.2 前端 (React)

| 组件 | 技术 | 用途 |
|------|------|------|
| 框架 | React 18.3 + TypeScript | UI 框架 |
| 构建工具 | Vite 6.2 | 构建和开发服务器 |
| UI 组件 | Ant Design 6.3 | 组件库 |
| 图表 | Chart.js 4.4 + react-chartjs-2 | 数据可视化 |
| HTTP | Axios 1.6 | API 请求 |
| 路由 | React Router 6.22 | 前端路由 |
| 网络图 | vis-network 10.0 | 拓扑图渲染 |
| 手势 | hammerjs | 触摸手势支持 |

## 5. 数据库架构

### 5.1 核心表

```
┌─────────────────────────────────────────────────────────────┐
│                        events (主表)                         │
├────────────┬────────────────────────────────────────────────┤
│ id         │ INTEGER PRIMARY KEY AUTOINCREMENT              │
│ timestamp  │ TEXT (ISO 8601)                                │
│ event_id   │ INTEGER (Windows Event ID, 如 4624)            │
│ level      │ INTEGER (1=Critical, 5=Verbose)                │
│ source     │ TEXT (事件源)                                   │
│ log_name   │ TEXT (Security/System/Application)             │
│ computer   │ TEXT (计算机名)                                 │
│ user       │ TEXT (用户名)                                   │
│ user_sid   │ TEXT (安全标识符)                               │
│ message    │ TEXT (事件消息)                                 │
│ raw_xml    │ TEXT (原始 XML)                                 │
│ session_id │ TEXT (会话 ID)                                  │
│ ip_address │ TEXT (IP 地址)                                  │
│ import_time│ TEXT (导入时间)                                 │
│ extracted  │ TEXT (JSON, 提取字段)                           │
└────────────┴────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   events_fts (FTS5 虚拟表)                    │
│ 全文搜索索引: source, log_name, computer, user, message     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                        alerts (告警表)                       │
├────────────┬────────────────────────────────────────────────┤
│ id         │ INTEGER PRIMARY KEY AUTOINCREMENT              │
│ rule_name  │ TEXT (触发规则名称)                             │
│ severity   │ INTEGER (0-5, critical→info)                   │
│ message    │ TEXT (告警消息)                                 │
│ event_ids  │ TEXT (JSON, Windows Event ID 列表)             │
│ event_db_ids│ TEXT (JSON, 数据库 ID 列表)                    │
│ first_seen │ TEXT (首次触发时间)                             │
│ last_seen  │ TEXT (最后触发时间)                             │
│ count      │ INTEGER (触发次数)                              │
│ mitre_attack│ TEXT (JSON, MITRE ATT&CK 技术 ID)             │
│ resolved   │ INTEGER (0/1, 是否已解决)                       │
│ false_positive│ INTEGER (0/1, 是否误报)                      │
│ rule_score │ REAL (规则评分)                                 │
└────────────┴────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                      其他核心表                              │
├─────────────────────────────────────────────────────────────┤
│ import_log      │ 导入历史记录                              │
│ live_events     │ 实时事件流                                │
│ live_channels   │ 实时监控通道配置                          │
│ persistence_detections │ 持久化检测结果                      │
│ processes       │ 进程快照                                  │
│ network_connections│ 网络连接                               │
│ users           │ 用户信息                                  │
│ drivers         │ 驱动信息                                  │
│ system_info     │ 系统信息快照                              │
│ reports         │ 报告记录                                  │
│ suppress_rules  │ 告警抑制规则                              │
│ rule_states     │ 规则启用/禁用状态                         │
│ ueba_baselines  │ UEBA 行为基线                             │
│ machine_assets  │ 机器资产                                  │
│ evidence_chain  │ 取证证据链                                │
│ global_timeline │ 全局时间线                                │
│ sessions        │ 会话记录                                  │
└─────────────────────────────────────────────────────────────┘
```

## 6. 安全架构

### 6.1 默认安全配置

- **监听地址**: `127.0.0.1:8080` (仅本地访问)
- **CORS**: 限制为 `localhost` 源
- **SQL 注入防护**: 白名单查询 (SELECT/EXPLAIN/WITH)、禁止注释、禁止 UNION、禁止文件操作
- **查询超时**: 5 分钟上限
- **连接池**: MaxOpenConns=10, MaxIdleConns=2

### 6.2 认证与授权

- JWT Token 认证 (可配置)
- 审计日志记录关键操作
- API 端点权限控制

## 7. 构建与部署

### 7.1 交叉编译

```
Linux amd64   → winalog-linux-amd64   (~37MB)
Windows amd64 → winalog-windows-amd64.exe (~38MB)
```

### 7.2 部署模式

- **单二进制部署**: 前端通过 Go embed 嵌入
- **开发模式**: 前后端分离，Vite 代理转发 API 请求
- **CLI 模式**: 直接命令行交互

### 7.3 配置文件

```yaml
# 默认配置 (~/.winalog/config.yaml)
database:
  path: ~/.winalog/winalog.db
  wal_mode: true

import:
  workers: 4
  batch_size: 10000

api:
  host: 127.0.0.1
  port: 8080
  cors_origins:
    - http://localhost
    - http://127.0.0.1
```
