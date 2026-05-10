# 接口文档

> 版本: v2.5.0 | 最后更新: 2026-05-09

## 1. REST API

基础路径: `http://127.0.0.1:8080/api`

### 1.1 健康检查

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/health` | 服务健康检查 |

### 1.2 事件管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/events` | 事件列表 (分页) |
| GET | `/api/events/:id` | 获取单个事件 |
| POST | `/api/events/search` | 全文搜索 |
| POST | `/api/events/export` | 事件导出 |

### 1.3 告警管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/alerts` | 告警列表 |
| GET | `/api/alerts/stats` | 告警统计 |
| GET | `/api/alerts/trend` | 告警趋势 |
| GET | `/api/alerts/export` | 告警导出 |
| POST | `/api/alerts/run-analysis` | 运行分析 |
| GET | `/api/alerts/:id` | 告警详情 |
| POST | `/api/alerts/:id/resolve` | 解决告警 |
| POST | `/api/alerts/:id/false-positive` | 标记误报 |
| DELETE | `/api/alerts/:id` | 删除告警 |
| POST | `/api/alerts/batch` | 批量操作 |

### 1.4 日志导入

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/import/logs` | 导入日志文件 |
| GET | `/api/import/status` | 导入状态 |
| GET | `/api/import/history` | 导入历史 |

### 1.5 实时监控

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/live/stats` | 监控统计 |
| GET | `/api/live/channels` | 通道列表 |
| POST | `/api/live/channels` | 更新通道 |
| GET | `/api/live/events` | 实时事件流 |
| POST | `/api/live/start` | 开始监控 |
| POST | `/api/live/stop` | 停止监控 |

### 1.6 时间线

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/timeline` | 时间线数据 |
| GET | `/api/timeline/stats` | 时间线统计 |
| GET | `/api/timeline/chains` | 攻击链 |

### 1.7 仪表板

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/dashboard/collection-stats` | 采集统计 |
| GET | `/api/dashboard/log-names` | 日志名称列表 |

### 1.8 系统信息

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/system/info` | 系统信息 |
| GET | `/api/system/processes` | 进程列表 |
| GET | `/api/system/network` | 网络连接 |
| GET | `/api/system/users` | 用户列表 |
| GET | `/api/system/drivers` | 驱动列表 |
| GET | `/api/system/software` | 软件列表 |

### 1.9 规则管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/rules` | 规则列表 |
| GET | `/api/rules/:id` | 规则详情 |
| POST | `/api/rules` | 创建规则 |
| PUT | `/api/rules/:id` | 更新规则 |
| DELETE | `/api/rules/:id` | 删除规则 |
| POST | `/api/rules/batch` | 批量操作 |

### 1.10 报告

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/reports` | 报告列表 |
| POST | `/api/reports/generate` | 生成报告 |
| GET | `/api/reports/:id` | 获取报告 |
| DELETE | `/api/reports/:id` | 删除报告 |

### 1.11 取证

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/forensics/collect` | 数据采集 |
| GET | `/api/forensics/evidence` | 证据列表 |
| POST | `/api/forensics/verify` | 完整性验证 |

### 1.12 配置

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/settings` | 获取配置 |
| PUT | `/api/settings` | 更新配置 |
| POST | `/api/settings/reload` | 重载配置 |

### 1.13 分析

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/analyze/bruteforce` | 暴力破解分析 |
| POST | `/api/analyze/login` | 登录行为分析 |
| POST | `/api/analyze/kerberos` | Kerberos 分析 |
| POST | `/api/analyze/powershell` | PowerShell 分析 |
| POST | `/api/analyze/exfiltration` | 数据外泄分析 |
| POST | `/api/analyze/lateral` | 横向移动分析 |
| POST | `/api/analyze/persistence` | 持久化分析 |
| POST | `/api/analyze/privesc` | 权限提升分析 |
| POST | `/api/analyze/dc` | 域控制器分析 |

### 1.14 抑制规则

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/suppress` | 抑制规则列表 |
| POST | `/api/suppress` | 创建抑制规则 |
| DELETE | `/api/suppress/:id` | 删除抑制规则 |

### 1.15 UEBA

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/ueba/baselines` | 行为基线 |
| POST | `/api/ueba/build` | 构建基线 |
| GET | `/api/ueba/anomalies` | 异常检测 |

### 1.16 关联分析

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/correlation/run` | 运行关联分析 |
| GET | `/api/correlation/results` | 关联结果 |

### 1.17 多机分析

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/multi/topology` | 网络拓扑 |
| POST | `/api/multi/analyze` | 多机分析 |
| GET | `/api/multi/chains` | 跨机攻击链 |

### 1.18 高级查询

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/query/sql` | SQL 查询 |
| POST | `/api/query/fts` | 全文搜索 |

### 1.19 策略管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/policy/templates` | 策略模板 |
| POST | `/api/policy/apply` | 应用策略 |

### 1.20 UI 操作

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/ui/config` | UI 配置 |
| POST | `/api/ui/action` | UI 操作 |

### 1.21 日志查看

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/logs` | 应用日志 |

### 1.22 资产管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/assets` | 资产列表 |
| POST | `/api/assets` | 创建资产 |
| PUT | `/api/assets/:id` | 更新资产 |
| DELETE | `/api/assets/:id` | 删除资产 |

### 1.23 持久化检测

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/persistence/detections` | 检测结果 |
| POST | `/api/persistence/scan` | 执行扫描 |
| GET | `/api/persistence/whitelist` | 白名单 |
| POST | `/api/persistence/whitelist` | 添加白名单 |

### 1.24 监控

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/monitor/status` | 监控状态 |
| POST | `/api/monitor/start` | 开始监控 |
| POST | `/api/monitor/stop` | 停止监控 |
| GET | `/api/monitor/processes` | 进程监控 |
| GET | `/api/monitor/network` | 网络监控 |

## 2. CLI 命令

基础命令: `winalog [command] [flags]`

### 2.1 全局参数

| 参数 | 说明 |
|------|------|
| `--db <path>` | 数据库路径 |
| `--log-level <level>` | 日志级别 (debug/info/warn/error) |
| `--config <path>` | 配置文件路径 |

### 2.2 核心命令

| 命令 | 说明 | 主要参数 |
|------|------|----------|
| `import <file>` | 导入日志文件 | `--workers`, `--batch-size`, `--incremental` |
| `search` | 搜索事件 | `--event-id`, `--level`, `--user`, `--computer`, `--start`, `--end`, `--keywords` |
| `query <sql>` | SQL 查询 | 直接输入 SQL |
| `export` | 导出数据 | `--format json\|csv\|excel\|timeline`, `--output` |

### 2.3 告警命令

| 命令 | 说明 | 主要参数 |
|------|------|----------|
| `alert list` | 列出告警 | `--severity`, `--resolved`, `--limit` |
| `alert show <id>` | 查看告警详情 | |
| `alert resolve <id>` | 解决告警 | |
| `alert delete <id>` | 删除告警 | |
| `alert stats` | 告警统计 | |
| `alert export` | 导出告警 | `--format` |

### 2.4 分析命令

| 命令 | 说明 | 主要参数 |
|------|------|----------|
| `analyze` | 运行专项分析 | `--type bruteforce\|login\|kerberos\|powershell\|...` |
| `correlate` | 关联分析 | `--window`, `--max-events` |
| `timeline` | 构建时间线 | `--start`, `--end`, `--category` |
| `ueba` | 用户行为分析 | `--build`, `--detect` |

### 2.5 系统命令

| 命令 | 说明 | 主要参数 |
|------|------|----------|
| `serve` | 启动 HTTP 服务 | `--host`, `--port` |
| `status` | 系统状态 | |
| `info` | 系统信息 (Windows) | |
| `metrics` | Prometheus 指标 | |
| `dashboard` | 仪表板统计 | |

### 2.6 管理命令

| 命令 | 说明 | 主要参数 |
|------|------|----------|
| `rules list` | 规则列表 | `--enabled`, `--severity` |
| `rules enable <id>` | 启用规则 | |
| `rules disable <id>` | 禁用规则 | |
| `config show` | 显示配置 | |
| `config set` | 设置配置 | `--key`, `--value` |
| `db status` | 数据库状态 | |
| `db vacuum` | 数据库优化 | |
| `whitelist` | 白名单管理 | `--add`, `--remove`, `--list` |

### 2.7 采集命令

| 命令 | 说明 | 主要参数 |
|------|------|----------|
| `collect` | 一键采集 | `--output`, `--evidence` |
| `live` | 实时监控 | `--start`, `--stop`, `--status` |
| `forensics` | 取证操作 | `--hash`, `--collect` |

### 2.8 转换命令

| 命令 | 说明 | 主要参数 |
|------|------|----------|
| `evtx2csv <file>` | EVTX 转 CSV | `--output` |

## 3. WebSocket 接口

### 3.1 实时事件流

连接: `ws://127.0.0.1:8080/ws/live`

消息格式:
```json
{
  "type": "event",
  "data": {
    "event_id": 4624,
    "timestamp": "2026-05-09T10:30:00Z",
    "message": "..."
  }
}
```

### 3.2 导入进度

消息格式:
```json
{
  "type": "import_progress",
  "data": {
    "file": "security.evtx",
    "processed": 15000,
    "total": 50000,
    "percent": 30.0
  }
}
```

## 4. 错误码

| HTTP 状态码 | 说明 |
|-------------|------|
| 200 | 成功 |
| 400 | 请求参数错误 |
| 401 | 未授权 |
| 403 | 禁止访问 |
| 404 | 资源不存在 |
| 500 | 服务器内部错误 |
