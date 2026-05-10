# 开发者指南

> 版本: v2.5.0 | 最后更新: 2026-05-09

## 1. 环境准备

### 1.1 系统要求

- **Go**: 1.25.0+
- **Node.js**: 18+ (前端开发)
- **操作系统**: Linux / Windows

### 1.2 克隆仓库

```bash
git clone https://github.com/kkkdddd-start/winalog-go-fix-.git
cd winalog-go
```

### 1.3 安装依赖

```bash
# Go 依赖
go mod download

# 前端依赖
cd internal/gui && npm install && cd ../..
```

## 2. 构建

### 2.1 Makefile 命令

| 命令 | 说明 |
|------|------|
| `make build` | 构建当前平台二进制 |
| `make build-linux` | 构建 Linux amd64 |
| `make build-windows` | 构建 Windows amd64 |
| `make build-all` | 构建所有平台 |
| `make clean` | 清理构建产物 |
| `make test` | 运行测试 |
| `make lint` | 代码检查 |

### 2.2 手动构建

```bash
# 构建当前平台
go build -o winalog ./cmd/winalog

# 交叉编译 Linux
GOOS=linux GOARCH=amd64 go build -o winalog-linux-amd64 ./cmd/winalog

# 交叉编译 Windows
GOOS=windows GOARCH=amd64 go build -o winalog-windows-amd64.exe ./cmd/winalog
```

### 2.3 前端构建

```bash
cd internal/gui
npm run dev          # 开发模式
npm run build        # 生产构建
```

## 3. 开发模式

### 3.1 前后端分离开发

**启动前端 (Vite)**:
```bash
cd internal/gui
npm run dev
```

**启动后端**:
```bash
go run ./cmd/winalog serve
```

前端开发服务器会通过 Vite 代理将 `/api` 请求转发到后端。

### 3.2 嵌入式构建

生产模式下，前端构建产物嵌入 Go 二进制:

```bash
# 1. 构建前端
cd internal/gui && npm run build

# 2. 构建后端 (包含前端)
go build -o winalog ./cmd/winalog
```

## 4. 代码结构

```
winalog-go/
├── cmd/winalog/              # CLI 入口
│   ├── main.go               # 程序入口
│   └── commands/             # CLI 命令
│       ├── root.go           # 根命令注册
│       ├── import.go         # import 命令
│       ├── search.go         # search 命令
│       ├── alert.go          # alert 命令
│       └── ...
│
├── internal/                 # 内部模块
│   ├── config/               # 配置管理
│   ├── storage/              # 数据存储
│   ├── engine/               # 处理引擎
│   ├── api/                  # REST API
│   │   ├── server.go         # HTTP 服务器
│   │   ├── routes.go         # 路由定义
│   │   ├── handlers_*.go     # 各模块 Handler
│   │   └── dist/             # 嵌入的前端静态文件
│   ├── gui/                  # Web UI 源码
│   │   ├── src/
│   │   │   ├── pages/        # 页面组件
│   │   │   ├── components/   # 通用组件
│   │   │   ├── api/          # API 客户端
│   │   │   └── utils/        # 工具函数
│   │   └── dist/             # 构建产物
│   ├── alerts/               # 告警引擎
│   ├── analyzers/            # 专项分析器
│   ├── rules/                # 规则引擎
│   ├── parsers/              # 日志解析器
│   ├── collectors/           # 数据采集器
│   ├── exporters/            # 数据导出器
│   ├── reports/              # 报告生成
│   ├── correlation/          # 关联分析
│   ├── timeline/             # 时间线
│   ├── ueba/                 # 用户行为分析
│   ├── forensics/            # 取证模块
│   ├── persistence/          # 持久化检测
│   ├── monitor/              # 实时监控
│   ├── multi/                # 多机分析
│   ├── types/                # 共享类型
│   ├── observability/        # 日志与指标
│   └── version/              # 版本信息
│
├── pkg/                      # 可复用包
│   ├── evtx/                 # EVTX 工具
│   └── mitre/                # MITRE ATT&CK 数据
│
├── data/rules/               # 规则配置文件
├── scripts/                  # 构建脚本
├── docs/                     # 文档
└── logs/                     # 日志目录
```

## 5. 扩展开发

### 5.1 添加新的日志解析器

1. 在 `internal/parsers/` 下创建子目录
2. 实现 `Parser` 接口:

```go
type Parser interface {
    CanParse(path string) bool
    Parse(path string) <-chan *types.Event
    ParseWithError(path string) ParseResult
    ParseBatch(path string) ([]*types.Event, error)
    GetType() string
    Priority() int
}
```

3. 在 `ParserRegistry` 中注册

### 5.2 添加新的安全规则

1. 在 `internal/rules/builtin/` 中定义规则:

```go
var MyRule = &types.AlertRule{
    Name:        "my-rule",
    Description: "规则描述",
    Enabled:     true,
    Severity:    types.SeverityHigh,
    Filter: &types.Filter{
        EventID: []int32{4624},
        LogName: "Security",
    },
    MITREAttack: "T1110",
}
```

2. 在 `registry.go` 中注册规则

### 5.3 添加新的分析器

1. 在 `internal/analyzers/` 下创建文件
2. 实现 `Analyzer` 接口:

```go
type Analyzer interface {
    Name() string
    Analyze(events []*types.Event) (*Result, error)
}
```

3. 在 API Handler 中注册端点

### 5.4 添加新的采集器

1. 在 `internal/collectors/` 下创建文件
2. 实现 `Collector` 接口:

```go
type Collector interface {
    Name() string
    Collect(ctx context.Context) ([]interface{}, error)
    RequiresAdmin() bool
}
```

3. 在 `collect.go` 中注册

### 5.5 添加新的导出格式

1. 在 `internal/exporters/` 下创建文件
2. 实现 `Exporter` 接口
3. 在 `ExporterFactory` 中注册

## 6. API 开发

### 6.1 添加新端点

1. 在 `internal/api/` 下创建 `handlers_xxx.go`
2. 定义 Handler 结构体和路由
3. 在 `routes.go` 中注册路由组

```go
// handlers_xxx.go
type XXXHandler struct {
    db *storage.DB
}

func (h *XXXHandler) RegisterRoutes(r *gin.RouterGroup) {
    xxx := r.Group("/xxx")
    xxx.GET("", h.List)
    xxx.POST("", h.Create)
}

func (h *XXXHandler) List(c *gin.Context) {
    // 实现逻辑
}
```

### 6.2 添加 Swagger 注释

```go
// @Summary 获取事件列表
// @Description 分页获取事件列表
// @Tags events
// @Accept json
// @Produce json
// @Param page query int false "页码"
// @Param size query int false "每页数量"
// @Success 200 {object} types.SearchResponse
// @Router /api/events [get]
func (h *AlertHandler) ListEvents(c *gin.Context) {
    // ...
}
```

生成文档:
```bash
swag init -g cmd/winalog/main.go -o internal/api/docs
```

## 7. 前端开发

### 7.1 添加新页面

1. 在 `internal/gui/src/pages/` 下创建组件
2. 在路由配置中添加路径
3. 使用 Ant Design 组件构建 UI

### 7.2 添加 API 调用

1. 在 `internal/gui/src/api/` 下创建 API 函数
2. 使用 axios 发送请求
3. 在页面组件中调用

```typescript
// api/events.ts
import axios from 'axios'

export const getEvents = async (page: number, size: number) => {
  const res = await axios.get('/api/events', { params: { page, size } })
  return res.data
}
```

### 7.3 状态管理

使用 React hooks 管理状态:
- `useState` - 组件状态
- `useEffect` - 副作用
- 自定义 hooks 封装业务逻辑

## 8. 测试

### 8.1 单元测试

```bash
go test ./internal/... -v
```

### 8.2 集成测试

```bash
# 导入测试数据后运行
go test ./internal/engine/... -v
```

## 9. 代码规范

### 9.1 Go 代码规范

- 遵循 Effective Go
- 使用 `go fmt` 格式化
- 使用 `go vet` 检查
- 包名小写，简短清晰
- 导出的标识符使用 PascalCase
- 私有标识符使用 camelCase

### 9.2 Git 提交规范

```
<type>(<scope>): <description>

feat: 新功能
fix: Bug 修复
docs: 文档更新
style: 代码格式
refactor: 重构
test: 测试
chore: 构建/工具
```

### 9.3 分支策略

- `main` - 稳定版本
- 功能分支: `feat/xxx`
- 修复分支: `fix/xxx`
- 发布标签: `vX.Y.Z`

## 10. 配置说明

### 10.1 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `WINALOG_DATABASE_PATH` | 数据库路径 | `~/.winalog/winalog.db` |
| `WINALOG_LOG_LEVEL` | 日志级别 | `info` |
| `WINALOG_CONFIG_PATH` | 配置文件路径 | `~/.winalog/config.yaml` |

### 10.2 配置文件

```yaml
# ~/.winalog/config.yaml
database:
  path: ~/.winalog/winalog.db
  wal_mode: true
  max_open_conns: 10
  max_idle_conns: 2

import:
  workers: 4
  batch_size: 10000
  incremental: true

parser:
  workers: 4
  max_memory_mb: 512

search:
  max_results: 10000
  timeout: 30s
  page_size: 100

alerts:
  dedup_window: 300s
  upgrade_rules:
    - severity: high
      count: 5
      window: 60s
  suppress_rules: []

correlation:
  window: 300s
  max_events: 1000

report:
  output_dir: ~/.winalog/reports
  formats: [html, json]

forensics:
  hash_algorithm: sha256
  verify_signature: true

api:
  host: 127.0.0.1
  port: 8080
  cors_origins:
    - http://localhost
    - http://127.0.0.1
  query_timeout: 300s

monitor:
  process_interval: 5s
  network_interval: 10s

auth:
  enabled: false
  jwt_secret: ""

audit:
  enabled: true
  log_file: ~/.winalog/audit.log
```

## 11. 常见问题

### 11.1 编译错误

**问题**: `missing go.sum entry`
**解决**: `go mod tidy`

**问题**: `C compiler not found` (sqlite3)
**解决**: 安装 gcc: `apt install gcc` 或 `yum install gcc`

### 11.2 运行错误

**问题**: `database is locked`
**解决**: 确保没有多个进程同时写入数据库

**问题**: `port already in use`
**解决**: 更改端口或关闭占用端口的进程

### 11.3 性能优化

- 增加导入 worker 数: `--workers 8`
- 增加批大小: `--batch-size 20000`
- 启用 WAL 模式提高并发性能
