# WinLogAnalyzer-Go 开发者指南

## 环境要求

- Go 1.22+
- Windows (用于实际运行)
- Git

## 获取源码

```bash
git clone https://github.com/kkkdddd-start/winalog-go.git
cd winalog-go
```

## 构建

### 标准构建

```bash
# 构建当前平台
make build

# 或直接使用 go build
go build -o winalog ./cmd/winalog
```

### 跨平台构建

```bash
# 构建所有平台
make build-all

# Linux
GOOS=linux GOARCH=amd64 go build -o winalog-linux-amd64 ./cmd/winalog

# Windows
GOOS=windows GOARCH=amd64 go build -o winalog-windows-amd64.exe ./cmd/winalog

# macOS
GOOS=darwin GOARCH=amd64 go build -o winalog-darwin-amd64 ./cmd/winalog
```

## 测试

```bash
# 运行所有测试
make test

# 或
go test ./...

# 运行测试并显示覆盖率
go test -cover ./...

# 运行特定包的测试
go test ./internal/engine/...
```

## 代码规范

### 格式化

```bash
# 格式化代码
go fmt ./...

# 使用 goimports (需安装)
go install golang.org/x/tools/cmd/goimports@latest
goimports -w .
```

### Lint

```bash
# 运行 golangci-lint (需安装)
golangci-lint run

# 或使用 make lint
make lint
```

### Vet

```bash
go vet ./...
```

## 项目结构

```
winalog-go/
├── cmd/winalog/           # CLI 命令入口
│   ├── main.go           # 主程序
│   └── commands/          # 子命令
├── internal/              # 内部包 (不可被外部导入)
│   ├── engine/           # 核心引擎
│   ├── parsers/          # 日志解析器
│   ├── storage/          # 数据存储
│   ├── alerts/            # 告警引擎
│   ├── correlation/       # 关联引擎
│   ├── rules/             # 规则系统
│   ├── analyzers/         # 专用分析器
│   ├── collectors/        # 采集器
│   ├── forensics/         # 取证
│   ├── reports/           # 报告
│   ├── exporters/         # 导出器
│   ├── timeline/          # 时间线
│   ├── multi/            # 多机分析
│   ├── observability/     # 可观测性
│   ├── api/               # HTTP API
│   ├── tui/               # 终端界面
│   ├── types/             # 类型定义
│   ├── config/            # 配置
│   └── utils/             # 工具函数
└── pkg/                   # 公共包 (可被外部导入)
    ├── evtx/             # EVTX 解析库
    └── mitre/             # MITRE ATT&CK 映射
```

## 添加新模块

### 1. 添加新的 Parser

创建 `internal/parsers/custom/parser.go`:

```go
package custom

import (
    "path/filepath"
    "github.com/kkkdddd-start/winalog-go/internal/types"
)

type CustomParser struct{}

func (p *CustomParser) CanParse(path string) bool {
    ext := filepath.Ext(path)
    return ext == ".custom"
}

func (p *CustomParser) Parse(path string) <-chan *types.Event {
    ch := make(chan *types.Event, 100)
    go func() {
        defer close(ch)
        // 解析逻辑
        for /* ... */ {
            event := &types.Event{...}
            ch <- event
        }
    }()
    return ch
}

func (p *CustomParser) ParseBatch(path string) ([]*types.Event, error) {
    var events []*types.Event
    for event := range p.Parse(path) {
        events = append(events, event)
    }
    return events, nil
}

func (p *CustomParser) GetType() string {
    return "custom"
}
```

注册到 Engine (`internal/engine/engine.go`):

```go
func (e *Engine) registerParsers() {
    e.parsers.Register(evtx.NewEvtxParser())
    e.parsers.Register(etl.NewEtlParser())
    e.parsers.Register(csv.NewCsvParser())
    e.parsers.Register(iis.NewIISParser())
    e.parsers.Register(sysmon.NewSysmonParser())
    // 添加新 Parser
    e.parsers.Register(custom.NewCustomParser())
}
```

### 2. 添加新的 Collector

创建 `internal/collectors/custom/collector.go`:

```go
package custom

import (
    "context"
)

type CustomCollector struct {
    BaseCollector
}

func NewCustomCollector() *CustomCollector {
    return &CustomCollector{
        BaseCollector: BaseCollector{
            info: CollectorInfo{
                Name:          "CustomCollector",
                Description:   "Custom data collector",
                RequiresAdmin: true,
                Version:       "1.0.0",
            },
        },
    }
}

func (c *CustomCollector) Collect(ctx context.Context) ([]interface{}, error) {
    // 采集逻辑
    var results []interface{}
    // ...
    return results, nil
}
```

### 3. 添加新的 Rule

创建 `internal/rules/custom_rule.go`:

```go
package rules

type CustomRule struct {
    AlertRule
}

func NewCustomRule() *AlertRule {
    return &AlertRule{
        Name:        "CustomRule",
        Description: "Custom detection rule",
        Enabled:     true,
        Severity:    SeverityHigh,
        Score:       80.0,
        MitreAttack: "T1234",
        Filter: &Filter{
            EventIDs: []int32{1234},
        },
        Message: "Custom alert: {{.EventID}}",
    }
}
```

### 4. 添加新的 Exporter

创建 `internal/exporters/custom.go`:

```go
package exporters

import (
    "encoding/json"
    "io"
    "github.com/kkkdddd-start/winalog-go/internal/types"
)

type CustomExporter struct{}

func (e *CustomExporter) Export(events []*types.Event, w io.Writer) error {
    data, err := json.Marshal(events)
    if err != nil {
        return err
    }
    _, err = w.Write(data)
    return err
}

func (e *CustomExporter) ContentType() string {
    return "application/json"
}

func (e *CustomExporter) FileExtension() string {
    return ".json"
}
```

## 依赖管理

### 添加依赖

```bash
go get github.com/example/package@latest
```

### 更新依赖

```bash
go get -u ./...
```

### 整理依赖

```bash
go mod tidy
```

## 调试

### 启用调试日志

```bash
winalog --log-level debug import security.evtx
```

### Go Delve

```bash
# 安装 delve
go install github.com/go-delve/delve/cmd/dlv@latest

# 调试主程序
dlv debug ./cmd/winalog

# 调试测试
dlv test ./internal/engine/...
```

## 性能分析

### CPU Profile

```bash
# 启动性能分析
./winalog import security.evtx &
pid=$!

# 采集 CPU profile
go tool pprof -http=:8080 http://localhost:6060/debug/pprof/profile?seconds=30

# 或者
curl -o cpu.prof "http://localhost:6060/debug/pprof/profile?seconds=30"
go tool pprof cpu.prof
```

### Memory Profile

```bash
curl -o mem.prof "http://localhost:6060/debug/pprof/heap"
go tool pprof mem.prof
```

## 常见问题

### SQLite 锁定

如果遇到 "database is locked" 错误:

1. 确保没有其他进程在访问数据库
2. 检查 WAL 模式是否启用
3. 增加 busy_timeout: `?_busy_timeout=30000`

### Windows API 调用失败

取证功能需要 Windows API，仅在 Windows 上可用。

### 构建失败

```bash
# 清理缓存
go clean -cache

# 重新下载依赖
go mod download

# 重新构建
go build ./...
```

## 提交规范

遵循 Conventional Commits:

```
feat: 添加新功能
fix: 修复问题
docs: 文档变更
style: 代码格式 (不影响功能)
refactor: 重构
perf: 性能优化
test: 测试
chore: 构建/工具
```

示例:

```
feat(parsers): 添加自定义日志格式解析器

添加对 .custom 格式的支持，包含:
- 流式解析
- 批量解析
- 类型推断

Fixes #123
```

## 发布

```bash
# 创建 tag
git tag v2.4.0
git push origin v2.4.0

# GitHub Actions 会自动构建和发布
```
