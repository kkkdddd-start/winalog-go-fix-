# 跨平台编译说明

本文档介绍如何将 winalog-go 编译为各平台的可执行文件。

## 前置要求

| 工具 | 版本要求 | 安装方式 |
|------|---------|---------|
| Go | 1.22+ | https://go.dev/dl/ |
| Git | 任意版本 | https://git-scm.com/ |
| Make | 任意版本 | Linux: `apt install make`, macOS: 自带, Windows: Git Bash/MSYS2 |

## 编译方式

### 方式一: Makefile (推荐)

```bash
cd winalog-go

# 查看所有编译目标
make help

# 编译当前平台
make build

# 全平台交叉编译（6 个目标）
make build-all
```

### 方式二: Go 交叉编译

Go 支持通过 `GOOS` 和 `GOARCH` 环境变量交叉编译：

```bash
cd winalog-go

# Linux x64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/winalog-linux-amd64 ./cmd/winalog

# Linux arm64
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/winalog-linux-arm64 ./cmd/winalog

# macOS x64 (Intel)
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/winalog-darwin-amd64 ./cmd/winalog

# macOS arm64 (Apple Silicon)
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/winalog-darwin-arm64 ./cmd/winalog

# Windows x64
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/winalog-windows-amd64.exe ./cmd/winalog

# Windows arm64
GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/winalog-windows-arm64.exe ./cmd/winalog
```

### 方式三: Windows PowerShell

```powershell
cd C:\path\to\winalog-go

# 编译 Windows x64
.\scripts\build.ps1

# 编译其他 Windows 架构
.\scripts\build.ps1 -Target arm64

# 编译并清理旧文件
.\scripts\build.ps1 -Clean
```

## 输出文件

| 文件 | 目标平台 | 架构 |
|------|---------|------|
| `dist/winalog-linux-amd64` | Linux | x86_64 |
| `dist/winalog-linux-arm64` | Linux | ARM64 |
| `dist/winalog-darwin-amd64` | macOS | x86_64 (Intel) |
| `dist/winalog-darwin-arm64` | macOS | ARM64 (Apple Silicon) |
| `dist/winalog-windows-amd64.exe` | Windows | x86_64 |
| `dist/winalog-windows-arm64.exe` | Windows | ARM64 |

## 编译参数说明

| 参数 | 说明 |
|------|------|
| `GOOS` | 目标操作系统: linux, darwin, windows |
| `GOARCH` | 目标架构: amd64, arm64 |
| `CGO_ENABLED=0` | 禁用 CGO，生成纯静态二进制 |
| `-ldflags="-s -w"` | 去除符号表和调试信息，减小文件体积（约 35-38MB） |

## 注意事项

- `CGO_ENABLED=0` 确保纯 Go 编译，无需系统 C 编译器
- 某些平台特定功能（实时监控、取证采集）仅 Windows 版本可用
- 非 Windows 平台提供存根实现（`_nix.go` 文件），`//go:build !windows` 标签控制
- 交叉编译使用 `_nix.go` 而非 `_linux.go` 文件名，避免 Go 隐式 GOOS 约束限制 macOS 编译

## 验证编译结果

```bash
# 检查文件大小
ls -lh dist/

# Linux/macOS 上检查可执行文件格式
file dist/winalog-linux-amd64

# 查看帮助
./dist/winalog-linux-amd64 --help

# 运行测试
go test ./...
```

## 常见问题

### Q: 编译很慢

首次编译需要下载依赖，之后会缓存。清理缓存后重新编译:

```bash
go clean -cache
make build
```

### Q: 如何编译 debug 版本?

去掉 `-ldflags="-s -w"` 参数保留调试符号:

```bash
go build -o dist/winalog-debug ./cmd/winalog
```

### Q: 交叉编译 mac 版本报错

确保使用了 `_nix.go` 文件名而非 `_linux.go`。Go 会将文件名中的 `_linux` 后缀解释为隐式 `linux` GOOS 约束，导致无法编译 macOS 版本。

### Q: 编译时提示 "build constraints exclude all Go files"

检查是否设置了 `GOOS=darwin` 而目标包中有 `_linux.go` 文件。将此类文件重命名为 `_nix.go` 或添加 `//go:build !windows` 标签。
