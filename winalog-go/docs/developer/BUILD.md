# Windows 打包编译说明

本文档介绍如何在 Windows 上编译 WinLogAnalyzer-Go 为可执行文件 (exe)。

## 前置要求

### 1. 安装 Go

下载并安装 Go 1.22 或更高版本: https://go.dev/dl/

### 2. 安装 Git

下载并安装 Git: https://git-scm.com/download/win

## 编译方式

### 方式一: PowerShell 脚本 (推荐)

```powershell
cd C:\path\to\winalog-go

# 编译默认版本 (amd64)
.\scripts\build.ps1

# 编译 32 位版本
.\scripts\build.ps1 -Target 386

# 编译 ARM64 版本
.\scripts\build.ps1 -Target arm64

# 编译并清理旧文件
.\scripts\build.ps1 -Clean
```

### 方式二: 批处理文件

```cmd
cd C:\path\to\winalog-go\scripts
build.bat          # 编译 amd64
build.bat 386      # 编译 32 位
build.bat arm64    # 编译 ARM64
build.bat clean    # 清理
```

### 方式三: Makefile

需要安装 Make (如通过 Git Bash 或 MSYS2):

```bash
cd /c/path/to/winalog-go
make build-win
make build-all
```

### 方式四: 直接使用 Go 命令

```cmd
cd C:\path\to\winalog-go

# 编译 amd64
go build -ldflags="-s -w" -o dist/winalog.exe ./cmd/winalog
```

## 输出文件

| 路径 | 说明 |
|------|------|
| `dist\winalog-amd64.exe` | PowerShell 脚本默认输出 |
| `dist\winalog-386.exe` | 32 位 Windows |
| `dist\winalog-arm64.exe` | ARM64 Windows |

## 验证编译结果

```powershell
# 查看文件
Get-ChildItem dist\

# 检查是否为有效 Windows 可执行文件
$bytes = [System.IO.File]::ReadAllBytes("dist\winalog-amd64.exe")[0..1]
if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
    Write-Host "Valid Windows executable"
}

# 运行测试
go run .\cmd\winalog\main.go --help
```

## 常见问题

### Q: 编译很慢

首次编译需要下载依赖，之后会缓存。清理缓存后重新编译:

```powershell
go clean -cache
.\scripts\build.ps1
```

### Q: 如何编译 debug 版本?

```powershell
go build -o dist/winalog-debug.exe ./cmd/winalog
```

## 编译参数说明

| 参数 | 说明 |
|------|------|
| `-ldflags="-s -w"` | 去除符号表和调试信息，减小文件体积 |
| `GOOS=windows` | 目标操作系统 |
| `GOARCH=amd64` | 目标架构 |
