# WinLogAnalyzer-Go

[![Version](https://img.shields.io/badge/version-v2.5.0-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)]()

**Windows 安全取证与日志分析工具**

WinLogAnalyzer-Go 是一个高性能的 Windows 安全取证与日志分析工具，使用 Go 语言开发。支持 EVTX/ETL/CSV/IIS 等多种日志格式解析，内置 60+ 安全检测规则，提供实时告警、关联分析、取证导出等完整功能。

---

## 🚀 快速开始

### 1. 下载

| 平台 | 文件 | 大小 | SHA256 |
|------|------|------|--------|
| Windows x64 | `winalog-windows-amd64.exe` | 38MB | (运行后查看) |
| Linux x64 | `winalog-linux-amd64` | 37MB | (运行后查看) |

### 2. 启动服务

```bash
# Windows
.\winalog-windows-amd64.exe serve

# Linux
./winalog-linux-amd64 serve

# 访问 Web UI
# http://127.0.0.1:8080
```

### 3. 导入日志

```bash
# 导入 EVTX 文件
.\winalog-windows-amd64.exe import security.evtx

# 一键采集所有日志源
.\winalog-windows-amd64.exe collect --output evidence.zip

# 搜索事件
.\winalog-windows-amd64.exe search --event-id 4624
```

---

## ✨ 核心特性

| 特性 | 说明 | 状态 |
|------|------|------|
| 🔒 **安全优先** | 默认仅本地访问，SQL 注入防护，CORS 限制 | ✅ |
| ⚡ **高性能** | 150 万条/分钟 EVTX 解析，并发处理 | ✅ |
| 🎯 **60+ 检测规则** | MITRE ATT&CK 映射，暴力破解/登录/Kerberos 等 | ✅ |
| 🖥️ **Web UI** | React 前端，实时仪表板，图表可视化 | ✅ |
| 📊 **关联分析** | 多事件关联，攻击链检测 | ✅ |
| 🔍 **全文搜索** | 关键字/正则/事件 ID/时间范围过滤 | ✅ |
| 📁 **取证导出** | 文件哈希，签名验证，证据链管理 | ✅ |
| 🧩 **持久化检测** | 30+ Windows 持久化技术检测 | ✅ |
| 👤 **UEBA** | 用户行为异常分析 | ✅ |
| 📝 **报告生成** | HTML/JSON/PDF 格式综合报告 | ✅ |

---

## 📖 文档

### 用户文档
- [📚 用户指南](docs/user/USER_GUIDE.md) - 详细使用说明
- [⚡ 快速开始](docs/user/QUICKSTART.md) - 5 分钟上手
- [❓ 常见问题](docs/user/FAQ.md) - FAQ

### 开发文档
- [🏗️ 架构设计](docs/developer/ARCHITECTURE.md) - 系统架构
- [📡 API 参考](docs/developer/API.md) - REST API 文档
- [🔧 构建指南](docs/developer/BUILD.md) - 编译和部署
- [🛡️ 安全开发](docs/developer/SECURITY_GUIDE.md) - 安全最佳实践

### 参考资料
- [📋 功能清单](docs/reference/FEATURES.md) - 完整功能列表
- [📐 设计决策](docs/reference/design.md) - 核心设计文档
- [📝 事件 ID 参考](docs/guides/WINDOWS_EVENT_ID.md) - Windows 事件 ID
- [📝 事件 ID 补充](docs/guides/WINDOWS_EVENT_ID_SUPPLEMENT.md) - 补充事件 ID

---

## 🛡️ 安全说明

### 默认安全配置

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| **监听地址** | `127.0.0.1` | 仅本地访问，不暴露到公网 |
| **CORS** | `localhost:8080` | 仅允许本地来源 |
| **SQL 注入防护** | ✅ 已启用 | 禁止注释、UNION、文件操作 |
| **查询超时** | 5 分钟 | 防止复杂查询卡死服务 |
| **连接池** | 10 个连接 | 防止资源耗尽 |

### 如需外部访问

⚠️ **警告**: 仅在受信任的网络环境中开放外部访问！

1. **修改配置文件** (`config.yaml`):
```yaml
api:
  host: "0.0.0.0"  # 谨慎使用！
  port: 8080
  cors:
    allowed_origins:
      - "https://your-domain.com"
```

2. **添加防火墙规则**:
```bash
# Linux (UFW)
sudo ufw allow 8080/tcp

# Windows (PowerShell)
New-NetFirewallRule -DisplayName "WinLogAnalyzer" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow
```

3. **使用反向代理** (推荐):
```nginx
# Nginx 配置
server {
    listen 443 ssl;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 📦 CLI 命令

| 命令 | 说明 | 示例 |
|------|------|------|
| `import` | 批量导入日志文件 | `winalog import security.evtx` |
| `search` | 全文搜索事件 | `winalog search --event-id 4624` |
| `collect` | 一键采集所有日志源 | `winalog collect --output evidence.zip` |
| `alert` | 告警管理 | `winalog alert list` |
| `analyze` | 专用分析器 | `winalog analyze bruteforce` |
| `report` | 报告生成 | `winalog report --format html` |
| `dashboard` | 仪表板统计 | `winalog dashboard` |
| `config` | 配置管理 | `winalog config show` |
| `persistence` | Windows 持久化检测 | `winalog persistence detect` |
| `system` | 系统信息 | `winalog system processes` |
| `ueba` | 用户行为分析 | `winalog ueba analyze` |
| `whitelist` | 白名单管理 | `winalog whitelist list` |
| `db` | 数据库管理 | `winalog db status` |
| `tui` | 终端界面 | `winalog tui` |
| `serve` | HTTP API + Web UI | `winalog serve --port 8080` |

---

## 🔧 开发

### 环境要求

- Go 1.22+
- Node.js 18+ (用于 Web UI)
- Windows (用于实际运行和测试)

### 构建

```bash
# 构建当前平台
make build

# 交叉编译
make build-windows  # Windows x64
make build-linux    # Linux x64

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
│   └── commands/          # 19 个子命令
├── internal/              # 内部包
│   ├── engine/           # 核心引擎
│   ├── parsers/          # 日志解析器
│   ├── storage/          # SQLite 存储
│   ├── alerts/           # 告警引擎
│   ├── api/              # HTTP API
│   └── ...               # 其他模块
├── internal/gui/          # React Web UI
└── docs/                  # 文档
    ├── user/             # 用户文档
    ├── developer/        # 开发文档
    └── reference/        # 参考资料
```

---

## 📝 更新日志

见 [CHANGELOG.md](CHANGELOG.md)

### 最新版本 (v2.5.0 - 2026-05-09)

**安全加固**:
- ✅ 默认监听 `127.0.0.1` (不再暴露到公网)
- ✅ CORS 限制为 localhost
- ✅ SQL 注入防护 (禁止注释、UNION、文件操作)
- ✅ 查询超时保护 (5 分钟)

**Bug 修复**:
- ✅ Dashboard 崩溃修复
- ✅ SQL 查询假阳性修复
- ✅ URL 参数编码修复
- ✅ localStorage 异常处理

**性能优化**:
- ✅ 连接池配置
- ✅ 静态资源相对路径

---

## 🤝 贡献

欢迎贡献代码、报告问题或提出建议！

详见 [CONTRIBUTING.md](CONTRIBUTING.md)

### 快速贡献

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

---

## 📄 许可证

MIT License

---

## 📧 联系方式

- **项目主页**: https://github.com/kkkdddd-start/winalog-go-fix-
- **问题反馈**: https://github.com/kkkdddd-start/winalog-go-fix-/issues
- **文档**: https://github.com/kkkdddd-start/winalog-go-fix-/tree/main/docs

---

**版本**: v2.5.0  
**最后更新**: 2026-05-09  
**许可证**: MIT
