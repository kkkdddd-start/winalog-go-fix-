# Changelog

所有重要变更将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/)，
版本号遵循 [语义化版本](https://semver.org/)。

## [Unreleased] - 2026-05-09

### 🔒 Security

- 默认监听地址改为 `127.0.0.1` (之前是 `0.0.0.0`)
- CORS 默认仅允许 `http://127.0.0.1:8080` 和 `http://localhost:8080`
- SQL 注入防护增强：
  - 禁止 SQL 注释 (`--`, `/*`, `#`)
  - 禁止 UNION 联合查询注入
  - 禁止文件读写操作 (`INTO OUTFILE`, `LOAD_FILE`)
- 查询超时保护 (5 分钟)
- 数据库连接池配置 (MaxOpenConns: 10, MaxIdleConns: 2)

### 🐛 Bug Fixes

- 修复 Dashboard 页面在 `timeline.entries` 为空时崩溃
  - 添加可选链操作符和空数组回退
- 修复 SQL 查询验证误杀合法查询
  - 移除黑名单关键词检查 (DELETE, DROP 等)
  - 改用白名单机制 (仅允许 SELECT/EXPLAIN/WITH 开头)
- 修复 URL 参数未编码导致特殊字符请求失败
  - alertsAPI.list: severity 参数编码
  - systemAPI.getNetwork: protocol 参数编码
  - forensicsAPI: path 和 expected 参数编码
- 修复 localStorage 在隐私模式下抛异常
  - 创建统一的 storage.ts 工具类
  - 隐私模式自动降级到内存存储

### ⚡ Performance

- 数据库连接池配置
  - `SetMaxOpenConns(10)` - 最大 10 个连接
  - `SetMaxIdleConns(2)` - 空闲时保留 2 个
  - `SetConnMaxLifetime(time.Hour)` - 连接存活 1 小时
- 静态资源使用相对路径
  - 支持部署到子目录 (如 `example.com/winalog/`)
  - 不再使用绝对路径 `/assets/`
- 查询超时机制
  - 防止复杂 SQL 卡死服务
  - 超时时间：5 分钟

### 📦 Build

- 全平台交叉编译支持（6 个目标）：
  - Linux: x64 / arm64
  - macOS: x64 (Intel) / arm64 (Apple Silicon)
  - Windows: x64 / arm64
- 交叉编译修复：10 个 `_linux.go` 文件重命名为 `_nix.go`
  - 修复 Go 文件名隐式 `_linux` GOOS 约束导致无法编译 macOS 版本
  - 文件均含 `//go:build !windows` 标签，Windows 编译不受影响

### 🛡️ Rules

- 误报削减：402 万事件全量分析，告警从 52 条降至 15 条
  - **admin-login-unusual**: 删除宽泛的 `Admin` 子串匹配（误匹配 RestrictedAdminMode），仅保留 `Administrator` 精确匹配
  - **kerberoasting**: 排除机器账户 `$@`（120 位随机密码无法破解），仅匹配 RC4 加密类型 0x0017/0x0018
  - **dll-search-order-hijacking**: 添加 6 条操作系统/安全软件正常操作白名单
  - **service-installation**: 添加 20 条 Defender/VMware/火绒/打印机/浏览器等驱动白名单
  - **mass-privilege-assignment**: 排除 SYSTEM 账户，阈值 5→20，时间窗口 10→30min，消息添加研判提示
  - **mimikatz-suspect**: 排除 tasklist/procexp 进程名（正常进程查看工具）
  - **tunneling-tool-detected**: 排除 MicrosoftEdgeUpdate（Edge 浏览器更新）
- LogNames 过滤修复：46 条规则添加 LogNames，10,093→1,547 告警
- 模板变量渲染修复：`getMessageValue()` 消息回退解析，`BuildMessage` 14 个模板变量
- 阈值 fired 标记修复：`eventCountEntry` 添加 `fired` 布尔字段，防止重复触发

### 🖥️ Frontend

- 新增 `false_positive_notes` 字段：规则详情弹窗展示白名单/误报排除说明
- 7 条已修改规则均编写了对应的白名单说明
- 数据流：`definitions.go` → `GetFalsePositiveNotes()` → API JSON → `Rules.tsx` 详情弹窗

### 📦 Build

- 文档结构化重组
  - 用户文档：`docs/user/`
  - 开发文档：`docs/developer/`
  - 参考资料：`docs/reference/`
  - 归档内容：`docs/_archive/`
- 新增文档：
  - `CHANGELOG.md` - 版本变更日志
  - `SECURITY.md` - 安全策略说明
  - `CONTRIBUTING.md` - 贡献指南
- 更新文档：
  - `README.md` - 完全重写，反映最新功能
  - `USER_GUIDE.md` - 更新安全配置说明
  - `API.md` - 更新 SQL 防护和超时机制

---

## [v2.4.0] - 2026-04-17

### Added

- 多机横向移动分析
- 事件 ID 知识库扩充 (20+ 新增事件 ID)
- 知识库页面深度导出支持
- PowerShell 日期解析优化
- 分析页面使用指南面板

### Changed

- 导出 API 从 GET 改为 POST (安全加固)
- 日志视图布局优化 (可展开消息)
- UEBA 基线加载竞态条件修复
- 关联引擎递归切片别名问题修复
- 多机拓扑 IP 到主机名映射

### Fixed

- 修复 UEBA LoadBaselines 竞态条件
- 修复关联引擎递归切片别名问题
- 修复 PowerShell 日期解析错误
- 修复多机分析 IP-主机名映射

---

## [v2.3.0] - 2026-04-13

### Added

- 告警引擎完整性增强
  - 添加 evaluator/stats/trend/upgrade/suppress 5 个模块
- API Handler 详细设计
- Alert 结构添加 FalsePositive 字段
- 扩展错误码定义
- 配置结构完善 (AlertConfig, SearchConfig 等)

### Changed

- 统一使用 `modernc.org/sqlite` (Pure Go, 无 CGO)
- 目录结构完整性增强
  - 添加 dll_info.go, user_info.go, stats.go 等
- 章节编号重排 (9-19 章)

### Fixed

- SQL 注入漏洞 (events.go:127,131)
- 正则表达式 DoS 风险 (evaluator.go:293)
- Pipeline Pacer Goroutine 泄漏
- Evaluator 清理 Goroutine 无停止机制
- 代码重复 (scanEvent 与 scanEventFromRows)

---

## [v2.2.0] - 2026-04-10

### Added

- 解析器自注册机制
- 规则验证增强
- 模块对比文档 (Python vs Go)

### Changed

- 从 CGO SQLite 切换到 Pure Go SQLite
- 优化内存管理

---

## [v2.1.0] - 2026-04-05

### Added

- Web UI 基础框架
- React + Vite + TypeScript
- 基础仪表板页面

### Changed

- TUI 框架从 Cocoa 切换到 Bubble Tea

---

## [v2.0.0] - 2026-03-28

### Added

- Go 语言完整重写
- 高性能 EVTX 解析器
- SQLite WAL 模式存储
- 告警引擎基础框架
- CLI 命令集 (Cobra)

### Changed

- 从 Python 迁移到 Go
- 架构重新设计

---

## [v1.4.7] - 2026-03-15

### Added

- Python 版本最终版本
- 持久化检测模块
- UEBA 基础功能

### Deprecated

- Python 版本停止维护，推荐使用 Go 版本

---

## 版本说明

### v2.5.0 (当前版本)

**主题**: 安全加固与用户体验优化

**关键改进**:
- 默认安全配置 (127.0.0.1, CORS 限制)
- SQL 注入全面防护
- 查询超时和连接池保护
- 前端稳定性增强

**适用场景**: 生产环境部署

### v2.4.0

**主题**: 功能完整性

**关键改进**:
- 多机分析增强
- 事件 ID 知识库扩充
- UEBA 和关联引擎优化

### v2.3.0

**主题**: 核心架构完善

**关键改进**:
- 告警引擎 7 个模块完整实现
- API Handler 详细设计
- 数据类型统一

### v2.2.0

**主题**: 依赖优化

**关键改进**:
- Pure Go SQLite (无 CGO)
- 解析器自注册机制

### v2.0.0

**主题**: Go 重写

**关键改进**:
- 完整 Go 语言重写
- 性能提升 10 倍+
- 单二进制部署

---

## 迁移指南

### v2.4.x → v2.5.0

**破坏性变更**:
- 默认监听地址从 `0.0.0.0` 改为 `127.0.0.1`
- CORS 默认不再允许所有来源

**迁移步骤**:
1. 如需外部访问，修改 `config.yaml`:
   ```yaml
   api:
     host: "0.0.0.0"
     cors:
       allowed_origins:
         - "https://your-domain.com"
   ```
2. 更新防火墙规则
3. 检查是否有 SQL 查询使用注释 (需要移除)

### v2.3.x → v2.4.x

**无破坏性变更**

### v2.2.x → v2.3.x

**配置变更**:
- 数据库驱动从 `github.com/mattn/go-sqlite3` 改为 `modernc.org/sqlite`
- 无需修改配置，自动兼容

---

## 已知问题

### v2.5.0

- [ ] TUI 界面暂不支持 Windows 终端
- [ ] PDF 报告生成需要外部依赖

### 已解决

- [x] Dashboard 崩溃 (v2.5.0)
- [x] SQL 假阳性 (v2.5.0)
- [x] URL 编码 (v2.5.0)
- [x] localStorage 异常 (v2.5.0)

---

**文档维护**: 每次发布新版本时更新此文件  
**最后更新**: 2026-05-09
