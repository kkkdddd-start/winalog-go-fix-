# WinLogAnalyzer-Go 文档导航

欢迎使用 WinLogAnalyzer-Go 文档！本文档库包含用户指南、开发文档和参考资料。

---

## 📖 按读者分类

### 👤 用户文档

面向**终端用户**，包含安装、配置和使用说明。

| 文档 | 说明 | 位置 |
|------|------|------|
| 🚀 **快速开始** | 5 分钟上手指南 | [docs/user/QUICKSTART.md](user/QUICKSTART.md) |
| 📚 **用户指南** | 完整使用说明 | [docs/user/USER_GUIDE.md](user/USER_GUIDE.md) |
| ❓ **常见问题** | FAQ | [docs/user/FAQ.md](user/FAQ.md) |
| 🛡️ **安全配置** | 安全相关说明 | [SECURITY.md](../SECURITY.md) |

### 👨‍💻 开发文档

面向**开发者**，包含架构、API 和构建指南。

| 文档 | 说明 | 位置 |
|------|------|------|
| 🏗️ **架构设计** | 系统架构和模块设计 | [docs/developer/ARCHITECTURE.md](developer/ARCHITECTURE.md) |
| 📡 **API 参考** | REST API 完整文档 | [docs/developer/API.md](developer/API.md) |
| 🔧 **构建指南** | 编译和部署说明 | [docs/developer/BUILD.md](developer/BUILD.md) |
| 🛡️ **安全开发** | 安全最佳实践 | [docs/developer/SECURITY_GUIDE.md](developer/SECURITY_GUIDE.md) |
| 📝 **贡献指南** | 如何贡献代码 | [CONTRIBUTING.md](../CONTRIBUTING.md) |

### 📋 参考资料

面向**所有读者**，包含功能清单和技术参考。

| 文档 | 说明 | 位置 |
|------|------|------|
| 📋 **功能清单** | 完整功能列表 | [docs/reference/FEATURES.md](reference/FEATURES.md) |
| 📐 **设计决策** | 核心设计文档 | [docs/reference/design.md](reference/design.md) |
| 📝 **事件 ID 参考** | Windows 事件 ID 大全 | [docs/guides/WINDOWS_EVENT_ID.md](guides/WINDOWS_EVENT_ID.md) |
| 📝 **事件 ID 补充** | 补充事件 ID | [docs/guides/WINDOWS_EVENT_ID_SUPPLEMENT.md](guides/WINDOWS_EVENT_ID_SUPPLEMENT.md) |

---

## 🎯 按任务分类

### 我想安装和启动

1. 阅读 [快速开始](user/QUICKSTART.md)
2. 下载对应平台的二进制文件
3. 运行 `winalog serve`
4. 访问 http://127.0.0.1:8080

### 我想导入日志

1. 阅读 [用户指南 - 日志导入](user/USER_GUIDE.md#日志导入)
2. 使用 `winalog import security.evtx`
3. 或使用 Web UI 导入

### 我想搜索事件

1. 阅读 [用户指南 - 事件搜索](user/USER_GUIDE.md#事件搜索)
2. 使用 `winalog search --event-id 4624`
3. 或使用 Web UI 搜索功能

### 我想查看告警

1. 阅读 [用户指南 - 告警管理](user/USER_GUIDE.md#告警管理)
2. 使用 `winalog alert list`
3. 或使用 Web UI 仪表板

### 我想开发新功能

1. 阅读 [架构设计](developer/ARCHITECTURE.md)
2. 阅读 [API 参考](developer/API.md)
3. 阅读 [贡献指南](../CONTRIBUTING.md)
4. 创建功能分支并开发

### 我想排查问题

1. 阅读 [常见问题](user/FAQ.md)
2. 查看日志文件 `logs/winalog.log`
3. 运行 `winalog db status` 检查数据库

---

## 📚 文档结构

```
docs/
├── README.md                      # 本文档 (导航)
│
├── user/                          # 用户文档
│   ├── QUICKSTART.md              # 快速开始
│   ├── USER_GUIDE.md              # 用户指南
│   └── FAQ.md                     # 常见问题
│
├── developer/                     # 开发文档
│   ├── ARCHITECTURE.md            # 架构设计
│   ├── API.md                     # API 参考
│   ├── BUILD.md                   # 构建指南
│   └── SECURITY_GUIDE.md          # 安全开发
│
├── reference/                     # 参考资料
│   ├── FEATURES.md                # 功能清单
│   ├── design.md                  # 设计决策
│   └── requirements.md            # 需求文档
│
├── guides/                        # 指南
│   ├── WINDOWS_EVENT_ID.md        # Windows 事件 ID
│   └── WINDOWS_EVENT_ID_SUPPLEMENT.md  # 补充事件 ID
│
├── cli/                           # CLI 文档
│   └── COMMANDS.md                # CLI 命令说明
│
└── _archive/                      # 归档内容 (历史参考)
    ├── plans/                     # 历史计划文档
    ├── reports/                   # 历史测试报告
    └── modules-zh/                # 中文模块文档
```

---

## 🔄 文档更新

### 更新频率

- **用户文档**: 每次功能更新时
- **开发文档**: 架构变更时
- **CHANGELOG**: 每次发布时

### 如何贡献文档

1. 找到相关文档文件
2. 进行修改
3. 提交 PR，说明更改内容
4. 更新 `CHANGELOG.md` (如适用)

### 文档版本

| 版本 | 日期 | 说明 |
|------|------|------|
| v2.5.0 | 2026-05-09 | 当前版本，安全加固 |
| v2.4.0 | 2026-04-17 | 功能完整性增强 |
| v2.3.0 | 2026-04-13 | 核心架构完善 |

---

## 📞 反馈

如发现文档错误或有改进建议：

1. 提交 [GitHub Issue](https://github.com/kkkdddd-start/winalog-go-fix-/issues)
2. 标注为 `documentation` 标签
3. 说明具体问题和建议

---

## 🔗 相关链接

- **项目主页**: https://github.com/kkkdddd-start/winalog-go-fix-
- **更新日志**: [CHANGELOG.md](../CHANGELOG.md)
- **安全策略**: [SECURITY.md](../SECURITY.md)
- **贡献指南**: [CONTRIBUTING.md](../CONTRIBUTING.md)

---

**最后更新**: 2026-05-09  
**文档版本**: v2.5.0
