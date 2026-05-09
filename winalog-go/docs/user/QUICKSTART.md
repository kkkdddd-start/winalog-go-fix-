# 快速开始

5 分钟快速上手 WinLogAnalyzer-Go。

---

## 🎯 前提条件

- Windows 10/11 或 Linux (推荐 Ubuntu 22.04+)
- 无需安装任何依赖 (单二进制文件)

---

## 📦 步骤 1: 下载

### Windows

```powershell
# 下载 Windows 版本
Invoke-WebRequest -Uri "https://github.com/kkkdddd-start/winalog-go-fix-/releases/download/v2.5.0/winalog-windows-amd64.exe" -OutFile "winalog.exe"
```

### Linux

```bash
# 下载 Linux 版本
wget https://github.com/kkkdddd-start/winalog-go-fix-/releases/download/v2.5.0/winalog-linux-amd64 -O winalog
chmod +x winalog
```

---

## 🚀 步骤 2: 启动服务

### Windows

```powershell
.\winalog.exe serve
```

### Linux

```bash
./winalog serve
```

你将看到：

```
[INFO] Starting server on http://127.0.0.1:8080
[INFO] Web UI available at http://127.0.0.1:8080
[INFO] Press Ctrl+C to stop
```

---

## 🌐 步骤 3: 访问 Web UI

打开浏览器访问：

```
http://127.0.0.1:8080
```

你将看到仪表板页面。

---

## 📥 步骤 4: 导入日志

### 方法 1: Web UI 导入

1. 点击左侧菜单 **日志导入**
2. 选择 `.evtx` 文件
3. 点击 **导入**
4. 等待导入完成

### 方法 2: CLI 导入

```bash
# Windows
.\winalog.exe import security.evtx

# Linux
./winalog import security.evtx
```

---

## 🔍 步骤 5: 搜索事件

### 按事件 ID 搜索

**Web UI**:
1. 点击左侧菜单 **事件浏览**
2. 在筛选器中输入 `4624`
3. 点击 **搜索**

**CLI**:
```bash
.\winalog.exe search --event-id 4624
```

### 按关键字搜索

**Web UI**:
1. 在搜索框中输入关键字 (如 `logon`)
2. 点击 **搜索**

**CLI**:
```bash
.\winalog.exe search --keyword "logon"
```

---

## 🔔 步骤 6: 查看告警

### 仪表板

1. 点击左侧菜单 **仪表板**
2. 查看告警统计
3. 查看事件趋势图

### 告警列表

1. 点击左侧菜单 **告警管理**
2. 查看未解决的告警
3. 点击告警查看详情

### 解决告警

1. 在告警列表中选择告警
2. 点击 **解决** 按钮
3. 输入备注
4. 点击 **确认**

---

## ⏭️ 下一步

恭喜！你已经完成快速入门。

接下来可以：

- 📚 阅读 [完整用户指南](USER_GUIDE.md) 了解更多功能
- 🔍 探索 [事件搜索高级用法](USER_GUIDE.md#事件搜索)
- 🛡️ 了解 [安全配置选项](../SECURITY.md)
- 📊 学习 [仪表板使用方法](USER_GUIDE.md#仪表板)

---

## ❓ 常见问题

### Q: 无法访问 http://127.0.0.1:8080？

**A**: 检查服务是否启动：

```bash
# Windows
Get-Process winalog

# Linux
ps aux | grep winalog
```

### Q: 导入速度慢？

**A**: 大文件导入需要时间，查看进度：

```bash
.\winalog.exe db status
```

### Q: 如何停止服务？

**A**: 按 `Ctrl+C` 停止服务。

### Q: 日志文件在哪里？

**A**: `logs/winalog.log`

---

## 🆘 需要帮助？

- 📖 阅读 [用户指南](USER_GUIDE.md)
- ❓ 查看 [常见问题](FAQ.md)
- 🐛 提交 [Issue](https://github.com/kkkdddd-start/winalog-go-fix-/issues)

---

**最后更新**: 2026-05-09  
**版本**: v2.5.0
