# WinLogAnalyzer-Go 用户手册

**版本**: v2.4.0  
**更新日期**: 2026-04-17

---

## 目录

1. [概述](#1-概述)
2. [安装与配置](#2-安装与配置)
3. [快速开始](#3-快速开始)
4. [日志导入](#4-日志导入)
5. [事件搜索](#5-事件搜索)
6. [告警管理](#6-告警管理)
7. [威胁分析](#7-威胁分析)
8. [实时监控](#8-实时监控)
9. [取证功能](#9-取证功能)
10. [持久化检测](#10-持久化检测)
11. [报告生成](#11-报告生成)
12. [时间线分析](#12-时间线分析)
13. [多机分析](#13-多机分析)
14. [UEBA用户行为分析](#14-ueba用户行为分析)
15. [TUI终端界面](#15-tui终端界面)
16. [API服务](#16-api服务)
17. [配置参考](#17-配置参考)

---

## 1. 概述

WinLogAnalyzer-Go 是一个高性能的 Windows 安全取证与日志分析工具，使用 Go 语言开发，支持：

| 特性 | 说明 |
|------|------|
| **多格式解析** | EVTX, ETL, CSV, IIS, Sysmon |
| **实时监控** | Windows Event Log 实时订阅 |
| **告警检测** | 60+ 内置规则，MITRE ATT&CK 映射 |
| **关联分析** | 多事件关联，攻击链检测 |
| **取证功能** | 文件哈希，签名验证，证据链 |
| **持久化检测** | 30+ Windows 持久化技术检测 |
| **用户行为分析** | UEBA 异常检测 |
| **报告导出** | HTML, JSON, CSV, PDF |

### 性能指标

| 指标 | 目标 |
|------|------|
| EVTX 解析速度 | ≥150万条/分钟 |
| 内存占用 (1GB EVTX) | ≤200MB |
| 启动时间 | ≤100ms |

---

## 2. 安装与配置

### 2.1 系统要求

- **操作系统**: Windows 10/11, Windows Server 2016/2019/2022, Linux (仅部分功能)
- **Go 版本**: 1.22+
- **内存**: 最少 4GB (推荐 8GB+)
- **磁盘**: 最少 1GB 可用空间

### 2.2 下载与安装

```bash
# 从 GitHub Releases 下载
wget https://github.com/kkkdddd-start/winalog-go/releases/latest/download/winalog-linux-amd64.tar.gz
tar -xzf winalog-linux-amd64.tar.gz

# 或者从源码编译
git clone https://github.com/kkkdddd-start/winalog-go.git
cd winalog-go/winalog-go
make build
```

### 2.3 初始配置

```bash
# 创建默认配置
winalog config init

# 查看配置目录
winalog info
```

配置文件位于 `~/.winalog/config.yaml`：

```yaml
database:
  path: "~/.winalog/winalog.db"
  wal_mode: true

api:
  host: "127.0.0.1"
  port: 8080

log:
  level: "info"
  format: "json"
```

---

## 3. 快速开始

### 3.1 导入事件日志

```bash
# 导入单个 EVTX 文件
winalog import Security.evtx

# 导入多个文件
winalog import /var/logs/*.evtx

# 指定日志名称
winalog import --log-name "CustomLog" custom.evtx

# 并行导入（4个worker）
winalog import --workers 8 /var/logs/

# 导入后触发告警分析
winalog import --alert-on-import security.evtx
```

### 3.2 搜索事件

```bash
# 基本搜索
winalog search --keywords "登录失败"

# 多关键词 AND 搜索
winalog search --keywords "登录失败" "账户名" --keyword-mode AND

# 搜索特定事件ID
winalog search --event-id 4625 --event-id 4624

# 按级别过滤 (1=Critical, 2=Error, 3=Warning, 4=Info)
winalog search --level 1 --level 2

# 时间范围
winalog search --start-time "2026-04-01T00:00:00Z" --end-time "2026-04-17T23:59:59Z"

# 分页输出
winalog search --keywords "登录" --page 1 --page-size 50

# 输出到文件
winalog search --keywords "恶意" --output results.json --format json
```

### 3.3 告警管理

```bash
# 查看所有告警
winalog alert list

# 按严重性过滤
winalog alert list --severity critical
winalog alert list --severity high

# 查看告警详情
winalog alert show <alert_id>

# 标记为已解决
winalog alert resolve <alert_id>

# 标记为误报
winalog alert false-positive <alert_id>

# 导出告警
winalog alert export alerts.json

# 查看统计
winalog alert stats
```

### 3.4 生成报告

```bash
# 生成安全摘要报告
winalog report generate security_summary --format html --output report.html

# 生成告警报告
winalog report generate alert_report --format html

# 生成时间线报告
winalog report generate timeline_report --format json

# 指定时间范围
winalog report generate --time-range 7d
```

---

## 4. 日志导入

### 4.1 支持的格式

| 格式 | 文件扩展名 | 说明 |
|------|-----------|------|
| Windows Event Log | `.evtx` | Windows 事件日志文件 |
| Event Trace Log | `.etl` | Windows ETW 跟踪日志 |
| CSV/LOG | `.csv`, `.log`, `.txt` | 自定义分隔符格式 |
| IIS W3C Extended | `.log` | IIS 日志 |
| Sysmon | `.evtx` | Sysmon 事件日志 |

### 4.2 导入命令详解

```bash
winalog import [flags] <path> [paths...]
```

**主要参数**:

| 参数 | 说明 |
|------|------|
| `<path>` | 要导入的文件或目录路径 |

**主要选项**:

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--log-name` | string | "" | 指定日志名称 |
| `--incremental` | bool | true | 启用增量导入（跳过已导入文件） |
| `--workers` | int | 4 | 并行 worker 数量 |
| `--batch-size` | int | 10000 | 批量插入大小 |
| `--skip-patterns` | string | "" | 跳过的文件模式（逗号分隔） |
| `--alert-on-import` | bool | false | 导入后触发告警分析 |

### 4.3 实际案例

**案例 1: 导入整个 Security 日志目录**

```bash
winalog import --log-name "Security" --workers 8 --batch-size 20000 /mnt/windows/Security/*.evtx
```

**案例 2: 增量导入（跳过已处理文件）**

```bash
winalog import --incremental --log-name "System" /var/logs/system/
```

**案例 3: 导入时排除调试日志**

```bash
winalog import --skip-patterns "Diagnostics,Debug" /mnt/logs/
```

**案例 4: 导入后自动分析**

```bash
winalog import --alert-on-import --workers 4 security.evtx
```

### 4.4 导入进度监控

```bash
# 查看导入状态
winalog status

# 查看数据库状态
winalog db status

# 清理旧导入记录
winalog db clean --before "2026-01-01"
```

---

## 5. 事件搜索

### 5.1 基本搜索

```bash
# 关键词搜索
winalog search --keywords "登录成功"

# 正则表达式搜索
winalog search --regex --keywords "EventID=46\d{2}"

# OR 模式
winalog search --keywords "错误" --keyword-mode OR --keywords "失败"
```

### 5.2 高级过滤

```bash
# 按事件ID
winalog search --event-id 4624 --event-id 4625

# 按级别
winalog search --level 1 --level 2  # Critical + Error

# 按日志名称
winalog search --log-name Security --log-name System

# 按来源
winalog search --source "Microsoft-Windows-Security-Auditing"

# 按用户
winalog search --user "Administrator" --user "SYSTEM"

# 按计算机
winalog search --computer "DC01" --computer "FILE01"
```

### 5.3 时间过滤

```bash
# 最近24小时
winalog search --start-time "2026-04-16T00:00:00Z"

# 指定范围
winalog search --start-time "2026-04-01T00:00:00Z" --end-time "2026-04-17T00:00:00Z"

# 快捷方式
winalog search --hours 24  # 最近24小时
```

### 5.4 输出格式

```bash
# 表格输出（默认）
winalog search --keywords "登录"

# JSON 输出
winalog search --keywords "登录" --format json

# CSV 输出
winalog search --keywords "登录" --format csv

# 分页
winalog search --page 1 --page-size 100

# 排序
winalog search --sort-by timestamp --sort-order desc

# 高亮显示
winalog search --highlight --keywords "失败"

# 输出到文件
winalog search --keywords "恶意" --output results.json
```

### 5.5 实际案例

**案例 1: 查找登录失败事件**

```bash
winalog search \
  --event-id 4625 \
  --level 2 \
  --start-time "2026-04-01T00:00:00Z" \
  --sort-by timestamp \
  --sort-order desc
```

**案例 2: 查找账户创建事件**

```bash
winalog search \
  --event-id 4720 \
  --keywords "Administrator" \
  --output new_admin_accounts.json \
  --format json
```

**案例 3: 查找可疑网络活动**

```bash
winalog search \
  --keywords "远程桌面" \
  --source "Microsoft-Windows-TerminalServices*" \
  --start-time "2026-04-01T00:00:00Z"
```

---

## 6. 告警管理

### 6.1 列出告警

```bash
# 所有告警
winalog alert list

# 按严重性过滤
winalog alert list --severity critical
winalog alert list --severity high
winalog alert list --severity medium
winalog alert list --severity low

# 仅未解决
winalog alert list --resolved false

# 按规则名称过滤
winalog alert list --rule "BruteForceDetection"

# 限制数量
winalog alert list --limit 50

# 分页
winalog alert list --page 2 --page-size 20
```

### 6.2 查看告警详情

```bash
winalog alert show <alert_id>
```

输出示例：
```
Alert ID: 12345
Rule: BruteForceDetection
Severity: High
Message: 检测到 10 次登录失败
First Seen: 2026-04-17 10:30:00
Last Seen: 2026-04-17 10:45:00
Count: 10
MITRE: T1110 - Brute Force
```

### 6.3 管理告警

```bash
# 标记为已解决
winalog alert resolve <alert_id>

# 标记为误报
winalog alert false-positive <alert_id>

# 删除告警
winalog alert delete <alert_id>

# 批量解决
winalog alert resolve --rule "SuspiciousProcessCreation" --severity low
```

### 6.4 告警分析

```bash
# 对所有事件运行告警分析
winalog alert run

# 指定时间窗口
winalog alert run --time-window 48h

# 持续监控模式
winalog alert monitor
```

### 6.5 导出告警

```bash
# 导出为 JSON
winalog alert export alerts.json

# 导出为 CSV
winalog alert export alerts.csv --format csv

# 导出特定规则的告警
winalog alert export filtered_alerts.json --rule "BruteForceDetection"
```

### 6.6 实际案例

**案例 1: 处理暴力破解告警**

```bash
# 1. 查看告警详情
winalog alert show 12345

# 2. 查看相关事件
winalog search --event-id 4625 --start-time "2026-04-17T10:00:00Z"

# 3. 如果确认为攻击，标记为已解决并添加备注
winalog alert resolve 12345 --notes "确认来自恶意IP 192.168.1.100"

# 4. 如为误报，标记为误报
winalog alert false-positive 12345 --reason "测试账户正常行为"
```

**案例 2: 批量处理高风险告警**

```bash
# 1. 查看所有高风险告警
winalog alert list --severity critical --limit 100

# 2. 导出到文件
winalog alert export critical_alerts.json --severity critical

# 3. 逐个处理
for id in $(winalog alert list --severity critical --format json | jq -r '.[].id'); do
  winalog alert show $id
  read -p "处理此告警? (y/n): " confirm
  if [ "$confirm" = "y" ]; then
    winalog alert resolve $id
  fi
done
```

---

## 7. 威胁分析

### 7.1 分析器列表

```bash
winalog analyze list
```

可用分析器：

| 分析器 | 说明 | 检测技术 |
|--------|------|----------|
| `bruteforce` | 暴力破解检测 | T1110 |
| `lateral_movement` | 横向移动检测 | T1021 |
| `persistence` | 持久化检测 | T1053, T1546 |
| `privilege_escalation` | 权限提升检测 | T1068 |
| `credential_access` | 凭证访问检测 | T1003 |
| `defense_evasion` | 防御规避检测 | T1562 |
| `initial_access` | 初始访问检测 | T1190 |

### 7.2 运行分析

```bash
# 基本用法
winalog analyze bruteforce

# 指定时间窗口
winalog analyze bruteforce --hours 48

# 输出为 JSON
winalog analyze lateral_movement --format json

# 输出到文件
winalog analyze persistence --output persistence_report.json
```

### 7.3 实际案例

**案例 1: 检测暴力破解**

```bash
# 分析最近24小时的暴力破解
winalog analyze bruteforce --hours 24

# 输出示例
# [HIGH] Brute Force Detected
#   User: Administrator
#   Source IP: 192.168.1.100
#   Failed Attempts: 156
#   Time Window: 2026-04-16 14:00 - 2026-04-16 15:30
#   Recommended Action: 封锁 IP 192.168.1.100
```

**案例 2: 检测横向移动**

```bash
# 检测横向移动
winalog analyze lateral_movement --hours 72 --format json

# 查看详细结果
cat lateral_movement_report.json | jq '.[]'
```

**案例 3: 权限提升分析**

```bash
winalog analyze privilege_escalation --time-window 48h --output priv_esc.json
```

---

## 8. 实时监控

### 8.1 启动实时采集

```bash
# 采集 Security 日志
winalog live collect --channel Security

# 采集多个日志
winalog live collect --channel Security --channel System

# 带过滤条件
winalog live collect --channel Security --event-id 4625 --level 2
```

### 8.2 实时监控选项

| 选项 | 说明 |
|------|------|
| `--channel` | 要监控的 Windows 事件日志通道 |
| `--event-id` | 只监控特定事件ID |
| `--level` | 只监控特定级别 |
| `--bookmark-file` | 书签文件路径（用于断点续传） |

### 8.3 实际案例

**案例: 监控登录事件**

```bash
# 启动实时监控 Security 日志
winalog live collect --channel Security

# 同时监控登录成功和失败事件
winalog live collect --channel Security --event-id 4624 --event-id 4625

# 带书签续传
winalog live collect --channel Security --bookmark-file security.bookmark
```

---

## 9. 取证功能

### 9.1 文件哈希

```bash
# 计算单个文件哈希
winalog forensics hash malicious.exe

# 计算多种哈希
winalog forensics hash --algorithm sha256 --algorithm md5 --algorithm sha1 file.exe

# 批量计算
winalog forensics hash /path/to/files/
```

**输出示例**:
```
File: malicious.exe
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
SHA1:   da39a3ee5e6b4b0d3255bfef95601890afd80709
MD5:    d41d8cd98f00b204e9800998ecf8427e
```

### 9.2 签名验证

```bash
# 验证文件签名
winalog forensics verify signature.exe

# 检查是否签名
winalog forensics is-signed application.exe

# 获取签名详情
winalog forensics signature driver.sys
```

### 9.3 证据采集

```bash
# 采集取证数据
winalog forensics collect --output evidence.zip

# 指定采集项
winalog forensics collect \
  --include-hashes \
  --include-signatures \
  --include-timestamps \
  --output forensic_collection.zip
```

### 9.4 证据链

```bash
# 生成证据清单
winalog forensics manifest /path/to/evidence/

# 查看监管链
winalog forensics chain-of-custody evidence.zip
```

### 9.5 实际案例

**案例: 分析可疑文件**

```bash
# 1. 计算哈希
winalog forensics hash suspicious.dll --algorithm sha256

# 2. 验证签名
winalog forensics verify signature suspicious.dll

# 3. 检查签名状态
winalog forensics is-signed suspicious.dll

# 4. 采集为证据
winalog forensics collect --include-hashes --include-signatures suspicious.dll
```

---

## 10. 持久化检测

### 10.1 基本用法

```bash
# 检测所有持久化机制
winalog persistence detect

# 按类别检测
winalog persistence detect --category "Registry"

# 按 MITRE 技术检测
winalog persistence detect --technique T1546.001

# 输出到文件
winalog persistence detect --output persistence_results.json
```

### 10.2 支持的技术

| 技术 ID | 技术名称 | 类别 |
|---------|----------|------|
| T1546.001 | Accessibility Features |  registry |
| T1546.003 | WMI Event Subscription | wmi |
| T1546.010 | AppInit_DLLs | registry |
| T1546.012 | IFEO Debugger | registry |
| T1546.015 | COM Hijacking | com |
| T1546.016 | Startup Folder | file |
| T1547.001 | Registry Run Keys | registry |
| T1547.016 | Registry PowerShell | registry |
| T1053.005 | Scheduled Tasks | tasks |
| T1543.003 | Windows Service | service |

### 10.3 输出格式

```bash
# JSON 格式（默认）
winalog persistence detect --format json --output results.json

# CSV 格式
winalog persistence detect --format csv --output results.csv

# 文本格式
winalog persistence detect --format text

# 显示进度
winalog persistence detect --progress
```

### 10.4 实际案例

**案例: 检测注册表持久化**

```bash
# 1. 检测所有注册表持久化点
winalog persistence detect --category registry --output registry_persistence.json

# 2. 查看详细结果
cat registry_persistence.json | jq '.[] | select(.technique=="T1547.001")'

# 3. 检测特定技术
winalog persistence detect --technique T1546.003 --format json
```

**案例: 全面持久化扫描**

```bash
# 扫描所有类别
winalog persistence detect --category registry --category wmi --category tasks --category service

# 输出完整报告
winalog persistence detect --output full_persistence_scan.json --format json
```

---

## 11. 报告生成

### 11.1 报告类型

| 类型 | 说明 |
|------|------|
| `security_summary` | 安全摘要（默认） |
| `alert_report` | 告警详情报告 |
| `event_report` | 原始事件报告 |
| `timeline_report` | 时间线报告 |
| `login_report` | 登录分析报告 |
| `file_report` | 文件操作报告 |
| `network_report` | 网络活动报告 |
| `threat_report` | 威胁检测报告 |

### 11.2 生成报告

```bash
# 基本用法
winalog report generate --output report.html

# 指定类型
winalog report generate security_summary --output summary.html

# 指定格式
winalog report generate --format html --output report.html
winalog report generate --format json --output report.json

# 指定时间范围
winalog report generate --time-range 7d --output weekly_report.html
winalog report generate --time-range 30d --output monthly_report.html

# 指定标题
winalog report generate --title "2026年4月安全报告" --output april_report.html
```

### 11.3 导出格式

```bash
# HTML 报告
winalog export html --output report.html

# JSON 导出
winalog export json --output events.json

# CSV 导出
winalog export csv --output events.csv

# 时间线导出
winalog export timeline --output timeline.csv
```

### 11.4 实际案例

**案例: 生成每日安全报告**

```bash
# 生成日报告
winalog report generate \
  --title "每日安全报告" \
  --time-range 24h \
  --format html \
  --output daily_report_$(date +%Y%m%d).html
```

**案例: 生成告警分析报告**

```bash
# 生成告警详情报告
winalog report generate alert_report \
  --format html \
  --include-ioc \
  --include-mitre \
  --output alert_analysis.html
```

**案例: 生成合规报告**

```bash
# 生成事件报告用于合规审计
winalog report generate event_report \
  --start-time "2026-01-01T00:00:00Z" \
  --end-time "2026-03-31T23:59:59Z" \
  --format json \
  --output Q1_events.json
```

---

## 12. 时间线分析

### 12.1 构建时间线

```bash
# 构建全局时间线
winalog timeline build

# 指定时间范围
winalog timeline build --start "2026-04-01T00:00:00Z" --end "2026-04-17T23:59:59Z"
```

### 12.2 查询时间线

```bash
# 基本查询
winalog timeline query

# 按类别过滤
winalog timeline query --category authentication
winalog timeline query --category network
winalog timeline query --category process

# 按计算机过滤
winalog timeline query --computer DC01

# 时间范围
winalog timeline query --start "2026-04-01T00:00:00Z" --end "2026-04-17T23:59:59Z"
```

### 12.3 导出时间线

```bash
# 导出为 CSV
winalog timeline export --output timeline.csv --format csv

# 导出为 JSON
winalog timeline export --output timeline.json --format json

# 导出为 HTML 可视化
winalog timeline export --output timeline.html --format html
```

### 12.4 实际案例

**案例: 分析攻击时间线**

```bash
# 1. 构建最近一周的时间线
winalog timeline build --start "2026-04-10T00:00:00Z" --end "2026-04-17T23:59:59Z"

# 2. 查询认证相关事件
winalog timeline query --category authentication --output auth_timeline.json

# 3. 导出为可视化 HTML
winalog timeline export --output attack_timeline.html --format html
```

---

## 13. 多机分析

### 13.1 跨机器关联分析

```bash
# 运行多机分析
winalog multi analyze

# 指定时间窗口
winalog multi analyze --time-window 48h

# 输出结果
winalog multi analyze --output multi_analysis.json
```

### 13.2 横向移动检测

```bash
# 检测横向移动
winalog multi lateral

# 查看详细结果
winalog multi lateral --format json --output lateral_movement.json
```

### 13.3 实际案例

**案例: 检测跨机器攻击**

```bash
# 1. 分析横向移动
winalog multi lateral --format json

# 2. 查看可疑活动
# 假设输出显示: User "admin" 从 IP 192.168.1.50 登录到多台机器

# 3. 进一步调查
winalog search --user "admin" --event-id 4624 --start-time "2026-04-17T00:00:00Z"
```

---

## 14. UEBA用户行为分析

### 14.1 运行 UEBA 分析

```bash
# 基本分析
winalog ueba analyze

# 指定时间窗口
winalog ueba analyze --hours 168  # 最近一周

# 保存为告警
winalog ueba analyze --save-alerts
```

### 14.2 用户画像

```bash
# 查看所有用户画像
winalog ueba profiles

# 查看特定用户
winalog ueba profiles --user Administrator

# JSON 输出
winalog ueba profiles --format json
```

### 14.3 基线管理

```bash
# 学习基线
winalog ueba baseline --action learn

# 查看基线
winalog ueba baseline --action show

# 清除基线
winalog ueba baseline --action clear
```

### 14.4 实际案例

**案例: 检测异常用户行为**

```bash
# 1. 学习两周的正常行为
winalog ueba baseline --action learn --hours 336

# 2. 运行 UEBA 分析
winalog ueba analyze --hours 24 --save-alerts

# 3. 查看检测到的异常
winalog alert list --severity high --rule "UEBA"
```

---

## 15. TUI终端界面

### 15.1 启动 TUI

```bash
winalog tui
```

### 15.2 视图导航

| 键 | 功能 |
|----|------|
| `1-9` | 切换视图 |
| `Tab` | 下一个视图 |
| `q` | 退出 |
| `j/k` | 上/下移动 |
| `Enter` | 选择/确认 |
| `Esc` | 返回 |

### 15.3 主要视图

| 视图 | 快捷键 | 说明 |
|------|--------|------|
| Dashboard | `1` | 系统仪表盘 |
| Events | `2` | 事件列表 |
| Event Detail | `3` | 事件详情 |
| Alerts | `4` | 告警列表 |
| Alert Detail | `5` | 告警详情 |
| Search | `6` | 搜索界面 |
| Timeline | `7` | 时间线 |
| Collect | `8` | 采集 |
| Help | `9` | 帮助 |

### 15.4 实际案例

**案例: 使用 TUI 进行交互式分析**

```bash
# 1. 启动 TUI
winalog tui

# 2. 按 4 进入告警视图
# 3. 使用 j/k 浏览告警
# 4. 按 Enter 查看详情
# 5. 按 r 标记为已解决
# 6. 按 q 退出
```

---

## 16. API服务

### 16.1 启动 API 服务器

```bash
# 基本启动
winalog serve

# 指定地址和端口
winalog serve --host 0.0.0.0 --port 8080

# 使用配置文件
winalog serve --config /path/to/config.yaml
```

### 16.2 API 认证

```bash
# 启用 JWT 认证（需配置）
winalog serve --auth-enabled
```

### 16.3 健康检查

```bash
curl http://localhost:8080/api/health
```

---

## 17. 配置参考

### 17.1 完整配置示例

```yaml
# ~/.winalog/config.yaml

database:
  path: "~/.winalog/winalog.db"
  wal_mode: true
  pool_size: 10
  max_open_conns: 25

import:
  workers: 4
  batch_size: 10000
  skip_patterns: ["Diagnostics", "Debug"]
  incremental: true
  calculate_hash: true

parser:
  workers: 4
  memory_limit: 2048

search:
  max_results: 100000
  timeout: 30s
  highlight_max_length: 200
  default_page_size: 100

alerts:
  enabled: true
  dedup_window: 5m
  stats_retention: 720h

correlation:
  enabled: true
  time_window: 24h
  max_events: 10000

report:
  output_dir: "./reports"
  template_dir: "./templates"
  default_format: "html"

forensics:
  hash_algorithm: "sha256"
  sign_reports: false

api:
  host: "127.0.0.1"
  port: 8080
  mode: "debug"
  cors:
    allowed_origins: ["*"]
    allowed_methods: ["GET", "POST", "PUT", "DELETE"]
    allowed_headers: ["*"]

auth:
  enabled: false
  jwt_secret: ""

audit:
  enabled: true
  output_dir: "./audit"
  max_size: 100
  max_age: 30
  retention: 2160h

log:
  level: "info"
  format: "json"
  output: "stdout"
  file_path: ""

tui:
  theme: "dark"
  key_mode: "vi"
  auto_update: true
```

### 17.2 配置选项详解

#### 数据库配置

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `database.path` | `~/.winalog/winalog.db` | 数据库文件路径 |
| `database.wal_mode` | `true` | 启用 WAL 模式 |
| `database.pool_size` | `10` | 连接池大小 |
| `database.max_open_conns` | `25` | 最大打开连接数 |

#### 导入配置

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `import.workers` | `4` | 并行 worker 数量 |
| `import.batch_size` | `10000` | 批量插入大小 |
| `import.skip_patterns` | `[]` | 跳过的文件模式 |
| `import.incremental` | `true` | 启用增量导入 |
| `import.calculate_hash` | `true` | 计算文件哈希 |

#### 搜索配置

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `search.max_results` | `100000` | 最大结果数 |
| `search.timeout` | `30s` | 查询超时 |
| `search.default_page_size` | `100` | 默认分页大小 |
| `search.max_query_limit` | `1000` | 最大查询限制 |

#### 告警配置

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `alerts.enabled` | `true` | 启用告警 |
| `alerts.dedup_window` | `5m` | 去重时间窗口 |
| `alerts.stats_retention` | `720h` | 统计保留时间 |

#### API 配置

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `api.host` | `127.0.0.1` | API 监听地址 |
| `api.port` | `8080` | API 监听端口 |
| `api.mode` | `debug` | 运行模式 |
| `api.cors.allowed_origins` | `["*"]` | CORS 允许来源 |

---

## 附录 A: 常见问题

### Q: 导入速度慢怎么办？

```bash
# 增加 worker 数量
winalog import --workers 8 --batch-size 20000 /path/to/files

# 使用 SSD 存储数据库
```

### Q: 告警太多如何处理？

```bash
# 使用白名单
winalog whitelist add "MaintenanceWindow" \
  --event-id 4624 \
  --reason "计划维护时间段" \
  --scope global

# 配置抑制规则
winalog suppress add --rule "LowSeverityRule" --duration 60
```

### Q: 如何清理旧数据？

```bash
# 清理30天前的事件
winalog db clean --before "2026-03-17"

# 清理已解决的告警
winalog alert delete --resolved true

# 优化数据库
winalog db vacuum
```

### Q: 如何备份数据？

```bash
# 备份数据库
cp ~/.winalog/winalog.db ~/.winalog/winalog_backup_$(date +%Y%m%d).db

# 备份配置
cp ~/.winalog/config.yaml ~/.winalog/config_backup.yaml
```

---

## 附录 B: 事件 ID 参考

### 常用 Security 事件 ID

| 事件 ID | 说明 |
|---------|------|
| 4624 | 登录成功 |
| 4625 | 登录失败 |
| 4627 | 登录会话跟踪 |
| 4634 | 注销 |
| 4648 | 显式凭据登录 |
| 4672 | 特权分配 |
| 4720 | 创建用户账户 |
| 4722 | 启用用户账户 |
| 4723 | 更改密码 |
| 4724 | 重置密码 |
| 4725 | 禁用用户账户 |
| 4726 | 删除用户账户 |
| 4732 | 添加到安全组 |
| 4733 | 从安全组移除 |
| 4756 | 添加到通用安全组 |
| 4757 | 从通用安全组移除 |

---

**文档版本**: v2.4.0  
**最后更新**: 2026-04-17
