# WinLogAnalyzer-Go 缺失功能清单

## 一、功能对比分析

### 1.1 CLI 已有但 Web UI 缺失的功能

| 功能 | CLI 命令 | Web UI 状态 | 说明 |
|------|----------|-------------|------|
| 关联分析 | `correlate` | ❌ 无 | Web UI 没有攻击链检测页面 |
| 多机分析 | `multi analyze/lateral` | ❌ 无 | Web UI 没有横向移动检测页面 |
| SQL查询 | `query <sql>` | ❌ 无 | Web UI 没有原始SQL查询接口 |
| 终端UI | `tui` | ✅ 有 | Web UI 可以替代 |

**说明**: Web UI 虽然有 `serve` 启动的 API 服务器和内置界面，但缺少以下 CLI 独有功能的 Web 页面:
- 关联分析页面
- 多机分析页面  
- SQL 查询页面

### 1.2 Web UI 已有但 CLI 缺失的功能

| 功能 | Web UI 页面 | CLI 状态 | 说明 |
|------|-------------|----------|------|
| 仪表盘 | `/Dashboard.tsx` | ❌ 无 | CLI 没有统计图表概览命令 |
| 白名单管理 | `/Settings.tsx` | ❌ 无 | CLI 没有白名单配置命令 |
| 设置页面 | `/Settings.tsx` | ⚠️ 部分 | CLI 有 `config get/set` 但无完整UI |

**说明**: Web UI 的 Settings 页面包含白名单管理功能，但 CLI 只有 `config get/set` 基本配置命令。

### 1.3 两者都缺失或都有的功能

| 功能 | CLI | Web UI | 状态 |
|------|-----|--------|------|
| UEBA分析 | ⚠️ 有代码 | ⚠️ 有API | ⚠️ 部分实现 (覆盖率0%) |
| 实时监控 | `live collect` | `/Live.tsx` | ⚠️ 需要Windows |

---

## 二、详细缺失功能清单

### 2.1 Web UI 缺失的 CLI 功能

#### 1. 关联分析 (Correlation) - 高优先级
```
CLI: winalog correlate --time-window 24h
Web UI: 无对应页面
需要: /api/correlation 端点 + Correlation.tsx 页面
```

#### 2. 多机分析 (Multi-machine) - 中优先级
```
CLI: winalog multi analyze
CLI: winalog multi lateral
Web UI: 无对应页面
需要: Multi.tsx 页面 + 相关 API 端点
```

#### 3. SQL 查询接口 - 中优先级
```
CLI: winalog query "SELECT * FROM events LIMIT 10"
Web UI: 无对应页面
需要: Query.tsx 页面 + /api/query 端点
```

### 2.2 CLI 缺失的 Web UI 功能

#### 1. 仪表盘 (Dashboard) - 高优先级
```
Web UI: Dashboard.tsx 有完整的统计图表
CLI: 无对应命令
建议: 添加 winalog dashboard 命令输出统计摘要
```

#### 2. 白名单管理 (Whitelist) - 中优先级
```
Web UI: Settings.tsx 有白名单配置UI
CLI: 无对应命令
建议: 添加 winalog whitelist add/remove/list 命令
```

### 2.3 两者都缺失或部分实现的功能

#### 1. UEBA (用户行为分析) - 低优先级
```
当前状态:
- internal/ueba/ 有代码 (engine.go, baseline.go, models.go)
- internal/api/handlers_ueba.go 有 API 端点
- Web UI: /api/ueba/analyze, /api/ueba/profiles, /api/ueba/anomaly/:type
- CLI: 无对应命令

问题: 代码存在但测试覆盖率0%，可能功能不完整
建议: 完成 UEBA 功能实现并添加 CLI 命令
```

---

## 三、实现建议

### 3.1 高优先级

1. **Web UI 添加关联分析页面** (`Correlation.tsx`)
   - 调用 `/api/correlation` 端点
   - 显示检测到的攻击链
   - 支持时间窗口选择

2. **Web UI 添加 SQL 查询页面** (`Query.tsx`)
   - 调用 `/api/query` 端点
   - 提供 SQL 输入框
   - 表格展示结果

3. **CLI 添加仪表盘命令** (`winalog dashboard`)
   - 输出事件统计摘要
   - Top 10 事件类型
   - Top 10 来源
   - 时间分布

### 3.2 中优先级

4. **Web UI 添加多机分析页面** (`Multi.tsx`)
   - 调用相关 API 端点
   - 显示横向移动检测结果

5. **CLI 添加白名单管理命令**
   ```
   winalog whitelist add <rule> --reason <原因>
   winalog whitelist remove <rule>
   winalog whitelist list
   ```

### 3.3 低优先级

6. **完善 UEBA 功能**
   - 补全内部/ueba/ 模块实现
   - 添加 CLI 命令 `winalog ueba analyze`
   - 添加 Web UI 页面

---

## 四、当前功能状态速查表

| 模块 | CLI | Web UI | 备注 |
|------|-----|--------|------|
| **数据导入** | ✅ import | ✅ Collect | 完整 |
| **事件搜索** | ✅ search | ✅ Events | 完整 |
| **安全分析** | ✅ analyze | ✅ Analyze | 完整 |
| **关联分析** | ✅ correlate | ❌ | 需添加Web页面 |
| **多机分析** | ✅ multi | ❌ | 需添加Web页面 |
| **报告生成** | ✅ report | ✅ Reports | 完整 |
| **时间线** | ✅ timeline | ✅ Timeline | 完整 |
| **持久化检测** | ✅ persistence | ✅ Persistence | 完整 |
| **取证功能** | ✅ forensics | ✅ Forensics | 完整 |
| **规则管理** | ✅ rules | ✅ Rules | 完整 |
| **告警管理** | ✅ alert | ✅ Alerts | 完整 |
| **仪表盘** | ❌ | ✅ Dashboard | 需添加CLI |
| **白名单** | ❌ | ✅ Settings | 需添加CLI |
| **SQL查询** | ✅ query | ❌ | 需添加Web页面 |
| **UEBA** | ❌ | ⚠️ 部分 | 需完善 |
| **实时监控** | ✅ live | ✅ Live | 需Windows |
| **系统信息** | ✅ info | ✅ SystemInfo | 完整 |
| **数据库** | ✅ db | - | 完整 |
| **配置管理** | ✅ config | ✅ Settings | 基本完整 |
| **指标导出** | ✅ metrics | ✅ Metrics | 完整 |
| **文件验证** | ✅ verify | ⚠️ Forensics | 部分 |
| **API服务** | ✅ serve | ✅ 内置 | 完整 |
| **终端UI** | ✅ tui | - | 独立功能 |

---

## 五、总结

| 类别 | 数量 | 说明 |
|------|------|------|
| 两者都完整 | ~15 | 大部分核心功能 |
| CLI 独有 Web 缺失 | 3 | correlate, multi, query |
| Web 独有 CLI 缺失 | 2 | dashboard, whitelist |
| 两者都缺失/不完整 | 1 | UEBA |
| 需要Windows | 2 | live, collect |

**建议优先实现**:
1. Web UI 关联分析页面 (使用频率高)
2. CLI 仪表盘命令 (用户体验一致)
3. Web UI SQL 查询页面 (高级用户需求)
