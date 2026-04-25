# 改进建议评估报告

**创建日期**: 2026-04-15
**来源**: 用户提供的在线剪切板建议
**项目**: WinLogAnalyzer-Go

---

## 一、P1 紧急问题（阻塞性）

### 1.1 规则引擎 - 规则条件过于简单

| 项目 | 内容 |
|------|------|
| **严重程度** | P1 |
| **问题描述** | 当前规则仅匹配 EventID + Level，未验证关键字段 |
| **状态** | 待评估 |

**建议改进**:
```go
// 当前:
Filter: &rules.Filter{
    EventIDs: []int32{4625},
    Levels: []int{2},
}

// 改进后:
Filter: &rules.Filter{
    EventIDs: []int32{4625},
    Levels: []int{2},
    LogonTypes: []int{3, 10, 11},        // 仅检测交互式登录
    ExcludeUsers: []string{"ANONYMOUS LOGON", "SYSTEM"},
    ExcludeComputers: []string{"DOMAINCONTROLLER"},
    MinFailCount: 5,                      // 可配置阈值
}
```

### 1.2 规则引擎 - 缺少上下文关联

| 项目 | 内容 |
|------|------|
| **严重程度** | P1 |
| **问题描述** | 未关联 LogonType、IpAddress、Computer 等字段 |
| **状态** | 待评估 |

### 1.3 告警引擎 - 去重逻辑简单

| 项目 | 内容 |
|------|------|
| **严重程度** | P1 |
| **问题描述** | 当前仅基于规则名称去重 |
| **状态** | 待评估 |

**建议改进**:
```go
type DeduplicationKey struct {
    RuleName     string    // 规则名称
    AffectedUser string    // 受影响用户
    SourceIP     string    // 攻击源IP
    AffectedHost string    // 受影响主机
    TimeWindow   time.Duration
}
```

### 1.4 告警引擎 - 趋势分析有 BUG

| 项目 | 内容 |
|------|------|
| **严重程度** | P1 |
| **问题描述** | trend.go 存在键不匹配问题 |
| **状态** | 待验证 |

### 1.5 事件解析器 - ETL parser 编译错误

| 项目 | 内容 |
|------|------|
| **严重程度** | P1 |
| **问题描述** | ETL 解析器有编译错误，阻塞解析功能 |
| **状态** | 待修复 |

### 1.6 Sysmon 解析不完整

| 项目 | 内容 |
|------|------|
| **严重程度** | P2 |
| **问题描述** | 仅支持部分 Event ID |
| **状态** | 待评估 |

### 1.7 持久化检测 - 检测方法单一

| 项目 | 内容 |
|------|------|
| **严重程度** | P1 |
| **问题描述** | 仅检测注册表和文件，缺少 ETW、WMI 等 |
| **状态** | 待评估 |

### 1.8 关联分析 - 关联规则简单

| 项目 | 内容 |
|------|------|
| **严重程度** | P1 |
| **问题描述** | 仅支持单 Event ID 序列 |
| **状态** | 待评估 |

### 1.9 API 服务 - 路由未注册

| 项目 | 内容 |
|------|------|
| **严重程度** | P1 |
| **问题描述** | Collect/Settings/Analyze 未注册 |
| **状态** | ✅ 已修复 |

---

## 二、P2 重要功能（功能缺失）

### 2.1 规则引擎

| 功能 | 严重程度 | 说明 |
|------|----------|------|
| 白名单机制 | P2 | 产生大量误报 |
| 可配置阈值 | P2 | 暴力破解阈值固定 |
| 规则置信度等级 | P3 | 影响告警优先级 |
| 资产关联加权 | P3 | 根据资产重要性加权 |

### 2.2 事件解析器

| 功能 | 严重程度 | 说明 |
|------|----------|------|
| 完善事件字段提取 | P2 | 大量字段未解析 |
| CSV/JSON 批量导入 | P2 | 解析格式有限 |
| 解析质量报告 | P3 | 无解析统计 |

### 2.3 告警引擎

| 功能 | 严重程度 | 说明 |
|------|----------|------|
| 多维度抑制规则 | P2 | 仅支持时间窗口抑制 |
| 告警智能分类 | P2 | 缺少告警分级处理 |
| 告警评分模型 | P2 | 无综合评分 |

### 2.4 持久化检测

| 功能 | 严重程度 | 说明 |
|------|----------|------|
| 基线对比检测 | P2 | 无法检测新增持久化 |
| ETW 扫描检测 | P2 | 未覆盖 |
| WMI Subscription 检测 | P2 | 未覆盖 |
| AMDF 检测 | P3 | 新型技术 |
| 进程注入检测 | P3 | 未覆盖 |

### 2.5 关联分析

| 功能 | 严重程度 | 说明 |
|------|----------|------|
| 复杂事件序列关联 | P2 | 仅单 Event ID |
| 时间窗口动态调整 | P2 | 固定不可调 |
| 跨数据源关联 | P2 | 仅限 Windows 日志 |
| 异常检测关联 | P3 | 需基线对比 |
| 跨资产关联 | P3 | 横向移动检测 |
| 威胁情报关联 | P3 | IP/域名黑名单 |

### 2.6 分析器

| 功能 | 严重程度 | 说明 |
|------|----------|------|
| 新增分析器 | P1 | 仅 3 个分析器 |
| UEBA 异常检测 | P3 | 机器学习 |
| 统计异常检测 | P2 | 3-sigma 规则 |
| 进程行为分析 | P2 | LOLBAS 检测 |

### 2.7 取证分析

| 功能 | 严重程度 | 说明 |
|------|----------|------|
| 完整内存取证 | P3 | LSASS 提取 |
| 文件时间线分析 | P3 | TLN 格式 |
| 注册表取证 | P2 | Run Keys/SHIMCache |

### 2.8 采集器

| 功能 | 严重程度 | 说明 |
|------|----------|------|
| Sysmon 全 Event ID | P2 | 未覆盖所有 ID |

### 2.9 报告生成

| 功能 | 严重程度 | 说明 |
|------|----------|------|
| PDF 输出 | P2 | ✅ 已实现 |
| 自定义报告模板 | P3 | 不可配置 |
| 自动化报告调度 | P3 | 定时任务 |

### 2.10 时间线分析

| 功能 | 严重程度 | 说明 |
|------|----------|------|
| 增强可视化 | P2 | D3.js 图形化 |
| 智能时间线压缩 | P3 | 相似事件聚合 |
| 多维度时间线 | P3 | 分层展示 |
| 关联时间线分析 | P3 | 攻击阶段识别 |

### 2.11 API 服务

| 功能 | 严重程度 | 说明 |
|------|----------|------|
| 路由注册 | P1 | ✅ 已修复 |
| 认证中间件 | P2 | 无认证 |
| WebSocket 实时推送 | P3 | 无实时推送 |

### 2.12 Web UI

| 功能 | 严重程度 | 说明 |
|------|----------|------|
| 响应式设计 | P2 | 移动端体验差 |
| 快捷操作面板 | P3 | 建议优化 |

---

## 三、建议的新增规则

### 3.1 登录类型异常
```yaml
Name: "logon-type-mismatch"
Description: "登录类型异常(网络登录到本地账户)"
EventID: 4624
Condition: "LogonType == 3 AND TargetUserName NOT CONTAINS '$'"
Severity: "high"
Score: 70
```

### 3.2 管理员账户远程登录
```yaml
Name: "admin-account-remote-login"
Description: "管理员账户从非常用位置远程登录"
EventID: 4624
Condition: "(TargetUserName IN ['Administrator', 'Domain Admin']) AND (LogonType IN [3, 10, 12]) AND (IpAddress NOT IN ['10.0.0.0/8', '192.168.0.0/16'])"
Severity: "critical"
Score: 90
```

### 3.3 服务账户 AD 复制
```yaml
Name: "service-account-ad-replication"
Description: "服务账户执行AD复制(潜在DCSync)"
EventID: 4662
Condition: "SubjectLogonId == '0x3e7' AND Properties CONTAINS 'DS-Replication-Get-Changes-All'"
Severity: "critical"
Score: 95
```

### 3.4 RAR 压缩检测
```yaml
Name: "rar-compression-detection"
Description: "使用RAR压缩敏感文件(数据外泄准备)"
EventID: 4688
Condition: "CommandLine CONTAINS 'rar' AND CommandLine CONTAINS ANY ['.docx', '.xlsx', '.pdf', '.zip', '.bak']"
Severity: "high"
Score: 75
```

### 3.5 LOLBAS 攻击检测
```yaml
Name: "living-off-land-detected"
Description: "LOLBAS攻击检测(wmic bitsadmin certutil)"
EventID: 4688
Condition: "ImagePath CONTAINS ANY ['wmic.exe', 'bitsadmin.exe', 'certutil.exe', 'mshta.exe'] AND CommandLine NOT LIKE '%system32%'"
Severity: "high"
Score: 80
```

---

## 四、优先级实施计划

### 第一阶段（紧急 - 1-2周）
- [ ] 1. ETL parser 编译错误修复
- [ ] 2. 规则多条件过滤 (Filter 扩展)
- [ ] 3. 告警去重逻辑增强
- [ ] 4. 告警趋势分析 BUG 修复
- [ ] 5. Sysmon 全 Event ID 支持

### 第二阶段（重要 - 1个月）
- [ ] 6. 白名单机制实现
- [ ] 7. 持久化检测增强 (ETW/WMI)
- [ ] 8. 关联规则序列支持
- [ ] 9. 事件字段完善提取
- [ ] 10. 分析器扩展

### 第三阶段（优化 - 长期）
- [ ] 11. UEBA 异常检测
- [ ] 12. 威胁情报集成
- [ ] 13. 报告模板自定义
- [ ] 14. 时间线可视化
- [ ] 15. WebSocket 实时推送

---

## 五、评估总结

### 可立即实施 (可行性高)
1. Filter 结构扩展 - 规则多条件过滤
2. DeduplicationKey 多维度去重
3. Sysmon Event ID 1-22 全支持
4. 新增检测规则 (logon-type-mismatch 等)

### 需进一步研究 (可行性中等)
1. UEBA 异常检测 - 需要历史数据基线
2. 威胁情报集成 - 需要外部 API
3. 内存取证 - 需要 Windows API

### 依赖其他模块 (可行性较低)
1. 复杂关联规则 - 依赖规则引擎完善
2. 时间线可视化 - 需要前端较大改动
