# 安全分析器 (analyzers)

安全分析器是 WinLog 的核心检测单元，每个分析器专注于一种安全威胁模式的识别。

## 目录

- [文件结构](#文件结构)
- [核心接口与类型](#核心接口与类型)
- [分析器完整列表](#分析器完整列表)
- [分析器注册机制](#分析器注册机制)
- [各分析器详解](#各分析器详解)

## 文件结构

| 文件 | 说明 |
|------|------|
| `analyzer.go` | Analyzer 接口、Result 结构体、Finding 结构体 |
| `brute_force.go` | 暴力破解检测（RDP、NTLM、Kerberos） |
| `login.go` | 登录异常检测（非常规时间、异地登录） |
| `kerberos.go` | Kerberos 攻击检测（Roasting、Golden Ticket） |
| `powershell.go` | PowerShell 可疑行为检测 |
| `data_exfiltration.go` | 数据外泄检测（大文件共享、USB 设备） |
| `lateral_movement.go` | 横向移动检测（WMI、PsExec、SMB） |
| `persistence.go` | 持久化检测（计划任务、注册表、服务） |
| `privilege_escalation.go` | 权限提升检测（令牌操作、UAC 绕过） |
| `domain_controller.go` | 域控安全检测（DCSync、DCShadow） |
| `analyzer_test.go` | 分析器测试 |

## 核心接口与类型

### Analyzer 接口

```go
type Analyzer interface {
    Name() string
    Analyze(events []*types.Event) *Result
}
```

### Result 结构体

```go
type Result struct {
    RuleName    string     `json:"rule_name"`
    Findings    []*Finding `json:"findings"`
    Metadata    Metadata   `json:"metadata"`
    Timestamp   time.Time  `json:"timestamp"`
}
```

### Finding 结构体

```go
type Finding struct {
    Description string                 `json:"description"`
    Severity    string                 `json:"severity"`
    Confidence  int                    `json:"confidence"`
    Count       int                    `json:"count"`
    Events      []*types.Event         `json:"events"`
    Details     map[string]interface{} `json:"details"`
}
```

### Metadata 结构体

```go
type Metadata struct {
    MITRETactic    string `json:"mitre_tactic"`
    MITRETechnique string `json:"mitre_technique"`
    MITREMITRE     string `json:"mitre_mitre"`
}
```

## 分析器完整列表

| 分析器 | 规则名 | 监控 EventID | MITRE ATT&CK | 严重级别 |
|--------|--------|-------------|--------------|----------|
| BruteForceAnalyzer | `brute_force_rdp` | 4625, 4771, 4776 | T1110 (暴力破解) | High |
| BruteForceAnalyzer | `brute_force_ntlm` | 4625, 4771 | T1110.002 | High |
| LoginAnalyzer | `suspicious_login_time` | 4624 | T1078 (有效账户) | Medium |
| KerberosAnalyzer | `kerberoasting` | 4769 | T1558.003 | Critical |
| KerberosAnalyzer | `as_rep_roasting` | 4768 | T1558.004 | High |
| KerberosAnalyzer | `golden_ticket` | 4769 | T1558.001 | Critical |
| PowerShellAnalyzer | `suspicious_powershell` | 4104 | T1059.001 | High |
| PowerShellAnalyzer | `encoded_command` | 4104 | T1027 | Medium |
| DataExfiltrationAnalyzer | `large_file_copy` | 5145 | T1048 (数据外泄) | High |
| DataExfiltrationAnalyzer | `usb_device_connected` | 6416, 6417 | T1091 | Medium |
| LateralMovementAnalyzer | `wmi_execution` | 5857, 5860, 5861 | T1047 | High |
| LateralMovementAnalyzer | `psexec_execution` | 7036, 7045 | T1570 | Critical |
| PersistenceAnalyzer | `scheduled_task_created` | 4698 | T1053.005 | High |
| PersistenceAnalyzer | `registry_persistence` | 4657 | T1547 | High |
| PrivilegeEscalationAnalyzer | `token_manipulation` | 4674, 4672 | T1134 | Critical |
| PrivilegeEscalationAnalyzer | `uac_bypass` | 4674 | T1548.002 | High |
| DomainControllerAnalyzer | `dcsync_attack` | 4662 | T1003.006 | Critical |
| DomainControllerAnalyzer | `dc_shadow_sync` | 4933, 4934 | T1207 | Critical |

## 分析器注册机制

```go
var registry = make(map[string]func() Analyzer)

func Register(name string, factory func() Analyzer) {
    registry[name] = factory
}

func NewAnalyzer(name string) (Analyzer, error) {
    factory, exists := registry[name]
    if !exists {
        return nil, fmt.Errorf("analyzer not found: %s", name)
    }
    return factory(), nil
}

func GetAllAnalyzers() []Analyzer {
    analyzers := make([]Analyzer, 0, len(registry))
    for _, factory := range registry {
        analyzers = append(analyzers, factory())
    }
    return analyzers
}
```

### 各分析器 init 注册

```go
// brute_force.go
func init() {
    Register("brute_force", func() Analyzer { return NewBruteForceAnalyzer() })
}

// kerberos.go
func init() {
    Register("kerberos", func() Analyzer { return NewKerberosAnalyzer() })
}
```

## 各分析器详解

### BruteForceAnalyzer - 暴力破解检测

检测逻辑：
1. 筛选 EventID 4625（登录失败）、4771（Kerberos 预认证失败）、4776（NTLM 验证失败）
2. 按 `(computer, user)` 分组
3. 统计 5 分钟窗口内的失败次数
4. 阈值：同一用户在同一机器上失败 >= 10 次

```go
func (a *BruteForceAnalyzer) Analyze(events []*types.Event) *Result {
    var result = &Result{RuleName: "brute_force"}

    // 筛选失败事件
    failed := filterEvents(events, []int32{4625, 4771, 4776})

    // 按 (computer, user) 分组
    groups := groupBy(failed, func(e *Event) string {
        return e.Computer + "|" + extractUser(e)
    })

    // 阈值检查
    for key, group := range groups {
        if len(group) >= 10 {
            result.Findings = append(result.Findings, &Finding{
                Description: fmt.Sprintf("Brute force detected: %s", key),
                Severity:    "High",
                Count:       len(group),
                Events:      group,
            })
        }
    }

    return result
}
```

### KerberosAnalyzer - Kerberos 攻击检测

#### Kerberoasting 检测
- EventID: 4769（Kerberos 服务票据请求）
- 检测：请求 RC4-HMAC 加密类型 (0x17) 且服务名非 `krbtgt`
- 说明：攻击者请求可离线破解的服务票据

#### AS-REP Roasting 检测
- EventID: 4768（Kerberos TGT 请求）
- 检测：预认证失败 (Status: 0x1) 且加密类型为 RC4

#### Golden Ticket 检测
- EventID: 4769
- 检测：票据有效期异常长（> 10 小时）或 Ticket 选项异常

```go
func (a *KerberosAnalyzer) detectKerberoasting(events []*Event) []*Finding {
    var findings []*Finding
    for _, e := range events {
        if e.EventID == 4769 {
            ticketOptions := extractXMLField(e.Message, "TicketOptions")
            encryption := extractXMLField(e.Message, "TicketEncryptionType")
            if encryption == "0x17" && !isKrbtgt(e) {
                findings = append(findings, &Finding{
                    Description: "Possible Kerberoasting attack detected",
                    Severity:    "Critical",
                    Events:      []*Event{e},
                })
            }
        }
    }
    return findings
}
```

### PowerShellAnalyzer - PowerShell 可疑行为

#### 可疑命令检测
- EventID: 4104（脚本块日志）
- 关键词匹配：
  - `Invoke-Mimikatz`
  - `Invoke-WebRequest` + `DownloadString`
  - `New-Object` + `Net.WebClient`
  - `[Convert]::FromBase64String`
  - `Bypass` + `ExecutionPolicy`
  - `EncodedCommand`

#### Base64 编码命令检测
- 检测脚本中包含 `[System.Convert]::FromBase64String()`
- 检测 `-EncodedCommand` 参数
- 解码后检查是否包含可疑关键词

```go
var suspiciousPatterns = []string{
    `(?i)invoke-mimikatz`,
    `(?i)invoke-webrequest.*downloadstring`,
    `(?i)new-object.*net\.webclient`,
    `(?i)frombase64string`,
    `(?i)bypass.*executionpolicy`,
    `(?i)encodedcommand`,
    `(?i)iex.*\(new-object`,
    `(?i)downloadfile`,
    `(?i)start-process.*-verb runas`,
}
```

### LateralMovementAnalyzer - 横向移动检测

#### WMI 执行检测
- EventID: 5857, 5860, 5861（WMI 活动日志）
- 检测远程 WMI 调用

#### PsExec 检测
- EventID: 7045（新服务安装）
- 检测服务名匹配 `PSEXESVC` 或路径包含 `PSEXESVC.exe`

#### SMB 共享访问检测
- EventID: 5145（共享对象访问）
- 检测 ADMIN$、C$ 等管理共享访问

### PersistenceAnalyzer - 持久化检测

#### 计划任务创建
- EventID: 4698（计划任务创建）
- 检测可疑任务名称或路径

#### 注册表修改
- EventID: 4657（注册表值修改）
- 检测 Run、RunOnce 键值修改
- 检测 `HKLM\...\CurrentVersion\Run`

#### 服务创建
- EventID: 7045（新服务安装）
- 检测可疑服务路径

### PrivilegeEscalationAnalyzer - 权限提升检测

#### 令牌操作
- EventID: 4674（特权对象操作）
- EventID: 4672（特殊权限登录）
- 检测 `SeDebugPrivilege`、`SeTcbPrivilege` 等敏感权限获取

#### UAC 绕过
- EventID: 4674
- 检测 `consent.exe`、`fodhelper.exe` 等已知 UAC 绕过工具

### DomainControllerAnalyzer - 域控安全检测

#### DCSync 攻击
- EventID: 4662（目录服务对象访问）
- 检测：
  - 访问 `DS-Replication-Get-Changes` (GUID: `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`)
  - 访问 `DS-Replication-Get-Changes-All` (GUID: `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`)

#### DCShadow 攻击
- EventID: 4933, 4934（目录服务复制）
- 检测非域控制器发起的复制请求
