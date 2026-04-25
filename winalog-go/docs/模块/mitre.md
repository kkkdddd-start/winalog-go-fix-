# MITRE ATT&CK 模块

**路径**: `pkg/mitre/`

内置 MITRE ATT&CK 框架技术映射，支持 80+ 攻击技术。

## 类型定义

```go
type ATTACKTechnique struct {
    ID          string   `json:"id"`           // TXXXX
    Name        string   `json:"name"`         // 技术名称
    Tactic      string   `json:"tactic"`        // 战术名称
    Description string   `json:"description"`   // 技术描述
    Platforms   []string `json:"platforms,omitempty"`  // 支持平台
    DataSources []string `json:"data_sources,omitempty"` // 数据来源
}

type ATTACKTactic struct {
    ID          string   `json:"id"`          // TAXXXX
    Name        string   `json:"name"`        // 战术名称
    Description string   `json:"description"`  // 战术描述
    Techniques  []string `json:"techniques,omitempty"` // 技术列表
}
```

## 战术 (Tactics)

| ID | 名称 | 说明 |
|----|------|------|
| TA0001 | Initial Access | 初始访问 |
| TA0002 | Execution | 执行 |
| TA0003 | Persistence | 持久化 |
| TA0004 | Privilege Escalation | 权限提升 |
| TA0005 | Defense Evasion | 防御规避 |
| TA0006 | Credential Access | 凭证访问 |
| TA0007 | Discovery | 发现 |
| TA0008 | Lateral Movement | 横向移动 |
| TA0009 | Collection | 收集 |
| TA0010 | Exfiltration | 数据泄露 |
| TA0011 | Command and Control | 命令与控制 |
| TA0040 | Impact | 影响 |

## 核心技术映射

### TA0001 - Initial Access

| ID | 名称 | 数据来源 |
|----|------|---------|
| T1078 | Valid Accounts | Windows Event Logs |
| T1190 | Exploit Public-Facing Application | Network Traffic |
| T1133 | External Remote Services | Windows Event Logs |

### TA0002 - Execution

| ID | 名称 | 数据来源 |
|----|------|---------|
| T1059 | Command and Scripting Interpreter | PowerShell Logs |
| T1047 | Windows Management Instrumentation | WMI |
| T1106 | Native API | API Monitoring |

### TA0003 - Persistence

| ID | 名称 | 数据来源 |
|----|------|---------|
| T1053 | Scheduled Task/Job | Windows Task Scheduler |
| T1098 | Account Manipulation | Windows Event Logs |
| T1078 | Valid Accounts | Windows Event Logs |
| T1037 | Boot or Logon Initialization Scripts | File System |

### TA0006 - Credential Access

| ID | 名称 | 数据来源 |
|----|------|---------|
| T1003 | OS Credential Dumping | LSASS, Windows Event Logs |
| T1110 | Brute Force | Windows Event Logs |
| T1078 | Valid Accounts | Windows Event Logs |
| T1086 | PowerShell | PowerShell Logs |

### TA0007 - Discovery

| ID | 名称 | 数据来源 |
|----|------|---------|
| T1082 | System Information Discovery | Windows Event Logs, Registry |
| T1018 | Remote System Discovery | Network Traffic |
| T1057 | Process Discovery | Process Monitoring |
| T1063 | Security Software Discovery | Windows Event Logs |

### TA0008 - Lateral Movement

| ID | 名称 | 数据来源 |
|----|------|---------|
| T1021 | Remote Services | Windows Event Logs |
| T1072 | Software Deployment Tools | Windows Event Logs |
| T1097 | Pass the Ticket | Kerberos Logs |
| T1028 | Windows Remote Management | Windows Event Logs |

### TA0005 - Defense Evasion

| ID | 名称 | 数据来源 |
|----|------|---------|
| T1070 | Indicator Removal | File System, Windows Event Logs |
| T1055 | Process Injection | Process Monitoring |
| T1112 | Modify Registry | Registry Monitoring |

### TA0011 - Command and Control

| ID | 名称 | 数据来源 |
|----|------|---------|
| T1071 | Application Layer Protocol | Network Traffic |
| T1095 | Non-Application Layer Protocol | Network Traffic |

## API 函数

```go
// 获取所有技术
func GetAllTechniques() []*ATTACKTechnique

// 根据 ID 获取技术
func GetTechnique(id string) (*ATTACKTechnique, error)

// 获取所有战术
func GetAllTactics() []*ATTACKTactic

// 根据 ID 获取战术
func GetTactic(id string) (*ATTACKTactic, error)

// 根据战术获取所有技术
func GetTechniquesByTactic(tacticName string) []*ATTACKTechnique

// 搜索技术
func SearchTechniques(query string) []*ATTACKTechnique
```

## 使用示例

```go
import "github.com/kkkdddd-start/winalog-go/pkg/mitre"

// 获取技术
tech, err := mitre.GetTechnique("T1003")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Technique: %s\n", tech.Name)
fmt.Printf("Tactic: %s\n", tech.Tactic)
fmt.Printf("Description: %s\n", tech.Description)

// 获取战术
tactic, err := mitre.GetTactic("TA0006")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Tactic: %s\n", tactic.Name)

// 获取某战术下所有技术
techs := mitre.GetTechniquesByTactic("Credential Access")
for _, t := range techs {
    fmt.Printf("- %s: %s\n", t.ID, t.Name)
}

// 搜索技术
results := mitre.SearchTechniques("password")
for _, t := range results {
    fmt.Printf("- %s: %s\n", t.ID, t.Name)
}
```

## 告警映射

在 AlertRule 中使用 MITRE ID:

```go
rule := &rules.AlertRule{
    Name:        "CredentialDumping",
    MitreAttack: "T1003",  // OS Credential Dumping
    Severity:    rules.SeverityCritical,
    Message:     "Possible credential dumping detected",
}
```

## 数据来源

常见数据来源映射:

| 数据来源 | 对应事件 |
|---------|---------|
| Windows Event Logs | Security, System, Application |
| PowerShell Logs | Microsoft-Windows-PowerShell/Operational |
| WMI | WMI 事件跟踪 |
| Process Monitoring | Sysmon Event ID 1, 10 |
| Network Traffic | Windows Firewall, Network logs |
| DNS | DNS Server logs |
| Kerberos Logs | Security Event ID 4768, 4769 |
| LSASS | Sysmon Event ID 10 |
