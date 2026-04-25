# Windows 事件 ID 参考手册

**项目**: WinLogAnalyzer-Go
**版本**: v2.0
**日期**: 2026-04-17
**状态**: 完整版

---

## 一、概述

本文档是 Windows 安全事件日志的完整参考手册，专为应急响应和安全分析场景编写。

### 1.1 文档目的

- 提供 Windows 各类事件日志的完整事件 ID 清单
- 解释每个事件 ID 的含义、字段和应急场景
- 按攻击链和 MITRE ATT&CK 框架组织事件，便于快速溯源
- 辅助 WinLogAnalyzer-Go 用户理解告警规则和关联分析逻辑

### 1.2 Windows 事件日志类型汇总

| 日志名称 | 日志通道 | 说明 |
|----------|----------|------|
| Security | Security | 安全相关事件，用户登录、权限操作等 |
| System | System | 系统组件事件，服务、驱动、系统级事件 |
| Application | Application | 应用程序事件 |
| Setup | Setup | 系统安装和升级事件 |
| Forwarded Events | ForwardedEvents | 转发的事件 |
| Sysmon | Microsoft-Windows-Sysmon/Operational | Sysmon 系统监控 |
| PowerShell | Microsoft-Windows-PowerShell/Operational | PowerShell 执行日志 |
| SMB Server | Microsoft-Windows-SMBServer/Operational | SMB 服务器事件 |
| SMB Client | Microsoft-Windows-SMBClient/Operational | SMB 客户端事件 |
| WinRM | Microsoft-Windows-WinRM/Operational | Windows 远程管理 |
| Windows Firewall | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | 防火墙事件 |
| Windows Defender | Microsoft-Windows-Windows Defender/Operational | Windows Defender |
| Windows Defender Exploit Guard | Microsoft-Windows-Windows Defender Exploit Guard/Operational | WDEG |
| DHCP Client | Microsoft-Windows-Dhcp-Client/Operational | DHCP 客户端事件 |
| DHCP Server | Microsoft-Windows-Dhcpv6-Client/Operational | DHCP 服务器事件 |
| DNS Client | Microsoft-Windows-DNS Client/Operational | DNS 客户端事件 |
| DNS Server | Microsoft-Windows-DNSServer/Operational | DNS 服务器事件 |
| Active Directory | Microsoft-Windows-Directory Services-SAM/Operational | AD 账户事件 |
| Terminal Services | Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational | RDP 连接管理 |
| Terminal Services | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | 本地会话 |
| BitLocker | Microsoft-Windows-BitLocker/DriveEncryptionReady | BitLocker 状态 |
| Windows Update | Microsoft-Windows-WindowsUpdateClient/Operational | Windows 更新 |
| Print Spooler | Microsoft-Windows-PrintService/Admin | 打印服务管理 |
| Print Service | Microsoft-Windows-PrintService/Operational | 打印服务操作 |
| Network Policy Server | Microsoft-Windows-NPS/Operational | NPS/RADIUS |
| RemoteAccess | Microsoft-Windows-RemoteAccess/Operational | VPN/路由远程访问 |
| BranchCache | Microsoft-Windows-BranchCache/Operational | BranchCache 事件 |
| Hyper-V | Microsoft-Windows-Hyper-V-*-Operational | Hyper-V 虚拟化 |
| Hyper-V VMMS | Microsoft-Windows-Hyper-V-VmSwitch/Operational | Hyper-V 虚拟交换机 |
| Windows Deployment Services | Microsoft-Windows-Deployment-Services/Management | WDS 管理 |
| Security Center | Microsoft-Windows-Security-Auditing | 安全审核 |
| WMI | Microsoft-Windows-WMI-Activity/Operational | WMI 活动 |
| Group Policy | Microsoft-Windows-GroupPolicy/Operational | 组策略事件 |
| Task Scheduler | Microsoft-Windows-TaskScheduler/Operational | 计划任务事件 |
| Certificate Services | Microsoft-Windows-CertificateServices/Operational | 证书服务 |
| Distributed Transaction Coordinator | Microsoft-Windows-DistributedCOM | 分布式 COM |
| Windows SharePoint | Microsoft-SharePoint Products | SharePoint 事件 |
| File Server Resource Manager | Microsoft-Windows-FileServerResourceManager/Operational | FSRM 事件 |
| IIS | Microsoft-IIS_Configuration* | IIS 配置 |
| IIS FTP | Microsoft-IIS_FTP* | IIS FTP 事件 |
| AppLocker | Microsoft-Windows-AppLocker/EXE and DLL | AppLocker 事件 |
| Windows Event Collector | Microsoft-Windows-EventCollector/Operational | 事件收集器 |
| Credential Guard | Microsoft-Windows-CredentialUI | 凭据保护 |
| Secure Boot | Microsoft-Windows-SecureBoot/Operational | 安全启动 |
| Device Guard | Microsoft-Windows-DeviceGuard/Operational | Device Guard |
| Windows Subsystem for Linux | Microsoft-Windows-Windows Subsystem for Linux/Operational | WSL 事件 |

### 1.3 事件级别

| 值 | 常量 | 说明 |
|----|------|------|
| 0 | LogAlways | 无关紧要 |
| 1 | Critical | 严重错误 |
| 2 | Error | 错误 |
| 3 | Warning | 警告 |
| 4 | Information | 信息 |
| 5 | Verbose | 详细 |

> **注意**: Windows Security 日志使用审核级别 (Audit Success/Audit Failure)，在事件视图中显示为"审核成功"/"审核失败"。

### 1.4 快速查询表

| 场景 | 推荐查看的日志 |
|------|---------------|
| 账户登录异常 | Security, WinRM, Terminal Services |
| 横向移动 | Security, SMB Server/Client, WinRM |
| 持久化 | Security, System, Task Scheduler, Services |
| 权限提升 | Security, Application |
| 数据窃取 | SMB Server, DNS, Firewall |
| 恶意软件 | Windows Defender, Sysmon, PowerShell |
| 网络攻击 | Firewall, SMB, DNS, WinRM |
| 凭证攻击 | Security, Active Directory, NPS |
| 持久化检测 | Registry, Services, Scheduled Tasks, WMI |

---

## 二、安全日志 (Security) 事件 ID

安全日志是应急响应中最重要的日志源，记录账户登录、权限变更、策略修改等关键安全事件。

### 2.1 账户登录类 (4624-4634, 4648, 4672)

#### 4624 - 登录成功

**级别**: 审核成功 (AuditSuccess)
**描述**: 用户成功登录到计算机

**重要字段**:

| 字段 | 说明 | 应急场景 |
|------|------|----------|
| SubjectUserName | 登录账户 | 确认登录人 |
| TargetUserName | 目标账户 | 确认被登录的账户 |
| LogonType | 登录类型 (见附录A) | 判断登录方式 |
| IpAddress | 来源 IP | 判断攻击来源 |
| WorkstationName | 来源计算机 | 判断攻击路径 |
| AuthenticationPackage | 认证包 | NTLM/Kerberos 鉴别 |

**LogonType 登录类型详解**:

| 值 | 类型名称 | 说明 | 风险 |
|----|----------|------|------|
| 2 | Interactive | 本地交互登录 | 低 |
| 3 | Network | 网络共享/SMB | 中 |
| 4 | Batch | 计划任务 | 中 |
| 5 | Service | 服务账户 | 高 |
| 7 | Unlock | 解锁工作站 | 低 |
| 8 | NetworkCleartext | 网络明文 (HTTP) | 高 |
| 9 | NewCredentials | RunAs / 网络带凭据 | 高 |
| 10 | RemoteInteractive | RDP 远程桌面 | 高 |
| 11 | CachedInteractive | 缓存登录 | 低 |

**应急场景**:
- **RDP 横向移动**: LogonType=10 且来自外部 IP → 检查是否为合法管理员登录
- **Pass-the-Hash**: LogonType=3 且存在 Golden Ticket 特征
- **异常时间登录**: 非工作时间的管理员登录

---

#### 4625 - 登录失败

**级别**: 审核失败 (AuditFailure)
**描述**: 用户登录计算机失败

**重要字段**:

| 字段 | 说明 | 应急场景 |
|------|------|----------|
| TargetUserName | 目标账户 | 确认被尝试破解的账户 |
| FailureReason | 失败原因 | 分析失败原因 |
| Status | 状态码 | NTLM 状态 |
| SubStatus | 子状态 | Kerberos 详细状态 |
| IpAddress | 来源 IP | 定位攻击源 |

**常见 FailureReason**:

| 值 | 说明 | 风险 |
|----|------|------|
| Unknown user name or bad password | 用户名不存在或密码错误 | 中 |
| Account locked out | 账户已锁定 | 高 |
| The specified account password has expired | 密码已过期 | 低 |
| No such user | 用户不存在 | 低 |

**应急场景**:
- **暴力破解**: 同一账户短时间内大量 4625 → 可能是密码喷洒或暴力破解
- **密码喷洒**: 多个不同账户少量失败尝试 → 攻击者使用常见密码批量尝试
- **密码猜测**: 单一账户大量失败 → 定向攻击

---

#### 4626 - 登录成功/失败 (仅域控制器)

**级别**: 审核成功/失败
**描述**: 域控制器上的登录尝试

---

#### 4634 - 注销

**级别**: 审核成功
**描述**: 用户注销会话

**应急场景**:
- 短时间登录后立即注销 → 可能存在异常
- 结合 4624 分析会话时长

---

#### 4648 - 显式凭据登录

**级别**: 审核成功
**描述**: 使用显式凭据登录（不同于当前登录用户的凭据）

**重要字段**:

| 字段 | 说明 |
|------|------|
| SubjectUserName | 发起账户 |
| TargetUserName | 目标账户 |
| TargetServerName | 目标服务器 |
| IpAddress | 来源 IP |

**应急场景**:
- **横向移动**: 使用本地管理员账户通过网络登录其他主机
- **RunAs 执行**: 管理员使用其他账户身份运行程序
- **Pass-the-Hash**: 攻击者使用窃取的哈希进行横向移动

---

#### 4672 - 特权分配

**级别**: 审核成功
**描述**: 被授予特殊权限的账户

**常见分配权限**:
- SeSecurityPrivilege (管理安全日志)
- SeBackupPrivilege (备份文件和目录)
- SeRestorePrivilege (恢复文件和目录)
- SeTakeOwnershipPrivilege (取得文件或其他对象的所有权)
- SeDebugPrivilege (调试程序)
- SeSystemEnvironmentPrivilege (修改固件环境值)
- SeLoadDriverPrivilege (加载或卸载驱动程序)
- SeRemoteShutdownPrivilege (从远程系统强制关机)

**应急场景**:
- **权限提升**: 普通用户获得管理员权限
- **黄金票据**: 攻击者获得 KRBTGT 账户的特殊权限
- **检测**: 监视非管理员账户获得 SeDebugPrivilege 或 SeLoadDriverPrivilege

---

#### 4673 - 特权服务请求

**级别**: 审核成功
**描述**: 账户请求了特权服务

---

#### 4674 - 对特权对象操作

**级别**: 审核成功
**描述**: 对令牌对象执行了操作

---

### 2.2 账户管理类 (4720-4737)

#### 4720 - 账户已创建

**级别**: 审核成功
**描述**: 创建了新用户账户

**应急场景**:
- **恶意账户**: 攻击者创建后门账户用于持久化
- **服务账户**: 攻击者创建服务账户用于横向移动
- **检测**: 事件 ID 4720 之后紧接着 4672 → 账户创建后立即获得特权

---

#### 4722 - 账户已启用

**级别**: 审核成功
**描述**: 禁用的账户被启用

---

#### 4723 - 尝试更改账户密码

**级别**: 审核成功
**描述**: 用户尝试更改密码

---

#### 4724 - 尝试重置账户密码

**级别**: 审核成功
**描述**: 重置了账户密码

**应急场景**:
- **密码重置**: 攻击者重置管理员密码获取持久化

---

#### 4725 - 账户已禁用

**级别**: 审核成功
**描述**: 账户被禁用

---

#### 4726 - 账户已删除

**级别**: 审核成功
**描述**: 账户被删除

---

#### 4727 - 启用全局组成员

**级别**: 审核成功
**描述**: 启用全局安全组成员

---

#### 4728 - 添加到安全组

**级别**: 审核成功
**描述**: 账户被添加到安全组

**重要字段**:
| 字段 | 说明 |
|------|------|
| Member | 新增成员 (Sid 或 User) |
| TargetUserName | 目标组名 |

**应急场景**:
- 用户被添加到 Domain Admins → 严重安全事件
- 用户被添加到 Backup Operators → 可能是数据窃取准备

---

#### 4729 - 从安全组移除

**级别**: 审核成功
**描述**: 账户从安全组移除

---

#### 4730 - 启用安全组

**级别**: 审核成功
**描述**: 启用安全组

---

#### 4731 - 创建安全组

**级别**: 审核成功
**描述**: 创建新的安全组

---

#### 4732 - 添加到安全组

**级别**: 审核成功
**描述**: 成员被添加到受限制的安全组

**重要字段**:
- Member: 新增成员的账户名或 SID
- TargetUserName: 目标组名

**应急场景**:
- 用户被添加到 Administrators 组 → 权限提升
- 用户被添加到 Remote Desktop Users 组 → 远程访问
- 用户被添加到 Network Configuration Operators → 网络配置修改

---

#### 4733 - 从安全组移除

**级别**: 审核成功
**描述**: 成员从安全组移除

---

#### 4735 - 安全组已更改

**级别**: 审核成功
**描述**: 安全组属性被修改

---

#### 4737 - 安全组已更改

**级别**: 审核成功
**描述**: 安全组被修改

---

#### 4738 - 用户账户已更改

**级别**: 审核成功
**描述**: 用户账户属性被修改

---

#### 4740 - 账户已锁定

**级别**: 审核成功
**描述**: 账户因登录失败次数过多被锁定

**应急场景**:
- **暴力破解**: 大量 4625 后紧接着 4740 → 确认暴力破解正在进行

---

#### 4741 - 计算机账户已创建

**级别**: 审核成功
**描述**: 创建了新的计算机账户

---

#### 4742 - 计算机账户已更改

**级别**: 审核成功
**描述**: 计算机账户属性被修改

---

#### 4743 - 计算机账户已删除

**级别**: 审核成功
**描述**: 计算机账户被删除

---

### 2.3 进程和计划任务类 (4688, 4697-4698, 4702)

#### 4688 - 新进程创建

**级别**: 审核成功
**描述**: 创建了新进程

**重要字段**:

| 字段 | 说明 | 应急场景 |
|------|------|----------|
| NewProcessName | 新进程路径 | 识别恶意软件 |
| CreatorProcessId | 父进程 PID | 追踪父进程 |
| TokenElevationType | 令牌提升类型 | UAC 检测 |
| ProcessCommandLine | 命令行参数 | 分析攻击意图 |
| TargetUserName | 进程所有者 | 确认权限 |

**TokenElevationType 值**:

| 值 | 类型 | 说明 |
|----|------|------|
| TokenElevationTypeDefault | 默认 | 非管理员 |
| TokenElevationTypeFull | 完全提升 | 管理员且已提升 |
| TokenElevationTypeLimited | 受限提升 | 管理员但未提升 |

**应急场景**:
- **恶意软件执行**: 异常路径的进程 (如 Temp 目录下的 exe)
- **Living Off the Land**: 使用 certutil、mshta、cmstp 等合法工具下载执行
- **横向移动**: RDP 剪贴板同步或 SMBD spawned 进程
- **检测特征**: 长命令行、Base64 编码、Powershell -enc 参数

---

#### 4689 - 进程退出

**级别**: 审核成功
**描述**: 进程退出

---

#### 4697 - 服务创建

**级别**: 审核成功
**描述**: 创建了新的服务

**重要字段**:

| 字段 | 说明 |
|------|------|
| ServiceName | 服务名称 |
| ImagePath | 服务可执行文件路径 |
| StartType | 启动类型 |
| ServiceAccount | 服务运行账户 |

**应急场景**:
- **持久化**: 创建异常服务
- **恶意服务**: 服务可执行文件来自 Temp 或网络路径
- **检测**: 常见恶意服务名称 (如 svc-host, update, security)

---

#### 4698 - 计划任务创建

**级别**: 审核成功
**描述**: 创建了新的计划任务

**重要字段**:

| 字段 | 说明 |
|------|------|
| TaskName | 任务名称 |
| TaskContent | 任务内容 XML |
| Author | 任务创建者 |
| TriggerString | 触发器描述 |

**应急场景**:
- **持久化**: 恶意计划任务用于定时执行
- **检测**: 异常执行时间、异常路径的任务

---

#### 4699 - 计划任务删除

**级别**: 审核成功
**描述**: 计划任务被删除

---

#### 4700 - 计划任务启用

**级别**: 审核成功
**描述**: 计划任务被启用

---

#### 4701 - 计划任务禁用

**级别**: 审核成功
**描述**: 计划任务被禁用

---

#### 4702 - 计划任务更改

**级别**: 审核成功
**描述**: 计划任务被修改

---

### 2.4 文件系统和注册表操作类 (4656-4658, 4660-4663, 4670)

#### 4656 - 请求对象句柄

**级别**: 审核成功/失败
**描述**: 请求访问对象的句柄

**重要字段**:
| 字段 | 说明 |
|------|------|
| ObjectType | 对象类型 (File, Key, Process 等) |
| ObjectName | 对象名称 |
| AccessMask | 请求的访问权限 |

**注意**: 此事件需开启"审核对象访问"策略

---

#### 4657 - 注册表键创建/修改

**级别**: 审核成功
**描述**: 创建或修改注册表键

**重要字段**:

| 字段 | 说明 |
|------|------|
| ObjectName | 注册表路径 |
| OperationType | 操作类型 |
| OldAttributes | 旧属性 |
| NewAttributes | 新属性 |

**应急场景**:
- **持久化**: 修改 Run 键 (HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Run)
- **UAC 绕过**: 修改 AlwaysInstallElevated 或 fodhelper
- **攻击**: 修改服务配置或权限

---

#### 4658 - 关闭对象句柄

**级别**: 审核成功
**描述**: 关闭对象句柄

---

#### 4660 - 删除对象

**级别**: 审核成功
**描述**: 删除对象

---

#### 4662 - 对象操作

**级别**: 审核成功
**描述**: 对目录服务对象执行操作

---

#### 4663 - 尝试访问对象

**级别**: 审核成功/失败
**描述**: 尝试访问对象

**重要字段**:
| 字段 | 说明 |
|------|------|
| ObjectType | 对象类型 |
| ObjectName | 对象名称 |
| AccessMask | 请求的访问权限 |

**应急场景**:
- **数据窃取**: 访问敏感文件 (数据库、备份)
- **权限变更**: 修改文件权限

---

#### 4670 - 对象权限更改

**级别**: 审核成功
**描述**: 对象的权限被修改

---

### 2.5 网络和共享类 (5140-5145)

#### 5140 - 网络文件夹访问

**级别**: 审核成功
**描述**: 访问网络共享

**重要字段**:

| 字段 | 说明 |
|------|------|
| ShareName | 共享名称 |
| SubjectUserName | 访问账户 |
| IpAddress | 来源 IP |

---

#### 5141 - 网络文件夹详细

**级别**: 审核成功
**描述**: 网络共享详细信息

---

#### 5142 - SMB 详细

**级别**: 审核成功
**描述**: SMB 会话设置

---

#### 5143 - SMB 详细

**级别**: 审核成功
**描述**: SMB 会话断开

---

#### 5144 - SMB 详细

**级别**: 审核成功
**描述**: SMB 会话重新连接

---

#### 5145 - 网络共享访问检查

**级别**: 审核成功/失败
**描述**: 检查网络共享访问权限

**重要字段**:

| 字段 | 说明 | 应急场景 |
|------|------|----------|
| ShareName | 共享名称 | 确认被访问的共享 |
| RelativeTargetName | 目标文件名 | 分析攻击意图 |
| AccessMask | 访问权限 | 读/写/删除 |
| IpAddress | 来源 IP | 定位攻击源 |

**应急场景**:
- **数据外泄**: 访问 admin$、c$ 等管理共享
- **横向移动**: 通过 SMB 访问其他主机
- **检测**: 异常时间访问敏感共享

---

### 2.6 日志和审计类 (1102, 4719)

#### 1102 - 安全日志已清除

**级别**: 审核成功
**描述**: 安全日志被清除

**重要字段**:

| 字段 | 说明 |
|------|------|
| SubjectUserName | 执行清除的账户 |
| SubjectDomainName | 账户所在域/计算机 |

**应急场景**:
- **攻击者痕迹隐藏**: 清除日志是最常见的攻击后行为
- **误报排除**: 管理员正常维护
- **必查事件**: 发现此事件应立即调查之前时间段的所有活动

---

#### 1104 - 安全日志记录已满

**级别**: 信息
**描述**: 安全日志达到最大大小

---

#### 4719 - 审核策略已更改

**级别**: 审核成功
**描述**: 系统审核策略被修改

**重要字段**:

| 字段 | 说明 |
|------|------|
| SubjectUserName | 修改策略的账户 |
| AuditPolicyChanges | 变更内容 |

**应急场景**:
- **攻击者**: 关闭审核功能以避免检测
- **持久化**: 修改审核策略确保长期隐藏

---

### 2.7 Kerberos 认证类 (4768-4774)

#### 4768 - TGT 请求

**级别**: 审核成功/失败
**描述**: 请求 Kerberos TGT (票据授予票据)

**重要字段**:

| 字段 | 说明 |
|------|------|
| TargetUserName | 请求的账户 |
| TargetDomainName | 目标域 |
| Status | 请求状态 |
| PreAuthType | 预认证类型 |

**应急场景**:
- **密码猜测**: 大量 4768 失败 → 可能是 AS-REProasting
- **Golden Ticket**: 使用伪造的 TGT (需结合 4672 分析)

---

#### 4769 - TGS 请求

**级别**: 审核成功/失败
**描述**: 请求 Kerberos TGS (票据授予服务)

**重要字段**:

| 字段 | 说明 |
|------|------|
| TargetUserName | 目标账户 |
| ServiceName | 请求的服务 |
| Status | 请求状态 |

**应急场景**:
- **Kerberoasting**: 请求服务票据后离线破解密码
- **检测**: 监视非正常服务账户的 TGS 请求

---

#### 4770 - TGS 更新

**级别**: 审核成功
**描述**: Kerberos TGS 票据已更新

---

#### 4771 - 预认证失败

**级别**: 审核失败
**描述**: Kerberos 预认证失败

**Status 值**:

| 值 | 说明 |
|----|------|
| 0x6 | KDC_ERR_PREAUTH_FAILED - 密码错误 |
| 0x17 | KDC_ERR_CLIENT_REVOKED - 账户已禁用/锁定 |
| 0x18 | KDC_ERR_KEY_EXPIRED - 密码已过期 |

**应急场景**:
- **密码猜测**: 攻击者尝试破解密码
- **AS-REProasting**: 不使用预认证的账户被攻击

---

#### 4772 - TGT 请求失败

**级别**: 审核失败
**描述**: TGT 请求失败

---

#### 4773 - TGS 请求失败

**级别**: 审核失败
**描述**: TGS 请求失败

---

#### 4774 - 账户登录信息显示

**级别**: 审核成功
**描述**: 账户映射请求

---

#### 4776 - 域控制器尝试验证账户凭据

**级别**: 审核成功/失败
**描述**: DC 尝试验证账户凭据

**应急场景**:
- **凭据验证**: Pass-the-Hash 验证
- **密码喷洒**: 多个账户凭据验证失败

---

## 三、系统日志 (System) 事件 ID

### 3.1 服务类事件 (7045, 7030-7036)

#### 7045 - 服务创建

**级别**: 信息
**描述**: 创建了新的 Windows 服务

**重要字段**:

| 字段 | 说明 |
|------|------|
| ServiceName | 服务名称 |
| ImagePath | 服务可执行文件路径 |
| ServiceType | 服务类型 |
| StartType | 启动类型 |
| ServiceAccount | 服务运行账户 |

**应急场景**:
- **恶意服务**: 攻击者创建服务实现持久化
- **检测**: 可执行文件路径为 Temp、网络路径或短文件名
- **常见恶意服务名**: sc.exe 创建的服务可能使用随机名称

---

#### 7030 - 安全权限警告

**级别**: 警告
**描述**: 服务配置的安全权限不是最佳

---

#### 7031 - 服务意外终止

**级别**: 错误
**描述**: 服务意外终止

**应急场景**:
- **攻击**: 服务被攻击者手动终止
- **检测**: 分析服务终止前的其他异常事件

---

#### 7032 - 服务控制管理器

**级别**: 错误
**描述**: 服务控制管理器无法处理启动失败

---

#### 7033 - 服务恢复

**级别**: 信息
**描述**: 服务进入故障恢复状态

---

#### 7034 - 服务意外退出

**级别**: 错误
**描述**: 服务意外退出

---

#### 7035 - 发送控制到服务

**级别**: 信息
**描述**: 发送控制代码到服务

---

#### 7036 - 服务状态更改

**级别**: 信息
**描述**: 服务启动、停止或暂停

**应急场景**:
- **监控**: 监控关键服务状态变更
- **异常**: 非预期的服务停止

---

#### 7037 - 服务权限警告

**级别**: 警告
**描述**: 服务权限不足以访问资源

---

#### 7040 - 服务启动类型更改

**级别**: 信息
**描述**: 服务的启动类型已更改

---

#### 7045 - 服务创建

同 3.1 节所述

---

### 3.2 系统类事件

#### 6005 - 事件日志服务已启动

**级别**: 信息
**描述**: 系统启动

**应急场景**:
- **系统重启**: 结合其他事件分析系统运行时间

---

#### 6006 - 事件日志服务已停止

**级别**: 信息
**描述**: 系统正常关机

---

#### 6008 - 意外关闭

**级别**: 错误
**描述**: 系统意外关闭

---

#### 41 - 系统意外重启

**级别**: 关键
**描述**: 系统在没有正确关机的情况下重启

**可能原因**:
- 电源故障
- 硬件故障
- 系统崩溃 (BSOD)
- 远程攻击导致重启

---

## 四、Sysmon 事件 ID (1-22)

Sysmon (System Monitor) 是 Microsoft 的免费工具，提供系统活动的高级监控能力。

### 4.1 进程活动 (Event ID 1)

#### EventID 1 - Process Creation

**描述**: 创建新进程

**字段**:

| 字段 | 说明 | 应急场景 |
|------|------|----------|
| Image | 可执行文件路径 | 识别恶意软件 |
| CommandLine | 命令行参数 | 分析攻击意图 |
| ParentImage | 父进程路径 | 追踪来源 |
| ParentCommandLine | 父进程命令行 | 分析父进程行为 |
| User | 进程所有者 | 确认权限 |
| Hashes | 文件哈希 | 恶意软件识别 |

**应急场景**:
- **攻击**: 使用 mshta、rundll32、regsvr32 执行恶意代码
- **检测**: ParentImage 为 cmd.exe 或 powershell.exe 的异常子进程
- **特征**: 长命令行、Base64、环境变量混淆

---

### 4.2 文件时间戳修改 (Event ID 2)

#### EventID 2 - File Creation Time Changed

**描述**: 文件创建时间被修改

**字段**:
| 字段 | 说明 |
|------|------|
| Image | 修改进程路径 |
| TargetFilename | 目标文件 |
| CreationUtcTime | 原创建时间 |
| PreviousCreationUtcTime | 之前的创建时间 |

**应急场景**:
- **反取证**: 攻击者修改文件时间戳隐藏恶意文件
- **检测**: 异常时间戳修改或与正常模式不符的时间

---

### 4.3 网络连接 (Event ID 3)

#### EventID 3 - Network Connection

**描述**: 建立网络连接

**字段**:

| 字段 | 说明 | 应急场景 |
|------|------|----------|
| Image | 进程路径 | 识别连接来源 |
| DestPort | 目标端口 | 分析攻击目标 |
| DestIp | 目标 IP | 定位 C2 服务器 |
| Protocol | 协议 (TCP/UDP) | 分析连接类型 |

**应急场景**:
- **C2 通信**: 恶意软件与命令控制服务器通信
- **数据外泄**: 异常向外连接
- **检测**: 连接到可疑端口 (4444, 8080, 443) 或 IP

---

### 4.4 进程镜像加载 (Event ID 4, 7)

#### EventID 4 - Reserved

#### EventID 7 - Image Loaded

**描述**: 进程加载了模块

**字段**:

| 字段 | 说明 | 应急场景 |
|------|------|----------|
| Image | 加载模块的进程 | 分析加载来源 |
| ImageLoaded | 加载的模块路径 | 检测 DLL 注入 |
| Hashes | 模块哈希 | 恶意 DLL 识别 |

**应急场景**:
- **DLL 注入**: 恶意 DLL 被加载到合法进程
- **供应链攻击**: 恶意 DLL 替换合法模块
- **检测**: 加载来自 Temp 或网络路径的 DLL

---

### 4.5 线程和进程操作 (Event ID 8, 10)

#### EventID 8 - CreateRemoteThread

**描述**: 创建远程线程

**字段**:

| 字段 | 说明 | 应急场景 |
|------|------|----------|
| SourceImage | 源进程 | 攻击者进程 |
| TargetImage | 目标进程 | 被注入进程 |
| StartAddress | 线程起始地址 | 检测恶意代码执行 |

**应急场景**:
- **进程注入**: 攻击者将代码注入到其他进程
- **检测**: 注入到 lsass.exe、explorer.exe 等系统进程

---

#### EventID 10 - ProcessAccess

**描述**: 访问进程内存

**字段**:

| 字段 | 说明 | 应急场景 |
|------|------|----------|
| SourceImage | 访问进程 | 攻击者 |
| TargetImage | 被访问进程 | 目标 |
| GrantedAccess | 访问权限 | 分析操作意图 |

**应急场景**:
- **凭据窃取**: 访问 lsass.exe 进程内存
- **检测**: GrantedAccess 包含 PROCESS_VM_READ (0x10)

---

### 4.6 文件操作 (Event ID 5, 6, 9, 15)

#### EventID 5 - Process Terminated

**描述**: 进程终止

#### EventID 6 - Driver Loaded

**描述**: 驱动加载

#### EventID 9 - RawAccessRead

**描述**: 通过 \\.\ 读取原始磁盘

#### EventID 15 - FileCreate

**描述**: 文件创建

---

### 4.7 注册表操作 (Event ID 12, 13, 14)

#### EventID 12 - RegistryEvent (Object Create/Delete)

**描述**: 注册表键或值创建/删除

#### EventID 13 - RegistryEvent (Value Set)

**描述**: 注册表值修改

#### EventID 14 - RegistryEvent (Key/Rename)

**描述**: 注册表键重命名

**重要字段**:

| 字段 | 说明 | 应急场景 |
|------|------|----------|
| Image | 操作进程 | 识别操作来源 |
| TargetObject | 注册表路径 | 分析持久化 |
| Details | 操作详情 | 分析修改内容 |

**应急场景**:
- **持久化**: 修改 Run、RunOnce、IFEO 等键
- **UAC 绕过**: 修改 App Paths、Fodhelper
- **检测**: 分析注册表修改的上下文

---

### 4.8 Sysmon 状态事件 (Event ID 4, 16, 17, 18)

#### EventID 16 - Sysmon Configuration Changed

**描述**: Sysmon 配置已更改

#### EventID 17 - Pipe Created

**描述**: 命名管道创建

#### EventID 18 - Pipe Connected

**描述**: 命名管道连接

**应急场景**:
- **横向移动**: 使用命名管道进行进程间通信
- **检测**: 分析管道的创建和使用模式

---

### 4.9 WMI 活动 (Event ID 19, 20, 21)

#### EventID 19 - WmiEventFilter

**描述**: WMI 事件过滤器创建

#### EventID 20 - WmiEventConsumer

**描述**: WMI 事件消费者创建

#### EventID 21 - WmiEventConsumerToFilter

**描述**: WMI 消费者绑定到过滤器

**应急场景**:
- **WMI 持久化**: 使用 WMI 实现无文件持久化
- **检测**: 分析 WMI 过滤器和消费者的内容

---

### 4.10 其他 Sysmon 事件

#### EventID 22 - DNSEvent

**描述**: DNS 查询事件

**应急场景**:
- **C2 检测**: 分析 DNS 查询模式
- **数据外泄**: 通过 DNS 隧道传输数据

---

## 五、PowerShell 事件 ID

PowerShell 是攻击者常用的工具，完整记录其执行日志对应急响应至关重要。

### 5.1 PowerShell 操作日志

#### 4103 - 模块日志

**描述**: PowerShell 模块执行

**字段**:

| 字段 | 说明 |
|------|------|
| ScriptName | 脚本名称 |
| ScriptPath | 脚本路径 |
| Command | 执行的命令 |
| Member | 执行类型 |

---

#### 4104 - 脚本块日志

**描述**: PowerShell 脚本块执行

**字段**:

| 字段 | 说明 | 应急场景 |
|------|------|----------|
| ScriptBlockText | 执行的脚本内容 | 分析恶意代码 |
| Path | 脚本路径 | 识别来源 |

**应急场景**:
- **攻击**: 编码命令执行 (Base64)
- **检测**: 分析脚本内容是否包含恶意特征
- **特征**: DownloadString、DownloadFile、Invoke-Expression、IEX

---

## 六、IIS HTTP 日志

### 6.1 IIS 日志格式

IIS 日志默认位置: `%SystemDrive%\inetpub\logs\LogFiles\`

**日志字段 (W3C 扩展格式)**:

| 字段 | 说明 | 应急场景 |
|------|------|----------|
| date | 日期 | 时间分析 |
| time | 时间 | 时间分析 |
| s-ip | 服务器 IP | 确认响应服务器 |
| cs-method | HTTP 方法 | GET/POST/PUT |
| cs-uri-stem | 请求 URI | 分析攻击目标 |
| cs-uri-query | 请求参数 | 分析攻击payload |
| s-port | 服务器端口 | 确认服务端口 |
| cs-username | 用户名 | 识别攻击者 |
| c-ip | 客户端 IP | 定位攻击源 |
| cs(User-Agent) | 客户端代理 | 识别攻击工具 |
| sc-status | HTTP 状态码 | 分析响应 |
| sc-substatus | HTTP 子状态码 | 详细错误 |
| time-taken | 响应时间 | 分析性能 |

### 6.2 常见 HTTP 状态码

| 状态码 | 说明 | 应急场景 |
|--------|------|----------|
| 200 | OK | 正常请求 |
| 301 | 永久重定向 | - |
| 302 | 临时重定向 | - |
| 400 | 错误请求 | 可能的攻击尝试 |
| 401 | 未授权 | 认证失败 |
| 403 | 禁止访问 | 权限不足或被拒绝 |
| 404 | 未找到 | 目录扫描 |
| 500 | 服务器内部错误 | 应用漏洞 |
| 502 | 错误网关 | 攻击特征 |

### 6.3 WebShell 检测特征

- 请求路径包含异常文件名 (cmd.aspx, shell.aspx)
- 请求参数包含可疑命令 (whoami, dir, type)
- User-Agent 包含常见攻击工具特征
- 大量 POST 请求到同一文件
- 异常时间的请求

---

## 七、WinRM (Windows Remote Management) 事件 ID

**日志通道**: `Microsoft-Windows-WinRM/Operational`

WinRM 是 Windows 远程管理的基础组件，常被用于横向移动和远程执行。

### 7.1 WinRM 服务事件

#### EventID 6 - WinRM 服务已启动

**描述**: WinRM 服务成功启动

**级别**: 信息

---

#### EventID 4 - WinRM 错误

**描述**: WinRM 服务发生错误

**字段**:
| 字段 | 说明 |
|------|------|
| ErrorCode | 错误代码 |
| Service | 服务名称 |
| Command | 相关命令 |

**应急场景**:
- WinRM 连接失败 → 可能是凭据问题或网络限制
- 异常错误代码 → 排查安全配置

---

#### EventID 8 - 客户端事件

**描述**: WinRM 客户端尝试连接

**字段**:
| 字段 | 说明 |
|------|------|
| ClientIP | 客户端 IP 地址 |
| ClientPort | 客户端端口 |
| Target | 目标计算机 |
| Action | 操作类型 |

**应急场景**:
- 异常的 WinRM 连接 → 可能存在横向移动
- 连接到非预期目标 → 检测可疑活动

---

### 7.2 WinRM 远程命令执行

#### EventID 81 - WSMan 操作

**描述**: WSMan (WMI over WS-Man) 操作

**字段**:
| 字段 | 说明 |
|------|------|
| Operation | 操作类型 |
| ResourceURI | 资源 URI |
| User | 执行用户 |

**应急场景**:
- 检测远程 WMI 执行
- 分析 WinRM 命令历史

---

#### EventID 82-91 - Shell 操作

**描述**: WinRM Shell 操作事件

| EventID | 操作 |
|---------|------|
| 82 | Shell 创建 |
| 83 | Shell 关闭 |
| 84 | Shell 错误 |
| 85 | 命令执行 |
| 86 | 命令完成 |
| 87 | 数据接收 |
| 88 | 数据发送 |
| 89 | Shell 超时 |
| 90 | 会话断开 |
| 91 | 会话重连 |

**字段**:
| 字段 | 说明 |
|------|------|
| ShellId | Shell 会话 ID |
| Command | 执行的命令 |
| ExitCode | 退出代码 |

**应急场景**:
- **远程命令执行**: 攻击者通过 WinRM 执行恶意命令
- **检测**: 分析 Shell 创建和命令执行的时间线
- **横向移动**: 检测从一个主机到另一个主机的 WinRM 连接

---

### 7.3 WinRM 攻击检测特征

**攻击特征**:
- 从非工作时间发起的大量 WinRM 连接
- WinRM 连接后立即创建新进程
- 连接到多个不同目标主机的 WinRM 流量
- WinRM 连接来自异常 IP 地址

**检测规则**:
```
EventID 82 (Shell 创建) + EventID 85 (命令执行) → 关联分析
```

---

## 八、SMB Server/Client 事件 ID

**日志通道**: 
- `Microsoft-Windows-SMBServer/Operational`
- `Microsoft-Windows-SMBClient/Operational`

SMB (Server Message Block) 是 Windows 文件共享和横向移动的核心协议。

### 8.1 SMB Server 连接事件

#### EventID 1 - SMB 连接

**描述**: 建立了 SMB 连接

**字段**:
| 字段 | 说明 | 应急场景 |
|------|------|----------|
| ClientIP | 客户端 IP | 定位攻击源 |
| ServerIP | 服务器 IP | 确认目标 |
| ShareName | 访问的共享 | 分析攻击意图 |
| UserName | 连接用户 | 确认账户 |

---

#### EventID 2 - SMB 断开连接

**描述**: SMB 连接断开

---

#### EventID 3 - SMB Guest 访问

**描述**: 客户端以 Guest 身份访问

**应急场景**:
- 攻击者尝试使用 Guest 账户枚举共享
- 检测网络侦察活动

---

### 8.2 SMB 访问事件

#### EventID 4 - SMB 会话设置

**描述**: SMB 会话建立

**字段**:
| 字段 | 说明 |
|------|------|
| SessionId | 会话 ID |
| ClientIP | 客户端 IP |
| UserName | 用户名 |

---

#### EventID 5 - SMB 会话终止

**描述**: SMB 会话结束

---

### 8.3 SMB 文件访问事件

#### EventID 6 - 文件打开

**描述**: 打开文件

**字段**:
| 字段 | 说明 | 应急场景 |
|------|------|----------|
| ShareName | 共享名称 | 确认访问的共享 |
| RelativeTargetName | 目标文件名 | 分析攻击意图 |
| UserName | 操作用户 | 确认账户 |

**应急场景**:
- **数据窃取**: 大量访问敏感文件
- **勒索软件**: 访问大量文件并加密

---

#### EventID 7 - 文件关闭

**描述**: 关闭文件

---

### 8.4 SMB 树连接事件

#### EventID 8 - 树连接

**描述**: 连接到 SMB 共享

**字段**:
| 字段 | 说明 |
|------|------|
| ShareName | 共享名称 |
| TreeId | 树连接 ID |
| ClientIP | 客户端 IP |

---

#### EventID 9 - 树断开

**描述**: 断开树连接

---

### 8.5 SMB 签名事件

#### EventID 10 - SMB 签名要求

**描述**: SMB 连接签名设置

---

#### EventID 11 - SMB 签名失败

**描述**: SMB 签名验证失败

**应急场景**:
- 中间人攻击尝试
- SMB 连接篡改

---

### 8.6 SMB 错误事件

#### EventID 1000 - SMB Server 错误

**描述**: SMB 服务器错误

**字段**:
| 字段 | 说明 |
|------|------|
| ErrorCode | 错误代码 |
| FileNotFound | 文件未找到 |

---

#### EventID 1001 - SMB Server 警告

**描述**: SMB 服务器警告

---

#### EventID 2000 - SMB 拒绝访问

**描述**: SMB 访问被拒绝

**应急场景**:
- 权限不足的访问尝试
- 攻击者尝试访问受限共享

---

#### EventID 2001 - SMB 连接限制

**描述**: 连接数量达到限制

---

### 8.7 SMB 客户端事件

#### EventID 301 - SMB 客户端连接

**描述**: SMB 客户端连接到服务器

**字段**:
| 字段 | 说明 |
|------|------|
| ServerName | 服务器名称 |
| ServerIP | 服务器 IP |
| ShareName | 共享名称 |

---

#### EventID 302 - SMB 客户端断开

**描述**: SMB 客户端断开连接

---

#### EventID 303 - SMB 客户端错误

**描述**: SMB 客户端错误

---

### 8.8 SMB 攻击检测特征

**攻击特征**:
- 同一客户端 IP 大量 5145 事件 → 可能是数据窃取
- SMB 连接来自外部 IP → 可能是外部攻击
- 访问 admin$、c$ 等管理共享 → 横向移动
- SMB 连接后紧接着 4688 事件 → 远程执行

**关联规则**:
```
EventID 5140/5145 (SMB 访问) + EventID 4688 (进程创建) → 横向移动
```

---

## 九、Windows Firewall 事件 ID

**日志通道**: `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`

### 9.1 防火墙规则事件

#### EventID 2000 - 规则允许入站连接

**描述**: 入站连接被允许

**字段**:
| 字段 | 说明 |
|------|------|
| RuleName | 规则名称 |
| ModifyingUser | 修改用户 |
| ApplicationPath | 应用程序路径 |
| LocalAddress | 本地地址 |
| RemoteAddress | 远程地址 |
| Protocol | 协议 (TCP/UDP) |
| LocalPort | 本地端口 |
| RemotePort | 远程端口 |
| Direction | 方向 (入站/出站) |

---

#### EventID 2001 - 规则阻止入站连接

**描述**: 入站连接被阻止

**应急场景**:
- 检测外部扫描
- 分析攻击面

---

#### EventID 2002 - 规则允许出站连接

**描述**: 出站连接被允许

**应急场景**:
- C2 通信检测
- 数据外泄监测

---

#### EventID 2003 - 规则阻止出站连接

**描述**: 出站连接被阻止

**应急场景**:
- 恶意软件尝试连接 C2
- 检测未授权的网络行为

---

### 9.2 防火墙状态变更事件

#### EventID 2004 - 新规则添加

**描述**: 添加了新防火墙规则

**字段**:
| 字段 | 说明 |
|------|------|
| RuleId | 规则 ID |
| RuleName | 规则名称 |
| Origin | 规则来源 |

**应急场景**:
- 攻击者开放端口实现持久化
- 恶意软件开放后门端口

---

#### EventID 2005 - 规则修改

**描述**: 防火墙规则被修改

---

#### EventID 2006 - 规则删除

**描述**: 防火墙规则被删除

---

#### EventID 2007 - 默认规则修改

**描述**: 默认防火墙策略被修改

---

### 9.3 连接安全事件

#### EventID 3000 - 连接安全规则创建

**描述**: 创建了 IPsec 连接安全规则

---

#### EventID 3001 - IPsec 主模式协商

**描述**: IPsec 主模式 SA 建立

**字段**:
| 字段 | 说明 |
|------|------|
| LocalAddress | 本地地址 |
| RemoteAddress | 远程地址 |
| KeyingModule | 密钥模块 |
| NegotiationMode | 协商模式 |

---

#### EventID 3002 - IPsec 快速模式协商

**描述**: IPsec 快速模式 SA 建立

---

#### EventID 3003 - IPsec 主模式失败

**描述**: IPsec 主模式协商失败

**应急场景**:
- VPN 连接问题
- 恶意干扰 VPN 连接

---

### 9.4 防火墙审计事件

#### EventID 4000 - 防火墙启动

**描述**: 防火墙服务启动

---

#### EventID 4001 - 防火墙关闭

**描述**: 防火墙服务停止

**应急场景**:
- 攻击者禁用防火墙实现持久化
- 恶意软件尝试禁用防火墙

---

#### EventID 4002 - 防火墙配置更改

**描述**: 防火墙配置被修改

---

## 十、DHCP 事件 ID

**日志通道**: 
- `Microsoft-Windows-Dhcp-Client/Operational`
- `Microsoft-Windows-Dhcpv6-Client/Operational`
- `Microsoft-Windows-DhcpServer/Operational`

### 10.1 DHCP 客户端事件

#### EventID 1000 - DHCP 租约续订成功

**描述**: DHCP 租约成功续订

**字段**:
| 字段 | 说明 |
|------|------|
| IPAddress | 分配的 IP 地址 |
| HostName | 主机名 |
| MACAddress | MAC 地址 |
| RelayAgent | 中继代理地址 |

---

#### EventID 1001 - DHCP 租约获取

**描述**: 获取新的 DHCP 租约

**应急场景**:
- 新设备加入网络
- 异常 IP 分配

---

#### EventID 1002 - DHCP 租约释放

**描述**: 释放 DHCP 租约

---

#### EventID 1003 - DHCP 发现

**描述**: 客户端发送 DHCP Discover

---

#### EventID 1004 - DHCP 请求

**描述**: 客户端发送 DHCP Request

---

#### EventID 1005 - DHCP  Decline

**描述**: 客户端拒绝 DHCP Offer

---

#### EventID 1006 - DHCP Inform

**描述**: 客户端发送 DHCP Inform

---

#### EventID 1007 - DHCP NACK

**描述**: 服务器发送 DHCP NACK

---

### 10.2 DHCP 服务器事件 (10000-10999)

#### EventID 10000 - 地址分配

**描述**: DHCP 服务器分配地址

**字段**:
| 字段 | 说明 |
|------|------|
| IPAddress | 分配的 IP 地址 |
| ClientID | 客户端 ID (MAC) |
| VendorClass | 供应商类别 |
| UserClass | 用户类别 |

---

#### EventID 10001 - 地址续订

**描述**: DHCP 服务器续订地址

---

#### EventID 10002 - 地址释放

**描述**: DHCP 服务器释放地址

---

#### EventID 10003 - 冲突检测

**描述**: 检测到 IP 地址冲突

**应急场景**:
- 网络中存在 IP 地址冲突
- 可能的 ARP 欺骗攻击

---

#### EventID 10004 - 审核失败

**描述**: DHCP 审核失败

---

### 10.3 DHCP 攻击检测

**攻击特征**:
- 大量 10003 (冲突检测) → 可能是 ARP 欺骗
- 异常 MAC 地址请求大量 IP → 可能是 DHCP 饥饿攻击
- 来自非授权 DHCP 服务器的响应 → Rogue DHCP 检测

---

## 十一、DNS 事件 ID

**日志通道**: 
- `Microsoft-Windows-DNS Client/Operational`
- `Microsoft-Windows-DNSServer/Operational`

### 11.1 DNS 客户端事件

#### EventID 1000 - DNS 缓存成功

**描述**: DNS 查询成功

**字段**:
| 字段 | 说明 | 应急场景 |
|------|------|----------|
| QueryName | 查询的域名 | 分析查询目标 |
| QueryType | 查询类型 (A/AAAA/MX/TXT) | 分析查询意图 |
| QueryOptions | 查询选项 | - |
| SourceIP | DNS 服务器 IP | 确认使用的 DNS |
| Transport | 传输协议 (UDP/TCP) | - |

**应急场景**:
- 大量对外部域的查询 → 可能的 C2 通信
- 对可疑域名的查询 → 检测恶意软件

---

#### EventID 1001 - DNS 查询失败

**描述**: DNS 查询失败

**应急场景**:
- 对 C2 域名的查询失败 → 可能的 DNS 隧道
- 大量 DNS 查询失败 → 可能的网络攻击

---

#### EventID 1010 - DNS 缓存条目添加

**描述**: 添加 DNS 缓存条目

---

#### EventID 1011 - DNS 缓存条目删除

**描述**: 删除 DNS 缓存条目

---

### 11.2 DNS 服务器事件

#### EventID 2 - DNS 服务器启动

**描述**: DNS 服务器服务启动

---

#### EventID 4 - DNS 服务器关闭

**描述**: DNS 服务器服务关闭

---

#### EventID 6 - DNS 查询被处理

**描述**: DNS 服务器处理查询

**字段**:
| 字段 | 说明 |
|------|------|
| Fqdn | 完全限定域名 |
| QueryType | 查询类型 |
| ClientIP | 客户端 IP |
| ServerIP | 服务器 IP |
| Transport | 传输协议 |

---

#### EventID 7 - DNS 更新被处理

**描述**: DNS 动态更新

**字段**:
| 字段 | 说明 |
|------|------|
| UpdateType | 更新类型 |
| ZoneName | 区域名称 |
| ScavengingEnabled | 清理是否启用 |

---

#### EventID 8 - 区域传输请求

**描述**: 区域传输 (AXFR/IXFR) 请求

**应急场景**:
- 攻击者尝试获取 DNS 区域数据 → DNS 区域复制攻击
- 异常的 zone transfer → 数据窃取

---

#### EventID 9 - 区域传输完成

**描述**: 区域传输完成

---

#### EventID 10 - 安全区域传输请求

**描述**: 安全区域传输请求

---

#### EventID 11 - 递归查询超时

**描述**: 递归查询超时

---

#### EventID 12 - 递归查询失败

**描述**: 递归查询失败

---

### 11.3 DNS 攻击检测

**攻击特征**:
- 对异常长域名的查询 → DNS 隧道检测
- 大量不同子域的查询 → DGA (域名生成算法) 检测
- 来自单个源的快速连续查询 → 可能的 DNS 放大攻击
- 异常的 TXT 记录查询 → 数据窃取或 DNS 隧道

**检测规则**:
```
大量 EventID 1000 + 相似的查询间隔 → DGA 活动
```

---

## 十二、Terminal Services (RDP) 事件 ID

**日志通道**: 
- `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`
- `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`
- `Microsoft-Windows-TerminalServices-Publishing/Operational`

### 12.1 RDP 连接管理器事件

#### EventID 1140 - RDP 连接授权

**描述**: RDP 连接授权事件

**字段**:
| 字段 | 说明 |
|------|------|
| UserName | 用户名 |
| DomainName | 域名 |
| ClientIP | 客户端 IP |
| ListenerName | 监听器名称 |

---

#### EventID 1141 - RDP 用户会话重新连接

**描述**: 用户重新连接到现有会话

---

#### EventID 1142 - RDP 会话断开

**描述**: RDP 会话断开

---

#### EventID 1143 - RDP 连接超时

**描述**: RDP 连接超时

---

#### EventID 1144 - RDP 用户认证

**描述**: RDP 用户身份验证

**字段**:
| 字段 | 说明 |
|------|------|
| AuthenticationMethod | 认证方法 (NLA/Cert) |
| ClientIP | 客户端 IP |
| ClientBuild | 客户端版本 |

---

#### EventID 1145 - RDP 加密级别

**描述**: RDP 加密级别设置

---

#### EventID 1146 - RDP 许可警告

**描述**: RDP 许可警告

---

#### EventID 1147 - RDP 临时客户端连接

**描述**: 临时客户端连接

---

#### EventID 1148 - RDP 安全层

**描述**: RDP 安全层设置

---

#### EventID 1149 - RDP 用户成功登录

**描述**: 用户通过 RDP 成功登录

**字段**:
| 字段 | 说明 |
|------|------|
| UserName | 用户名 |
| DomainName | 域名 |
| ClientIP | 客户端 IP |
| SessionId | 会话 ID |

**应急场景**:
- **横向移动**: 攻击者通过 RDP 横向移动
- **外部访问**: 非预期来源的 RDP 登录
- **异常时间**: 非工作时间的 RDP 登录

---

### 12.2 本地会话管理器事件

#### EventID 21 - RDP 会话登录成功

**描述**: RDP 会话登录成功

**字段**:
| 字段 | 说明 |
|------|------|
| UserName | 用户名 |
| SessionId | 会话 ID |
| ClientIP | 客户端 IP |

---

#### EventID 22 - RDP 会话注销

**描述**: RDP 会话注销

---

#### EventID 23 - RDP 会话被锁定

**描述**: RDP 会话被锁定

---

#### EventID 24 - RDP 会话解锁

**描述**: RDP 会话解锁

---

#### EventID 25 - RDP 会话被终止

**描述**: RDP 会话被终止

---

#### EventID 27 - 会话已创建

**描述**: 创建了新会话

---

#### EventID 28 - 会话已删除

**描述**: 删除了会话

---

#### EventID 39 - Shell 启动

**描述**: 用户 shell 启动

---

#### EventID 40 - Shell 终止

**描述**: 用户 shell 终止

---

### 12.3 RDP 攻击检测

**攻击特征**:
- 来自外部 IP 的 1149 事件 → 外部 RDP 访问
- 短时间内多次 RDP 登录失败 → RDP 暴力破解
- 同一账户的多个并发 RDP 会话 → 账户共享或被盗
- RDP 登录后执行可疑命令 (4688) → 攻击者执行

**检测规则**:
```
EventID 1149 + 异常来源 IP → 外部访问告警
EventID 4624 LogonType=10 + 1149 → RDP 登录关联
```

---

## 十三、Active Directory 事件 ID

**日志通道**: 
- `Microsoft-Windows-ActiveDirectory_DomainService/Operational` (AD DS)
- `Microsoft-Windows-DirectoryServices-SAM/Operational` (账户管理)
- `NTDS*` (AD 审计日志，需特殊配置)

### 13.1 AD 账户登录事件

#### EventID 4768 - Kerberos TGT 请求

**描述**: 请求 Kerberos 票据授予票据

**字段**:
| 字段 | 说明 | 应急场景 |
|------|------|----------|
| TargetUserName | 目标用户名 | 确认被请求的账户 |
| TargetDomainName | 目标域 | - |
| TicketOptions | 票据选项 | - |
| PreAuthType | 预认证类型 | 分析认证方式 |
| IpAddress | 来源 IP | 定位请求来源 |
| Status | 状态 | 分析请求结果 |

**应急场景**:
- **AS-REProasting**: 不使用预认证的账户被攻击
- **Golden Ticket**: 异常长的票据生命周期
- **密码猜测**: 大量失败后成功 → 暴力破解成功

---

#### EventID 4769 - Kerberos TGS 请求

**描述**: 请求 Kerberos 票据授予服务

**字段**:
| 字段 | 说明 | 应急场景 |
|------|------|----------|
| TargetUserName | 目标账户 | 分析目标服务 |
| ServiceName | 服务名称 | 检测 Kerberoasting |
| TicketOptions | 票据选项 | - |
| Status | 状态 | - |

**应急场景**:
- **Kerberoasting**: 攻击者请求服务票据后离线破解
- 检测非预期账户的 TGS 请求

---

#### EventID 4770 - Kerberos TGS 更新

**描述**: Kerberos TGS 票据更新

---

#### EventID 4771 - Kerberos 预认证失败

**描述**: Kerberos 预认证失败

**Status 代码**:
| 值 | 说明 |
|----|------|
| 0x6 | KDC_ERR_PREAUTH_FAILED - 密码错误 |
| 0x18 | KDC_ERR_KEY_EXPIRED - 密码已过期 |
| 0x25 | KDC_ERR_CLIENT_REVOKED - 账户已禁用 |

**应急场景**:
- 密码猜测攻击
- Golden Ticket 攻击检测

---

#### EventID 4772 - TGT 请求失败

**描述**: TGT 请求失败

---

#### EventID 4773 - TGS 请求失败

**描述**: TGS 请求失败

---

#### EventID 4776 - 凭据验证

**描述**: 域控制器尝试验证凭据

**字段**:
| 字段 | 说明 | 应急场景 |
|------|------|----------|
| TargetUserName | 目标用户名 | 确认被验证的账户 |
| TargetDomainName | 目标域 | - |
| Status | 状态 | 分析验证结果 |

**应急场景**:
- **Pass-the-Hash**: NTLM 验证
- **密码喷洒**: 多个账户的验证失败

---

### 13.2 AD 账户管理事件

#### EventID 4720 - 账户已创建

**描述**: 创建了新用户账户

**应急场景**:
- **恶意账户**: 攻击者创建后门账户
- **检测**: 4720 后紧跟 4672 → 新账户立即获得特权

---

#### EventID 4722 - 账户已启用

**描述**: 禁用的账户被启用

---

#### EventID 4723 - 密码更改尝试

**描述**: 用户尝试更改密码

---

#### EventID 4724 - 密码重置尝试

**描述**: 重置账户密码

**应急场景**:
- **密码重置攻击**: 攻击者重置管理员密码
- **检测**: 管理员密码被重置 → 紧急事件

---

#### EventID 4725 - 账户已禁用

**描述**: 账户被禁用

---

#### EventID 4726 - 账户已删除

**描述**: 账户被删除

---

#### EventID 4728 - 添加到安全组

**描述**: 账户被添加到安全组

**字段**:
| 字段 | 说明 | 应急场景 |
|------|------|----------|
| Member | 新增成员 | 分析谁被添加 |
| TargetUserName | 目标组名 | 分析添加到哪个组 |

**应急场景**:
- 添加到 Domain Admins → 严重告警
- 添加到 Account Operators → 权限提升

---

#### EventID 4729 - 从安全组移除

**描述**: 账户从安全组移除

---

#### EventID 4732 - 添加到安全组 (特权组)

**描述**: 成员被添加到受限制的安全组

**应急场景**:
- 添加到 Administrators → 权限提升
- 添加到 Schema Admins → 域管理员

---

#### EventID 4733 - 从安全组移除

**描述**: 成员从安全组移除

---

#### EventID 4735 - 安全组已更改

**描述**: 安全组属性被修改

---

#### EventID 4740 - 账户已锁定

**描述**: 账户因多次登录失败被锁定

**应急场景**:
- 暴力破解检测
- 密码喷洒攻击

---

#### EventID 4741 - 计算机账户已创建

**描述**: 创建了新的计算机账户

---

#### EventID 4742 - 计算机账户已更改

**描述**: 计算机账户属性被修改

---

#### EventID 4743 - 计算机账户已删除

**描述**: 计算机账户被删除

---

#### EventID 4744 - 禁用安全组已创建

**描述**: 创建了禁用安全组

---

#### EventID 4745 - 安全组已更改

**描述**: 安全组状态已更改

---

#### EventID 4750 - 安全组已重新启用

**描述**: 安全组被重新启用

---

#### EventID 4754 - 安全组已创建

**描述**: 创建了新的安全组

---

#### EventID 4756 - 通用组成员已添加

**描述**: 成员添加到通用安全组

---

#### EventID 4757 - 通用组成员已移除

**描述**: 成员从通用安全组移除

---

#### EventID 4758 - 通用安全组已删除

**描述**: 通用安全组被删除

---

#### EventID 4764 - 组类型已更改

**描述**: 组的类型被更改

---

### 13.3 AD DS 复制事件

#### EventID 4928 - AD 复制源设置

**描述**: 设置了 AD 复制源

**应急场景**:
- **DCSync 攻击**: 攻击者模拟域控制器同步
- 检测非授权的复制连接

---

#### EventID 4929 - AD 复制连接已删除

**描述**: 删除了 AD 复制连接

---

#### EventID 4930 - AD 复制连接已修改

**描述**: 修改了 AD 复制连接

---

#### EventID 4931 - AD 复制目标已修改

**描述**: 修改了 AD 复制目标

---

#### EventID 4932 - AD 命名上下文开始同步

**描述**: AD 命名上下文同步开始

---

#### EventID 4933 - AD 命名上下文结束同步

**描述**: AD 命名上下文同步结束

---

#### EventID 4934 - AD 对象属性已复制

**描述**: 复制了 AD 对象属性

---

#### EventID 4935 - AD 复制错误

**描述**: AD 复制错误

---

#### EventID 4936 - AD 复制同步完成

**描述**: AD 复制同步完成

---

### 13.4 AD Kerberos 票证事件

#### EventID 5136 - AD 对象权限已更改

**描述**: AD 对象权限被修改

---

#### EventID 5137 - AD 对象已创建

**描述**: 创建了 AD 对象

---

#### EventID 5138 - AD 对象已删除

**描述**: 删除了 AD 对象

---

#### EventID 5139 - AD 对象移动

**描述**: AD 对象被移动

---

#### EventID 5140 - 网络共享访问

**描述**: 访问网络共享

(同 Security 日志)

---

#### EventID 5141 - AD 对象已修改

**描述**: AD 对象被修改

---

### 13.5 AD 攻击检测

**攻击特征**:
- 4768/4769 大量请求 → Kerberoasting
- 4720 后紧跟 4672 → 恶意账户创建
- 4740 频繁触发 → 密码喷洒
- 4928 来自非 DC → DCSync 攻击

---

## 十四、Network Policy Server (NPS) 事件 ID

**日志通道**: `Microsoft-Windows-NPS/Operational`

NPS (网络策略服务器) 用于 RADIUS 身份验证和授权。

### 14.1 NPS 认证事件

#### EventID 1 - 接入请求

**描述**: 收到网络接入请求

**字段**:
| 字段 | 说明 |
|------|------|
| UserName | 用户名 |
| FullyQualifiedDistinguishedName | 用户 FQDN |
| NASIpAddress | NAS IP 地址 |
| NASIdentifier | NAS 标识符 |
| ProxyPolicyName | 代理策略名称 |
| NetworkPolicyName | 网络策略名称 |
| AuthenticationType | 认证类型 |
| NPAPolicyName | NPAP 策略名称 |
| ReAuthentication | 是否需要重新认证 |

---

#### EventID 2 - 接入接受

**描述**: 接受网络接入

**字段**:
| 字段 | 说明 |
|------|------|
| UserName | 用户名 |
| NetworkPolicyName | 网络策略名称 |
| PolicyMatch | 策略匹配结果 |

---

#### EventID 3 - 接入拒绝

**描述**: 拒绝网络接入

**应急场景**:
- **未授权访问**: 攻击者尝试访问网络
- **检测**: 分析拒绝原因

---

#### EventID 4 - 接入放弃

**描述**: 客户端放弃连接

---

#### EventID 5 - 重新认证和重新授权

**描述**: 重新认证和重新授权

---

### 14.2 NPS 错误事件

#### EventID 1000 - NPS 服务器错误

**描述**: NPS 服务器发生错误

---

#### EventID 1001 - NPS 服务器警告

**描述**: NPS 服务器警告

---

#### EventID 1002 - NPS 服务器信息

**描述**: NPS 服务器信息

---

### 14.3 NPS 攻击检测

**攻击特征**:
- 大量 EventID 3 (接入拒绝) → 暴力破解
- 来自异常 NAS 的请求 → 可能的 Rogue AP
- 异常的认证类型 → 协议降级攻击

---

## 十五、Print Spooler 事件 ID

**日志通道**: 
- `Microsoft-Windows-PrintService/Admin`
- `Microsoft-Windows-PrintService/Operational`

### 15.1 Print Service 管理事件

#### EventID 1 - 打印服务启动

**描述**: 打印服务成功启动

---

#### EventID 2 - 打印服务停止

**描述**: 打印服务停止

---

#### EventID 3 - 打印服务暂停

**描述**: 打印服务暂停

---

#### EventID 4 - 打印服务继续

**描述**: 打印服务继续

---

### 15.2 打印作业事件

#### EventID 10 - 打印作业创建

**描述**: 创建了新的打印作业

**字段**:
| 字段 | 说明 |
|------|------|
| JobId | 作业 ID |
| DocumentName | 文档名称 |
| UserName | 用户名 |
| PrinterName | 打印机名称 |
| PortName | 端口名称 |

---

#### EventID 11 - 打印作业完成

**描述**: 打印作业完成

---

#### EventID 12 - 打印作业删除

**描述**: 删除打印作业

---

#### EventID 13 - 打印作业暂停

**描述**: 暂停打印作业

---

#### EventID 14 - 打印作业恢复

**描述**: 恢复打印作业

---

#### EventID 15 - 打印作业状态更改

**描述**: 打印作业状态更改

---

### 15.3 打印机事件

#### EventID 16 - 打印机已添加

**描述**: 添加了新打印机

**应急场景**:
- **持久化**: 攻击者添加恶意打印机
- **检测**: 监控异常打印机添加

---

#### EventID 17 - 打印机已删除

**描述**: 删除了打印机

---

#### EventID 18 - 打印机已修改

**描述**: 打印机设置被修改

---

#### EventID 19 - 打印机连接

**描述**: 连接到打印机

---

#### EventID 20 - 打印机端口创建

**描述**: 创建了打印机端口

---

### 15.4 Print Spooler 安全事件

#### EventID 591 - 添加打印机驱动程序

**描述**: 添加了打印机驱动程序

**应急场景**:
- **DLL 劫持**: 恶意打印机驱动程序
- **权限提升**: 驱动程序漏洞利用

---

#### EventID 801 - 打印作业拒绝访问

**描述**: 打印作业访问被拒绝

---

#### EventID 802 - 打印作业无效

**描述**: 打印作业无效

---

### 15.5 Print Spooler 攻击 (PrintNightmare)

**CVE-2021-34527 (PrintNightmare)**:
- EventID 10 + 异常文件名 → 可能存在漏洞利用
- 添加到 Print Administrators 组 → 本地权限提升
- 检测: 大量 591 事件或异常的驱动程序安装

---

## 十六、BitLocker 事件 ID

**日志通道**: 
- `Microsoft-Windows-BitLocker/BitLocker Management/Operational`
- `Microsoft-Windows-BitLocker/DriveEncryptionReady`
- `Microsoft-Windows-BitLocker/DriveEncryptionStatus`

### 16.1 BitLocker 状态事件

#### EventID 1 - BitLocker 恢复

**描述**: BitLocker 恢复控制台启动

**字段**:
| 字段 | 说明 |
|------|------|
| DriveLetter | 驱动器字母 |
| RecoveryReason | 恢复原因 |
| RecoveryKeyId | 恢复密钥 ID |

**应急场景**:
- 异常恢复尝试 → 可能存在攻击
- 检测未授权的恢复

---

#### EventID 2 - BitLocker 密钥Retrieval 尝试

**描述**: 尝试获取 BitLocker 密钥

**应急场景**:
- 恶意软件尝试获取恢复密钥
- 攻击者尝试解密驱动器

---

#### EventID 3 - BitLocker 保护挂起

**描述**: BitLocker 保护被挂起

**应急场景**:
- 攻击者禁用 BitLocker 实现持久化
- 检测保护状态变更

---

#### EventID 4 - BitLocker 保护恢复

**描述**: BitLocker 保护恢复

---

#### EventID 5 - 保护状态更改

**描述**: 保护状态已更改

---

#### EventID 6 - TPM 更改

**描述**: TPM 设置被更改

---

### 16.2 BitLocker 加密事件

#### EventID 256 - 加密开始

**描述**: 驱动器加密开始

---

#### EventID 257 - 加密完成

**描述**: 驱动器加密完成

---

#### EventID 258 - 解密开始

**描述**: 驱动器解密开始

---

#### EventID 259 - 解密完成

**描述**: 驱动器解密完成

---

#### EventID 260 - 加密状态更改

**描述**: 加密状态已更改

---

### 16.3 BitLocker 密码事件

#### EventID 512 - BitLocker 密码设置

**描述**: 设置了 BitLocker 密码

---

#### EventID 513 - BitLocker 密码更改

**描述**: 更改了 BitLocker 密码

---

#### EventID 514 - BitLocker 密码重置

**描述**: 重置了 BitLocker 密码

---

### 16.4 BitLocker 攻击检测

**攻击特征**:
- EventID 1 频繁出现 → 异常恢复尝试
- EventID 3 异常挂起 → 可能存在攻击者禁用 BitLocker
- EventID 2 异常出现 → 可能存在凭据窃取

---

## 十七、Windows Update 事件 ID

**日志通道**: `Microsoft-Windows-WindowsUpdateClient/Operational`

### 17.1 Update 客户端事件

#### EventID 10 - 更新检测

**描述**: 检测到更新

**字段**:
| 字段 | 说明 |
|------|------|
| UpdateId | 更新 ID |
| Title | 更新标题 |
| SupportUrl | 支持 URL |
| Severity | 严重级别 |
| Result | 检测结果 |

---

#### EventID 16 - 更新安装开始

**描述**: 开始安装更新

**字段**:
| 字段 | 说明 |
|------|------|
| UpdateId | 更新 ID |
| Title | 更新标题 |
| ClientAppId | 客户端应用 ID |

---

#### EventID 17 - 更新安装完成

**描述**: 更新安装完成

**字段**:
| 字段 | 说明 |
|------|------|
| UpdateId | 更新 ID |
| HResult | 结果代码 |

---

#### EventID 18 - 更新安装失败

**描述**: 更新安装失败

**应急场景**:
- 分析失败原因
- 检测可能的攻击干扰

---

#### EventID 19 - 更新已批准

**描述**: 更新已被批准

---

#### EventID 20 - 更新已删除

**描述**: 更新被删除

---

#### EventID 21 - 更新下载开始

**描述**: 开始下载更新

---

#### EventID 22 - 更新下载完成

**描述**: 更新下载完成

---

#### EventID 23 - 更新下载失败

**描述**: 更新下载失败

---

### 17.2 Windows Update 攻击检测

**攻击特征**:
- EventID 16/17 异常时间 → 可能存在攻击
- 大量 EventID 18 → 可能是攻击者禁用更新
- 异常更新安装 → 可能存在供应链攻击

---

## 十八、WMI 事件 ID

**日志通道**: `Microsoft-Windows-WMI-Activity/Operational`

### 18.1 WMI 查询事件

#### EventID 5857 - WMI 提供者加载

**描述**: WMI 提供者已加载

**字段**:
| 字段 | 说明 |
|------|------|
| ProviderName | 提供者名称 |
| ProviderPath | 提供者路径 |
| ObjectCacheSize | 对象缓存大小 |

---

#### EventID 5858 - WMI 查询错误

**描述**: WMI 查询错误

**字段**:
| 字段 | 说明 |
|------|------|
| NameSpace | 命名空间 |
| Query | 查询内容 |
| ErrorCode | 错误代码 |

---

#### EventID 5859 - WMI 查询完成

**描述**: WMI 查询完成

---

#### EventID 5860 - WMI 永久事件注册

**描述**: 注册了永久 WMI 事件

**应急场景**:
- **WMI 持久化**: 攻击者通过 WMI 实现持久化
- **无文件攻击**: WMI 事件订阅常被用于无文件攻击

---

#### EventID 5861 - WMI 活动

**描述**: WMI 活动发生

**应急场景**:
- 检测 WMI 命令执行
- 分析 WMI 攻击

---

### 18.2 WMI 攻击检测

**攻击特征**:
- EventID 5860/5861 异常 → WMI 持久化
- WMI 提供者来自异常路径 → 恶意提供者
- 大量 WMI 查询错误 → 可能的攻击探测

---

## 十九、计划任务 (Task Scheduler) 事件 ID

**日志通道**: `Microsoft-Windows-TaskScheduler/Operational`

### 19.1 任务操作事件

#### EventID 100 - 任务已创建

**描述**: 创建了新计划任务

**字段**:
| 字段 | 说明 |
|------|------|
| TaskName | 任务名称 |
| Path | 任务路径 |
| UserName | 创建者用户 |

**应急场景**:
- **持久化**: 恶意计划任务
- **检测**: 异常时间或路径的任务

---

#### EventID 101 - 任务已删除

**描述**: 计划任务被删除

---

#### EventID 102 - 任务已更新

**描述**: 计划任务被修改

---

#### EventID 103 - 任务已启用

**描述**: 计划任务被启用

---

#### EventID 104 - 任务已禁用

**描述**: 计划任务被禁用

---

#### EventID 105 - 任务注册

**描述**: 注册了新计划任务

---

#### EventID 106 - 任务取消注册

**描述**: 取消注册计划任务

---

### 19.2 任务执行事件

#### EventID 107 - 任务启动

**描述**: 计划任务启动

**字段**:
| 字段 | 说明 |
|------|------|
| TaskName | 任务名称 |
| ActionName | 操作名称 |
| EnginePID | 引擎进程 ID |

---

#### EventID 108 - 任务终止

**描述**: 计划任务终止

**字段**:
| 字段 | 说明 |
|------|------|
| TaskName | 任务名称 |
| ResultCode | 结果代码 |

---

#### EventID 109 - 任务完成

**描述**: 计划任务完成

---

#### EventID 110 - 任务触发

**描述**: 计划任务被触发

---

### 19.3 任务错误事件

#### EventID 200 - 任务启动失败

**描述**: 计划任务启动失败

**字段**:
| 字段 | 说明 |
|------|------|
| TaskName | 任务名称 |
| ErrorCode | 错误代码 |
| ErrorDescription | 错误描述 |

---

#### EventID 201 - 任务动作失败

**描述**: 任务动作执行失败

---

#### EventID 202 - 任务操作超时

**描述**: 任务操作超时

---

### 19.4 计划任务攻击检测

**攻击特征**:
- 异常路径的任务 → 恶意任务
- 异常时间的任务执行 → 检测攻击时间线
- 任务执行后紧跟 4688 → 检测恶意代码执行

---

## 二十、Hyper-V 事件 ID

**日志通道**: `Microsoft-Windows-Hyper-V-*`

### 20.1 Hyper-V 虚拟机事件

#### EventID 1 - VM 启动

**描述**: 虚拟机启动

---

#### EventID 2 - VM 关闭

**描述**: 虚拟机关闭

---

#### EventID 3 - VM 暂停

**描述**: 虚拟机暂停

---

#### EventID 4 - VM 恢复

**描述**: 虚拟机恢复

---

#### EventID 5 - VM 重置

**描述**: 虚拟机重置

---

#### EventID 6 - VM 保存

**描述**: 虚拟机保存

---

#### EventID 7 - VM 恢复

**描述**: 虚拟机从保存状态恢复

---

#### EventID 8 - VM 快照创建

**描述**: 创建了 VM 快照

**应急场景**:
- 攻击者创建快照用于持久化
- 检测异常快照创建

---

#### EventID 9 - VM 快照恢复

**描述**: 从快照恢复 VM

---

#### EventID 10 - VM 快照删除

**描述**: 删除 VM 快照

---

### 20.2 Hyper-V 虚拟交换机事件

**日志通道**: `Microsoft-Windows-Hyper-V-VmSwitch/Operational`

#### EventID 100 - VMS 切换启动

**描述**: 虚拟交换机启动

---

#### EventID 101 - VMS 切换关闭

**描述**: 虚拟交换机关闭

---

#### EventID 102 - VMS 切换连接

**描述**: VM 连接到虚拟交换机

**字段**:
| 字段 | 说明 |
|------|------|
| PortName | 端口名称 |
| MACAddress | MAC 地址 |
| VMName | VM 名称 |
| VMSwitchName | 交换机名称 |

---

#### EventID 103 - VMS 切换断开

**描述**: VM 断开虚拟交换机连接

---

### 20.3 Hyper-V 集成服务事件

#### EventID 185 - 集成服务启动

**描述**: 集成服务启动

---

#### EventID 186 - 集成服务停止

**描述**: 集成服务停止

---

### 20.4 Hyper-V 攻击检测

**攻击特征**:
- 异常 VM 启动/关闭 → 攻击者操作 VM
- 快照创建/恢复 → 可能是攻击者备份或恢复
- 异常的网络流量 → VM 逃逸检测

---

## 二十一、证书服务 (Certificate Services) 事件 ID

**日志通道**: `Microsoft-Windows-CertificateServices/Operational`

### 21.1 证书颁发事件

#### EventID 100 - 证书申请已接收

**描述**: 收到证书申请

**字段**:
| 字段 | 说明 |
|------|------|
| RequestId | 申请 ID |
| RequesterName | 申请者名称 |
| CAId | CA ID |

---

#### EventID 101 - 证书申请已批准

**描述**: 证书申请已批准

---

#### EventID 102 - 证书申请已拒绝

**描述**: 证书申请被拒绝

---

#### EventID 103 - 证书已颁发

**描述**: 颁发了证书

**字段**:
| 字段 | 说明 |
|------|------|
| CertificateId | 证书 ID |
| CertificateTemplate | 证书模板 |
| SerialNumber | 序列号 |

---

#### EventID 104 - 证书申请已删除

**描述**: 证书申请被删除

---

### 21.2 CA 配置事件

#### EventID 200 - CA 配置已更改

**描述**: CA 配置被修改

---

#### EventID 201 - CA 证书已更新

**描述**: CA 证书已更新

---

#### EventID 202 - CA 已启动

**描述**: 证书服务启动

---

#### EventID 203 - CA 已停止

**描述**: 证书服务停止

---

### 21.3 证书吊销事件

#### EventID 300 - 证书吊销检查

**描述**: 检查证书吊销状态

---

#### EventID 301 - 证书已吊销

**描述**: 证书被吊销

---

#### EventID 302 - 吊销检查失败

**描述**: 证书吊销检查失败

---

### 21.4 证书服务攻击检测

**攻击特征**:
- 异常证书颁发 → 可能是攻击者获取证书
- 证书模板异常 → 可能是证书模板滥用
- 大量证书申请 → 可能是恶意软件申请证书

---

## 二十二、AppLocker 事件 ID

**日志通道**: `Microsoft-Windows-AppLocker/EXE and DLL` (需要启用审核)

### 22.1 AppLocker 规则事件

#### EventID 8000 - AppLocker 规则匹配

**描述**: AppLocker 规则匹配

**字段**:
| 字段 | 说明 | 应急场景 |
|------|------|----------|
| RuleId | 规则 ID |
| RuleName | 规则名称 |
| FilePath | 文件路径 | 分析被阻止的应用 |
| FileHash | 文件哈希 | 恶意软件识别 |
| UserId | 用户 ID | 确认操作用户 |
| Action | 操作 (允许/阻止) | 分析安全策略 |

---

#### EventID 8001 - AppLocker 规则不匹配

**描述**: 没有 AppLocker 规则匹配

---

#### EventID 8002 - AppLocker 脚本规则匹配

**描述**: 脚本规则匹配

---

#### EventID 8003 - AppLocker Windows 脚本规则匹配

**描述**: Windows 脚本规则匹配

---

#### EventID 8004 - AppLocker 可执行规则匹配

**描述**: 可执行文件规则匹配

---

#### EventID 8005 - AppLocker DLL 规则匹配

**描述**: DLL 规则匹配

---

#### EventID 8006 - AppLocker 安装程序规则匹配

**描述**: 安装程序规则匹配

---

#### EventID 8007 - AppLocker MSI 规则匹配

**描述**: MSI 规则匹配

---

### 22.2 AppLocker 攻击检测

**攻击特征**:
- EventID 8000 大量 Block → 恶意软件尝试执行
- 阻止但执行成功 → AppLocker 配置错误
- 异常路径的应用执行 → 检测攻击

---

## 二十三、分布式事务协调器 (MSDTC) 事件 ID

**日志通道**: `Microsoft-Windows-DistributedCOM`

### 23.1 DTC 事件

#### EventID 10000 - MSDTC 启动

**描述**: MSDTC 服务启动

---

#### EventID 10001 - MSDTC 停止

**描述**: MSDTC 服务停止

---

#### EventID 10002 - MSDTC 事务开始

**描述**: 分布式事务开始

**字段**:
| 字段 | 说明 |
|------|------|
| TransactionId | 事务 ID |
| TransactionDescription | 事务描述 |

---

#### EventID 10003 - MSDTC 事务提交

**描述**: 分布式事务提交

---

#### EventID 10004 - MSDTC 事务回滚

**描述**: 分布式事务回滚

---

#### EventID 10005 - MSDTC 事务超时

**描述**: 分布式事务超时

---

### 23.2 DTC 攻击检测

**攻击特征**:
- 异常的 DTC 连接 → 可能的横向移动
- DTC 事务异常 → 可能的攻击探测

---

## 二十四、EventCollector 事件 ID

**日志通道**: `Microsoft-Windows-EventCollector/Operational`

### 24.1 事件收集事件

#### EventID 1 - 收集会话启动

**描述**: 事件收集会话启动

---

#### EventID 2 - 收集会话停止

**描述**: 事件收集会话停止

---

#### EventID 3 - 事件传递

**描述**: 事件被传递到收集器

---

#### EventID 4 - 事件传递错误

**描述**: 事件传递失败

---

#### EventID 5 - 订阅创建

**描述**: 创建了事件订阅

---

#### EventID 6 - 订阅删除

**描述**: 删除了事件订阅

---

### 24.2 WinRM 事件转发

#### EventID 100 - 转发会话启动

**描述**: WinRM 事件转发会话启动

---

#### EventID 101 - 转发会话错误

**描述**: WinRM 事件转发错误

---

## 二十五、快速参考表

### 25.1 按攻击阶段分类

| 攻击阶段 | 关键日志 | 关键事件 ID |
|----------|----------|-------------|
| 初始访问 | Security, WinRM, RDP | 4624, 4625, 1149 |
| 凭证访问 | Security, AD | 4768, 4769, 4776 |
| 横向移动 | SMB, Security, WinRM | 5140, 5145, 4648 |
| 持久化 | Security, System, TaskScheduler | 4698, 7045, 4657 |
| 权限提升 | Security | 4672, 4688 |
| 数据窃取 | SMB, DNS | 5145, 1000 |
| 防御规避 | Security | 1102, 4670 |

### 25.2 事件 ID 速查

| EventID | 日志 | 说明 |
|---------|------|------|
| 4624 | Security | 登录成功 |
| 4625 | Security | 登录失败 |
| 4648 | Security | 显式凭据登录 |
| 4672 | Security | 特权分配 |
| 4688 | Security | 新进程创建 |
| 4697 | Security | 服务创建 |
| 4698 | Security | 计划任务创建 |
| 4702 | Security | 计划任务修改 |
| 4768 | Security | Kerberos TGT 请求 |
| 4769 | Security | Kerberos TGS 请求 |
| 5140 | Security | 网络共享访问 |
| 5145 | Security | SMB 访问检查 |
| 7045 | System | 服务创建 |
| 1102 | Security | 日志清除 |
| 4104 | PowerShell | 脚本块执行 |
| 6 | WinRM | WinRM 服务启动 |
| 82-91 | WinRM | Shell 操作 |
| 1-11 | SMB Server | SMB 服务器事件 |
| 1000-1007 | DNS Client | DNS 查询 |
| 1149 | TerminalServices | RDP 登录成功 |
| 4720-4759 | AD | 账户管理 |

---

## 七、应急响应场景

### 7.1 账户登录事件分析

**场景**: 检测暴力破解攻击

**特征事件**:
```
4625 (登录失败) x N + 4740 (账户锁定)
```

**分析方法**:
1. 统计 4625 事件中目标账户
2. 按 IpAddress 分组统计失败次数
3. 分析失败模式 (密码喷洒 vs 暴力破解)

**关联规则**:
- 同一账户 5 分钟内 10 次以上失败 → 告警

---

**场景**: 检测 Pass-the-Hash 横向移动

**特征事件**:
```
4624 (登录成功) LogonType=3 + 4672 (特权分配)
```

**分析方法**:
1. 查找 LogonType=3 且具有高权限的登录
2. 检查登录来源是否为内部 IP
3. 分析会话持续时间

---

**场景**: 检测 RDP 横向移动

**特征事件**:
```
4624 (登录成功) LogonType=10 (RDP)
```

**分析方法**:
1. 分析 RDP 登录的时间规律
2. 检查登录来源 IP 是否为已知
3. 分析被登录账户的权限

---

### 7.2 持久化检测

**场景**: 检测注册表 Run 键持久化

**特征事件**:
```
4657 (注册表修改) + HKLM\Software\Microsoft\Windows\CurrentVersion\Run
或
4657 (注册表修改) + HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

**分析方法**:
1. 检查新增的 Run 键值
2. 分析可执行文件路径是否异常
3. 检查文件哈希是否为已知恶意

---

**场景**: 检测服务持久化

**特征事件**:
```
4688 (新进程) + ServiceMain (服务入口)
或
7045 (新服务创建)
```

**分析方法**:
1. 分析新服务的可执行文件路径
2. 检查服务启动类型
3. 分析服务账户权限

---

**场景**: 检测计划任务持久化

**特征事件**:
```
4698 (计划任务创建)
```

**分析方法**:
1. 检查任务创建者权限
2. 分析任务执行的操作
3. 检查触发器配置

---

### 7.3 权限提升检测

**场景**: 检测令牌操纵

**特征事件**:
```
4672 (特权分配) + 4673/4674 (特权操作)
```

---

**场景**: 检测 UAC 绕过

**特征事件**:
```
4688 (新进程) + TokenElevationType=TokenElevationTypeFull
+ 可疑进程 (fodhelper.exe, eventvwr.exe, cmstp.exe)
```

---

### 7.4 数据窃取检测

**场景**: 检测凭据窃取

**特征事件**:
```
4688 (新进程) + 进程包含 lsass
或
4688 (新进程) + cmd.exe /c "reg save"
或
EventID 10 (进程访问) + TargetImage=lsass.exe
```

---

**场景**: 检测数据外泄

**特征事件**:
```
4688 (新进程) + rar.exe / 7z.exe
或
5145 (网络共享访问) + 大文件传输
```

---

## 八、攻击链分析

### 8.1 典型攻击链

#### 密码喷洒攻击链

```
4625 (登录失败) x N → 4624 (登录成功) → 4688 (进程执行)
```

#### Pass-the-Hash 横向移动

```
4624 (登录成功) LogonType=3 → 4672 (特权分配) → 4688 (远程执行)
```

#### 黄金票据攻击

```
4768 (TGT请求) → 4672 (特权分配) → 4688 (进程执行)
```

#### 持久化攻击链

```
4624 (管理员登录) → 4698 (计划任务) / 7045 (服务) / 4657 (注册表)
```

### 8.2 攻击链检测规则

| 攻击阶段 | 起始事件 | 后续事件 | 告警规则 |
|----------|----------|----------|----------|
| 暴力破解 | 4625 | 4740 | 5分钟内同一账户10次失败 |
| 账户入侵 | 4624 | 4672 | 登录后5分钟内获得特权 |
| 横向移动 | 4624(3) | 4688 | 网络登录后创建进程 |
| 持久化 | 4688 | 4698/7045 | 进程创建后创建服务/任务 |
| 数据窃取 | 4688 | 5145 | 访问共享后文件操作 |

---

## 九、附录

### 附录 A: LogonType 完整说明

| 值 | 名称 | 说明 | 常见场景 |
|----|------|------|----------|
| 0 | System | 系统账户 | 安全账户管理器启动 |
| 1 | Interactive | 本地交互登录 | 键盘登录 |
| 2 | Interactive | 远程交互登录 | Terminal Services/RDP |
| 3 | Network | 网络登录 | 文件共享、RPC |
| 4 | Batch | 批处理登录 | 计划任务 |
| 5 | Service | 服务账户登录 | Windows 服务 |
| 6 | Proxy | 代理登录 | 代理认证 |
| 7 | Unlock | 解锁工作站 | 按 Ctrl+Alt+Del |
| 8 | NetworkCleartext | 网络明文登录 | IIS Basic Auth |
| 9 | NewCredentials | 带凭据的网络登录 | RunAs / 网络驱动器映射 |
| 10 | RemoteInteractive | 远程桌面登录 | RDP |
| 11 | CachedInteractive | 缓存交互登录 | 离线登录 |

### 附录 B: 事件级别说明

| 级别 | 值 | Windows 事件查看器显示 | 说明 |
|------|----|----------------------|------|
| Critical | 1 | 严重 | 严重错误导致组件失败 |
| Error | 2 | 错误 | 错误但不影响组件 |
| Warning | 3 | 警告 | 不是错误但可能需要关注 |
| Information | 4 | 信息 | 重要事件的 informational |
| Verbose | 5 | 详细 | 调试信息 |

### 附录 C: MITRE ATT&CK 战术映射

| 战术 | 相关事件 ID |
|------|-------------|
| TA0001 初始访问 | 4624, 4625, 1149, 6 |
| TA0002 执行 | 4688, 4104, 82-91 (WinRM), 4688 |
| TA0003 持久化 | 4698, 7045, 4657, 100, 5860 (WMI), 5861 |
| TA0004 权限提升 | 4672, 4688, 4670 |
| TA0005 防御规避 | 1102, 4657, 4670, 4001 (Firewall) |
| TA0006 凭据访问 | 4624, 4625, 4672, 4768, 4769, 4776 |
| TA0007 发现 | 4688, 5140, 5145 |
| TA0008 横向移动 | 4624, 4648, 5140, 5145, 1-11 (SMB) |
| TA0009 收集 | 4688, 5145, 1000 (DNS) |
| TA0010 外泄 | 5145, 1000 (DNS Tunneling) |
| TA0011 命令与控制 | 3 (Sysmon), 1000 (DNS), 6 (WinRM) |
| TA0040 影响 | 1102, 4657, 802 (Print Spooler) |

### 附录 D: 推荐的安全事件审核策略

```
账户登录:
- 审核账户登录成功 [成功]
- 审核账户登录失败 [失败]

账户管理:
- 审核账户管理 [成功,失败]

对象访问:
- 审核文件系统 [成功,失败] (可选)
- 审核注册表 [成功,失败] (可选)

进程追踪:
- 审核进程创建 [成功]
- 审核进程终止 [成功]

详细文件追踪:
- 启用 (可选)

DS 访问:
- 审核目录服务访问 [失败] (仅 DC)

登录事件:
- 审核登录 [成功,失败]
- 审核注销 [成功]

策略更改:
- 审核审核策略更改 [成功,失败]
- 审核身份验证策略更改 [成功,失败]

特权使用:
- 审核特殊权限使用 [成功] (可选)
```

---

*本文档由 WinLogAnalyzer-Go 团队整理，供应急响应和安全分析参考。*
