# 资产清单 - 系统补丁与软件列表功能

> 本文档描述了在资产清单模块中新增"系统补丁"和"软件列表"两个Tab页的完整技术实现方案。

---

## 一、功能概述

### 1.1 系统补丁 (System Patches)
展示当前机器的 Windows 更新补丁列表，包括 KB 编号、描述、安装日期、安装者等信息。

### 1.2 软件列表 (Installed Software)
展示当前系统已安装的软件列表，内容等价于 Windows"添加/删除程序"中显示的内容，包括软件名称、版本、发布者、安装日期、安装位置等。

---

## 二、现有架构分析

### 2.1 项目技术栈

| 层级 | 技术 | 说明 |
|------|------|------|
| 前端 | React + TypeScript + Vite | SPA 单页应用 |
| 后端 | Go + Gin | HTTP API 服务 |
| 数据库 | SQLite | 本地存储 |
| 系统采集 | PowerShell / Go Win32 API / WMI / 注册表 | Windows 系统信息采集 |

### 2.2 现有数据流模式

```
前端 AssetInventory.tsx
  └─> systemAPI.getXxx()          # axios HTTP 请求
       └─> GET /api/system/xxx    # Gin 路由
            └─> handlers_system.go
                 └─> collectors/*.go  # 数据采集
                      └─> PowerShell 优先 → Go API 回退
```

### 2.3 关键技术依赖

| 依赖 | 用途 | 文件位置 |
|------|------|----------|
| `golang.org/x/sys/windows/registry` | 注册表读取 | `internal/utils/registry.go` |
| `github.com/StackExchange/wmi` | WMI 查询 | `internal/monitor/wmi/` |
| `github.com/yusufpapurcu/wmi` | WMI 查询 | `internal/persistence/wmi.go` |

### 2.4 Collector 标准模式

```go
type Collector interface {
    Name() string
    Collect(ctx context.Context) ([]interface{}, error)
    RequiresAdmin() bool
}
```

---

## 三、技术实现方案

### 3.1 系统补丁 (Patches)

#### 3.1.1 数据获取方式

**推荐：WMI 查询 `Win32_QuickFixEngineering`**

```powershell
Get-CimInstance -ClassName Win32_QuickFixEngineering |
    Select-Object HotFixID, Description, InstalledOn, InstalledBy |
    ConvertTo-Json
```

**优点**：
- Windows 标准 API，信息完整
- 项目已有 WMI 依赖和使用经验
- 查询速度快（通常 0.5 秒内完成）

**限制**：
- 仅 Windows 平台可用
- 不包含 .NET 累积更新（需结合注册表补充）

#### 3.1.2 数据类型定义

**文件**：`internal/types/system.go`

```go
type PatchInfo struct {
    KBID        string `json:"kb_id"`         // KB5034441
    Description string `json:"description"`   // Security Update
    InstalledOn string `json:"installed_on"`  // 2024-01-15
    InstalledBy string `json:"installed_by"`  // NT AUTHORITY\SYSTEM
}
```

#### 3.1.3 Collector 实现

**文件**：`internal/collectors/patch_collector.go`

```go
//go:build windows

package collectors

import (
    "context"
    "encoding/json"
    "fmt"
    "os/exec"
    "time"

    "github.com/kkkdddd-start/winalog-go/internal/observability"
    "github.com/kkkdddd-start/winalog-go/internal/types"
    "go.uber.org/zap"
)

type PatchCollector struct {
    BaseCollector
}

func NewPatchCollector() *PatchCollector {
    return &PatchCollector{
        BaseCollector: BaseCollector{
            info: CollectorInfo{
                Name:          "patch_info",
                Description:   "Collect installed Windows patches information",
                RequiresAdmin: false,
                Version:       "1.0.0",
            },
        },
    }
}

func (c *PatchCollector) Collect(ctx context.Context) ([]interface{}, error) {
    patches, err := c.collectPatches(ctx)
    if err != nil {
        return nil, err
    }
    interfaces := make([]interface{}, len(patches))
    for i, p := range patches {
        interfaces[i] = p
    }
    return interfaces, nil
}

func (c *PatchCollector) collectPatches(ctx context.Context) ([]*types.PatchInfo, error) {
    // 方式 1: PowerShell 优先
    patches, err := c.collectViaPowerShell(ctx)
    if err == nil && len(patches) > 0 {
        return patches, nil
    }

    // 方式 2: 回退到 Go WMI
    observability.Warn("PowerShell patch collection failed, falling back to Go WMI",
        zap.String("module", "patch_collector"),
        zap.Error(err))
    return c.collectViaWMI()
}

func (c *PatchCollector) collectViaPowerShell(ctx context.Context) ([]*types.PatchInfo, error) {
    script := `$ErrorActionPreference = 'SilentlyContinue'
Get-CimInstance -ClassName Win32_QuickFixEngineering |
    Select-Object HotFixID, Description, InstalledOn, InstalledBy |
    ConvertTo-Json -Compress`

    cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", script)
    cmd.Timeout = 30 * time.Second

    output, err := cmd.Output()
    if err != nil {
        return nil, fmt.Errorf("powershell execution failed: %w", err)
    }

    var psItems []struct {
        HotFixID    string `json:"HotFixID"`
        Description string `json:"Description"`
        InstalledOn string `json:"InstalledOn"`
        InstalledBy string `json:"InstalledBy"`
    }

    if err := json.Unmarshal(output, &psItems); err != nil {
        return nil, fmt.Errorf("JSON parse failed: %w", err)
    }

    var patches []*types.PatchInfo
    for _, item := range psItems {
        installedOn := item.InstalledOn
        // 标准化日期格式
        if t, err := time.Parse("M/d/yyyy hh:mm:ss tt", installedOn); err == nil {
            installedOn = t.Format("2006-01-02")
        } else if t, err := time.Parse("2006/1/2", installedOn); err == nil {
            installedOn = t.Format("2006-01-02")
        }

        patches = append(patches, &types.PatchInfo{
            KBID:        item.HotFixID,
            Description: item.Description,
            InstalledOn: installedOn,
            InstalledBy: item.InstalledBy,
        })
    }

    return patches, nil
}

func (c *PatchCollector) collectViaWMI() ([]*types.PatchInfo, error) {
    // 使用 github.com/StackExchange/wmi
    // SELECT HotFixID, Description, InstalledOn, InstalledBy FROM Win32_QuickFixEngineering
    // 实现略，参考 internal/monitor/wmi/ 中的 WMI 查询模式
    return nil, fmt.Errorf("WMI fallback not yet implemented")
}
```

**Linux 兼容文件**：`internal/collectors/patch_collector_linux.go`

```go
//go:build !windows

package collectors

import (
    "context"
    "fmt"
)

func NewPatchCollector() *PatchCollector {
    return &PatchCollector{
        BaseCollector: BaseCollector{
            info: CollectorInfo{
                Name:          "patch_info",
                Description:   "Not supported on Linux",
                RequiresAdmin: false,
                Version:       "1.0.0",
            },
        },
    }
}

func (c *PatchCollector) Collect(ctx context.Context) ([]interface{}, error) {
    return nil, fmt.Errorf("patch collection is only supported on Windows")
}
```

#### 3.1.4 Handler 实现

**文件**：`internal/api/handlers_system.go`（新增方法）

```go
type PatchResponse struct {
    Patches []*types.PatchInfo `json:"patches"`
    Total   int                `json:"total"`
}

// GetInstalledPatches godoc
// @Summary 获取已安装补丁列表
// @Description 返回系统已安装的 Windows 更新补丁
// @Tags system
// @Produce json
// @Success 200 {object} PatchResponse
// @Router /api/system/patches [get]
func (h *SystemHandler) GetInstalledPatches(c *gin.Context) {
    collector := collectors.NewPatchCollector()
    results, err := collector.Collect(c.Request.Context())
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{
            "error": fmt.Sprintf("Failed to collect patch info: %v", err),
        })
        return
    }

    var patches []*types.PatchInfo
    for _, r := range results {
        if p, ok := r.(*types.PatchInfo); ok {
            patches = append(patches, p)
        }
    }

    c.JSON(http.StatusOK, PatchResponse{
        Patches: patches,
        Total:   len(patches),
    })
}

// ExportInstalledPatches godoc
// @Summary 导出补丁列表为 CSV
// @Tags system
// @Produce csv
// @Success 200 {file} file
// @Router /api/system/patches/export [get]
func (h *SystemHandler) ExportInstalledPatches(c *gin.Context) {
    // 调用 GetInstalledPatches 逻辑
    // 生成 CSV 响应
    c.Header("Content-Disposition", "attachment; filename=patches_export.csv")
    c.Header("Content-Type", "text/csv")
    // 写入 CSV 数据
}
```

**路由注册**：

```go
// SetupSystemRoutes() 中新增
system.GET("/patches", systemHandler.GetInstalledPatches)
system.GET("/patches/export", systemHandler.ExportInstalledPatches)
```

### 3.2 软件列表 (Installed Software)

#### 3.2.1 数据获取方式

**推荐：注册表查询（三个路径）**

| 注册表路径 | 说明 | 架构 |
|-----------|------|------|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` | 64 位软件 | x64 |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` | 32 位软件 | x86 |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` | 当前用户安装 | 当前用户 |

**优点**：
- 项目已有完善的注册表读取工具（`utils/registry.go`）
- 信息比 WMI `Win32_Product` 更完整
- 不会触发 MSI 修复检查（WMI 的缺点）

#### 3.2.2 数据类型定义

**文件**：`internal/types/system.go`

```go
type InstalledSoftware struct {
    Name            string  `json:"name"`              // 软件名称
    Version         string  `json:"version"`           // 版本
    Publisher       string  `json:"publisher"`         // 发布者
    InstallDate     string  `json:"install_date"`      // 安装日期
    InstallLocation string  `json:"install_location"`  // 安装位置
    UninstallString string  `json:"uninstall_string"`  // 卸载命令
    EstimatedSizeMB float64 `json:"estimated_size_mb"` // 大小 (MB)
    Architecture    string  `json:"architecture"`      // x64/x86
    Source          string  `json:"source"`            // HKLM/HKCU
}
```

#### 3.2.3 Collector 实现

**文件**：`internal/collectors/software_collector.go`

```go
//go:build windows

package collectors

import (
    "context"
    "fmt"
    "strconv"
    "strings"

    "github.com/kkkdddd-start/winalog-go/internal/observability"
    "github.com/kkkdddd-start/winalog-go/internal/types"
    "github.com/kkkdddd-start/winalog-go/internal/utils"
    "go.uber.org/zap"
)

type SoftwareCollector struct {
    BaseCollector
}

// 注册表路径定义
var uninstallPaths = []struct {
    Path   string
    Arch   string
    Source string
}{
    {`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "x64", "HKLM"},
    {`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "x86", "HKLM"},
    {`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "x64", "HKCU"},
}

func NewSoftwareCollector() *SoftwareCollector {
    return &SoftwareCollector{
        BaseCollector: BaseCollector{
            info: CollectorInfo{
                Name:          "installed_software",
                Description:   "Collect installed software information from registry",
                RequiresAdmin: false,
                Version:       "1.0.0",
            },
        },
    }
}

func (c *SoftwareCollector) Collect(ctx context.Context) ([]interface{}, error) {
    software, err := c.collectSoftware()
    if err != nil {
        return nil, err
    }
    interfaces := make([]interface{}, len(software))
    for i, s := range software {
        interfaces[i] = s
    }
    return interfaces, nil
}

func (c *SoftwareCollector) collectSoftware() ([]*types.InstalledSoftware, error) {
    var allSoftware []*types.InstalledSoftware

    for _, pathInfo := range uninstallPaths {
        software, err := c.collectFromPath(pathInfo.Path, pathInfo.Arch, pathInfo.Source)
        if err != nil {
            observability.Warn("Failed to collect software from registry path",
                zap.String("path", pathInfo.Path),
                zap.Error(err))
            continue
        }
        allSoftware = append(allSoftware, software...)
    }

    observability.Info("collectSoftware completed",
        zap.String("module", "software_collector"),
        zap.Int("total", len(allSoftware)))

    return allSoftware, nil
}

func (c *SoftwareCollector) collectFromPath(basePath, arch, source string) ([]*types.InstalledSoftware, error) {
    subkeys, err := utils.ListRegistrySubkeys(basePath)
    if err != nil {
        return nil, err
    }

    var software []*types.InstalledSoftware

    for _, subkey := range subkeys {
        fullPath := basePath + `\` + subkey
        sw := c.parseRegistryKey(fullPath, arch, source)
        if sw != nil {
            software = append(software, sw)
        }
    }

    return software, nil
}

func (c *SoftwareCollector) parseRegistryKey(keyPath, arch, source string) *types.InstalledSoftware {
    // 读取 DisplayName（必需）
    displayName, err := utils.GetRegistryValue(keyPath, "DisplayName")
    if err != nil || displayName == "" {
        return nil // 没有 DisplayName 的不是有效软件条目
    }

    version, _ := utils.GetRegistryValue(keyPath, "DisplayVersion")
    publisher, _ := utils.GetRegistryValue(keyPath, "Publisher")
    installDate, _ := utils.GetRegistryValue(keyPath, "InstallDate")
    installLocation, _ := utils.GetRegistryValue(keyPath, "InstallLocation")
    uninstallString, _ := utils.GetRegistryValue(keyPath, "UninstallString")

    // 读取 EstimatedSize（DWORD，单位 KB）
    estSize, err := utils.GetRegistryDWORDValue(keyPath, "EstimatedSize")
    var sizeMB float64
    if err == nil {
        sizeMB = float64(estSize) / 1024.0
    }

    // 标准化日期格式 (YYYYMMDD -> YYYY-MM-DD)
    if len(installDate) == 8 {
        installDate = installDate[0:4] + "-" + installDate[4:6] + "-" + installDate[6:8]
    }

    return &types.InstalledSoftware{
        Name:            displayName,
        Version:         version,
        Publisher:       publisher,
        InstallDate:     installDate,
        InstallLocation: installLocation,
        UninstallString: uninstallString,
        EstimatedSizeMB: sizeMB,
        Architecture:    arch,
        Source:          source,
    }
}

// PowerShell 备选方案
func (c *SoftwareCollector) collectViaPowerShell() ([]*types.InstalledSoftware, error) {
    script := `$ErrorActionPreference = 'SilentlyContinue'
$paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
)

$results = @()
foreach ($path in $paths) {
    if (-not (Test-Path $path)) { continue }
    $arch = if ($path -match "WOW6432") { "x86" } else { "x64" }
    $source = if ($path -match "HKCU") { "HKCU" } else { "HKLM" }

    Get-ChildItem -Path $path | ForEach-Object {
        $props = $_.Property
        if ($props -contains "DisplayName") {
            $displayName = $_.GetValue("DisplayName")
            if ($displayName -and $displayName -ne "") {
                $version = $_.GetValue("DisplayVersion")
                $publisher = $_.GetValue("Publisher")
                $installDate = $_.GetValue("InstallDate")
                $installLocation = $_.GetValue("InstallLocation")
                $uninstallString = $_.GetValue("UninstallString")
                $estSize = $_.GetValue("EstimatedSize")
                $sizeMB = 0
                if ($estSize -is [int]) { $sizeMB = [math]::Round($estSize / 1024.0, 2) }

                # 标准化日期
                if ($installDate -and $installDate.Length -eq 8) {
                    $installDate = $installDate.Substring(0,4) + "-" + $installDate.Substring(4,2) + "-" + $installDate.Substring(6,2)
                }

                $results += @{
                    name = $displayName
                    version = if ($version) { $version } else { "" }
                    publisher = if ($publisher) { $publisher } else { "" }
                    install_date = if ($installDate) { $installDate } else { "" }
                    install_location = if ($installLocation) { $installLocation } else { "" }
                    uninstall_string = if ($uninstallString) { $uninstallString } else { "" }
                    estimated_size_mb = $sizeMB
                    architecture = $arch
                    source = $source
                }
            }
        }
    }
}

$results | ConvertTo-Json -Compress`

    // 执行 PowerShell 并解析 JSON...
    // 实现略，参考 registry_info.go 中的 collectAllViaPowerShell
    return nil, fmt.Errorf("PowerShell implementation pending")
}
```

**Linux 兼容文件**：`internal/collectors/software_collector_linux.go`

```go
//go:build !windows

package collectors

import (
    "context"
    "fmt"
)

func NewSoftwareCollector() *SoftwareCollector {
    return &SoftwareCollector{
        BaseCollector: BaseCollector{
            info: CollectorInfo{
                Name:          "installed_software",
                Description:   "Not supported on Linux",
                RequiresAdmin: false,
                Version:       "1.0.0",
            },
        },
    }
}

func (c *SoftwareCollector) Collect(ctx context.Context) ([]interface{}, error) {
    return nil, fmt.Errorf("software collection is only supported on Windows")
}
```

#### 3.2.4 Handler 实现

**文件**：`internal/api/handlers_system.go`（新增方法）

```go
type SoftwareResponse struct {
    Software []*types.InstalledSoftware `json:"software"`
    Total    int                        `json:"total"`
}

// GetInstalledSoftware godoc
// @Summary 获取已安装软件列表
// @Description 返回系统已安装的软件列表（等价于添加/删除程序）
// @Tags system
// @Produce json
// @Success 200 {object} SoftwareResponse
// @Router /api/system/software [get]
func (h *SystemHandler) GetInstalledSoftware(c *gin.Context) {
    collector := collectors.NewSoftwareCollector()
    results, err := collector.Collect(c.Request.Context())
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{
            "error": fmt.Sprintf("Failed to collect software info: %v", err),
        })
        return
    }

    var software []*types.InstalledSoftware
    for _, r := range results {
        if s, ok := r.(*types.InstalledSoftware); ok {
            software = append(software, s)
        }
    }

    c.JSON(http.StatusOK, SoftwareResponse{
        Software: software,
        Total:    len(software),
    })
}

// ExportInstalledSoftware godoc
// @Summary 导出软件列表为 CSV
// @Tags system
// @Produce csv
// @Success 200 {file} file
// @Router /api/system/software/export [get]
func (h *SystemHandler) ExportInstalledSoftware(c *gin.Context) {
    c.Header("Content-Disposition", "attachment; filename=software_export.csv")
    c.Header("Content-Type", "text/csv")
    // 写入 CSV 数据
}
```

**路由注册**：

```go
// SetupSystemRoutes() 中新增
system.GET("/software", systemHandler.GetInstalledSoftware)
system.GET("/software/export", systemHandler.ExportInstalledSoftware)
```

---

## 四、前端实现方案

### 4.1 API 定义

**文件**：`internal/gui/src/api/index.ts`

```typescript
export const systemAPI = {
  // ... 现有方法

  getPatches: () =>
    api.get('/system/patches'),
  exportPatches: () =>
    api.get('/system/patches/export', { responseType: 'blob' }),

  getSoftware: () =>
    api.get('/system/software'),
  exportSoftware: () =>
    api.get('/system/software/export', { responseType: 'blob' }),
}
```

### 4.2 接口定义

**文件**：`internal/gui/src/pages/AssetInventory.tsx`

```typescript
interface PatchInfo {
  kb_id: string
  description: string
  installed_on: string
  installed_by: string
}

interface InstalledSoftware {
  name: string
  version: string
  publisher: string
  install_date: string
  install_location: string
  uninstall_string: string
  estimated_size_mb: number
  architecture: string
  source: string
}
```

### 4.3 状态管理

```typescript
const [patches, setPatches] = useState<PatchInfo[]>([])
const [software, setSoftware] = useState<InstalledSoftware[]>([])
const [softwareSearch, setSoftwareSearch] = useState('')
```

### 4.4 Tab 页新增

```tsx
// 在现有 tabs 后添加
<button
  className={`tab ${activeTab === 'patches' ? 'active' : ''}`}
  onClick={() => {
    setActiveTab('patches')
    if (patches.length === 0) fetchPatches()
  }}
>
  {t('systemInfo.patches')} ({patches.length || '...'})
</button>

<button
  className={`tab ${activeTab === 'software' ? 'active' : ''}`}
  onClick={() => {
    setActiveTab('software')
    if (software.length === 0) fetchSoftware()
  }}
>
  {t('systemInfo.software')} ({software.length || '...'})
</button>
```

### 4.5 数据获取

```typescript
const fetchPatches = async () => {
  try {
    const res = await systemAPI.getPatches()
    setPatches(res.data.patches || [])
  } catch (err) {
    message.error(t('systemInfo.fetchPatchesFailed') || '获取补丁信息失败')
  }
}

const fetchSoftware = async () => {
  try {
    const res = await systemAPI.getSoftware()
    setSoftware(res.data.software || [])
  } catch (err) {
    message.error(t('systemInfo.fetchSoftwareFailed') || '获取软件列表失败')
  }
}
```

### 4.6 渲染 - 系统补丁 Tab

```tsx
{activeTab === 'patches' && (
  <div className="tab-content">
    <div className="tab-toolbar">
      <button className="btn-refresh" onClick={fetchPatches}>
        {t('common.refresh') || '刷新'}
      </button>
      <button className="btn-export" onClick={() => handleExport('patches')}>
        {t('common.export') || '导出'} CSV
      </button>
    </div>

    <table className="data-table">
      <thead>
        <tr>
          <th>{t('systemInfo.kbId') || 'KB编号'}</th>
          <th>{t('systemInfo.description') || '描述'}</th>
          <th>{t('systemInfo.installDate') || '安装日期'}</th>
          <th>{t('systemInfo.installedBy') || '安装者'}</th>
        </tr>
      </thead>
      <tbody>
        {patches.map((patch, i) => (
          <tr key={i}>
            <td className="kb-cell">{patch.kb_id}</td>
            <td>{patch.description}</td>
            <td>{patch.installed_on}</td>
            <td>{patch.installed_by}</td>
          </tr>
        ))}
      </tbody>
    </table>

    {patches.length === 0 && (
      <div className="empty-state">
        {t('systemInfo.noPatchData') || '暂无补丁信息'}
      </div>
    )}
  </div>
)}
```

### 4.7 渲染 - 软件列表 Tab

```tsx
{activeTab === 'software' && (
  <div className="tab-content">
    <div className="tab-toolbar">
      <input
        type="text"
        className="search-input"
        placeholder={t('systemInfo.searchSoftware') || '搜索软件...'}
        value={softwareSearch}
        onChange={(e) => setSoftwareSearch(e.target.value)}
      />
      <button className="btn-refresh" onClick={fetchSoftware}>
        {t('common.refresh') || '刷新'}
      </button>
      <button className="btn-export" onClick={() => handleExport('software')}>
        {t('common.export') || '导出'} CSV
      </button>
    </div>

    <table className="data-table">
      <thead>
        <tr>
          <th>{t('systemInfo.name') || '名称'}</th>
          <th>{t('systemInfo.version') || '版本'}</th>
          <th>{t('systemInfo.publisher') || '发布者'}</th>
          <th>{t('systemInfo.installDate') || '安装日期'}</th>
          <th>{t('systemInfo.size') || '大小'}</th>
          <th>{t('systemInfo.architecture') || '架构'}</th>
        </tr>
      </thead>
      <tbody>
        {software
          .filter(sw =>
            sw.name.toLowerCase().includes(softwareSearch.toLowerCase()) ||
            sw.publisher.toLowerCase().includes(softwareSearch.toLowerCase())
          )
          .map((sw, i) => (
            <tr key={i}>
              <td className="name-cell" title={sw.name}>{sw.name}</td>
              <td>{sw.version || '-'}</td>
              <td>{sw.publisher || '-'}</td>
              <td>{sw.install_date || '-'}</td>
              <td>{sw.estimated_size_mb > 0 ? `${sw.estimated_size_mb.toFixed(1)} MB` : '-'}</td>
              <td>
                <span className={`arch-badge ${sw.architecture}`}>
                  {sw.architecture}
                </span>
              </td>
            </tr>
          ))
        }
      </tbody>
    </table>

    {software.length === 0 && (
      <div className="empty-state">
        {t('systemInfo.noSoftwareData') || '暂无软件信息'}
      </div>
    )}
  </div>
)}
```

### 4.8 语言包更新

**文件**：`internal/gui/src/locales/index.ts`

```typescript
// 中文 (zh)
systemInfo: {
  // ... 现有键
  patches: '系统补丁',
  software: '软件列表',
  kbId: 'KB编号',
  installedBy: '安装者',
  fetchPatchesFailed: '获取补丁信息失败',
  fetchSoftwareFailed: '获取软件列表失败',
  searchSoftware: '搜索软件...',
  noPatchData: '暂无补丁信息',
  noSoftwareData: '暂无软件信息',
}

// 英文 (en)
systemInfo: {
  // ... existing keys
  patches: 'System Patches',
  software: 'Installed Software',
  kbId: 'KB ID',
  installedBy: 'Installed By',
  fetchPatchesFailed: 'Failed to fetch patch information',
  fetchSoftwareFailed: 'Failed to fetch software list',
  searchSoftware: 'Search software...',
  noPatchData: 'No patch information available',
  noSoftwareData: 'No software information available',
}
```

---

## 五、文件变更清单

| 文件 | 操作 | 变更内容 |
|------|------|---------|
| `internal/types/system.go` | 修改 | 新增 `PatchInfo` 和 `InstalledSoftware` 类型 |
| `internal/collectors/patch_collector.go` | 新增 | Windows 补丁采集器 |
| `internal/collectors/patch_collector_linux.go` | 新增 | Linux 兼容桩 |
| `internal/collectors/software_collector.go` | 新增 | Windows 软件列表采集器 |
| `internal/collectors/software_collector_linux.go` | 新增 | Linux 兼容桩 |
| `internal/api/handlers_system.go` | 修改 | 新增 GetInstalledPatches/Export、GetInstalledSoftware/Export 方法 |
| `internal/api/handlers_system.go` | 修改 | SetupSystemRoutes 注册新路由 |
| `internal/gui/src/api/index.ts` | 修改 | 新增 systemAPI.getPatches/getSoftware 方法 |
| `internal/gui/src/pages/AssetInventory.tsx` | 修改 | 新增 patches/software Tab 页 |
| `internal/gui/src/locales/index.ts` | 修改 | 新增翻译键 |

---

## 六、实施顺序

1. **Step 1**: 定义数据类型（`types/system.go`）
2. **Step 2**: 实现 Collector（`collectors/patch_collector.go`, `collectors/software_collector.go`）
3. **Step 3**: 实现 Handler 方法和路由注册
4. **Step 4**: 前端 API 定义
5. **Step 5**: 前端 Tab 页实现
6. **Step 6**: 语言包更新
7. **Step 7**: 测试验证

---

## 七、注意事项

### 7.1 平台兼容性
- 两个功能均仅 Windows 平台可用
- 需提供 Linux/macOS 兼容桩，返回友好错误信息

### 7.2 权限要求
- 系统补丁：无需管理员权限
- 软件列表：无需管理员权限（HKCU 路径），但 HKLM 路径可能需要

### 7.3 性能考虑
- 系统补丁：通常 100-300 条，查询 < 1 秒
- 软件列表：通常 50-200 条，查询 < 1 秒
- 数据量适合前端直接渲染，无需分页

### 7.4 数据准确性
- `Win32_QuickFixEngineering` 不包含 .NET 累积更新
- 注册表 Uninstall 路径可能存在无效条目（已卸载但未清理）
- 建议前端增加数据过滤逻辑

### 7.5 导出功能
- CSV 导出需处理特殊字符（逗号、引号、换行）
- 文件命名建议：`patches_export_YYYYMMDD.csv`、`software_export_YYYYMMDD.csv`

---

## 八、测试验证

### 8.1 后端测试
```bash
# 测试补丁接口
curl http://localhost:8080/api/system/patches

# 测试软件接口
curl http://localhost:8080/api/system/software

# 测试导出
curl -O http://localhost:8080/api/system/patches/export
curl -O http://localhost:8080/api/system/software/export
```

### 8.2 前端测试
1. 验证 Tab 页切换正常
2. 验证数据加载和显示
3. 验证搜索功能（软件列表）
4. 验证导出功能
5. 验证空状态显示

### 8.3 边界情况
- 无补丁/软件数据时的空状态
- PowerShell 不可用时的回退逻辑
- 注册表路径不存在时的容错处理
- 非 Windows 平台的友好提示

---

## 九、实施状态

### 已完成

| 步骤 | 文件 | 状态 |
|------|------|------|
| 类型定义 | `internal/types/system.go` | 已完成 - 新增 `PatchInfo` 和 `InstalledSoftware` |
| 补丁采集器 (Windows) | `internal/collectors/patch_collector.go` | 已完成 - PowerShell 采集 Win32_QuickFixEngineering |
| 补丁采集器 (Linux) | `internal/collectors/patch_collector_linux.go` | 已完成 - 兼容桩 |
| 软件采集器 (Windows) | `internal/collectors/software_collector.go` | 已完成 - PowerShell 采集三个注册表路径 |
| 软件采集器 (Linux) | `internal/collectors/software_collector_linux.go` | 已完成 - 兼容桩 |
| Handler 方法 | `internal/api/handlers_system.go` | 已完成 - `GetInstalledPatches` / `GetInstalledSoftware` |
| 导出 Handler | `internal/api/handlers_system_export.go` | 已完成 - `ExportInstalledPatches` / `ExportInstalledSoftware` |
| 非 Windows 导出桩 | `internal/api/handlers_system_export_nows.go` | 已完成 |
| 路由注册 | `internal/api/handlers_system.go` | 已完成 - 4 个新路由 |
| 前端 API | `internal/gui/src/api/index.ts` | 已完成 - `getPatches` / `getSoftware` |
| 前端页面 | `internal/gui/src/pages/AssetInventory.tsx` | 已完成 - Tab 页、数据表格、搜索、导出 |
| 语言包 | `internal/gui/src/locales/index.ts` | 已完成 - 中英文翻译键 |

### 构建验证

```bash
# 前端构建 - 成功
npm run build
# 输出: dist/index.html, dist/assets/index-*.css, dist/assets/index-*.js

# Go 构建 - 成功
go build -o winalog-go ./cmd/winalog/

# Go vet - 无问题
go vet ./...

# TypeScript 检查 - 无问题
npx tsc --noEmit
```

### 新增 API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/system/patches` | 获取已安装补丁列表 |
| GET | `/api/system/software` | 获取已安装软件列表 |
| GET | `/api/system/patches/export` | 导出补丁列表为 CSV |
| GET | `/api/system/software/export` | 导出软件列表为 CSV |
