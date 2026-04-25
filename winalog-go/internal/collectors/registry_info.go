//go:build windows

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/kkkdddd-start/winalog-go/internal/types"
	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type RegistryInfoCollector struct {
	BaseCollector
}

type RegistryKey struct {
	Path  string
	Name  string
	Type  string
	Value string
}

type PSRegistryItem struct {
	Category    string `json:"category"`
	Path        string `json:"path"`
	Name        string `json:"name"`
	Value       string `json:"value"`
	Kind        string `json:"kind"`
	Source      string `json:"source"`
	ImagePath   string `json:"image_path"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	StartType   string `json:"start_type"`
	ServiceType string `json:"service_type"`
	Debugger    string `json:"debugger"`
	DllName     string `json:"dll_name"`
	Enabled     bool   `json:"enabled"`
}

type PSRegistryResult struct {
	RunKeys         []PSRegistryItem `json:"run_keys"`
	UserInit        []PSRegistryItem `json:"user_init"`
	TaskScheduler   []PSRegistryItem `json:"task_scheduler"`
	Services        []PSRegistryItem `json:"services"`
	IFEO            []PSRegistryItem `json:"ifeo"`
	AppInitDLLs     []PSRegistryItem `json:"app_init_dlls"`
	KnownDLLs       []PSRegistryItem `json:"known_dlls"`
	BootExecute     []PSRegistryItem `json:"boot_execute"`
	AppCertDlls     []PSRegistryItem `json:"appcert_dlls"`
	LSASSettings    []PSRegistryItem `json:"lsa_settings"`
	ShellExtensions []PSRegistryItem `json:"shell_extensions"`
	BrowserHelpers  []PSRegistryItem `json:"browser_helpers"`
	StartupFolders  []PSRegistryItem `json:"startup_folders"`
}

func NewRegistryInfoCollector() *RegistryInfoCollector {
	return &RegistryInfoCollector{
		BaseCollector: BaseCollector{
			info: CollectorInfo{
				Name:          "registry_info",
				Description:   "Collect registry persistence information",
				RequiresAdmin: true,
				Version:       "1.0.0",
			},
		},
	}
}

func (c *RegistryInfoCollector) Collect(ctx context.Context) ([]interface{}, error) {
	entries, err := c.collectRegistryInfo()
	if err != nil {
		return nil, err
	}
	interfaces := make([]interface{}, len(entries))
	for i, e := range entries {
		interfaces[i] = e
	}
	return interfaces, nil
}

func (c *RegistryInfoCollector) collectRegistryInfo() ([]*types.RegistryPersistence, error) {
	psResult, err := c.collectAllViaPowerShell()
	if err != nil {
		log.Printf("[WARN] [REGISTRY] PowerShell collection failed, falling back to Go API: %v", err)
		return c.collectRegistryInfoFallback()
	}

	if psResult == nil {
		return c.collectRegistryInfoFallback()
	}

	entry := &types.RegistryPersistence{
		RunKeys:         psRegistryItemsToTypes(psResult.RunKeys),
		UserInit:        psRegistryItemsToTypes(psResult.UserInit),
		TaskScheduler:   psRegistryItemsToTypes(psResult.TaskScheduler),
		Services:        psRegistryItemsToTypes(psResult.Services),
		IFEO:            psRegistryItemsToTypes(psResult.IFEO),
		AppInitDLLs:     psRegistryItemsToTypes(psResult.AppInitDLLs),
		KnownDLLs:       psRegistryItemsToTypes(psResult.KnownDLLs),
		BootExecute:     psRegistryItemsToTypes(psResult.BootExecute),
		AppCertDlls:     psRegistryItemsToTypes(psResult.AppCertDlls),
		LSASSettings:    psRegistryItemsToTypes(psResult.LSASSettings),
		ShellExtensions: psRegistryItemsToTypes(psResult.ShellExtensions),
		BrowserHelpers:  psRegistryItemsToTypes(psResult.BrowserHelpers),
		StartupFolders:  c.collectStartupFolders(),
	}

	total := len(entry.RunKeys) + len(entry.UserInit) + len(entry.TaskScheduler) + len(entry.Services) +
		len(entry.IFEO) + len(entry.AppInitDLLs) + len(entry.KnownDLLs) + len(entry.BootExecute) +
		len(entry.AppCertDlls) + len(entry.LSASSettings) + len(entry.ShellExtensions) + len(entry.BrowserHelpers) +
		len(entry.StartupFolders)

	log.Printf("[INFO] [REGISTRY] collectRegistryInfo (PowerShell): total=%d, runkeys=%d, userinit=%d, tasks=%d, services=%d, ifeo=%d, appinit=%d, known=%d, boot=%d, appcert=%d, lsa=%d, shellext=%d, browser=%d, startup=%d",
		total, len(entry.RunKeys), len(entry.UserInit), len(entry.TaskScheduler), len(entry.Services),
		len(entry.IFEO), len(entry.AppInitDLLs), len(entry.KnownDLLs), len(entry.BootExecute),
		len(entry.AppCertDlls), len(entry.LSASSettings), len(entry.ShellExtensions), len(entry.BrowserHelpers),
		len(entry.StartupFolders))

	return []*types.RegistryPersistence{entry}, nil
}

func (c *RegistryInfoCollector) collectAllViaPowerShell() (*PSRegistryResult, error) {
	script := `
function Get-RegValues($path, $category, $source) {
    if (-not (Test-Path $path)) { return @() }
    $items = @()
    Get-Item -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
        $_.Property | ForEach-Object {
            $name = $_
            $value = $_ | ForEach-Object { ($_ | Get-ItemProperty -ErrorAction SilentlyContinue).$_ }
            if ($null -ne $value -and $value -ne "") {
                $items += @{
                    category = $category
                    path = $path
                    name = $name
                    value = "$value"
                    kind = "REG_SZ"
                    source = $source
                    image_path = ""
                    display_name = ""
                    description = ""
                    start_type = ""
                    service_type = ""
                    debugger = ""
                    dll_name = ""
                    enabled = $true
                }
            }
        }
    }
    return $items
}

$result = @{
    run_keys = @()
    user_init = @()
    task_scheduler = @()
    services = @()
    ifeo = @()
    app_init_dlls = @()
    known_dlls = @()
    boot_execute = @()
    appcert_dlls = @()
    lsa_settings = @()
    shell_extensions = @()
    browser_helpers = @()
    startup_folders = @()
}

# Run Keys
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
"HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" | ForEach-Object {
    $result.run_keys += @(Get-RegValues $_ "RunKeys" "RunKeys")
}

# UserInit / Winlogon
$userInitPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
)
$userInitKeys = @("Userinit", "Shell", "Notify")
foreach ($basePath in $userInitPaths) {
    if (Test-Path $basePath) {
        foreach ($keyName in $userInitKeys) {
            $val = Get-ItemProperty -Path $basePath -Name $keyName -ErrorAction SilentlyContinue
            if ($null -ne $val.$keyName -and $val.$keyName -ne "") {
                $result.user_init += @(@{
                    category = "UserInit"
                    path = "$basePath"
                    name = $keyName
                    value = "$($val.$keyName)"
                    kind = "REG_SZ"
                    source = "UserInit"
                    image_path = ""
                    display_name = ""
                    description = ""
                    start_type = ""
                    service_type = ""
                    debugger = ""
                    dll_name = ""
                    enabled = $true
                })
            }
        }
    }
}

# Services
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services") {
    Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction SilentlyContinue | ForEach-Object {
        $svcName = $_.PSChildName
        $props = $_ | Get-ItemProperty -ErrorAction SilentlyContinue
        $imagePath = ""
        $displayName = ""
        $startType = ""
        $serviceType = ""
        
        if ($null -ne $props.ImagePath) { $imagePath = "$($props.ImagePath)" }
        if ($null -ne $props.DisplayName) { $displayName = "$($props.DisplayName)" }
        if ($null -ne $props.Start) { $startType = "$($props.Start)" }
        if ($null -ne $props.Type) { $serviceType = "$($props.Type)" }
        
        if ($imagePath -ne "" -or $displayName -ne "") {
            $result.services += @(@{
                category = "Services"
                path = "HKLM\SYSTEM\CurrentControlSet\Services\$svcName"
                name = $svcName
                value = $imagePath
                kind = "Service"
                source = "Services"
                image_path = $imagePath
                display_name = $displayName
                description = $(if ($null -ne $props.Description) { "$($props.Description)" } else { "" })
                start_type = $startType
                service_type = $serviceType
                debugger = ""
                dll_name = ""
                enabled = $true
            })
        }
    }
}

# IFEO
"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem -Path $_ -ErrorAction SilentlyContinue | ForEach-Object {
            $props = $_ | Get-ItemProperty -ErrorAction SilentlyContinue
            $debugger = ""
            if ($null -ne $props.Debugger) { $debugger = "$($props.Debugger)" }
            if ($debugger -ne "") {
                $result.ifeo += @(@{
                    category = "IFEO"
                    path = "$($_.PSPath)" -replace '^Microsoft\.PowerShell\.Core\\Registry::'
                    name = $_.PSChildName
                    value = $debugger
                    kind = "IFEO"
                    source = "IFEO"
                    image_path = ""
                    display_name = ""
                    description = ""
                    start_type = ""
                    service_type = ""
                    debugger = $debugger
                    dll_name = ""
                    enabled = $true
                })
            }
        }
    }
}

# AppInit_DLLs
"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" | ForEach-Object {
    if (Test-Path $_) {
        $props = Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue
        $dlls = ""
        $loadVal = ""
        if ($null -ne $props.AppInit_DLLs) { $dlls = "$($props.AppInit_DLLs)" }
        if ($null -ne $props.LoadAppInit_DLLs) { $loadVal = "$($props.LoadAppInit_DLLs)" }
        if ($dlls -ne "" -or $loadVal -eq "1") {
            $result.app_init_dlls += @(@{
                category = "AppInit"
                path = "$($_.PSPath)" -replace '^Microsoft\.PowerShell\.Core\\Registry::'
                name = "AppInit_DLLs"
                value = $dlls
                kind = "AppInit"
                source = "AppInit"
                image_path = ""
                display_name = ""
                description = ""
                start_type = ""
                service_type = ""
                debugger = ""
                dll_name = $dlls
                enabled = $true
            })
        }
    }
}

# KnownDLLs
"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs32" | ForEach-Object {
    if (Test-Path $_) {
        $result.known_dlls += @(Get-RegValues $_ "KnownDLLs" "KnownDLLs")
    }
}

# BootExecute
"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" | ForEach-Object {
    if (Test-Path $_) {
        $props = Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue
        "BootExecute", "BootVerificationProgram", "GlobalFlag", "SetupExecute", "EarlyLaunch" | ForEach-Object {
            $valName = $_
            if ($null -ne $props.$valName) {
                $val = $props.$valName
                if ($val -is [array]) { $val = ($val -join ";") }
                if ("$val" -ne "") {
                    $result.boot_execute += @(@{
                        category = "BootExecute"
                        path = "$($_.PSPath)" -replace '^Microsoft\.PowerShell\.Core\\Registry::'
                        name = $valName
                        value = "$val"
                        kind = "REG_MULTI_SZ"
                        source = "BootExecute"
                        image_path = ""
                        display_name = ""
                        description = ""
                        start_type = ""
                        service_type = ""
                        debugger = ""
                        dll_name = ""
                        enabled = $true
                    })
                }
            }
        }
    }
}

# AppCertDlls
"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls",
"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls32" | ForEach-Object {
    if (Test-Path $_) {
        $result.appcert_dlls += @(Get-RegValues $_ "AppCertDlls" "AppCertDlls")
    }
}

# LSA Settings
"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | ForEach-Object {
    if (Test-Path $_) {
        $result.lsa_settings += @(Get-RegValues $_ "LSA" "LSA")
    }
}

# Shell Extensions
"HKLM:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers",
"HKLM:\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers",
"HKLM:\SOFTWARE\Classes\Folder\Shellex\ContextMenuHandlers",
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved" | ForEach-Object {
    if (Test-Path $_) {
        $result.shell_extensions += @(Get-RegValues $_ "ShellExtensions" "ShellExtensions")
    }
}

# Browser Helper Objects
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" | ForEach-Object {
    if (Test-Path $_) {
        $result.browser_helpers += @(Get-RegValues $_ "BrowserHelper" "BrowserHelper")
    }
}

$result | ConvertTo-Json -Depth 5 -Compress
`

	log.Printf("[INFO] [REGISTRY] Running single PowerShell script to collect all registry persistence data")

	result := utils.RunPowerShellWithTimeout(script, 120)
	if !result.Success() || result.Output == "" {
		return nil, fmt.Errorf("PowerShell script failed: %v", result.Error)
	}

	output := strings.TrimSpace(result.Output)
	if output == "" || output == "null" {
		return nil, fmt.Errorf("empty PowerShell output")
	}

	log.Printf("[DEBUG] [REGISTRY] PowerShell output length: %d", len(output))

	var psResult PSRegistryResult
	if err := json.Unmarshal([]byte(output), &psResult); err != nil {
		log.Printf("[WARN] [REGISTRY] Failed to parse PowerShell output: %v", err)
		return nil, err
	}

	log.Printf("[INFO] [REGISTRY] Parsed results: runkeys=%d, userinit=%d, tasks=%d, services=%d, ifeo=%d, appinit=%d, known=%d, boot=%d, appcert=%d, lsa=%d, shellext=%d, browser=%d",
		len(psResult.RunKeys), len(psResult.UserInit), len(psResult.TaskScheduler), len(psResult.Services),
		len(psResult.IFEO), len(psResult.AppInitDLLs), len(psResult.KnownDLLs), len(psResult.BootExecute),
		len(psResult.AppCertDlls), len(psResult.LSASSettings), len(psResult.ShellExtensions), len(psResult.BrowserHelpers))

	return &psResult, nil
}

func psRegistryItemsToTypes(items []PSRegistryItem) []*types.RegistryInfo {
	result := make([]*types.RegistryInfo, 0, len(items))
	for _, item := range items {
		info := &types.RegistryInfo{
			Path:        item.Path,
			Name:        item.Name,
			Value:       item.Value,
			Type:        item.Kind,
			Source:      item.Source,
			Enabled:     item.Enabled,
			DisplayName: item.DisplayName,
			ImagePath:   item.ImagePath,
			Description: item.Description,
			StartType:   item.StartType,
			ServiceType: item.ServiceType,
			Debugger:    item.Debugger,
			DllName:     item.DllName,
		}
		result = append(result, info)
	}
	return result
}

func (c *RegistryInfoCollector) collectRegistryInfoFallback() ([]*types.RegistryPersistence, error) {
	runKeys := c.collectRunKeys()
	userInit := c.collectUserInitKeys()
	taskScheduler := c.collectScheduledTaskKeys()
	services := c.collectServices()
	ifeo := c.collectIFEO()
	appInitDLLs := c.collectAppInitDLLs()
	knownDLLs := c.collectKnownDLLs()
	bootExecute := c.collectBootExecute()
	appCertDLLs := c.collectAppCertDlls()
	lsaSettings := c.collectLSASettings()
	shellExts := c.collectShellExtensions()
	browserHelpers := c.collectBrowserHelpers()
	startupFolders := c.collectStartupFolders()

	entry := &types.RegistryPersistence{
		RunKeys:         runKeys,
		UserInit:        userInit,
		TaskScheduler:   taskScheduler,
		Services:        services,
		IFEO:            ifeo,
		AppInitDLLs:     appInitDLLs,
		KnownDLLs:       knownDLLs,
		BootExecute:     bootExecute,
		AppCertDlls:     appCertDLLs,
		LSASSettings:    lsaSettings,
		ShellExtensions: shellExts,
		BrowserHelpers:  browserHelpers,
		StartupFolders:  startupFolders,
	}

	return []*types.RegistryPersistence{entry}, nil
}

func (c *RegistryInfoCollector) collectRunKeys() []*types.RegistryInfo {
	runKeyPaths := []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`,
	}

	return c.collectRegistryValues(runKeyPaths, "RunKeys")
}

func (c *RegistryInfoCollector) collectRegistryValues(paths []string, source string) []*types.RegistryInfo {
	items := make([]*types.RegistryInfo, 0)

	for _, keyPath := range paths {
		if !utils.RegistryKeyExists(keyPath) {
			continue
		}

		values, err := utils.ListRegistryValues(keyPath)
		if err != nil {
			continue
		}

		for _, valueName := range values {
			value, err := utils.GetRegistryValue(keyPath, valueName)
			if err != nil || value == "" {
				continue
			}

			items = append(items, &types.RegistryInfo{
				Path:   keyPath,
				Name:   valueName,
				Value:  value,
				Type:   "REG_SZ",
				Source: source,
				Enabled: true,
			})
		}
	}

	return items
}

func (c *RegistryInfoCollector) collectUserInitKeys() []*types.RegistryInfo {
	paths := []string{
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`,
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`,
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`,
		`HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`,
		`HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`,
	}

	userInitKeys := make([]*types.RegistryInfo, 0)

	for _, keyPath := range paths {
		if !utils.RegistryKeyExists(keyPath) {
			continue
		}

		value, _ := utils.GetRegistryValue(keyPath, "")
		if value != "" {
			name := keyPath[strings.LastIndex(keyPath, "\\")+1:]
			userInitKeys = append(userInitKeys, &types.RegistryInfo{
				Path:    keyPath,
				Name:    name,
				Type:    "REG_SZ",
				Value:   value,
				Source:  "UserInit",
				Enabled: true,
			})
		}
	}

	return userInitKeys
}

func (c *RegistryInfoCollector) collectScheduledTaskKeys() []*types.RegistryInfo {
	tasksPaths := []string{
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`,
	}

	items := make([]*types.RegistryInfo, 0)

	for _, basePath := range tasksPaths {
		if !utils.RegistryKeyExists(basePath) {
			continue
		}

		subkeys, _ := utils.ListRegistrySubkeys(basePath)
		for _, guid := range subkeys {
			fullPath := basePath + "\\" + guid
			if !utils.RegistryKeyExists(fullPath) {
				continue
			}

			taskPath, _ := utils.GetRegistryValue(fullPath, "Path")
			state, _ := utils.GetRegistryValue(fullPath, "State")

			if taskPath != "" {
				items = append(items, &types.RegistryInfo{
					Path:        fullPath,
					Name:        guid,
					DisplayName: taskPath,
					Value:       state,
					Source:      "TaskScheduler",
					Enabled:     true,
				})
			}
		}
	}

	return items
}

func (c *RegistryInfoCollector) collectServices() []*types.RegistryInfo {
	serviceBasePath := `HKLM\SYSTEM\CurrentControlSet\Services`

	services := make([]*types.RegistryInfo, 0)

	if !utils.RegistryKeyExists(serviceBasePath) {
		return services
	}

	subkeys, err := utils.ListRegistrySubkeys(serviceBasePath)
	if err != nil {
		log.Printf("[WARN] [REGISTRY] ListRegistrySubkeys failed for Services: %v", err)
		return services
	}

	for _, subkey := range subkeys {
		fullPath := serviceBasePath + "\\" + subkey

		imagePath, _ := utils.GetRegistryValue(fullPath, "ImagePath")
		displayName, _ := utils.GetRegistryValue(fullPath, "DisplayName")
		description, _ := utils.GetRegistryValue(fullPath, "Description")
		startType, _ := utils.GetRegistryValue(fullPath, "Start")
		serviceType, _ := utils.GetRegistryValue(fullPath, "Type")

		if imagePath == "" && displayName == "" {
			continue
		}

		services = append(services, &types.RegistryInfo{
			Path:        fullPath,
			Name:        subkey,
			DisplayName: displayName,
			ImagePath:   imagePath,
			Description: description,
			StartType:   startType,
			ServiceType: serviceType,
			Source:      "Services",
			Type:        "Service",
			Enabled:     true,
		})
	}

	return services
}

func (c *RegistryInfoCollector) collectIFEO() []*types.RegistryInfo {
	paths := []string{
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
	}

	ifeo := make([]*types.RegistryInfo, 0)

	for _, basePath := range paths {
		if !utils.RegistryKeyExists(basePath) {
			continue
		}

		subkeys, _ := utils.ListRegistrySubkeys(basePath)
		for _, subkey := range subkeys {
			fullPath := basePath + "\\" + subkey

			debugger, _ := utils.GetRegistryValue(fullPath, "Debugger")

			if debugger != "" {
				ifeo = append(ifeo, &types.RegistryInfo{
					Path:     fullPath,
					Name:     subkey,
					Debugger: debugger,
					Type:     "IFEO",
					Value:    debugger,
					Source:   "IFEO",
					Enabled:  true,
				})
			}
		}
	}

	return ifeo
}

func (c *RegistryInfoCollector) collectAppInitDLLs() []*types.RegistryInfo {
	paths := []string{
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
		`HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows`,
	}

	appInit := make([]*types.RegistryInfo, 0)

	for _, keyPath := range paths {
		if !utils.RegistryKeyExists(keyPath) {
			continue
		}

		dllName, _ := utils.GetRegistryValue(keyPath, "AppInit_DLLs")
		loadAppInitDLLs, _ := utils.GetRegistryValue(keyPath, "LoadAppInit_DLLs")

		if dllName != "" || loadAppInitDLLs == "1" {
			appInit = append(appInit, &types.RegistryInfo{
				Path:    keyPath,
				Name:    "AppInit_DLLs",
				DllName: dllName,
				Value:   loadAppInitDLLs,
				Source:  "AppInit",
				Type:    "AppInit",
				Enabled: true,
			})
		}
	}

	return appInit
}

func (c *RegistryInfoCollector) collectKnownDLLs() []*types.RegistryInfo {
	paths := []string{
		`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`,
	}

	return c.collectRegistryPaths(paths, "KnownDLLs")
}

func (c *RegistryInfoCollector) collectBootExecute() []*types.RegistryInfo {
	keyPath := `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`

	bootExecute := make([]*types.RegistryInfo, 0)

	if !utils.RegistryKeyExists(keyPath) {
		return bootExecute
	}

	valueNames := []string{"BootExecute", "BootVerificationProgram", "GlobalFlag", "SetupExecute", "EarlyLaunch"}

	for _, valueName := range valueNames {
		value, err := utils.GetRegistryValue(keyPath, valueName)
		if err == nil && value != "" {
			bootExecute = append(bootExecute, &types.RegistryInfo{
				Path:    keyPath,
				Name:    valueName,
				Type:    "REG_MULTI_SZ",
				Value:   value,
				Source:  "BootExecute",
				Enabled: true,
			})
		}
	}

	return bootExecute
}

func (c *RegistryInfoCollector) collectAppCertDlls() []*types.RegistryInfo {
	paths := []string{
		`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`,
	}

	return c.collectRegistryPaths(paths, "AppCertDlls")
}

func (c *RegistryInfoCollector) collectLSASettings() []*types.RegistryInfo {
	keyPath := `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`

	lsaSettings := make([]*types.RegistryInfo, 0)

	if !utils.RegistryKeyExists(keyPath) {
		return lsaSettings
	}

	valueNames, _ := utils.ListRegistryValues(keyPath)
	for _, valueName := range valueNames {
		value, _ := utils.GetRegistryValue(keyPath, valueName)
		if value != "" {
			lsaSettings = append(lsaSettings, &types.RegistryInfo{
				Path:    keyPath,
				Name:    valueName,
				Type:    "REG_SZ",
				Value:   value,
				Source:  "LSA",
				Enabled: true,
			})
		}
	}

	return lsaSettings
}

func (c *RegistryInfoCollector) collectShellExtensions() []*types.RegistryInfo {
	shellExtPaths := []string{
		`HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers`,
		`HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers`,
		`HKLM\SOFTWARE\Classes\Folder\Shellex\ContextMenuHandlers`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved`,
	}

	shellExts := make([]*types.RegistryInfo, 0)

	for _, basePath := range shellExtPaths {
		if !utils.RegistryKeyExists(basePath) {
			continue
		}

		subkeys, _ := utils.ListRegistrySubkeys(basePath)
		for _, clsid := range subkeys {
			fullPath := basePath + "\\" + clsid
			value, _ := utils.GetRegistryValue(fullPath, "")

			if value != "" {
				shellExts = append(shellExts, &types.RegistryInfo{
					Path:   fullPath,
					Name:   clsid,
					Value:  value,
					Type:   "ShellExt",
					Source: "ShellExtensions",
					Enabled: true,
				})
			}
		}
	}

	return shellExts
}

func (c *RegistryInfoCollector) collectBrowserHelpers() []*types.RegistryInfo {
	paths := []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`,
		`HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`,
	}

	browserHelpers := make([]*types.RegistryInfo, 0)

	for _, basePath := range paths {
		if !utils.RegistryKeyExists(basePath) {
			continue
		}

		subkeys, _ := utils.ListRegistrySubkeys(basePath)
		for _, subkey := range subkeys {
			fullPath := basePath + "\\" + subkey
			value, _ := utils.GetRegistryValue(fullPath, "")

			info := &types.RegistryInfo{
				Path:    fullPath,
				Name:    subkey,
				Value:   value,
				Source:  "BrowserHelper",
				Enabled: true,
			}

			if value != "" {
				info.Type = "BHO"
			}

			browserHelpers = append(browserHelpers, info)
		}
	}

	return browserHelpers
}

func (c *RegistryInfoCollector) collectRegistryPaths(paths []string, source string) []*types.RegistryInfo {
	items := make([]*types.RegistryInfo, 0)

	for _, keyPath := range paths {
		if !utils.RegistryKeyExists(keyPath) {
			continue
		}

		subkeys, _ := utils.ListRegistrySubkeys(keyPath)
		for _, subkey := range subkeys {
			fullPath := keyPath + "\\" + subkey
			value, err := utils.GetRegistryValue(keyPath, subkey)

			info := &types.RegistryInfo{
				Path:    fullPath,
				Name:    subkey,
				Source:  source,
				Enabled: true,
			}

			if err == nil && value != "" {
				info.Type = "REG_SZ"
				info.Value = value
			}

			items = append(items, info)
		}

		if len(subkeys) == 0 {
			value, _ := utils.GetRegistryValue(keyPath, "")
			if value != "" {
				name := keyPath[strings.LastIndex(keyPath, "\\")+1:]
				items = append(items, &types.RegistryInfo{
					Path:    keyPath,
					Name:    name,
					Type:    "REG_SZ",
					Value:   value,
					Source:  source,
					Enabled: true,
				})
			}
		}
	}

	return items
}

func ListRegistryKeys(path string) ([]RegistryKey, error) {
	keys := make([]RegistryKey, 0)

	subkeys, err := utils.ListRegistrySubkeys(path)
	if err != nil {
		return keys, err
	}

	for _, subkey := range subkeys {
		value, err := utils.GetRegistryValue(path, subkey)
		if err != nil {
			continue
		}

		keys = append(keys, RegistryKey{
			Path:  path + "\\" + subkey,
			Name:  subkey,
			Type:  "REG_SZ",
			Value: value,
		})
	}

	return keys, nil
}

func GetRegistryValue(keyPath, valueName string) (string, error) {
	return utils.GetRegistryValue(keyPath, valueName)
}

func RegistryKeyExists(path string) bool {
	return utils.RegistryKeyExists(path)
}

func (c *RegistryInfoCollector) collectStartupFolders() []*types.RegistryInfo {
	items := make([]*types.RegistryInfo, 0)

	programdata := os.Getenv("PROGRAMDATA")
	appdata := os.Getenv("APPDATA")

	folderPaths := []string{
		programdata + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
		appdata + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
	}

	executableExtensions := map[string]string{
		".exe": "Executable",
		".bat": "Batch Script",
		".cmd": "Command Script",
		".ps1": "PowerShell Script",
		".vbs": "VBScript",
		".js":  "JavaScript",
		".lnk": "Shortcut",
	}

	for _, folderPath := range folderPaths {
		if folderPath == "" {
			continue
		}

		files, err := os.ReadDir(folderPath)
		if err != nil {
			continue
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}

			fileNameLower := strings.ToLower(file.Name())
			description := "File"
			for ext, desc := range executableExtensions {
				if strings.HasSuffix(fileNameLower, ext) {
					description = desc
					break
				}
			}

			item := &types.RegistryInfo{
				Path:        folderPath,
				Name:        file.Name(),
				Value:       folderPath + "\\" + file.Name(),
				Type:        "StartupFolder",
				Source:      "StartupFolders",
				Description: description,
				Enabled:     true,
			}

			items = append(items, item)
		}
	}

	return items
}

func CollectRegistryPersistence(ctx context.Context) ([]*types.RegistryPersistence, error) {
	collector := NewRegistryInfoCollector()
	results, err := collector.Collect(ctx)
	if err != nil {
		return nil, fmt.Errorf("RegistryInfoCollector.Collect: %w", err)
	}

	entries := make([]*types.RegistryPersistence, 0, len(results))
	for _, r := range results {
		if e, ok := r.(*types.RegistryPersistence); ok {
			entries = append(entries, e)
		}
	}
	return entries, nil
}
