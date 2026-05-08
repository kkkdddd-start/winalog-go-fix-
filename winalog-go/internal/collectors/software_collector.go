//go:build windows

package collectors

import (
	"context"
	"encoding/json"
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
	psResult, err := c.collectViaPowerShell()
	if err == nil && len(psResult) > 0 {
		return psResult, nil
	}

	observability.Warn("PowerShell software collection failed, falling back to Go API",
		zap.String("module", "software_collector"),
		zap.Error(err))

	return c.collectViaGo()
}

func (c *SoftwareCollector) collectViaPowerShell() ([]*types.InstalledSoftware, error) {
	script := `$ErrorActionPreference = 'SilentlyContinue'
$paths = @(
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"; Arch="x64"; Source="HKLM"},
    @{Path="HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"; Arch="x86"; Source="HKLM"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"; Arch="x64"; Source="HKCU"}
)

$results = @()
foreach ($p in $paths) {
    if (-not (Test-Path $p.Path)) { continue }
    Get-ChildItem -Path $p.Path | ForEach-Object {
        $props = $_.Property
        if ($props -contains "DisplayName") {
            $displayName = $_.GetValue("DisplayName")
            if ($displayName -and $displayName -ne "") {
                $version = if ($props -contains "DisplayVersion") { $_.GetValue("DisplayVersion") } else { "" }
                $publisher = if ($props -contains "Publisher") { $_.GetValue("Publisher") } else { "" }
                $installDate = if ($props -contains "InstallDate") { $_.GetValue("InstallDate") } else { "" }
                $installLocation = if ($props -contains "InstallLocation") { $_.GetValue("InstallLocation") } else { "" }
                $uninstallString = if ($props -contains "UninstallString") { $_.GetValue("UninstallString") } else { "" }
                $estSize = if ($props -contains "EstimatedSize") { $_.GetValue("EstimatedSize") } else { 0 }
                $sizeMB = 0
                if ($estSize -is [int]) { $sizeMB = [math]::Round($estSize / 1024.0, 2) }

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
                    architecture = $p.Arch
                    source = $p.Source
                }
            }
        }
    }
}

$results | ConvertTo-Json -Compress`

	result := utils.RunPowerShellWithTimeout(script, 30*time.Second)
	if !result.Success() || result.Output == "" {
		return nil, fmt.Errorf("PowerShell execution failed: %v", result.Error)
	}

	output := strings.TrimSpace(result.Output)
	if output == "null" || output == "" {
		return nil, fmt.Errorf("empty PowerShell output")
	}

	var psItems []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &psItems); err != nil {
		var single map[string]interface{}
		if err2 := json.Unmarshal([]byte(output), &single); err2 == nil {
			psItems = append(psItems, single)
		} else {
			return nil, fmt.Errorf("JSON parse failed: %w", err)
		}
	}

	var software []*types.InstalledSoftware
	for _, item := range psItems {
		sw := &types.InstalledSoftware{}
		if v, ok := item["name"].(string); ok {
			sw.Name = v
		}
		if v, ok := item["version"].(string); ok {
			sw.Version = v
		}
		if v, ok := item["publisher"].(string); ok {
			sw.Publisher = v
		}
		if v, ok := item["install_date"].(string); ok {
			sw.InstallDate = v
		}
		if v, ok := item["install_location"].(string); ok {
			sw.InstallLocation = v
		}
		if v, ok := item["uninstall_string"].(string); ok {
			sw.UninstallString = v
		}
		if v, ok := item["architecture"].(string); ok {
			sw.Architecture = v
		}
		if v, ok := item["source"].(string); ok {
			sw.Source = v
		}
		if v, ok := item["estimated_size_mb"].(float64); ok {
			sw.EstimatedSizeMB = v
		}

		if sw.Name != "" {
			software = append(software, sw)
		}
	}

	observability.Info("collectSoftware (PowerShell) completed",
		zap.String("module", "software_collector"),
		zap.Int("total", len(software)))

	return software, nil
}

func (c *SoftwareCollector) collectViaGo() ([]*types.InstalledSoftware, error) {
	var allSoftware []*types.InstalledSoftware

	for _, pathInfo := range uninstallPaths {
		subkeys, err := utils.ListRegistrySubkeys(pathInfo.Path)
		if err != nil {
			observability.Warn("Failed to list subkeys",
				zap.String("path", pathInfo.Path),
				zap.Error(err))
			continue
		}

		for _, subkey := range subkeys {
			fullPath := pathInfo.Path + `\` + subkey
			sw := c.parseRegistryKey(fullPath, pathInfo.Arch, pathInfo.Source)
			if sw != nil {
				allSoftware = append(allSoftware, sw)
			}
		}
	}

	observability.Info("collectSoftware (Go) completed",
		zap.String("module", "software_collector"),
		zap.Int("total", len(allSoftware)))

	return allSoftware, nil
}

func (c *SoftwareCollector) parseRegistryKey(keyPath, arch, source string) *types.InstalledSoftware {
	displayName, err := utils.GetRegistryValue(keyPath, "DisplayName")
	if err != nil || displayName == "" {
		return nil
	}

	version, _ := utils.GetRegistryValue(keyPath, "DisplayVersion")
	publisher, _ := utils.GetRegistryValue(keyPath, "Publisher")
	installDate, _ := utils.GetRegistryValue(keyPath, "InstallDate")
	installLocation, _ := utils.GetRegistryValue(keyPath, "InstallLocation")
	uninstallString, _ := utils.GetRegistryValue(keyPath, "UninstallString")

	var sizeMB float64
	if estSizeStr, err := utils.GetRegistryValue(keyPath, "EstimatedSize"); err == nil && estSizeStr != "" {
		if estSize, err := strconv.ParseFloat(estSizeStr, 64); err == nil {
			sizeMB = estSize / 1024.0
		}
	}

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

func CollectInstalledSoftware(ctx context.Context) ([]*types.InstalledSoftware, error) {
	collector := NewSoftwareCollector()
	results, err := collector.Collect(ctx)
	if err != nil {
		return nil, fmt.Errorf("SoftwareCollector.Collect: %w", err)
	}

	software := make([]*types.InstalledSoftware, 0, len(results))
	for _, r := range results {
		if s, ok := r.(*types.InstalledSoftware); ok {
			software = append(software, s)
		}
	}
	return software, nil
}
