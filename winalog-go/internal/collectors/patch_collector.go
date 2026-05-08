//go:build windows

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"github.com/kkkdddd-start/winalog-go/internal/types"
	"github.com/kkkdddd-start/winalog-go/internal/utils"
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
	patches, err := c.collectPatches()
	if err != nil {
		return nil, err
	}
	interfaces := make([]interface{}, len(patches))
	for i, p := range patches {
		interfaces[i] = p
	}
	return interfaces, nil
}

type PSPatchItem struct {
	HotFixID    string `json:"HotFixID"`
	Description string `json:"Description"`
	InstalledOn string `json:"InstalledOn"`
	InstalledBy string `json:"InstalledBy"`
}

func (c *PatchCollector) collectPatches() ([]*types.PatchInfo, error) {
	patches, err := c.collectViaPowerShell()
	if err == nil && len(patches) > 0 {
		return patches, nil
	}

	observability.Warn("PowerShell patch collection failed",
		zap.String("module", "patch_collector"),
		zap.Error(err))

	return c.collectViaWMI()
}

func (c *PatchCollector) collectViaPowerShell() ([]*types.PatchInfo, error) {
	script := `$ErrorActionPreference = 'SilentlyContinue'
Get-CimInstance -ClassName Win32_QuickFixEngineering |
    Select-Object HotFixID, Description, 
        @{Name='InstalledOn';Expression={if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { '' }}},
        InstalledBy |
    ConvertTo-Json -Compress`

	result := utils.RunPowerShellWithTimeout(script, 30*time.Second)
	if !result.Success() || result.Output == "" {
		return nil, fmt.Errorf("PowerShell execution failed: %v", result.Error)
	}

	output := strings.TrimSpace(result.Output)
	if output == "null" || output == "" {
		return nil, fmt.Errorf("empty PowerShell output")
	}

	var psItems []PSPatchItem
	if err := json.Unmarshal([]byte(output), &psItems); err != nil {
		var single PSPatchItem
		if err2 := json.Unmarshal([]byte(output), &single); err2 == nil {
			psItems = append(psItems, single)
		} else {
			return nil, fmt.Errorf("JSON parse failed: %w", err)
		}
	}

	var patches []*types.PatchInfo
	for _, item := range psItems {
		patches = append(patches, &types.PatchInfo{
			KBID:        item.HotFixID,
			Description: item.Description,
			InstalledOn: item.InstalledOn,
			InstalledBy: item.InstalledBy,
		})
	}

	observability.Info("collectPatches (PowerShell) completed",
		zap.String("module", "patch_collector"),
		zap.Int("total", len(patches)))

	return patches, nil
}

func (c *PatchCollector) collectViaWMI() ([]*types.PatchInfo, error) {
	return nil, fmt.Errorf("WMI fallback not implemented")
}

func CollectInstalledPatches(ctx context.Context) ([]*types.PatchInfo, error) {
	collector := NewPatchCollector()
	results, err := collector.Collect(ctx)
	if err != nil {
		return nil, fmt.Errorf("PatchCollector.Collect: %w", err)
	}

	patches := make([]*types.PatchInfo, 0, len(results))
	for _, r := range results {
		if p, ok := r.(*types.PatchInfo); ok {
			patches = append(patches, p)
		}
	}
	return patches, nil
}
