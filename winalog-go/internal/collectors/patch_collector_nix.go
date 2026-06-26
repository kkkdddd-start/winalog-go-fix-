//go:build !windows

package collectors

import (
	"context"
	"fmt"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type PatchCollector struct {
	BaseCollector
}

func NewPatchCollector() *PatchCollector {
	return &PatchCollector{
		BaseCollector: BaseCollector{
			info: CollectorInfo{
				Name:          "patch_info",
				Description:   "Not supported on non-Windows platforms",
				RequiresAdmin: false,
				Version:       "1.0.0",
			},
		},
	}
}

func (c *PatchCollector) Collect(ctx context.Context) ([]interface{}, error) {
	return nil, fmt.Errorf("patch collection is only supported on Windows")
}

func CollectInstalledPatches(ctx context.Context) ([]*types.PatchInfo, error) {
	return nil, fmt.Errorf("patch collection is only supported on Windows")
}
