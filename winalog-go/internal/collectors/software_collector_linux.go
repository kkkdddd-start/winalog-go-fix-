//go:build !windows

package collectors

import (
	"context"
	"fmt"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type SoftwareCollector struct {
	BaseCollector
}

func NewSoftwareCollector() *SoftwareCollector {
	return &SoftwareCollector{
		BaseCollector: BaseCollector{
			info: CollectorInfo{
				Name:          "installed_software",
				Description:   "Not supported on non-Windows platforms",
				RequiresAdmin: false,
				Version:       "1.0.0",
			},
		},
	}
}

func (c *SoftwareCollector) Collect(ctx context.Context) ([]interface{}, error) {
	return nil, fmt.Errorf("software collection is only supported on Windows")
}

func CollectInstalledSoftware(ctx context.Context) ([]*types.InstalledSoftware, error) {
	return nil, fmt.Errorf("software collection is only supported on Windows")
}
