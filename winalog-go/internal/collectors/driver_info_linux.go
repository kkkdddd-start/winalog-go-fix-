//go:build !windows

package collectors

import (
	"context"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

func ListDrivers() ([]Driver, error) {
	return nil, ErrNotSupported
}

func CollectDriverInfo(ctx context.Context) ([]*types.DriverInfo, error) {
	return nil, ErrNotSupported
}
