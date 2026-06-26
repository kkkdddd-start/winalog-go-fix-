//go:build !windows

package collectors

import (
	"context"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

func ListProcesses() ([]Process, error) {
	return nil, ErrNotSupported
}

func ListNetworkConnections() ([]NetConnection, error) {
	return nil, ErrNotSupported
}

func RunOneClickCollection(ctx context.Context, opts interface{}) (interface{}, error) {
	return nil, ErrNotSupported
}

func VerifySignature(path string) (*SignatureResult, error) {
	return nil, ErrNotSupported
}

func RunPersistenceCollection(ctx context.Context) (string, error) {
	return "", ErrNotSupported
}

func ListLocalUsers() ([]*UserAccount, error) {
	return nil, ErrNotSupported
}

func CollectRegistryPersistence(ctx context.Context) ([]*types.RegistryPersistence, error) {
	return nil, ErrNotSupported
}

func GetProcessDLLs(pid int) ([]DLLModuleInfo, error) {
	return nil, ErrNotSupported
}
