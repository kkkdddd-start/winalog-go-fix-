//go:build !windows

package collectors

func ListLoadedDLLs() ([]DLLModuleInfo, error) {
	return nil, ErrNotSupported
}
