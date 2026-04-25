//go:build !windows

package utils

type WindowsVersion struct {
	Major      uint32
	Minor      uint32
	Build      uint32
	Platform   uint32
	CSDVersion string
}

func IsAdmin() bool {
	return false
}

func GetDomain() string {
	return ""
}

func GetHostName() (string, error) {
	return "linux-server", nil
}

func GetWindowsVersion() (*WindowsVersion, error) {
	return nil, nil
}
