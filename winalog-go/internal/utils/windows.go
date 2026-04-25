//go:build windows

package utils

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func GetComputerName() (string, error) {
	var name [windows.MAX_COMPUTERNAME_LENGTH + 1]uint16
	size := uint32(len(name))

	err := windows.GetComputerName(&name[0], &size)
	if err != nil {
		return "", err
	}

	return windows.UTF16ToString(name[:size]), nil
}

func IsAdmin() bool {
	return isAdminImpl()
}

func isAdminImpl() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	var token windows.Token
	handle, err := windows.GetCurrentProcess()
	if err != nil {
		return false
	}
	err = windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	var elevation uint32
	var returnedLen uint32
	err = windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &returnedLen)
	if err != nil {
		return false
	}

	return elevation != 0
}

func IsWindows() bool {
	return runtime.GOOS == "windows"
}

func GetHostname() (string, error) {
	if runtime.GOOS == "windows" {
		return GetComputerName()
	}
	return os.Hostname()
}

func GetDomain() string {
	if runtime.GOOS != "windows" {
		return ""
	}

	var domain [windows.MAX_PATH]uint16
	var size uint32 = windows.MAX_PATH

	err := windows.GetComputerNameEx(windows.NameUnknown, &domain[0], &size)
	if err != nil {
		return ""
	}

	return windows.UTF16ToString(domain[:size])
}

func GetUserName() (string, error) {
	var name [256]uint16
	size := uint32(len(name))

	err := windows.GetUserNameEx(windows.NameSamCompatible, &name[0], &size)
	if err != nil {
		return "", err
	}

	return windows.UTF16ToString(name[:size]), nil
}

func GetEnvironmentVariable(name string) string {
	if runtime.GOOS != "windows" {
		return os.Getenv(name)
	}

	var value [windows.MAX_PATH]uint16
	size, _ := windows.GetEnvironmentVariable(&windows.StringToUTF16(name)[0], &value[0], uint32(len(value)))

	if size == 0 {
		return ""
	}

	return windows.UTF16ToString(value[:size])
}

func SetEnvironmentVariable(name, value string) error {
	if runtime.GOOS != "windows" {
		return os.Setenv(name, value)
	}

	name16 := windows.StringToUTF16Ptr(name)
	value16 := windows.StringToUTF16Ptr(value)

	return windows.SetEnvironmentVariable(name16, value16)
}

func GetLastError() (int, string) {
	if runtime.GOOS != "windows" {
		return 0, ""
	}

	return 0, ""
}

type WindowsVersion struct {
	Major      uint32
	Minor      uint32
	Build      uint32
	Platform   uint32
	CSDVersion string
}

func GetWindowsVersion() (*WindowsVersion, error) {
	if runtime.GOOS != "windows" {
		return nil, nil
	}

	mod := windows.NewLazyDLL("ntdll.dll")
	procRtlGetVersion := mod.NewProc("RtlGetVersion")

	type RTL_OSVERSIONINFOW struct {
		DwOSVersionInfoSize uint32
		DwMajorVersion      uint32
		DwMinorVersion      uint32
		DwBuildNumber       uint32
		DwPlatformId        uint32
		CSDVersion          [128]uint16
	}

	var osInfo RTL_OSVERSIONINFOW
	osInfo.DwOSVersionInfoSize = uint32(unsafe.Sizeof(osInfo))

	ret, _, _ := procRtlGetVersion.Call(uintptr(unsafe.Pointer(&osInfo)))
	if ret != 0 {
		return nil, fmt.Errorf("RtlGetVersion failed with code: %d", ret)
	}

	return &WindowsVersion{
		Major:      osInfo.DwMajorVersion,
		Minor:      osInfo.DwMinorVersion,
		Build:      osInfo.DwBuildNumber,
		Platform:   osInfo.DwPlatformId,
		CSDVersion: windows.UTF16ToString(osInfo.CSDVersion[:]),
	}, nil
}

func GetProcessToken(pid uint32) (windows.Token, error) {
	if runtime.GOOS != "windows" {
		return 0, nil
	}

	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(handle)

	var token windows.Token
	err = windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token)
	if err != nil {
		return 0, err
	}

	return token, nil
}
