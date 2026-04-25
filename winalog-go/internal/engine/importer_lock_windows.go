//go:build windows

package engine

import (
	"os"

	"golang.org/x/sys/windows"
)

func tryLockFile(f *os.File) (*lockfd, error) {
	var flags uint32 = windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY
	overlapped := &windows.Overlapped{}

	err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, overlapped)
	if err != nil {
		return nil, err
	}
	return &lockfd{fd: f.Fd()}, nil
}

func unlockFile(lock *lockfd) error {
	overlapped := &windows.Overlapped{}
	return windows.UnlockFileEx(windows.Handle(lock.fd), 0, 1, 0, overlapped)
}
