//go:build !windows

package engine

import (
	"os"
	"syscall"
)

func tryLockFile(f *os.File) (*lockfd, error) {
	flock := syscall.Flock_t{
		Type:   syscall.F_WRLCK,
		Whence: 0,
		Start:  0,
		Len:    0,
	}
	err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &flock)
	if err != nil {
		return nil, err
	}
	return &lockfd{fd: f.Fd()}, nil
}

func unlockFile(lock *lockfd) error {
	flock := syscall.Flock_t{
		Type:   syscall.F_UNLCK,
		Whence: 0,
		Start:  0,
		Len:    0,
	}
	return syscall.FcntlFlock(lock.fd, syscall.F_SETLK, &flock)
}
