//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package journal

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockInstance(file *os.File) error {
	var info unix.Stat_t
	if unix.Fstat(int(file.Fd()), &info) != nil || info.Nlink != 1 {
		return ErrStore
	}
	if unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return ErrInstance
	}
	return nil
}
