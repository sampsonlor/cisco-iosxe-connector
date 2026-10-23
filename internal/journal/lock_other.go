//go:build !windows && !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package journal

import "os"

func lockInstance(*os.File) error { return ErrStore }
