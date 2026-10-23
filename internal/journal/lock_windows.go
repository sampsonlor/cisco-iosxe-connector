package journal

import (
	"os"

	"golang.org/x/sys/windows"
)

func lockInstance(file *os.File) error {
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info) != nil || info.NumberOfLinks != 1 {
		return ErrStore
	}
	// Beyond SQLite's maximum database size and its reserved locking bytes.
	// Windows permits locking past EOF; no database bytes are read or written.
	overlap := windows.Overlapped{OffsetHigh: 0x40000000}
	if windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlap) != nil {
		return ErrInstance
	}
	return nil
}
