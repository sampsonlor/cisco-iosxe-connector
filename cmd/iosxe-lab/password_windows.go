//go:build windows

package main

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type credentialUIInfo struct {
	Size             uint32
	Parent           uintptr
	Message, Caption *uint16
	Banner           uintptr
}

func promptPassword(username, target string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	message, _ := windows.UTF16PtrFromString("Enter the SSH password for this read-only lab run. No password will be saved.")
	caption, _ := windows.UTF16PtrFromString("Cisco IOS XE read-only acceptance")
	name, _ := windows.UTF16FromString(username)
	targetName, _ := windows.UTF16PtrFromString(target)
	var userBuffer [514]uint16
	copy(userBuffer[:], name)
	var passwordBuffer [514]uint16
	defer func() { clear(passwordBuffer[:]); runtime.KeepAlive(passwordBuffer) }()
	info := credentialUIInfo{Message: message, Caption: caption}
	info.Size = uint32(unsafe.Sizeof(info))
	var save int32
	proc := windows.NewLazySystemDLL("credui.dll").NewProc("CredUIPromptForCredentialsW")
	// Generic credentials, always show UI, never persist, keep supplied username.
	flags := uintptr(0x40000 | 0x80 | 0x2 | 0x100000)
	code, _, _ := proc.Call(uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(targetName)), 0, 0, uintptr(unsafe.Pointer(&userBuffer[0])), uintptr(len(userBuffer)), uintptr(unsafe.Pointer(&passwordBuffer[0])), uintptr(len(passwordBuffer)), uintptr(unsafe.Pointer(&save)), flags)
	if code != 0 || windows.UTF16ToString(userBuffer[:]) != username {
		return "", errors.New("password dialog cancelled or unavailable")
	}
	return windows.UTF16ToString(passwordBuffer[:]), nil
}
