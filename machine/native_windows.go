package machine

import (
	"syscall"
	"unsafe"
)

func nativeID() (string, string, error) {
	// Kernel32 is a Windows KnownDLL. No WMI subprocess, shell, registry
	// executable, elevation, or external dependency is required.
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemFirmwareTable")
	if err := proc.Find(); err != nil {
		return "windows-smbios", "", ErrUnavailable
	}
	const rsmb = 0x52534d42
	size, _, _ := proc.Call(rsmb, 0, 0, 0)
	if size < 8 || size > 1<<20 {
		return "windows-smbios", "", ErrUnavailable
	}
	b := make([]byte, int(size))
	n, _, _ := proc.Call(rsmb, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if n != size {
		return "windows-smbios", "", ErrUnavailable
	}
	id, err := smbiosUUID(b)
	return "windows-smbios", id, err
}
