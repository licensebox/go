package machine

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"regexp"
)

var platformID = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([0-9a-fA-F-]{36})"`)

func platformUUID(b []byte) (string, error) {
	m := platformID.FindSubmatch(b)
	if m == nil {
		return "", ErrUnavailable
	}
	return string(m[1]), nil
}

// smbiosUUID reads Windows RawSMBIOSData and the UUID at offset 8 in a
// Type 1 System Information structure (SMBIOS 2.1+). Bounds and the trailing
// string-set terminator are checked before advancing to another structure.
func smbiosUUID(raw []byte) (string, error) {
	if len(raw) < 8 {
		return "", ErrUnavailable
	}
	n := int(binary.LittleEndian.Uint32(raw[4:8]))
	if n > len(raw)-8 {
		return "", ErrUnavailable
	}
	b := raw[8 : 8+n]
	for len(b) >= 4 {
		length := int(b[1])
		if length < 4 || length > len(b) {
			return "", ErrUnavailable
		}
		if b[0] == 1 && length >= 24 {
			return hex.EncodeToString(b[8:24]), nil
		}
		if b[0] == 127 {
			return "", ErrUnavailable
		}
		end := bytes.Index(b[length:], []byte{0, 0})
		if end < 0 {
			return "", ErrUnavailable
		}
		b = b[length+end+2:]
	}
	return "", ErrUnavailable
}
