package machine

import (
	"os"
	"testing"
)

func TestLinuxNativeSources(t *testing.T) {
	for _, tt := range []struct {
		name, source string
		files        map[string]string
	}{
		{"firmware", "linux-dmi", map[string]string{"/sys/class/dmi/id/product_uuid": exampleUUID, "/etc/machine-id": "22345678123456789abc1234567890ab"}},
		{"arm", "linux-device-tree", map[string]string{"/sys/firmware/devicetree/base/serial-number": "0123456789abcdef\x00"}},
		{"unprivileged", "linux-machine-id", map[string]string{"/etc/machine-id": "12345678123456789abc1234567890ab\n"}},
		{"dbus", "linux-machine-id", map[string]string{"/etc/machine-id": "uninitialized", "/var/lib/dbus/machine-id": "12345678123456789abc1234567890ab"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source, _, err := linuxID(func(path string) ([]byte, error) {
				if v, ok := tt.files[path]; ok {
					return []byte(v), nil
				}
				return nil, os.ErrPermission
			})
			if err != nil || source != tt.source {
				t.Fatalf("got %s %v", source, err)
			}
		})
	}
	if _, _, err := linuxID(func(string) ([]byte, error) { return nil, os.ErrNotExist }); err == nil {
		t.Fatal("missing native identity silently accepted")
	}
}
