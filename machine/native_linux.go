package machine

import "os"

func nativeID() (string, string, error) { return linuxID(os.ReadFile) }

func linuxID(read func(string) ([]byte, error)) (string, string, error) {
	// Firmware identity when readable, including VMs with a distinct system
	// UUID. ARM boards may expose a device-tree serial instead of DMI.
	for _, item := range []struct{ path, source string }{
		{"/sys/class/dmi/id/product_uuid", "linux-dmi"},
		{"/sys/firmware/devicetree/base/serial-number", "linux-device-tree"},
		{"/etc/machine-id", "linux-machine-id"},
		{"/var/lib/dbus/machine-id", "linux-machine-id"},
	} {
		b, err := read(item.path)
		if err != nil {
			continue
		}
		if _, err := Derive("validate", item.source, string(b)); err == nil {
			return item.source, string(b), nil
		}
	}
	return "linux", "", ErrUnavailable
}
