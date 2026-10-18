package machine

import (
	"encoding/binary"
	"errors"
	"testing"
)

const exampleUUID = "12345678-1234-5678-9abc-1234567890ab"

func TestBindingsAreStableAndProductScoped(t *testing.T) {
	a, err := Derive("app-a", "macos-platform", exampleUUID)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Derive("app-a", "macos-platform", "12345678123456789ABC1234567890AB")
	c, _ := Derive("app-b", "macos-platform", exampleUUID)
	d, _ := Derive("app-a", "macos-platform", "22345678123456789abc1234567890ab")
	if a != b || a == c || a == d || !a.Valid() || a.Source() != "macos-platform" {
		t.Fatal("unstable or unscoped binding")
	}
	for _, raw := range []string{"", "hostname", "00000000000000000000000000000000", "ffffffffffffffffffffffffffffffff", "1234"} {
		if _, err := Derive("app", "linux-machine-id", raw); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("accepted unusable identity %q", raw)
		}
	}
	for _, bad := range []Binding{"", "m1:hostname:123", Binding("m1:unknown:" + string(a)[len(a)-64:])} {
		if bad.Valid() {
			t.Fatal("accepted invalid binding")
		}
	}
}

func TestNativeParsers(t *testing.T) {
	id, err := platformUUID([]byte(`+-o IOPlatformExpertDevice { "IOPlatformUUID" = "` + exampleUUID + `" }`))
	if err != nil || id != exampleUUID {
		t.Fatalf("macOS parse %v", err)
	}
	if _, err := platformUUID([]byte(`"IOPlatformSerialNumber"="not-a-uuid"`)); err == nil {
		t.Fatal("accepted missing UUID")
	}
	structure := make([]byte, 26)
	structure[0] = 1
	structure[1] = 24
	for i := range 16 {
		structure[8+i] = byte(i + 1)
	}
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint32(raw[4:], uint32(len(structure)))
	raw = append(raw, structure...)
	if got, err := smbiosUUID(raw); err != nil || got != "0102030405060708090a0b0c0d0e0f10" {
		t.Fatalf("SMBIOS parse %s %v", got, err)
	}
	for _, bad := range [][]byte{nil, raw[:7], raw[:15], append([]byte{0, 0, 0, 0, 255, 255, 255, 255}, structure...)} {
		if _, err := smbiosUUID(bad); err == nil {
			t.Fatal("accepted truncated SMBIOS")
		}
	}
}
