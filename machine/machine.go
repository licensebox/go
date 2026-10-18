// Package machine derives a product-scoped binding from the host's native
// identity. Raw system identifiers never leave this package. This detects
// copied credentials; it is not hardware attestation against a hostile OS.
package machine

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Binding is a versioned source and opaque product-specific digest.
type Binding string

// ErrUnavailable means a stable native identity could not be obtained.
// Licensing fails closed; no random, hostname, IP or MAC fallback is used.
var ErrUnavailable = errors.New("licensebox: a stable machine identity is unavailable; contact the product administrator")

var sources = map[string]bool{
	"linux-dmi": true, "linux-device-tree": true, "linux-machine-id": true,
	"windows-smbios": true, "macos-platform": true,
}

func (b Binding) Valid() bool {
	p := strings.Split(string(b), ":")
	if len(p) != 3 || p[0] != "m1" || !sources[p[1]] || len(p[2]) != 64 {
		return false
	}
	x, err := hex.DecodeString(p[2])
	return err == nil && hex.EncodeToString(x) == p[2]
}

// Source describes the native identifier used, without revealing it.
func (b Binding) Source() string {
	if !b.Valid() {
		return "unverified"
	}
	return strings.Split(string(b), ":")[1]
}

// Derive scopes an identifier to a product using a fixed application-specific
// HMAC key. It does not turn a spoofable OS identifier into an attestation.
// Integrators may use it for a platform-specific provider; applications should
// normally call Native. Do not persist rawID or expose it in logs.
func Derive(product, source, rawID string) (Binding, error) {
	if product == "" || strings.ContainsAny(product, "\r\n") || !sources[source] {
		return "", ErrUnavailable
	}
	id := strings.ToLower(strings.TrimSpace(strings.Trim(rawID, "\x00")))
	id = strings.ReplaceAll(id, "-", "")
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) < 8 || len(decoded) > 32 || source != "linux-device-tree" && len(decoded) != 16 {
		return "", ErrUnavailable
	}
	zero, ones := true, true
	for _, b := range decoded {
		zero = zero && b == 0
		ones = ones && b == 255
	}
	if zero || ones {
		return "", ErrUnavailable
	}
	key := sha256.Sum256([]byte("licensebox machine binding v1\n" + product))
	h := hmac.New(sha256.New, key[:])
	h.Write([]byte(source + "\n" + id))
	return Binding("m1:" + source + ":" + hex.EncodeToString(h.Sum(nil))), nil
}

// Native reads the OS/firmware identity and returns only the derived binding.
// Its implementation is selected at build time for each supported platform.
func Native(product string) (Binding, error) {
	source, id, err := nativeID()
	if err != nil {
		return "", fmt.Errorf("%w (%s)", ErrUnavailable, source)
	}
	return Derive(product, source, id)
}
