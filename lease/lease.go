// Package lease is the lease format of licensebox: a small document,
// signed by the server, that lets one installation of a product run the
// modules it names until it expires.
//
// A lease is encoded as base64url(payload) "." base64url(signature): the
// payload JSON, and a signature over a fixed prefix, the key's algorithm
// and the payload. Each product signs with its own keys, named in the
// lease by kid, so an app carrying the public keys can check a lease but
// not forge or edit one, and a new key can be added before the old one is
// retired. Keys are Hybrid: Ed25519 and ML-DSA-65 together.
package lease

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"licensebox.dev/machine"
	"licensebox.dev/policy"
)

// Version is the lease format's version.
const Version = 3

// Lease is what a lease says.
type Lease struct {
	V       int    `json:"v"`
	KID     string `json:"kid"`
	Product string `json:"product"`
	User    string `json:"user"`
	Email   string `json:"email"`
	// Machine is the installation's public key, "<alg>:<base64url>".
	Machine string `json:"machine"`
	// Binding ties the installation key to the native host identity.
	Binding machine.Binding `json:"binding"`
	Modules []string        `json:"modules"`
	Issued  time.Time       `json:"issued"`
	Expires time.Time       `json:"expires"`
	// Terms is the version of the terms the user accepted.
	Terms int `json:"terms"`
	// Heartbeat is optional signed scheduling policy. Expires remains the hard
	// authorization deadline, including for older clients.
	Heartbeat *policy.Heartbeat `json:"heartbeat,omitempty"`
}

// Has reports whether the lease lets its holder run the module.
func (l Lease) Has(module string) bool { return slices.Contains(l.Modules, module) }

// Keys are a product's public keys, by key id.
type Keys map[string]PublicKey

// Errors that Check returns.
var (
	ErrMalformed    = errors.New("lease: malformed")
	ErrUnknownKey   = errors.New("lease: signed by an unknown key")
	ErrBadSignature = errors.New("lease: bad signature")
	ErrExpired      = errors.New("lease: expired")
	ErrVersion      = errors.New("lease: unknown version")
)

// leaseMessage is what a product key signs for a lease: a prefix, so
// that no other message signed by a product key is also a lease, the
// key's algorithm, and the payload.
func leaseMessage(alg string, payload []byte) []byte {
	return append([]byte("licensebox lease v3\n"+alg+"\n"), payload...)
}

// Sign returns the lease signed with key, whose id the lease names.
func Sign(l Lease, kid string, key Signer) (string, error) {
	if !l.Binding.Valid() || !validHeartbeat(l) {
		return "", ErrMalformed
	}
	l.V, l.KID = Version, kid
	payload, err := json.Marshal(l)
	if err != nil {
		return "", err
	}
	sig, err := key.Sign(leaseMessage(key.Public().Algorithm(), payload))
	if err != nil {
		return "", err
	}
	return enc(payload) + "." + enc(sig), nil
}

// Parse returns what the token says, unchecked, as an app shows who it
// is signed in as even with an expired lease.
func Parse(token string) (Lease, []byte, []byte, error) {
	a, b, ok := strings.Cut(strings.TrimSpace(token), ".")
	if !ok {
		return Lease{}, nil, nil, ErrMalformed
	}
	payload, err1 := dec(a)
	sig, err2 := dec(b)
	if err1 != nil || err2 != nil || len(sig) == 0 {
		return Lease{}, nil, nil, ErrMalformed
	}
	var l Lease
	d := json.NewDecoder(bytes.NewReader(payload))
	if err := d.Decode(&l); err != nil {
		return Lease{}, nil, nil, ErrMalformed
	}
	return l, payload, sig, nil
}

// Check returns the lease the token holds if one of the keys signed it,
// for product, and it has not expired at now.
func Check(token, product string, keys Keys, now time.Time) (Lease, error) {
	l, payload, sig, err := Parse(token)
	if err != nil {
		return Lease{}, err
	}
	if l.V != Version {
		return l, ErrVersion
	}
	key, ok := keys[l.KID]
	if !ok {
		return l, ErrUnknownKey
	}
	if !key.Verify(leaseMessage(key.Algorithm(), payload), sig) {
		return l, ErrBadSignature
	}
	if l.Product != product {
		return l, fmt.Errorf("%w: for product %q, not %q", ErrMalformed, l.Product, product)
	}
	if !l.Binding.Valid() || !validHeartbeat(l) {
		return l, ErrMalformed
	}
	if !now.Before(l.Expires) {
		return l, ErrExpired
	}
	return l, nil
}

// The messages below are what an installation signs, with the
// algorithm of its key, alg. Each starts with its own prefix, so that no
// message is also another kind, and then names alg, so that a signature
// is never checked under another algorithm than it was made with.

// CallMessage returns what an installation signs to call the server
// with its lease at time t: the kind of call (as "renew" or "request"),
// the lease, the time, and a hash of the call's payload, so that a call
// can be neither replayed much later, nor made for another lease, nor
// given another payload.
func CallMessage(alg, kind, token string, binding machine.Binding, t time.Time, payload []byte) []byte {
	h := sha256.Sum256(payload)
	return []byte("licensebox " + kind + " v3\n" + alg + "\n" + strings.TrimSpace(token) + "\n" + string(binding) + "\n" + t.UTC().Format(time.RFC3339) + "\n" + hex.EncodeToString(h[:]))
}

// DeviceMessage returns what an installation signs to start a sign-in for
// a product at time t, proving it holds the key the lease will name.
func DeviceMessage(alg, product string, binding machine.Binding, t time.Time) []byte {
	return []byte("licensebox device v3\n" + alg + "\n" + product + "\n" + string(binding) + "\n" + t.UTC().Format(time.RFC3339))
}

// TokenMessage binds device-flow polling to the initiating key and host.
func TokenMessage(alg, code string, binding machine.Binding, t time.Time) []byte {
	return []byte("licensebox token v3\n" + alg + "\n" + code + "\n" + string(binding) + "\n" + t.UTC().Format(time.RFC3339))
}

// EncodeSignature and DecodeSignature write and read a signature. Its
// length is checked by the key that verifies it.
func EncodeSignature(s []byte) string { return enc(s) }

func DecodeSignature(s string) ([]byte, error) {
	b, err := dec(s)
	if err != nil || len(b) == 0 {
		return nil, ErrMalformed
	}
	return b, nil
}

func enc(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
func dec(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// A heartbeat policy never extends the ordinary signed lease expiry.
func validHeartbeat(l Lease) bool {
	if l.Heartbeat == nil {
		return true
	}
	p := *l.Heartbeat
	return p.Enabled() && p.Validate() == nil && !l.Issued.IsZero() &&
		l.Expires.After(l.Issued) && !l.Expires.After(l.Issued.Add(time.Duration(p.GraceSeconds)*time.Second))
}
