// Package lease is the lease format of licensebox: a small document,
// signed by the server, that lets one installation of a product run the
// modules it names until it expires.
//
// A lease is encoded as base64url(payload) "." base64url(signature): the
// payload JSON, and an Ed25519 signature over a fixed prefix and the
// payload. Each product signs with its own keys, named in the lease by
// kid, so an app carrying the public keys can check a lease but not forge
// or edit one, and a new key can be added before the old one is retired.
package lease

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Version is the lease format's version.
const Version = 1

// Lease is what a lease says.
type Lease struct {
	V       int    `json:"v"`
	KID     string `json:"kid"`
	Product string `json:"product"`
	User    string `json:"user"`
	Email   string `json:"email"`
	// Machine is the installation's public key, base64url.
	Machine string    `json:"machine"`
	Modules []string  `json:"modules"`
	Issued  time.Time `json:"issued"`
	Expires time.Time `json:"expires"`
	// Terms is the version of the terms the user accepted.
	Terms int `json:"terms"`
}

// Has reports whether the lease lets its holder run the module.
func (l Lease) Has(module string) bool { return slices.Contains(l.Modules, module) }

// Keys are a product's public keys, by key id.
type Keys map[string]ed25519.PublicKey

// Errors that Check returns.
var (
	ErrMalformed    = errors.New("lease: malformed")
	ErrUnknownKey   = errors.New("lease: signed by an unknown key")
	ErrBadSignature = errors.New("lease: bad signature")
	ErrExpired      = errors.New("lease: expired")
	ErrVersion      = errors.New("lease: unknown version")
)

// leasePrefix is signed with the payload, so that no other message
// signed by a product key is also a lease.
const leasePrefix = "licensebox lease v1\n"

// Sign returns the lease signed with key, whose id the lease names.
func Sign(l Lease, kid string, key ed25519.PrivateKey) (string, error) {
	l.V, l.KID = Version, kid
	payload, err := json.Marshal(l)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(key, append([]byte(leasePrefix), payload...))
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
	if err1 != nil || err2 != nil || len(sig) != ed25519.SignatureSize {
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
	if !ed25519.Verify(key, append([]byte(leasePrefix), payload...), sig) {
		return l, ErrBadSignature
	}
	if l.Product != product {
		return l, fmt.Errorf("%w: for product %q, not %q", ErrMalformed, l.Product, product)
	}
	if !now.Before(l.Expires) {
		return l, ErrExpired
	}
	return l, nil
}

// renewPrefix is signed with a renewal request, by the installation's
// key.
const renewPrefix = "licensebox renew v1\n"

// RenewMessage returns what an installation signs to renew a lease at
// time t: the token and the time, so that a renewal cannot be replayed
// much later.
func RenewMessage(token string, t time.Time) []byte {
	return []byte(renewPrefix + strings.TrimSpace(token) + "\n" + t.UTC().Format(time.RFC3339))
}

// EncodeKey and DecodeKey write and read a public key as base64url.
func EncodeKey(k ed25519.PublicKey) string { return enc(k) }

func DecodeKey(s string) (ed25519.PublicKey, error) {
	b, err := dec(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, ErrMalformed
	}
	return ed25519.PublicKey(b), nil
}

// MustKey returns the public key written as base64url, as an app builds
// its product's keys in; it panics on a malformed key.
func MustKey(s string) ed25519.PublicKey {
	k, err := DecodeKey(s)
	if err != nil {
		panic("lease: malformed public key " + s)
	}
	return k
}

// EncodeSignature and DecodeSignature write and read a signature.
func EncodeSignature(s []byte) string { return enc(s) }

func DecodeSignature(s string) ([]byte, error) {
	b, err := dec(s)
	if err != nil || len(b) != ed25519.SignatureSize {
		return nil, ErrMalformed
	}
	return b, nil
}

func enc(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
func dec(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
