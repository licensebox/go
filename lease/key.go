package lease

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"strings"
)

// Hybrid is the signature algorithm of protocol v3: Ed25519 and
// ML-DSA-65 (FIPS 204) over the same message, both of which must verify,
// so that a signature stays unforgeable if either one is broken.
//
// A key carries its algorithm, written "<alg>:<base64url>", and every
// signed message names it, so a signature is only ever checked under the
// algorithm of the trusted key, never one a token names.
const Hybrid = "ed25519-mldsa65"

// Sizes of a Hybrid key's parts: each part is the Ed25519 part followed
// by the ML-DSA-65 part.
const (
	PublicKeySize = ed25519.PublicKeySize + mldsa.MLDSA65PublicKeySize
	SignatureSize = ed25519.SignatureSize + mldsa.MLDSA65SignatureSize
	SeedSize      = ed25519.SeedSize + mldsa.PrivateKeySize
)

// PublicKey is a key that checks signatures. The zero PublicKey checks
// none.
type PublicKey struct {
	alg string
	ed  ed25519.PublicKey
	ml  *mldsa.PublicKey
}

// Algorithm returns the key's algorithm, as Hybrid.
func (k PublicKey) Algorithm() string { return k.alg }

// String returns the key as "<alg>:<base64url>".
func (k PublicKey) String() string {
	if k.alg == "" {
		return ""
	}
	return k.alg + ":" + enc(append(bytes.Clone(k.ed), k.ml.Bytes()...))
}

// Equal reports whether k and o are the same key.
func (k PublicKey) Equal(o PublicKey) bool { return k.alg != "" && k.String() == o.String() }

// Verify reports whether sig is k's signature of message. message is
// already domain separated, and names k's algorithm.
func (k PublicKey) Verify(message, sig []byte) bool {
	if k.alg != Hybrid || len(sig) != SignatureSize {
		return false
	}
	return ed25519.Verify(k.ed, message, sig[:ed25519.SignatureSize]) &&
		mldsa.Verify(k.ml, message, sig[ed25519.SignatureSize:], nil) == nil
}

// DecodeKey reads a public key written "<alg>:<base64url>". A key with
// no algorithm, or one this package does not know, is malformed.
func DecodeKey(s string) (PublicKey, error) {
	alg, b64, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || alg != Hybrid {
		return PublicKey{}, ErrMalformed
	}
	b, err := dec(b64)
	if err != nil || len(b) != PublicKeySize {
		return PublicKey{}, ErrMalformed
	}
	ml, err := mldsa.NewPublicKey(mldsa.MLDSA65(), b[ed25519.PublicKeySize:])
	if err != nil {
		return PublicKey{}, ErrMalformed
	}
	return PublicKey{alg: alg, ed: ed25519.PublicKey(b[:ed25519.PublicKeySize]), ml: ml}, nil
}

// MustKey returns the public key written "<alg>:<base64url>", as an app
// builds its product's keys in; it panics on a malformed key.
func MustKey(s string) PublicKey {
	k, err := DecodeKey(s)
	if err != nil {
		panic("lease: malformed public key " + s)
	}
	return k
}

// A Signer signs messages, as a product's key signs leases and an
// installation's key signs its calls. message is already domain
// separated, and names the algorithm of Public.
type Signer interface {
	Public() PublicKey
	Sign(message []byte) ([]byte, error)
}

// PrivateKey is a Hybrid private key. It is kept as its seed: the
// Ed25519 seed followed by the ML-DSA-65 seed.
type PrivateKey struct {
	ed ed25519.PrivateKey
	ml *mldsa.PrivateKey
}

// GenerateKey returns a new random Hybrid key.
func GenerateKey() (*PrivateKey, error) {
	seed := make([]byte, SeedSize)
	rand.Read(seed)
	return NewPrivateKey(seed)
}

// NewPrivateKey returns the Hybrid key with the seed.
func NewPrivateKey(seed []byte) (*PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, ErrMalformed
	}
	ml, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed[ed25519.SeedSize:])
	if err != nil {
		return nil, err
	}
	return &PrivateKey{ed: ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]), ml: ml}, nil
}

// Seed returns the key's seed, from which NewPrivateKey makes it again.
func (k *PrivateKey) Seed() []byte { return append(k.ed.Seed(), k.ml.Bytes()...) }

// Public returns the key's public half.
func (k *PrivateKey) Public() PublicKey {
	return PublicKey{alg: Hybrid, ed: k.ed.Public().(ed25519.PublicKey), ml: k.ml.PublicKey()}
}

// Sign signs message with both halves: pure Ed25519, and hedged ML-DSA-65
// with an empty context.
func (k *PrivateKey) Sign(message []byte) ([]byte, error) {
	ml, err := k.ml.Sign(nil, message, nil)
	if err != nil {
		return nil, err
	}
	return append(ed25519.Sign(k.ed, message), ml...), nil
}

// EncodePrivateKey and DecodePrivateKey write and read a private key as
// "<alg>:<base64url seed>", as an installation keeps its key in a file.
func EncodePrivateKey(k *PrivateKey) string { return Hybrid + ":" + enc(k.Seed()) }

func DecodePrivateKey(s string) (*PrivateKey, error) {
	alg, b64, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || alg != Hybrid {
		return nil, ErrMalformed
	}
	seed, err := dec(b64)
	if err != nil {
		return nil, ErrMalformed
	}
	return NewPrivateKey(seed)
}
