package lease

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSignCheck(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	l := Lease{Product: "edgewise", User: "u_1", Email: "ada@example.org", Modules: []string{"core", "print"}, Issued: now, Expires: now.Add(30 * 24 * time.Hour), Terms: 1}
	token, err := Sign(l, "k1", priv)
	if err != nil {
		t.Fatal(err)
	}
	keys := Keys{"k1": pub}
	got, err := Check(token, "edgewise", keys, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got.Email != l.Email || !got.Has("print") || got.Has("sim") || got.KID != "k1" || got.V != Version {
		t.Fatalf("got %+v", got)
	}
	if _, err := Check(token, "edgewise", keys, l.Expires); !errors.Is(err, ErrExpired) {
		t.Errorf("at expiry: %v", err)
	}
	if _, err := Check(token, "other", keys, now); !errors.Is(err, ErrMalformed) {
		t.Errorf("other product: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := Check(token, "edgewise", Keys{"k1": other}, now); !errors.Is(err, ErrBadSignature) {
		t.Errorf("other key: %v", err)
	}
	if _, err := Check(token, "edgewise", Keys{"k2": pub}, now); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("unknown kid: %v", err)
	}
	// An edited payload, the same signature.
	a, b, _ := strings.Cut(token, ".")
	edited := strings.Replace(string(mustDec(t, a)), `"core","print"`, `"core","print","sim"`, 1)
	if _, err := Check(enc([]byte(edited))+"."+b, "edgewise", keys, now); !errors.Is(err, ErrBadSignature) {
		t.Errorf("edited: %v", err)
	}
	for _, bad := range []string{"", "x", "a.b", token + "x"} {
		if _, err := Check(bad, "edgewise", keys, now); err == nil {
			t.Errorf("%q checked", bad)
		}
	}
}

func mustDec(t *testing.T, s string) []byte {
	b, err := dec(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
