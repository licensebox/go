package lease

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"licensebox.dev/machine"
)

func TestSignCheck(t *testing.T) {
	priv := mustKey(t)
	pub := priv.Public()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	binding, _ := machine.Derive("edgewise", "linux-machine-id", "1234567890abcdef1234567890abcdef")
	l := Lease{Binding: binding, Product: "edgewise", User: "u_1", Email: "ada@example.org", Modules: []string{"core", "print"}, Issued: now, Expires: now.Add(30 * 24 * time.Hour), Terms: 1}
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
	if _, err := Check(token, "edgewise", Keys{"k1": mustKey(t).Public()}, now); !errors.Is(err, ErrBadSignature) {
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

func TestHybridSignature(t *testing.T) {
	priv := mustKey(t)
	pub := priv.Public()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	binding, _ := machine.Derive("edgewise", "linux-machine-id", "1234567890abcdef1234567890abcdef")
	l := Lease{Binding: binding, Product: "edgewise", Modules: []string{"core"}, Issued: now, Expires: now.Add(time.Hour)}
	token, err := Sign(l, "k1", priv)
	if err != nil {
		t.Fatal(err)
	}
	keys := Keys{"k1": pub}
	a, b, _ := strings.Cut(token, ".")
	sig := mustDec(t, b)
	if len(sig) != SignatureSize {
		t.Fatalf("signature is %d bytes", len(sig))
	}
	check := func(sig []byte) error {
		_, err := Check(a+"."+enc(sig), "edgewise", keys, now)
		return err
	}
	// Each half alone is not enough: changing either one fails.
	for _, i := range []int{0, ed25519.SignatureSize - 1, ed25519.SignatureSize, SignatureSize - 1} {
		bad := append([]byte(nil), sig...)
		bad[i] ^= 1
		if err := check(bad); !errors.Is(err, ErrBadSignature) {
			t.Errorf("flipped byte %d: %v", i, err)
		}
	}
	for _, bad := range [][]byte{sig[:ed25519.SignatureSize], sig[:len(sig)-1], append(append([]byte(nil), sig...), 0)} {
		if err := check(bad); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%d-byte signature: %v", len(bad), err)
		}
	}
	// An Ed25519 signature under the v2 domain, from the Ed25519 half.
	payload := mustDec(t, a)
	old := ed25519.Sign(priv.ed, append([]byte("licensebox lease v2\n"), payload...))
	if err := check(old); !errors.Is(err, ErrBadSignature) {
		t.Errorf("v2 Ed25519 signature: %v", err)
	}
	// A v2 lease, re-signed properly, is still refused by its version.
	var v map[string]any
	json.Unmarshal(payload, &v)
	v["v"] = 2
	p2, _ := json.Marshal(v)
	s2, _ := priv.Sign(leaseMessage(Hybrid, p2))
	if _, err := Check(enc(p2)+"."+enc(s2), "edgewise", keys, now); !errors.Is(err, ErrVersion) {
		t.Errorf("v2 lease: %v", err)
	}
	// A message signed under another algorithm name does not verify.
	s3, _ := priv.Sign(leaseMessage("ed25519", payload))
	if err := check(s3); !errors.Is(err, ErrBadSignature) {
		t.Errorf("other algorithm: %v", err)
	}
	if !pub.Verify(leaseMessage(Hybrid, payload), sig) || (PublicKey{}).Verify(leaseMessage(Hybrid, payload), sig) {
		t.Error("Verify")
	}
}

func TestKeys(t *testing.T) {
	priv := mustKey(t)
	s := priv.Public().String()
	if !strings.HasPrefix(s, Hybrid+":") || len(s) != len(Hybrid)+1+(PublicKeySize*4+2)/3 {
		t.Fatalf("public key %q", s)
	}
	got, err := DecodeKey(s)
	if err != nil || !got.Equal(priv.Public()) || got.Algorithm() != Hybrid {
		t.Fatalf("DecodeKey: %v", err)
	}
	if got.Equal(mustKey(t).Public()) || (PublicKey{}).Equal(PublicKey{}) {
		t.Error("Equal")
	}
	again, err := DecodePrivateKey(EncodePrivateKey(priv))
	if err != nil || !again.Public().Equal(priv.Public()) || len(priv.Seed()) != SeedSize {
		t.Fatalf("DecodePrivateKey: %v", err)
	}
	edOnly, _, _ := ed25519.GenerateKey(nil)
	b64 := s[len(Hybrid)+1:]
	for _, bad := range []string{
		"", b64, enc(edOnly), "ed25519:" + enc(edOnly), Hybrid + ":" + enc(edOnly),
		"ed25519-mldsa44:" + b64, "ED25519-MLDSA65:" + b64, Hybrid + ":" + b64[:len(b64)-4], Hybrid + ":" + b64 + "AAAA",
	} {
		if _, err := DecodeKey(bad); err == nil {
			t.Errorf("DecodeKey(%.40q) accepted", bad)
		}
	}
	for _, bad := range []string{"", enc(priv.Seed()), enc(priv.ed.Seed()), Hybrid + ":" + enc(priv.ed.Seed()), "x:" + enc(priv.Seed())} {
		if _, err := DecodePrivateKey(bad); err == nil {
			t.Errorf("DecodePrivateKey(%q) accepted", bad)
		}
	}
}

func TestMachineID(t *testing.T) {
	a, b := mustKey(t).Public().String(), mustKey(t).Public().String()
	id := MachineID(a)
	if len(id) != 16 || strings.Trim(id, "0123456789abcdef") != "" || id != MachineID(a) || id == MachineID(b) {
		t.Errorf("MachineID %q, %q", id, MachineID(b))
	}
	// Pinned, so that every SDK and the server agree.
	if got := MachineID("ed25519-mldsa65:AAAA"); got != "6a7f662d752ffabd" {
		t.Errorf("MachineID of a fixed key: %s", got)
	}
}

func mustKey(t testing.TB) *PrivateKey {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func BenchmarkSign(b *testing.B) {
	k := mustKey(b)
	msg := make([]byte, 3200)
	for b.Loop() {
		k.Sign(msg)
	}
}

func BenchmarkVerify(b *testing.B) {
	k := mustKey(b)
	msg := make([]byte, 3200)
	sig, _ := k.Sign(msg)
	pub := k.Public()
	for b.Loop() {
		pub.Verify(msg, sig)
	}
}

func mustDec(t *testing.T, s string) []byte {
	b, err := dec(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
