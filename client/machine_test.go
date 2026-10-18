package client

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"licensebox.dev/machine"
)

func copyCredentials(t *testing.T, from, to string) {
	t.Helper()
	for _, name := range []string{"install.key", "lease", "seen"} {
		b, err := os.ReadFile(filepath.Join(from, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCopiedCredentialsBlockedOnlineAndOffline(t *testing.T) {
	a, b := newSetup(t), newSetup(t)
	b.srv = a.srv
	b.url = a.url
	ctx := context.Background()
	if _, err := a.run(t).Lease(ctx); err != nil {
		t.Fatal(err)
	}
	copyCredentials(t, a.dir, b.dir)
	for _, offline := range []bool{false, true} {
		a.srv.set(func(s *server) { s.down = offline })
		if _, err := b.run(t).Lease(ctx); !errors.Is(err, ErrMachineChanged) {
			t.Fatalf("copied credentials, offline=%v: %v", offline, err)
		}
		if _, err := b.run(t).Status(); !errors.Is(err, ErrMachineChanged) {
			t.Fatalf("status accepted copied credentials: %v", err)
		}
	}
	if signs, renews := a.srv.count(); signs != 1 || renews != 0 {
		t.Fatalf("copied machine contacted server: %d %d", signs, renews)
	}
	a.srv.set(func(s *server) { s.down = false })
	oldKey, _ := os.ReadFile(filepath.Join(b.dir, "install.key"))
	l, err := b.run(t).SignIn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	newKey, _ := os.ReadFile(filepath.Join(b.dir, "install.key"))
	if string(oldKey) == string(newKey) || l.Binding != bindingFor(b.dir) {
		t.Fatal("explicit activation reused copied identity")
	}
}

func TestMissingNativeIdentityFailsClosed(t *testing.T) {
	st := newSetup(t)
	c := st.run(t)
	c.cfg.MachineBinding = func() (machine.Binding, error) { return "", machine.ErrUnavailable }
	if _, err := c.Require(context.Background(), "core"); !errors.Is(err, machine.ErrUnavailable) {
		t.Fatalf("missing identity: %v", err)
	}
	if signs, renews := st.srv.count(); signs != 0 || renews != 0 {
		t.Fatal("missing identity started sign-in")
	}
}
