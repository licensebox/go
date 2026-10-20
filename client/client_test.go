package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"licensebox.dev/lease"
	"licensebox.dev/machine"
)

// server is a licensebox server for one product and one user, enough to
// test the client against: it signs in at the second poll, renews leases
// signed by their installation, and can be revoked, given modules, or
// made unreachable.
type server struct {
	t   *testing.T
	key *lease.PrivateKey
	now func() time.Time

	mu       sync.Mutex
	modules  []string
	life     time.Duration
	revoked  bool
	down     bool
	polls    int
	signIns  int
	renewals int
	usageOn  bool
	usage    map[string]int // runs counted, by command
	requests [][]string
	bindings map[string]machine.Binding
}

func (s *server) issue(machine string) string {
	l := lease.Lease{Binding: s.bindings[machine], Product: "myapp", User: "u_1", Email: "ada@example.org", Machine: machine,
		Modules: s.modules, Issued: s.now(), Expires: s.now().Add(s.life), Terms: 1}
	token, err := lease.Sign(l, "k1", s.key)
	if err != nil {
		s.t.Fatal(err)
	}
	return token
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fail := func(status int, code string) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": code})
	}
	if s.down {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	var req map[string]string
	json.NewDecoder(r.Body).Decode(&req)
	switch r.URL.Path {
	case "/v1/device":
		t, _ := time.Parse(time.RFC3339, req["time"])
		key, _ := lease.DecodeKey(req["machine"])
		sig, _ := lease.DecodeSignature(req["signature"])
		if !key.Verify(lease.DeviceMessage(key.Algorithm(), req["product"], machine.Binding(req["binding"]), t), sig) {
			fail(http.StatusUnauthorized, "invalid_signature")
			return
		}
		if s.bindings == nil {
			s.bindings = map[string]machine.Binding{}
		}
		s.bindings[req["machine"]] = machine.Binding(req["binding"])
		s.polls = 0
		json.NewEncoder(w).Encode(map[string]any{"device_code": "dc:" + req["machine"], "user_code": "WDJB-MJHT",
			"verification_uri": "https://example.org/activate", "expires_in": 600, "interval_ms": 1})
	case "/v1/token":
		if s.polls++; s.polls < 2 {
			fail(http.StatusBadRequest, "authorization_pending")
			return
		}
		s.signIns++
		json.NewEncoder(w).Encode(map[string]any{"lease": s.issue(strings.TrimPrefix(req["device_code"], "dc:")), "usage": s.usageOn})
	case "/v1/renew", "/v1/modules", "/v1/request":
		l, err := lease.Check(req["lease"], "myapp", lease.Keys{"k1": s.key.Public()}, time.Time{})
		if err != nil && !errors.Is(err, lease.ErrExpired) {
			fail(http.StatusBadRequest, "invalid_lease")
			return
		}
		t, _ := time.Parse(time.RFC3339, req["time"])
		key, _ := lease.DecodeKey(l.Machine)
		sig, _ := lease.DecodeSignature(req["signature"])
		kind := strings.TrimPrefix(r.URL.Path, "/v1/")
		if !key.Verify(lease.CallMessage(key.Algorithm(), kind, req["lease"], machine.Binding(req["binding"]), t, []byte(req["payload"])), sig) {
			fail(http.StatusUnauthorized, "invalid_signature")
			return
		}
		if s.revoked {
			fail(http.StatusForbidden, "revoked")
			return
		}
		switch kind {
		case "renew":
			var p struct{ Usage []UsageCount }
			json.Unmarshal([]byte(req["payload"]), &p)
			for _, u := range p.Usage {
				if s.usage == nil {
					s.usage = map[string]int{}
				}
				s.usage[u.Command] += u.OK + u.Failed
			}
			s.renewals++
			json.NewEncoder(w).Encode(map[string]any{"lease": s.issue(l.Machine), "usage": s.usageOn})
		case "modules":
			json.NewEncoder(w).Encode([]Module{{Name: "core", Free: true, Have: true}, {Name: "export", Description: "exporting"}})
		case "request":
			var p struct {
				Modules []string
				Note    string
			}
			json.Unmarshal([]byte(req["payload"]), &p)
			s.requests = append(s.requests, p.Modules)
			json.NewEncoder(w).Encode(Request{ID: "r1", Modules: p.Modules, Note: p.Note, Status: "pending"})
		}
	default:
		http.NotFound(w, r)
	}
}

func (s *server) set(f func(*server)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

func (s *server) count() (signIns, renewals int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signIns, s.renewals
}

type setup struct {
	srv   *server
	url   string
	dir   string
	clock *time.Time
	out   *bytes.Buffer
}

func newSetup(t *testing.T) setup {
	key := mustKey(t)
	clock := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	st := setup{dir: t.TempDir(), clock: &clock, out: &bytes.Buffer{}}
	st.srv = &server{t: t, key: key, now: func() time.Time { return *st.clock }, modules: []string{"core"}, life: 24 * time.Hour}
	hs := httptest.NewServer(st.srv)
	t.Cleanup(hs.Close)
	st.url = hs.URL
	return st
}

// run is a run of the app: a new client over the same folder.
func (st setup) run(t *testing.T) *Client {
	c, err := New(Config{
		Product: "myapp", Keys: lease.Keys{"k1": st.srv.key.Public()},
		MachineBinding: func() (machine.Binding, error) { return bindingFor(st.dir), nil }, Server: st.url, Dir: st.dir, Out: st.out, Now: func() time.Time { return *st.clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEveryRunRenews(t *testing.T) {
	st := newSetup(t)
	ctx := context.Background()
	l, err := st.run(t).Lease(ctx)
	if err != nil || l.Email != "ada@example.org" || !strings.Contains(st.out.String(), "WDJB-MJHT") {
		t.Fatalf("first run: %v, %+v, %q", err, l, st.out.String())
	}
	if s, r := st.srv.count(); s != 1 || r != 0 {
		t.Fatalf("first run: %d sign-ins, %d renewals; want 1, 0", s, r)
	}
	for run := 1; run <= 3; run++ {
		*st.clock = st.clock.Add(time.Hour)
		c := st.run(t)
		for range 3 { // several checks in one run: one renewal
			if _, err := c.Require(ctx, "core"); err != nil {
				t.Fatalf("run %d: %v", run, err)
			}
		}
		if s, r := st.srv.count(); s != 1 || r != run {
			t.Fatalf("after run %d: %d sign-ins, %d renewals; want 1, %d", run, s, r, run)
		}
	}
}

func TestGrantAndRevokeAtNextRun(t *testing.T) {
	st := newSetup(t)
	ctx := context.Background()
	if _, err := st.run(t).Lease(ctx); err != nil {
		t.Fatal(err)
	}
	var me *ModuleError
	if _, err := st.run(t).Require(ctx, "export"); !errors.As(err, &me) || me.Module != "export" {
		t.Fatalf("an ungranted module: %v", err)
	}
	st.srv.set(func(s *server) { s.modules = []string{"core", "export"} })
	if l, err := st.run(t).Require(ctx, "export"); err != nil || !l.Has("export") {
		t.Fatalf("granted: %v", err)
	}
	st.srv.set(func(s *server) { s.revoked = true })
	if _, err := st.run(t).Lease(ctx); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked: %v", err)
	}
	if _, err := os.Stat(filepath.Join(st.dir, "lease")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the lease is still kept after revocation: %v", err)
	}
}

func TestOffline(t *testing.T) {
	st := newSetup(t)
	ctx := context.Background()
	if _, err := st.run(t).Lease(ctx); err != nil {
		t.Fatal(err)
	}
	st.srv.set(func(s *server) { s.down = true })
	*st.clock = st.clock.Add(23 * time.Hour)
	if l, err := st.run(t).Require(ctx, "core"); err != nil || !l.Has("core") {
		t.Fatalf("offline within the lease: %v", err)
	}
	*st.clock = st.clock.Add(2 * time.Hour)
	if _, err := st.run(t).Lease(ctx); !errors.Is(err, ErrOffline) {
		t.Fatalf("offline past the lease: %v, want ErrOffline", err)
	}
	st.srv.set(func(s *server) { s.down = false })
	if _, err := st.run(t).Lease(ctx); err != nil {
		t.Fatalf("back online: %v", err)
	}
	if s, _ := st.srv.count(); s != 1 {
		t.Errorf("%d sign-ins; an expired lease should be renewed, not signed in again", s)
	}
}

func TestOfflineThenGranted(t *testing.T) {
	st := newSetup(t)
	ctx := context.Background()
	c := st.run(t)
	if _, err := c.Lease(ctx); err != nil {
		t.Fatal(err)
	}
	// A run that started offline, then reached the server.
	st.srv.set(func(s *server) { s.down = true })
	c = st.run(t)
	if _, err := c.Lease(ctx); err != nil {
		t.Fatal(err)
	}
	st.srv.set(func(s *server) { s.down = false; s.modules = []string{"core", "export"} })
	if _, err := c.Require(ctx, "export"); err != nil {
		t.Fatalf("Require should try the server again for a missing module: %v", err)
	}
}

func TestSignInAgain(t *testing.T) {
	ctx := context.Background()
	for name, damage := range map[string]func(st setup){
		"damaged lease": func(st setup) { os.WriteFile(filepath.Join(st.dir, "lease"), []byte("garbage\n"), 0o600) },
		"unknown key": func(st setup) {
			token, _ := lease.Sign(lease.Lease{Binding: bindingFor(st.dir), Product: "myapp", Expires: *st.clock}, "k0", mustKey(t))
			os.WriteFile(filepath.Join(st.dir, "lease"), []byte(token+"\n"), 0o600)
		},
		"refused by the server": func(st setup) {
			st.srv.set(func(s *server) { s.key = mustKey(t) })
		},
	} {
		t.Run(name, func(t *testing.T) {
			st := newSetup(t)
			if _, err := st.run(t).Lease(ctx); err != nil {
				t.Fatal(err)
			}
			damage(st)
			c := st.run(t)
			if name == "refused by the server" {
				// The client must trust the server's new key for the new lease.
				c.cfg.Keys["k1"] = st.srv.key.Public()
			}
			if _, err := c.Lease(ctx); err != nil {
				t.Fatal(err)
			}
			if s, _ := st.srv.count(); s != 2 {
				t.Errorf("%d sign-ins, want 2", s)
			}
		})
	}
}

func mustKey(t *testing.T) *lease.PrivateKey {
	k, err := lease.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestClockTurnedBack(t *testing.T) {
	st := newSetup(t)
	ctx := context.Background()
	if _, err := st.run(t).Lease(ctx); err != nil {
		t.Fatal(err)
	}
	st.srv.set(func(s *server) { s.down = true })
	*st.clock = st.clock.Add(30 * time.Hour) // past the lease, offline
	if _, err := st.run(t).Lease(ctx); !errors.Is(err, ErrOffline) {
		t.Fatalf("past the lease: %v", err)
	}
	*st.clock = st.clock.Add(-29 * time.Hour) // the clock turned back to within it
	if _, err := st.run(t).Lease(ctx); !errors.Is(err, ErrOffline) {
		t.Fatalf("with the clock turned back, the expired lease was used: %v", err)
	}
}

func TestLeaseFromAnotherMachine(t *testing.T) {
	a, b := newSetup(t), newSetup(t)
	b.srv = a.srv
	b.url = a.url
	ctx := context.Background()
	if _, err := a.run(t).Lease(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := b.run(t).Lease(ctx); err != nil { // b signs in, making its own key
		t.Fatal(err)
	}
	token, _ := os.ReadFile(filepath.Join(a.dir, "lease"))
	os.WriteFile(filepath.Join(b.dir, "lease"), token, 0o600)
	if _, err := b.run(t).Status(); err == nil {
		t.Error("Status accepted a lease copied from another machine")
	}
	if _, err := b.run(t).Lease(ctx); !errors.Is(err, ErrMachineChanged) {
		t.Fatalf("copied lease should require explicit activation: %v", err)
	}
	if l, err := b.run(t).SignIn(ctx); err != nil || !b.run(t).own(l) {
		t.Errorf("explicit activation: %v", err)
	}
	if s, _ := a.srv.count(); s != 3 {
		t.Errorf("%d sign-ins, want 3: the copied lease is replaced by signing in", s)
	}
}

func TestOneInstallKey(t *testing.T) {
	st := newSetup(t)
	keys := make(chan string, 16)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k, err := st.run(t).installKey()
			if err != nil {
				t.Error(err)
				return
			}
			keys <- k.Public().String()
		}()
	}
	wg.Wait()
	close(keys)
	first := ""
	for k := range keys {
		if first == "" {
			first = k
		} else if k != first {
			t.Fatal("runs at once made different install keys")
		}
	}
}

func TestUnsignedDeviceRequest(t *testing.T) {
	st := newSetup(t)
	resp, err := http.Post(st.url+"/v1/device", "application/json", strings.NewReader(`{"product":"myapp","machine":"AAAA"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("an unsigned sign-in request: %d", resp.StatusCode)
	}
}

func TestUsage(t *testing.T) {
	st := newSetup(t)
	ctx := context.Background()
	st.srv.set(func(s *server) { s.usageOn = true })
	c := st.run(t)
	if _, err := c.Lease(ctx); err != nil {
		t.Fatal(err)
	}
	c.Record("export", true, time.Second)
	c.Record("export", false, time.Second)
	c.Record("batch", true, time.Second)
	if _, err := st.run(t).Lease(ctx); err != nil {
		t.Fatal(err)
	}
	st.srv.mu.Lock()
	got := st.srv.usage
	st.srv.mu.Unlock()
	if got["export"] != 2 || got["batch"] != 1 {
		t.Errorf("usage sent %v", got)
	}
	if _, err := os.Stat(filepath.Join(st.dir, "usage.json")); !errors.Is(err, os.ErrNotExist) {
		t.Error("usage kept after it was sent")
	}
	// A product that doesn't collect usage: nothing is counted.
	st.srv.set(func(s *server) { s.usageOn = false; s.usage = nil })
	st.run(t).Lease(ctx)
	c = st.run(t)
	c.Record("export", true, time.Second)
	if _, err := os.Stat(filepath.Join(st.dir, "usage.json")); !errors.Is(err, os.ErrNotExist) {
		t.Error("usage counted for a product that doesn't collect it")
	}
}

func TestAccess(t *testing.T) {
	st := newSetup(t)
	ctx := context.Background()
	c := st.run(t)
	ms, err := c.Modules(ctx)
	if err != nil || len(ms) != 2 || ms[1].Name != "export" || ms[1].Have {
		t.Fatalf("modules %+v %v", ms, err)
	}
	r, err := c.RequestAccess(ctx, []string{"export"}, "for work")
	if err != nil || r.Status != "pending" || r.Note != "for work" {
		t.Fatalf("request %+v %v", r, err)
	}
	if len(st.srv.requests) != 1 {
		t.Errorf("requests at the server %v", st.srv.requests)
	}
}

func bindingFor(host string) machine.Binding {
	sum := sha256.Sum256([]byte(host))
	b, err := machine.Derive("myapp", "linux-machine-id", hex.EncodeToString(sum[:16]))
	if err != nil {
		panic(err)
	}
	return b
}
