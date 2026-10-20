// Package client is how an app uses licensebox: it signs the user in
// once, keeps the lease it gets, checks it with the server at every run
// (and offline, for a day, when the server cannot be reached), and tells
// the app which modules it may run.
//
//	lic, err := client.New(client.Config{Product: "edgewise", Keys: keys})
//	...
//	if _, err := lic.Require(ctx, "print"); err != nil {
//		return err // says how to get the module
//	}
//
// The lease and the installation's key are kept in the user's
// configuration folder; the key never leaves it.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"licensebox.dev/lease"
	"licensebox.dev/machine"
)

// DefaultServer is the licensebox server.
const DefaultServer = "https://licensebox.dev"

// checkTimeout bounds the check with the server at each run, after
// which the lease kept is used as it is.
const checkTimeout = 3 * time.Second

// Config sets up a Client.
type Config struct {
	// Product is the product's id at the server, and Keys its public
	// keys, with which its leases are checked.
	Product string
	// MachineBinding supplies a native binding for platform integrations/tests.
	// The default uses machine.Native(Product); do not supply user-controlled IDs.
	MachineBinding func() (machine.Binding, error)
	Keys           lease.Keys
	// Server is the server's URL; empty means DefaultServer.
	Server string
	// Version is the app's version, reported to the server.
	Version string
	// Dir is where the lease and the installation key are kept; empty
	// means licensebox/<product> in the user's configuration folder.
	Dir string
	// Out is where sign-in instructions go; nil means standard error.
	Out io.Writer
	// OpenBrowser, if set, is called with the sign-in link.
	OpenBrowser func(url string) error
	// HTTP is the client for the server; nil means one with a timeout.
	HTTP *http.Client
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Client holds a product's licence on this machine.
type Client struct {
	cfg         Config
	bindingOnce sync.Once
	hostBinding machine.Binding
	bindingErr  error

	mu sync.Mutex
	// checked is the lease the server gave this run, if it has.
	checked *lease.Lease
}

// Errors.
var (
	// ErrRevoked is returned when the server refuses to renew: the user
	// or this machine is no longer licensed.
	ErrNotSignedIn = errors.New("licensebox: not signed in; explicitly sign in before starting protected work")
	ErrRevoked     = errors.New("licensebox: the licence was revoked")
	// ErrDenied is returned when a sign-in is refused.
	ErrDenied = errors.New("licensebox: sign-in refused")
	// ErrSignInExpired is returned when a sign-in is not finished in time.
	ErrSignInExpired = errors.New("licensebox: the sign-in expired before it was finished")
	// ErrOffline is returned when the lease kept has expired and the
	// server cannot be reached to renew it.
	ErrOffline = errors.New("licensebox: the licence has expired and the licence server cannot be reached: connect to the internet and run again")
)

// ModuleError is returned by Require for a module the lease leaves out.
type ModuleError struct {
	Product, Module, Email string
}

func (e *ModuleError) Error() string {
	return fmt.Sprintf("%s: the %s module is not licensed to %s", e.Product, e.Module, e.Email)
}

// New returns a client for the product.
func New(cfg Config) (*Client, error) {
	if cfg.Product == "" || len(cfg.Keys) == 0 {
		return nil, errors.New("licensebox: a product and its public keys are needed")
	}
	if cfg.Server == "" {
		cfg.Server = DefaultServer
	}
	cfg.Server = strings.TrimRight(cfg.Server, "/")
	if cfg.Dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		cfg.Dir = filepath.Join(base, "licensebox", cfg.Product)
	}
	if cfg.Out == nil {
		cfg.Out = os.Stderr
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 20 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Client{cfg: cfg}, nil
}

func (c *Client) leasePath() string { return filepath.Join(c.cfg.Dir, "lease") }
func (c *Client) keyPath() string   { return filepath.Join(c.cfg.Dir, "install.key") }

// stored returns the lease kept, unchecked, or "" if none.
func (c *Client) stored() string {
	b, err := os.ReadFile(c.leasePath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (c *Client) save(token string) error {
	if err := c.write(c.leasePath(), token); err != nil {
		return err
	}
	return c.clearDenial()
}

// write replaces a file whole, through a file of its own, so that two
// runs at once never leave it half written.
func (c *Client) write(path, content string) error {
	if err := os.MkdirAll(c.cfg.Dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(c.cfg.Dir, ".tmp-*")
	if err != nil {
		return err
	}
	_, err = f.WriteString(content + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(f.Name(), 0o600)
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

func (c *Client) seenPath() string { return filepath.Join(c.cfg.Dir, "seen") }

// now is the clock, but never earlier than the latest time this
// installation has seen: a clock turned back does not make an expired
// lease valid again.
func (c *Client) now() time.Time {
	t := c.cfg.Now()
	if b, err := os.ReadFile(c.seenPath()); err == nil {
		if seen, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(b))); err == nil && seen.After(t) {
			return seen
		}
	}
	c.write(c.seenPath(), t.UTC().Format(time.RFC3339Nano))
	return t
}

// own reports whether the lease names this installation's key.
func (c *Client) ownsKey(l lease.Lease) bool {
	key, err := c.installKey()
	return err == nil && l.Machine == key.Public().String()
}

func (c *Client) binding() (machine.Binding, error) {
	c.bindingOnce.Do(func() {
		if c.cfg.MachineBinding != nil {
			c.hostBinding, c.bindingErr = c.cfg.MachineBinding()
		} else {
			c.hostBinding, c.bindingErr = machine.Native(c.cfg.Product)
		}
		if c.bindingErr == nil && !c.hostBinding.Valid() {
			c.bindingErr = machine.ErrUnavailable
		}
	})
	return c.hostBinding, c.bindingErr
}

func (c *Client) own(l lease.Lease) bool {
	binding, err := c.binding()
	return err == nil && binding == l.Binding && c.ownsKey(l)
}

// installKey returns this installation's key, made on first use. Two
// runs making it at once agree on one: the key file is created only if
// it is not there, and a run that finds another's still being written
// waits for it.
func (c *Client) installKey() (*lease.PrivateKey, error) {
	for range 40 {
		b, err := os.ReadFile(c.keyPath())
		if err == nil {
			if k, err := decodeSeed(strings.TrimSpace(string(b))); err == nil {
				return k, nil
			}
			if info, err := os.Stat(c.keyPath()); err == nil && time.Since(info.ModTime()) > 5*time.Second {
				return nil, fmt.Errorf("licensebox: %s is damaged; remove it to sign in again", c.keyPath())
			}
			time.Sleep(25 * time.Millisecond) // another run is writing it
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		key, err := lease.GenerateKey()
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(c.cfg.Dir, 0o700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(c.keyPath(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue // another run made it first
		}
		if err != nil {
			return nil, err
		}
		_, err = f.WriteString(encodeSeed(key) + "\n")
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(c.keyPath())
			return nil, err
		}
		return key, nil
	}
	return nil, fmt.Errorf("licensebox: %s is damaged; remove it to sign in again", c.keyPath())
}

func encodeSeed(k *lease.PrivateKey) string { return lease.EncodePrivateKey(k) }

func decodeSeed(s string) (*lease.PrivateKey, error) { return lease.DecodePrivateKey(s) }

// Lease returns a valid lease. The first call in a run renews the lease
// kept with the server, so that every run sees grants and revocations as
// they are; if the server is not reached within a few seconds, the lease
// kept is used until it expires, and after that ErrOffline is returned.
// With no lease, or one the server will not renew, the user signs in.
// Later calls in the same run return the lease the server gave.
func (c *Client) Lease(ctx context.Context) (lease.Lease, error) {
	l, _, err := c.lease(ctx)
	return l, err
}

// lease is Lease, and whether the server gave the lease this run.
func (c *Client) lease(ctx context.Context) (lease.Lease, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	binding, err := c.binding()
	if err != nil {
		return lease.Lease{}, false, err
	}
	now := c.now()
	if c.checked != nil && now.Before(c.checked.Expires) && c.denial() == nil {
		return *c.checked, true, nil
	}
	token := c.stored()
	if token == "" {
		return c.signIn(ctx)
	}
	kept, kerr := lease.Check(token, c.cfg.Product, c.cfg.Keys, now)
	if kerr != nil && !errors.Is(kerr, lease.ErrExpired) || !c.ownsKey(kept) {
		return c.signIn(ctx) // damaged, from another product or key, or copied from another machine
	}
	if kept.Binding != binding {
		return lease.Lease{}, false, ErrMachineChanged
	}
	rctx, cancel := context.WithTimeout(ctx, checkTimeout)
	l, err := c.renew(rctx, token)
	cancel()
	savedDenial := c.denial()
	var e *apiError
	switch {
	case err == nil:
		c.checked = &l
		return l, true, nil
	case errors.Is(err, ErrRevoked):
		return lease.Lease{}, false, err
	case errors.As(err, &e) && (e.Code == "invalid_lease" || e.Code == "terms_changed"):
		// Signed by a retired key, or the terms
		// changed and must be accepted again.
		if e.Code == "terms_changed" {
			fmt.Fprintln(c.cfg.Out, "The terms of use have changed.")
		}
		return c.signIn(ctx)
	case errors.Is(err, ErrSeatTransferred) || errors.Is(err, ErrLocationDenied) || errors.Is(err, ErrMachineChanged):
		return lease.Lease{}, false, err
	case errors.As(err, &e) && e.status >= 300 && e.status < 500:
		return lease.Lease{}, false, err
	case savedDenial != nil:
		return lease.Lease{}, false, savedDenial
	case kerr == nil:
		return kept, false, nil // offline: the lease kept holds until it expires
	default:
		return lease.Lease{}, false, fmt.Errorf("%w (%v)", ErrOffline, err)
	}
}

func (c *Client) signIn(ctx context.Context) (lease.Lease, bool, error) {
	l, err := c.signInFlow(ctx, false)
	if err != nil {
		return l, false, err
	}
	c.checked = &l
	return l, true, nil
}

// Require returns the lease if it lets this installation run the module;
// otherwise a *ModuleError, or the error Lease returns. If the lease
// could not be renewed this run, it is tried once more first, in case
// the module was granted since.
func (c *Client) Require(ctx context.Context, module string) (lease.Lease, error) {
	l, fresh, err := c.lease(ctx)
	if err != nil {
		return l, err
	}
	if !l.Has(module) && !fresh {
		c.mu.Lock()
		nl, err := c.renew(ctx, c.stored())
		if err == nil {
			c.checked, l = &nl, nl
		}
		c.mu.Unlock()
		if errors.Is(err, ErrRevoked) || errors.Is(err, ErrSeatTransferred) || errors.Is(err, ErrLocationDenied) || errors.Is(err, ErrMachineChanged) {
			return lease.Lease{}, err
		}
	}
	if !l.Has(module) {
		return l, &ModuleError{Product: c.cfg.Product, Module: module, Email: l.Email}
	}
	return l, nil
}

// Status returns the lease kept and whether it is valid now, without
// signing in or renewing.
func (c *Client) Status() (lease.Lease, error) {
	if err := c.denial(); err != nil {
		return lease.Lease{}, err
	}
	token := c.stored()
	if token == "" {
		return lease.Lease{}, ErrNotSignedIn
	}
	l, err := lease.Check(token, c.cfg.Product, c.cfg.Keys, c.now())
	if err == nil || errors.Is(err, lease.ErrExpired) {
		binding, berr := c.binding()
		if berr != nil {
			return l, berr
		}
		if binding != l.Binding || !c.ownsKey(l) {
			return l, ErrMachineChanged
		}
	}
	return l, err
}

// Logout removes the lease kept; the installation key stays.
func (c *Client) Logout() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.forget()
}

// forget removes the lease kept and this run's; c.mu is held.
func (c *Client) forget() error {
	c.checked = nil
	c.clearDenial()
	os.Remove(c.usagePath())
	os.Remove(c.usageOnPath())
	err := os.Remove(c.leasePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// apiError is the server's error answer.
type apiError struct {
	status int
	Code   string `json:"error"`
	Detail string `json:"error_description"`
}

func (e *apiError) Error() string {
	if e.Detail != "" {
		return "licensebox: " + e.Detail
	}
	return "licensebox: " + e.Code
}

// post sends a JSON request and decodes the answer into out, or returns
// the server's error.
func (c *Client) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Server+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// A redirect must never forward a signed lease/body to another endpoint.
	httpClient := *c.cfg.HTTP
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		// Refusal headers remain authoritative even when its body stalls.
		if resp.StatusCode >= 300 && resp.StatusCode < 500 {
			return &apiError{status: resp.StatusCode, Code: "http_error", Detail: resp.Status}
		}
		return err
	}
	if resp.StatusCode != http.StatusOK {
		e := &apiError{status: resp.StatusCode}
		if json.Unmarshal(data, e) != nil || e.Code == "" {
			e.Code, e.Detail = "http_error", resp.Status
			return e
		}
		if e.Code == "revoked" {
			c.forget()
			return ErrRevoked
		}
		if e.Code == "seat_transferred" || e.Code == "location_denied" || e.Code == "location_unknown" || e.Code == "machine_changed" {
			return c.rememberDenial(e)
		}
		return e
	}
	return json.Unmarshal(data, out)
}

// call sends a call signed with this installation's key, as the holder
// of the lease token: its kind, the lease, the time and the payload, as
// JSON, are signed together (lease.CallMessage).
func (c *Client) call(ctx context.Context, kind, token string, payload, out any) error {
	binding, err := c.binding()
	if err != nil {
		return err
	}
	kept, _, _, err := lease.Parse(token)
	if err != nil {
		return err
	}
	if kept.Binding != binding {
		return ErrMachineChanged
	}
	key, err := c.installKey()
	if err != nil {
		return err
	}
	return c.callSigned(ctx, kind, token, payload, out, key, binding)
}

// callSigned uses a previously verified installation key. Heartbeat uses this
// path so missing/deleted credentials can never create a replacement identity.
func (c *Client) callSigned(ctx context.Context, kind, token string, payload, out any, key *lease.PrivateKey, binding machine.Binding) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	t := c.cfg.Now().UTC().Truncate(time.Second)
	sig, err := key.Sign(lease.CallMessage(lease.Hybrid, kind, token, binding, t, body))
	if err != nil {
		return err
	}
	req := map[string]any{
		"lease": token, "binding": binding, "time": t, "version": c.cfg.Version, "payload": string(body),
		"signature": lease.EncodeSignature(sig),
	}
	err = c.post(ctx, "/v1/"+kind, req, out)
	var e *apiError
	if errors.As(err, &e) && e.Code == "revoked" {
		c.forget()
		return ErrRevoked
	}
	return err
}

// renew trades the lease for a fresh one, and keeps it, sending the
// usage counted since the last renewal if the product collects it.
func (c *Client) renew(ctx context.Context, token string) (lease.Lease, error) {
	key, err := c.installKey()
	if err != nil {
		return lease.Lease{}, err
	}
	binding, err := c.binding()
	if err != nil {
		return lease.Lease{}, err
	}
	return c.renewWithKey(ctx, token, key, binding)
}

func (c *Client) renewWithKey(ctx context.Context, token string, key *lease.PrivateKey, binding machine.Binding) (lease.Lease, error) {
	if token == "" {
		return lease.Lease{}, ErrNotSignedIn
	}
	sent := c.pendingUsage()
	var resp struct {
		Lease string `json:"lease"`
		Usage bool   `json:"usage"`
	}
	if err := c.callSigned(ctx, "renew", token, map[string]any{"usage": sent}, &resp, key, binding); err != nil {
		return lease.Lease{}, err
	}
	l, err := lease.Check(resp.Lease, c.cfg.Product, c.cfg.Keys, c.now())
	if err != nil {
		return l, err
	}
	if l.Binding != binding || l.Machine != key.Public().String() {
		return lease.Lease{}, errors.New("licensebox: the server sent a lease for another machine")
	}
	c.usageSent(sent, resp.Usage)
	return l, c.save(resp.Lease)
}

// SignIn signs the user in: it shows a code and a link, opened on any
// device, and waits for the user to finish there.
func (c *Client) SignIn(ctx context.Context) (lease.Lease, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	l, err := c.signInFlow(ctx, true)
	if err == nil {
		c.checked = &l
	}
	return l, err
}

func (c *Client) rotateKey() error {
	key, err := lease.GenerateKey()
	if err != nil {
		return err
	}
	if err := c.write(c.keyPath(), encodeSeed(key)); err != nil {
		return err
	}
	return c.forget()
}

func (c *Client) signInFlow(ctx context.Context, explicit bool) (lease.Lease, error) {
	binding, err := c.binding()
	if err != nil {
		return lease.Lease{}, err
	}
	if l, _, _, err := lease.Parse(c.stored()); err == nil && l.Binding.Valid() && l.Binding != binding {
		if !explicit {
			return lease.Lease{}, ErrMachineChanged
		}
		if err := c.rotateKey(); err != nil {
			return lease.Lease{}, err
		}
	}
	key, err := c.installKey()
	if err != nil {
		return lease.Lease{}, err
	}
	var d struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
		IntervalMS              int64  `json:"interval_ms"`
	}
	t := c.cfg.Now().UTC().Truncate(time.Second)
	sig, err := key.Sign(lease.DeviceMessage(lease.Hybrid, c.cfg.Product, binding, t))
	if err != nil {
		return lease.Lease{}, err
	}
	req := map[string]any{
		"product": c.cfg.Product, "binding": binding, "machine": key.Public().String(),
		"os": runtime.GOOS, "arch": runtime.GOARCH, "version": c.cfg.Version,
		"time": t, "signature": lease.EncodeSignature(sig),
	}
	if err := c.post(ctx, "/v1/device", req, &d); err != nil {
		if explicit && errors.Is(err, ErrMachineChanged) {
			if err := c.rotateKey(); err != nil {
				return lease.Lease{}, err
			}
			return c.signInFlow(ctx, false)
		}
		return lease.Lease{}, err
	}
	fmt.Fprintf(c.cfg.Out, "%s needs a one-time sign-in.\nOpen %s and enter the code %s\n", c.cfg.Product, d.VerificationURI, d.UserCode)
	if c.cfg.OpenBrowser != nil && c.cfg.OpenBrowser(d.VerificationURIComplete) == nil {
		fmt.Fprintln(c.cfg.Out, "(opening your browser...)")
	}
	fmt.Fprint(c.cfg.Out, "Waiting for sign-in... ")
	interval := time.Duration(d.IntervalMS) * time.Millisecond
	if interval <= 0 {
		interval = time.Duration(max(d.Interval, 1)) * time.Second
	}
	deadline := time.Now().Add(time.Duration(d.ExpiresIn) * time.Second)
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(c.cfg.Out)
			return lease.Lease{}, ctx.Err()
		case <-time.After(interval):
		}
		var resp struct {
			Lease string `json:"lease"`
			Usage bool   `json:"usage"`
		}
		at := c.cfg.Now().UTC().Truncate(time.Second)
		sig, err := key.Sign(lease.TokenMessage(lease.Hybrid, d.DeviceCode, binding, at))
		if err != nil {
			return lease.Lease{}, err
		}
		err = c.post(ctx, "/v1/token", map[string]any{"device_code": d.DeviceCode, "binding": binding, "time": at, "signature": lease.EncodeSignature(sig)}, &resp)
		var e *apiError
		switch {
		case err == nil:
			l, err := lease.Check(resp.Lease, c.cfg.Product, c.cfg.Keys, c.now())
			if err != nil {
				return lease.Lease{}, err
			}
			if !c.own(l) {
				return lease.Lease{}, errors.New("licensebox: the server sent a lease for another machine")
			}
			if old, _, _, err := lease.Parse(c.stored()); err == nil && old.User != l.User {
				os.Remove(c.usagePath())
			}
			c.usageSent(nil, resp.Usage)
			if err := c.save(resp.Lease); err != nil {
				return lease.Lease{}, err
			}
			fmt.Fprintf(c.cfg.Out, "done. Signed in as %s; offline access until %s (renews automatically).\n", l.Email, l.Expires.Local().Format("2006-01-02 15:04 MST"))
			return l, nil
		case errors.As(err, &e) && e.Code == "authorization_pending":
		case errors.As(err, &e) && e.Code == "slow_down":
			interval += 5 * time.Second
		case errors.As(err, &e) && e.Code == "access_denied":
			fmt.Fprintln(c.cfg.Out)
			return lease.Lease{}, ErrDenied
		case errors.Is(err, ErrRevoked) || errors.Is(err, ErrLocationDenied) || errors.Is(err, ErrMachineChanged) || errors.Is(err, ErrSeatTransferred):
			fmt.Fprintln(c.cfg.Out)
			return lease.Lease{}, err
		case errors.As(err, &e) && e.Code == "expired_token":
			fmt.Fprintln(c.cfg.Out)
			return lease.Lease{}, ErrSignInExpired
		case time.Now().After(deadline):
			fmt.Fprintln(c.cfg.Out)
			return lease.Lease{}, err
		}
		// Network errors: tried again until the sign-in expires.
	}
}
