// Package client is how an app uses licensebox: it signs the user in
// once, keeps the lease it gets, checks it offline on every run, renews
// it before it expires, and tells the app which modules it may run.
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
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"licensebox.dev/lease"
)

// DefaultServer is the licensebox server.
const DefaultServer = "https://licensebox.dev"

// renewBefore is how long before a lease expires the app renews it.
const renewBefore = 7 * 24 * time.Hour

// Config sets up a Client.
type Config struct {
	// Product is the product's id at the server, and Keys its public
	// keys, with which its leases are checked.
	Product string
	Keys    lease.Keys
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
	cfg Config
}

// Errors.
var (
	// ErrRevoked is returned when the server refuses to renew: the user
	// or this machine is no longer licensed.
	ErrRevoked = errors.New("licensebox: the licence was revoked")
	// ErrDenied is returned when a sign-in is refused.
	ErrDenied = errors.New("licensebox: sign-in refused")
	// ErrSignInExpired is returned when a sign-in is not finished in time.
	ErrSignInExpired = errors.New("licensebox: the sign-in expired before it was finished")
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
	return &Client{cfg}, nil
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
	if err := os.MkdirAll(c.cfg.Dir, 0o700); err != nil {
		return err
	}
	tmp := c.leasePath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(token+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.leasePath())
}

// installKey returns this installation's key, made on first use.
func (c *Client) installKey() (ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(c.keyPath()); err == nil {
		k, err := decodeSeed(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, fmt.Errorf("licensebox: %s is damaged; remove it to sign in again", c.keyPath())
		}
		return k, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(c.cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(c.keyPath(), []byte(encodeSeed(key)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func encodeSeed(k ed25519.PrivateKey) string { return base64.RawURLEncoding.EncodeToString(k.Seed()) }

func decodeSeed(s string) (ed25519.PrivateKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, errors.New("malformed key")
	}
	return ed25519.NewKeyFromSeed(b), nil
}

// Lease returns a valid lease: the one kept, renewed first if it is near
// its end or past it, or a new one from signing in.
func (c *Client) Lease(ctx context.Context) (lease.Lease, error) {
	now := c.cfg.Now()
	if token := c.stored(); token != "" {
		l, err := lease.Check(token, c.cfg.Product, c.cfg.Keys, now)
		switch {
		case err == nil && l.Expires.Sub(now) > renewBefore:
			return l, nil
		case err == nil:
			// Near its end: renewed if the server is reached soon,
			// else used as it is.
			rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			nl, rerr := c.renew(rctx, token)
			cancel()
			if rerr == nil {
				return nl, nil
			}
			if errors.Is(rerr, ErrRevoked) {
				return lease.Lease{}, rerr
			}
			return l, nil
		case errors.Is(err, lease.ErrExpired):
			nl, rerr := c.renew(ctx, token)
			if rerr == nil {
				return nl, nil
			}
			if errors.Is(rerr, ErrRevoked) {
				return lease.Lease{}, rerr
			}
		}
	}
	return c.SignIn(ctx)
}

// Require returns the lease if it lets this installation run the module,
// renewing it once first if it does not, in case the module was granted
// since; otherwise a *ModuleError, or ErrRevoked if the renewal is
// refused.
func (c *Client) Require(ctx context.Context, module string) (lease.Lease, error) {
	l, err := c.Lease(ctx)
	if err != nil {
		return l, err
	}
	if l.Has(module) {
		return l, nil
	}
	nl, err := c.renew(ctx, c.stored())
	switch {
	case err == nil:
		l = nl
		if l.Has(module) {
			return l, nil
		}
	case errors.Is(err, ErrRevoked):
		return lease.Lease{}, err
	}
	return l, &ModuleError{Product: c.cfg.Product, Module: module, Email: l.Email}
}

// Status returns the lease kept and whether it is valid now, without
// signing in or renewing.
func (c *Client) Status() (lease.Lease, error) {
	token := c.stored()
	if token == "" {
		return lease.Lease{}, errors.New("licensebox: not signed in")
	}
	return lease.Check(token, c.cfg.Product, c.cfg.Keys, c.cfg.Now())
}

// Logout removes the lease kept; the installation key stays.
func (c *Client) Logout() error {
	err := os.Remove(c.leasePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// apiError is the server's error answer.
type apiError struct {
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
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		e := &apiError{}
		if json.Unmarshal(data, e) != nil || e.Code == "" {
			return fmt.Errorf("licensebox: %s", resp.Status)
		}
		return e
	}
	return json.Unmarshal(data, out)
}

// renew trades the lease for a fresh one, signed by this installation's
// key, and keeps it.
func (c *Client) renew(ctx context.Context, token string) (lease.Lease, error) {
	if token == "" {
		return lease.Lease{}, errors.New("licensebox: no lease")
	}
	key, err := c.installKey()
	if err != nil {
		return lease.Lease{}, err
	}
	t := c.cfg.Now().UTC().Truncate(time.Second)
	req := map[string]any{
		"lease": token, "time": t, "version": c.cfg.Version,
		"signature": lease.EncodeSignature(ed25519.Sign(key, lease.RenewMessage(token, t))),
	}
	var resp struct {
		Lease string `json:"lease"`
	}
	if err := c.post(ctx, "/v1/renew", req, &resp); err != nil {
		var e *apiError
		if errors.As(err, &e) && e.Code == "revoked" {
			c.Logout()
			return lease.Lease{}, ErrRevoked
		}
		return lease.Lease{}, err
	}
	l, err := lease.Check(resp.Lease, c.cfg.Product, c.cfg.Keys, c.cfg.Now())
	if err != nil {
		return lease.Lease{}, err
	}
	return l, c.save(resp.Lease)
}

// SignIn signs the user in: it shows a code and a link, opened on any
// device, and waits for the user to finish there.
func (c *Client) SignIn(ctx context.Context) (lease.Lease, error) {
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
	req := map[string]string{
		"product": c.cfg.Product, "machine": lease.EncodeKey(key.Public().(ed25519.PublicKey)),
		"os": runtime.GOOS, "arch": runtime.GOARCH, "version": c.cfg.Version,
	}
	if err := c.post(ctx, "/v1/device", req, &d); err != nil {
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
		}
		err := c.post(ctx, "/v1/token", map[string]string{"device_code": d.DeviceCode}, &resp)
		var e *apiError
		switch {
		case err == nil:
			l, err := lease.Check(resp.Lease, c.cfg.Product, c.cfg.Keys, c.cfg.Now())
			if err != nil {
				return lease.Lease{}, err
			}
			if err := c.save(resp.Lease); err != nil {
				return lease.Lease{}, err
			}
			fmt.Fprintf(c.cfg.Out, "done. Signed in as %s; licence valid until %s.\n", l.Email, l.Expires.Local().Format("2006-01-02"))
			return l, nil
		case errors.As(err, &e) && e.Code == "authorization_pending":
		case errors.As(err, &e) && e.Code == "slow_down":
			interval += 5 * time.Second
		case errors.As(err, &e) && e.Code == "access_denied":
			fmt.Fprintln(c.cfg.Out)
			return lease.Lease{}, ErrDenied
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
