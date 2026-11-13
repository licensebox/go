package client

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"licensebox.dev/lease"
)

// Floating copies and service accounts.
//
// A floating module is one the user's customer holds a pool of copies
// of, used on any machine but by at most so many at once: Require checks
// a copy out, heartbeats keep it, and Checkin returns it. A copy whose
// heartbeats stop is freed after the product's heartbeat grace, so
// floating modules need a connection to the server, unlike modules held
// outright, which run offline until the lease expires.
//
// A service account is a machine, such as a server or a build runner,
// licensed in its own name rather than a person's: it signs in once with
// a one-time token an admin issues (Config.Token, or LICENSEBOX_ENROL_TOKEN),
// without a browser.

var (
	// ErrNoFreeCopy is returned when every floating copy of a module is
	// checked out by other machines.
	ErrNoFreeCopy = errors.New("licensebox: all floating copies are in use; try again when one is checked in")
	// ErrEnrolment is returned when a service account's token is unknown,
	// used or expired.
	ErrEnrolment = errors.New("licensebox: the enrolment token is unknown, used or expired; ask the product's admin for a new one")
)

// TokenEnv is the environment variable a service account's one-time
// enrolment token is read from when Config.Token is empty.
const TokenEnv = "LICENSEBOX_ENROL_TOKEN"

func (c *Client) token() string {
	if c.cfg.Token != "" {
		return c.cfg.Token
	}
	return strings.TrimSpace(os.Getenv(TokenEnv))
}

// Enrol signs this machine in as a service account with a one-time token
// an admin issued, without a person or a browser. The token is spent;
// the machine renews its lease as any other from then on.
func (c *Client) Enrol(ctx context.Context, token string) (lease.Lease, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	l, err := c.enrol(ctx, token)
	if err == nil {
		c.checked = &l
	}
	return l, err
}

// enrol is Enrol with c.mu held.
func (c *Client) enrol(ctx context.Context, token string) (lease.Lease, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return lease.Lease{}, ErrEnrolment
	}
	binding, err := c.binding()
	if err != nil {
		return lease.Lease{}, err
	}
	if l, _, _, err := lease.Parse(c.stored()); err == nil && l.Binding.Valid() && l.Binding != binding {
		if err := c.rotateKey(); err != nil {
			return lease.Lease{}, err
		}
	}
	key, err := c.installKey()
	if err != nil {
		return lease.Lease{}, err
	}
	t := c.cfg.Now().UTC().Truncate(time.Second)
	sig, err := key.Sign(lease.EnrolMessage(lease.Hybrid, c.cfg.Product, token, binding, t))
	if err != nil {
		return lease.Lease{}, err
	}
	req := map[string]any{
		"product": c.cfg.Product, "token": token, "binding": binding, "machine": key.Public().String(),
		"os": runtime.GOOS, "arch": runtime.GOARCH, "version": c.cfg.Version,
		"time": t, "signature": lease.EncodeSignature(sig),
	}
	var resp struct {
		Lease string `json:"lease"`
		Usage bool   `json:"usage"`
	}
	err = c.post(ctx, "/v1/enrol", req, &resp)
	var e *apiError
	switch {
	case errors.As(err, &e) && e.Code == "invalid_token":
		return lease.Lease{}, ErrEnrolment
	case errors.As(err, &e) && e.Code == "access_denied":
		return lease.Lease{}, ErrDenied
	case err != nil:
		return lease.Lease{}, err
	}
	l, err := lease.Check(resp.Lease, c.cfg.Product, c.cfg.Keys, c.now())
	if err != nil {
		return lease.Lease{}, err
	}
	if !c.own(l) {
		return lease.Lease{}, errors.New("licensebox: the server sent a lease for another machine")
	}
	c.clearDenial()
	c.usageSent(nil, resp.Usage)
	return l, c.save(resp.Lease)
}

// Checkout checks a floating copy of the module out for this machine and
// returns the lease that has it; ErrNoFreeCopy if every copy is in use,
// or a *ModuleError if the module is not the user's to check out. A
// module held outright needs no copy, and is returned as it is. Keep the
// copy with Heartbeat or Watch while working, and Checkin after.
func (c *Client) Checkout(ctx context.Context, module string) (lease.Lease, error) {
	if _, err := c.Lease(ctx); err != nil {
		return lease.Lease{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checkout(ctx, module)
}

// checkout is Checkout with c.mu held and a lease kept.
func (c *Client) checkout(ctx context.Context, module string) (lease.Lease, error) {
	l, err := c.leaseCall(ctx, "checkout", map[string]any{"module": module})
	var e *apiError
	switch {
	case errors.As(err, &e) && e.Code == "no_free_copy":
		return lease.Lease{}, fmt.Errorf("%w (%s)", ErrNoFreeCopy, module)
	case errors.As(err, &e) && e.Code == "not_floating":
		kept, _, _, _ := lease.Parse(c.stored())
		return lease.Lease{}, &ModuleError{Product: c.cfg.Product, Module: module, Email: kept.Email}
	case err != nil:
		return lease.Lease{}, err
	}
	if !l.Has(module) {
		return l, &ModuleError{Product: c.cfg.Product, Module: module, Email: l.Email}
	}
	return l, nil
}

// Checkin returns this machine's floating copies of the modules, or all
// of them with none named, to the pool.
func (c *Client) Checkin(ctx context.Context, modules ...string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if modules == nil {
		modules = []string{}
	}
	_, err := c.leaseCall(ctx, "checkin", map[string]any{"modules": modules})
	return err
}

// leaseCall makes a signed call with the lease kept that answers with a
// fresh lease, and keeps it; c.mu is held.
func (c *Client) leaseCall(ctx context.Context, kind string, payload any) (lease.Lease, error) {
	token := c.stored()
	if token == "" {
		return lease.Lease{}, ErrNotSignedIn
	}
	var resp struct {
		Lease string `json:"lease"`
		Usage bool   `json:"usage"`
	}
	if err := c.call(ctx, kind, token, payload, &resp); err != nil {
		return lease.Lease{}, err
	}
	l, err := lease.Check(resp.Lease, c.cfg.Product, c.cfg.Keys, c.now())
	if err != nil {
		return l, err
	}
	if !c.own(l) {
		return lease.Lease{}, errors.New("licensebox: the server sent a lease for another machine")
	}
	if err := c.save(resp.Lease); err != nil {
		return lease.Lease{}, err
	}
	c.checked = &l
	return l, nil
}

// floating reports whether the lease lets its holder check the module out.
func floating(l lease.Lease, module string) bool { return slices.Contains(l.Floating, module) }
