package client

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"licensebox.dev/lease"
)

// HeartbeatResult reports a module authorization and whether the server was
// reached. An offline result never extends the returned signed lease expiry.
type HeartbeatResult struct {
	Lease        lease.Lease `json:"lease"`
	Online       bool        `json:"online"`
	observedAt   time.Time
	observedWall time.Time
}

// Heartbeat explicitly renews and checks module even when this process has a
// fresh lease. It never opens a browser, prompts for sign-in, creates an identity
// or transfers a seat. Applications choose when to call it and how to stop work.
func (c *Client) Heartbeat(ctx context.Context, module string) (HeartbeatResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checked = nil
	if strings.TrimSpace(module) == "" {
		return HeartbeatResult{}, errors.New("licensebox: heartbeat requires a module")
	}
	if err := ctx.Err(); err != nil {
		return HeartbeatResult{}, err
	}
	token := c.stored()
	if token == "" {
		return HeartbeatResult{}, ErrNotSignedIn
	}
	now := c.now()
	kept, verifyErr := lease.Check(token, c.cfg.Product, c.cfg.Keys, now)
	if verifyErr != nil && !errors.Is(verifyErr, lease.ErrExpired) {
		return HeartbeatResult{}, verifyErr
	}
	// Read existing identity only: background checks must not create a new key.
	seed, err := os.ReadFile(c.keyPath())
	if errors.Is(err, os.ErrNotExist) {
		return HeartbeatResult{}, ErrNotSignedIn
	}
	if err != nil {
		return HeartbeatResult{}, err
	}
	key, err := decodeSeed(strings.TrimSpace(string(seed)))
	if err != nil {
		return HeartbeatResult{}, err
	}
	if kept.Machine != lease.EncodeKey(key.Public().(ed25519.PublicKey)) {
		return HeartbeatResult{}, ErrMachineChanged
	}
	binding, err := c.binding()
	if err != nil {
		return HeartbeatResult{}, err
	}
	if binding != kept.Binding {
		return HeartbeatResult{}, ErrMachineChanged
	}
	rctx, cancel := context.WithTimeout(ctx, checkTimeout)
	fresh, err := c.renewWithKey(rctx, token, key, binding)
	cancel()
	if err == nil {
		c.checked = &fresh
		if !fresh.Has(module) {
			return HeartbeatResult{}, &ModuleError{Product: c.cfg.Product, Module: module, Email: fresh.Email}
		}
		return c.heartbeatResult(fresh, true)
	}
	if ctx.Err() != nil {
		return HeartbeatResult{}, ctx.Err()
	}
	var api *apiError
	if errors.As(err, &api) {
		if api.status < 500 {
			// Expose a stable public code without initiating an interactive terms flow.
			return HeartbeatResult{}, &PolicyError{Code: api.Code, Detail: api.Error()}
		}
	} else {
		var transport *url.Error
		if !errors.As(err, &transport) && !errors.Is(err, context.DeadlineExceeded) {
			return HeartbeatResult{}, err
		}
	}
	if denial := c.denial(); denial != nil {
		return HeartbeatResult{}, denial
	}
	// The request may have consumed the last part of the contact allowance.
	if !c.now().Before(kept.Expires) {
		return HeartbeatResult{}, fmt.Errorf("%w (%v)", ErrOffline, err)
	}
	if !kept.Has(module) {
		return HeartbeatResult{}, &ModuleError{Product: c.cfg.Product, Module: module, Email: kept.Email}
	}
	c.checked = &kept
	return c.heartbeatResult(kept, false)
}

func copyHeartbeatLease(l lease.Lease) lease.Lease {
	l.Modules = slices.Clone(l.Modules)
	if l.Heartbeat != nil {
		p := *l.Heartbeat
		l.Heartbeat = &p
	}
	return l
}

func (c *Client) heartbeatResult(l lease.Lease, online bool) (HeartbeatResult, error) {
	observedAt := c.now()
	if !observedAt.Before(l.Expires) {
		return HeartbeatResult{}, ErrOffline
	}
	return HeartbeatResult{Lease: copyHeartbeatLease(l), Online: online, observedAt: observedAt, observedWall: time.Now()}, nil
}
