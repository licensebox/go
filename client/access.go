package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Module is one of the product's modules, as its user sees it.
type Module struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Free modules everyone may run; Have is whether this user may run it
	// now; Requested whether they have asked for it and await an answer.
	Free      bool `json:"free"`
	Have      bool `json:"have"`
	Requested bool `json:"requested"`
}

// Request is a user's request for modules, and its answer.
type Request struct {
	ID      string    `json:"id"`
	Modules []string  `json:"modules"`
	Note    string    `json:"note"`
	Created time.Time `json:"created"`
	// Status is "pending", "approved" or "declined"; Granted the modules
	// approved, until Until if it is not zero; Answer the admins' note.
	Status   string    `json:"status"`
	Granted  []string  `json:"granted"`
	Until    time.Time `json:"until"`
	Answer   string    `json:"answer"`
	Answered time.Time `json:"answered"`
}

// Modules returns the product's modules this user may run or ask for,
// signing in first if need be.
func (c *Client) Modules(ctx context.Context) ([]Module, error) {
	var out []Module
	return out, c.withLease(ctx, func(token string) error { return c.call(ctx, "modules", token, struct{}{}, &out) })
}

// RequestAccess asks the product's admins for modules, saying why in
// note. They are told by email, and so is the user when they answer; a
// grant reaches the app at its next run.
func (c *Client) RequestAccess(ctx context.Context, modules []string, note string) (Request, error) {
	var out Request
	return out, c.withLease(ctx, func(token string) error {
		return c.call(ctx, "request", token, map[string]any{"modules": modules, "note": note}, &out)
	})
}

// Requests returns this user's requests for the product, newest first.
func (c *Client) Requests(ctx context.Context) ([]Request, error) {
	var out []Request
	return out, c.withLease(ctx, func(token string) error { return c.call(ctx, "requests", token, struct{}{}, &out) })
}

// AccessLink returns a link, good for a few minutes and once, to a page
// where the user, signed in already, sees the modules and asks for those
// they want.
func (c *Client) AccessLink(ctx context.Context) (string, error) {
	var out struct {
		URL string `json:"url"`
	}
	return out.URL, c.withLease(ctx, func(token string) error { return c.call(ctx, "access-link", token, struct{}{}, &out) })
}

// withLease runs f with a valid lease's token.
func (c *Client) withLease(ctx context.Context, f func(token string) error) error {
	if _, err := c.Lease(ctx); err != nil {
		return err
	}
	return f(c.stored())
}

// Usage: what the app ran, counted by day, command, version and system,
// kept beside the lease and sent with the next renewal, for products that
// collect it. Only names and counts: no files, arguments or data.

// UsageCount is the count of one command's runs on one day.
type UsageCount struct {
	// ID stays the same while a count is queued, so retries are idempotent.
	ID      string `json:"id"`
	Day     string `json:"day"` // as 2026-10-17, UTC
	Command string `json:"command"`
	Version string `json:"version"`
	OS      string `json:"os"`
	OK      int    `json:"ok"`
	Failed  int    `json:"failed"`
	// Millis is the time the runs took, in all.
	Millis int64 `json:"ms"`
}

func (c *Client) usagePath() string   { return filepath.Join(c.cfg.Dir, "usage.json") }
func (c *Client) usageOnPath() string { return filepath.Join(c.cfg.Dir, "usage-on") }

func (c *Client) readUsage() []UsageCount {
	var us []UsageCount
	if b, err := os.ReadFile(c.usagePath()); err == nil {
		json.Unmarshal(b, &us)
	}
	return us
}

// Record counts a run of a command, by name, whether it succeeded and how
// long it took, if the product collects usage. Call it once the command
// is done; the count is sent with the next run's check.
func (c *Client) Record(command string, ok bool, took time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if b, err := os.ReadFile(c.usageOnPath()); err != nil || strings.TrimSpace(string(b)) != "on" {
		return
	}
	if command == "" || len(command) > 64 {
		return
	}
	version := c.cfg.Version
	if len(version) > 64 {
		version = version[:64]
	}
	u := UsageCount{Day: c.cfg.Now().UTC().Format(time.DateOnly), Command: command, Version: version, OS: osName}
	us := c.readUsage()
	i := slices.IndexFunc(us, func(x UsageCount) bool {
		return x.Day == u.Day && x.Command == u.Command && x.Version == u.Version && x.OS == u.OS
	})
	if i < 0 {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return
		}
		u.ID = hex.EncodeToString(id[:])
		us = append(us, u)
		i = len(us) - 1
	}
	if ok {
		us[i].OK++
	} else {
		us[i].Failed++
	}
	us[i].Millis += took.Milliseconds()
	if len(us) > 1000 { // kept bounded if the server is long out of reach
		us = us[len(us)-1000:]
	}
	b, _ := json.Marshal(us)
	c.write(c.usagePath(), string(b))
}

// pendingUsage returns the counts not yet sent.
func (c *Client) pendingUsage() []UsageCount {
	us := c.readUsage()
	if us == nil {
		us = []UsageCount{}
	}
	return us[:min(len(us), 100)]
}

// usageSent forgets the counts sent, keeping any counted since, and
// remembers whether the product collects usage. Counts changed while a
// report was in flight keep their cumulative totals and ID for retry.
func (c *Client) usageSent(sent []UsageCount, on bool) {
	flag := "off"
	if on {
		flag = "on"
	}
	c.write(c.usageOnPath(), flag)
	if len(sent) == 0 {
		return
	}
	left := c.readUsage()
	for _, s := range sent {
		if i := slices.IndexFunc(left, func(x UsageCount) bool {
			return x.ID == s.ID
		}); i >= 0 {
			if left[i].OK == s.OK && left[i].Failed == s.Failed && left[i].Millis == s.Millis {
				left = slices.Delete(left, i, i+1)
			}
		}
	}
	if len(left) == 0 {
		os.Remove(c.usagePath())
		return
	}
	b, _ := json.Marshal(left)
	c.write(c.usagePath(), string(b))
}
