// Package admin is a client of licensebox's admin API: creating and
// changing products, their signing keys and admins, and managing their
// users: grants, revocations, activity and numbers. The licensebox
// command is built on it; use it to automate the same, as granting a
// module when a payment comes in.
//
//	a := admin.New(token)
//	_, err := a.Grant(ctx, "myapp", admin.GrantRequest{Email: "ada@example.org", Modules: []string{"export"}})
//
// A token comes from signing in (StartLogin, then FinishLogin), as
// `licensebox login` does.
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultServer is the licensebox server.
const DefaultServer = "https://licensebox.dev"

// Client calls the admin API.
type Client struct {
	// Server is the server's URL; empty means DefaultServer.
	Server string
	// Token is the admin's session token.
	Token string
	// HTTP is the client for the server; nil means one with a timeout.
	HTTP *http.Client
}

// New returns a client of the licensebox server with the token.
func New(token string) *Client { return &Client{Token: token} }

// Error is an error the server answered with.
type Error struct {
	Status int
	Code   string `json:"error"`
	Detail string `json:"error_description"`
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return e.Code
}

// IsNotFound reports whether err says what was asked for does not exist,
// or is not the caller's to manage.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

// Product is a product as the server keeps it.
type Product struct {
	ID string `json:"id"`
	Settings
	Admins  []string  `json:"admins"`
	Created time.Time `json:"created"`
}

// Settings are what an admin sets on a product.
type Settings struct {
	Name    string   `json:"name"`
	Modules []string `json:"modules"`
	// Free are the modules everyone who signs in may run; TrialModules
	// those each user may try for TrialDays from their first sign-in.
	Free         []string `json:"free"`
	TrialModules []string `json:"trial_modules"`
	TrialDays    int      `json:"trial_days"`
	// LeaseHours is how long an app runs offline after its last check;
	// zero means 24.
	LeaseHours int `json:"lease_hours"`
	// Terms is the version of the terms users accept, at TermsURL.
	Terms    int    `json:"terms"`
	TermsURL string `json:"terms_url"`
	// Contact is where users ask for modules.
	Contact string `json:"contact"`
}

// Key is one of a product's signing keys: the public half, as apps carry
// it.
type Key struct {
	KID     string    `json:"kid"`
	Public  string    `json:"public"`
	Current bool      `json:"current"`
	Created time.Time `json:"created"`
}

// Created is a new product and its first key.
type Created struct {
	Product Product `json:"product"`
	Key     Key     `json:"key"`
}

// User is a user of a product, with their machines and grants for it.
type User struct {
	ID       string    `json:"user"`
	Product  string    `json:"product"`
	Email    string    `json:"email"`
	Created  time.Time `json:"created"`
	Purpose  string    `json:"purpose"`
	Terms    int       `json:"terms"`
	Revoked  bool      `json:"revoked"`
	Note     string    `json:"note"`
	Machines []Machine `json:"machines"`
	Grants   []Grant   `json:"grants"`
}

// Machine is an installation.
type Machine struct {
	Key     string    `json:"key"`
	OS      string    `json:"os"`
	Arch    string    `json:"arch"`
	Version string    `json:"version"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	Revoked bool      `json:"revoked"`
}

// Grant lets a user run a module until a time, or always where Until is
// zero.
type Grant struct {
	Module  string    `json:"module"`
	Until   time.Time `json:"until"`
	Note    string    `json:"note"`
	Created time.Time `json:"created"`
}

// Active reports whether the grant holds at t.
func (g Grant) Active(t time.Time) bool { return g.Until.IsZero() || t.Before(g.Until) }

// GrantRequest grants modules to a user, until a time or, with Until
// zero, for good.
type GrantRequest struct {
	Email   string    `json:"email"`
	Modules []string  `json:"modules"`
	Until   time.Time `json:"until"`
	Note    string    `json:"note"`
}

// Event is a line of a product's activity.
type Event struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`
	User    string    `json:"user"`
	Product string    `json:"product"`
	Detail  string    `json:"detail"`
	By      string    `json:"by"`
}

// Stats counts a product's users and machines.
type Stats struct {
	Users    int            `json:"users"`
	Revoked  int            `json:"revoked"`
	Machines int            `json:"machines"`
	Active   int            `json:"active_machines"`
	Versions map[string]int `json:"versions"`
}

// Me is who a token belongs to.
type Me struct {
	Email     string `json:"email"`
	Operator  bool   `json:"operator"`
	MayCreate bool   `json:"may_create"`
}

// Session is a signed-in admin's token.
type Session struct {
	Token   string    `json:"token"`
	Email   string    `json:"email"`
	Expires time.Time `json:"expires"`
}

// Allowed is an address the operators allow to create products.
type Allowed struct {
	Email   string    `json:"email"`
	Created time.Time `json:"created"`
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	server := strings.TrimRight(c.Server, "/")
	if server == "" {
		server = DefaultServer
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, server+"/v1/admin/"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		e := &Error{Status: resp.StatusCode}
		if json.Unmarshal(data, e) != nil || e.Code == "" {
			return fmt.Errorf("licensebox: %s from %s", resp.Status, server)
		}
		return e
	}
	if out == nil {
		return nil
	}
	if raw, ok := out.(*json.RawMessage); ok {
		*raw = data
		return nil
	}
	return json.Unmarshal(data, out)
}

func p(parts ...string) string {
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

// Raw calls the API and returns its answer as it is, for printing.
func (c *Client) Raw(ctx context.Context, method, path string, in any) (json.RawMessage, error) {
	var raw json.RawMessage
	return raw, c.do(ctx, method, path, in, &raw)
}

// StartLogin mails a sign-in code to an admin's address, if it may sign
// in; FinishLogin trades it for a session.
func (c *Client) StartLogin(ctx context.Context, email string) error {
	return c.do(ctx, "POST", "login", map[string]string{"email": email}, nil)
}

func (c *Client) FinishLogin(ctx context.Context, email, code string) (Session, error) {
	var s Session
	return s, c.do(ctx, "POST", "login/finish", map[string]string{"email": email, "code": code}, &s)
}

// Logout ends the session of the client's token.
func (c *Client) Logout(ctx context.Context) error { return c.do(ctx, "POST", "logout", nil, nil) }

func (c *Client) Me(ctx context.Context) (Me, error) {
	var m Me
	return m, c.do(ctx, "GET", "me", nil, &m)
}

// Products returns the products the admin manages.
func (c *Client) Products(ctx context.Context) ([]Product, error) {
	var ps []Product
	return ps, c.do(ctx, "GET", "products", nil, &ps)
}

func (c *Client) Product(ctx context.Context, id string) (Product, error) {
	var pr Product
	return pr, c.do(ctx, "GET", p("products", id), nil, &pr)
}

// CreateProduct creates a product, with its first signing key, managed
// by the admin.
func (c *Client) CreateProduct(ctx context.Context, id string, s Settings) (Created, error) {
	var cr Created
	in := struct {
		ID string `json:"id"`
		Settings
	}{id, s}
	return cr, c.do(ctx, "POST", "products", in, &cr)
}

// UpdateProduct replaces a product's settings.
func (c *Client) UpdateProduct(ctx context.Context, id string, s Settings) (Product, error) {
	var pr Product
	return pr, c.do(ctx, "PUT", p("products", id), s, &pr)
}

func (c *Client) Keys(ctx context.Context, product string) ([]Key, error) {
	var ks []Key
	return ks, c.do(ctx, "GET", p("products", product, "keys"), nil, &ks)
}

// AddKey makes a new signing key, the current one from now.
func (c *Client) AddKey(ctx context.Context, product string) (Key, error) {
	var k Key
	return k, c.do(ctx, "POST", p("products", product, "keys"), nil, &k)
}

// RetireKey removes a key that is not the current one.
func (c *Client) RetireKey(ctx context.Context, product, kid string) error {
	return c.do(ctx, "DELETE", p("products", product, "keys", kid), nil, nil)
}

func (c *Client) AddAdmin(ctx context.Context, product, email string) (Product, error) {
	var pr Product
	return pr, c.do(ctx, "POST", p("products", product, "admins"), map[string]string{"email": email}, &pr)
}

func (c *Client) RemoveAdmin(ctx context.Context, product, email string) (Product, error) {
	var pr Product
	return pr, c.do(ctx, "DELETE", p("products", product, "admins", email), nil, &pr)
}

// Users returns the product's users, those whose email or purpose
// contains q if it is not empty.
func (c *Client) Users(ctx context.Context, product, q string) ([]User, error) {
	var us []User
	return us, c.do(ctx, "GET", p("products", product, "users")+"?q="+url.QueryEscape(q), nil, &us)
}

func (c *Client) User(ctx context.Context, product, email string) (User, error) {
	var u User
	return u, c.do(ctx, "GET", p("products", product, "users", email), nil, &u)
}

// Grant grants modules; the address need not have signed in yet.
func (c *Client) Grant(ctx context.Context, product string, g GrantRequest) ([]Grant, error) {
	var gs []Grant
	return gs, c.do(ctx, "POST", p("products", product, "grants"), g, &gs)
}

// Ungrant takes modules back.
func (c *Client) Ungrant(ctx context.Context, product, email string, modules ...string) ([]Grant, error) {
	var gs []Grant
	return gs, c.do(ctx, "POST", p("products", product, "grants", "remove"), GrantRequest{Email: email, Modules: modules}, &gs)
}

// Revoke refuses a user's apps, and their signing in again; Restore
// undoes it.
func (c *Client) Revoke(ctx context.Context, product, email, note string) error {
	return c.do(ctx, "POST", p("products", product, "revoke"), map[string]string{"email": email, "note": note}, nil)
}

func (c *Client) Restore(ctx context.Context, product, email string) error {
	return c.do(ctx, "POST", p("products", product, "restore"), map[string]string{"email": email}, nil)
}

// RevokeMachine refuses one installation; RestoreMachine undoes it.
func (c *Client) RevokeMachine(ctx context.Context, product, key, note string) error {
	return c.do(ctx, "POST", p("products", product, "revoke"), map[string]string{"machine": key, "note": note}, nil)
}

func (c *Client) RestoreMachine(ctx context.Context, product, key string) error {
	return c.do(ctx, "POST", p("products", product, "restore"), map[string]string{"machine": key}, nil)
}

// Events returns the product's latest activity, newest first.
func (c *Client) Events(ctx context.Context, product string, limit int) ([]Event, error) {
	var es []Event
	return es, c.do(ctx, "GET", p("products", product, "events")+"?limit="+strconv.Itoa(limit), nil, &es)
}

func (c *Client) Stats(ctx context.Context, product string) (Stats, error) {
	var st Stats
	return st, c.do(ctx, "GET", p("products", product, "stats"), nil, &st)
}

// Allowed lists who may create products, for operators; Allow and
// Disallow change it.
func (c *Client) Allowed(ctx context.Context) ([]Allowed, error) {
	var as []Allowed
	return as, c.do(ctx, "GET", "allowed", nil, &as)
}

func (c *Client) Allow(ctx context.Context, email string) error {
	return c.do(ctx, "PUT", p("allowed", email), nil, nil)
}

func (c *Client) Disallow(ctx context.Context, email string) error {
	return c.do(ctx, "DELETE", p("allowed", email), nil, nil)
}
