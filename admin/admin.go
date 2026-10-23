// Package admin is a client of licensebox's admin API: creating and
// changing products, their signing keys and admins, and managing their
// users: grants, revocations, activity and numbers. The licensebox
// command is built on it; use it to automate the same, as granting a
// module after an admin approves a request.
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

	"licensebox.dev/machine"
	"licensebox.dev/policy"
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
	// DeleteAt, if set, is when the product is deleted for good; until
	// then apps are refused, and UndeleteProduct takes it back.
	DeleteAt time.Time `json:"delete_at,omitzero"`
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
	// Heartbeat controls optional long-running application checks; zero disables.
	Heartbeat policy.Heartbeat `json:"heartbeat"`
	// MachineLimit is seats per user and product; zero means unrestricted.
	MachineLimit int              `json:"machine_limit"`
	Locations    policy.Locations `json:"locations"`
	// Terms is the version of the terms users accept, at TermsURL.
	Terms    int    `json:"terms"`
	TermsURL string `json:"terms_url"`
	// Contact is shown where users are refused.
	Contact string `json:"contact"`
	// Descriptions say what each module is for, as users asking for
	// access see it; Hidden modules users neither see nor can ask for.
	Descriptions map[string]string `json:"descriptions"`
	Hidden       []string          `json:"hidden"`
	// Usage is whether apps send counts of the commands they run.
	Usage bool `json:"usage"`
}

// Request is a user's request for modules, and its answer.
type Request struct {
	ID      string    `json:"id"`
	Email   string    `json:"email"`
	Modules []string  `json:"modules"`
	Note    string    `json:"note"`
	Created time.Time `json:"created"`
	// Status is "pending", "approved" or "declined".
	Status     string    `json:"status"`
	Granted    []string  `json:"granted"`
	Until      time.Time `json:"until"`
	Answer     string    `json:"answer"`
	AnsweredBy string    `json:"answered_by"`
	Answered   time.Time `json:"answered"`
}

// Answer approves a request, for all its modules or those given, until
// a time if Until is not zero, or declines it; Note is sent to the user.
type Answer struct {
	Modules []string  `json:"modules"`
	Until   time.Time `json:"until"`
	Note    string    `json:"note"`
}

// UsageReport sums a product's usage over the days since Since.
type UsageReport struct {
	Since    string         `json:"since"`
	Runs     int            `json:"runs"`
	Failed   int            `json:"failed"`
	Days     []UsageLine    `json:"days"`
	Commands []UsageLine    `json:"commands"`
	Users    []UsageLine    `json:"users"`
	Versions []UsageLine    `json:"versions"`
	Systems  map[string]int `json:"systems"`
}

// UsageLine is the runs of one day, command, user or version: Millis is
// the mean time a run took, Users how many users ran it.
type UsageLine struct {
	Name   string `json:"name"`
	Runs   int    `json:"runs"`
	Failed int    `json:"failed"`
	Millis int64  `json:"ms"`
	Users  int    `json:"users"`
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
	// ID is lease.MachineID(Key): the short id to revoke or restore it by.
	ID        string          `json:"id"`
	Binding   machine.Binding `json:"binding"`
	Key       string          `json:"key"`
	OS        string          `json:"os"`
	Arch      string          `json:"arch"`
	Version   string          `json:"version"`
	First     time.Time       `json:"first"`
	Last      time.Time       `json:"last"`
	Revoked   bool            `json:"revoked"`
	Allocated bool            `json:"allocated"`
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

// DeleteProduct schedules the product's deletion, seven days on; confirm
// must be its id again. From now on apps are refused as if it were gone.
func (c *Client) DeleteProduct(ctx context.Context, id, confirm string) (Product, error) {
	var pr Product
	return pr, c.do(ctx, "DELETE", p("products", id), map[string]string{"confirm": confirm}, &pr)
}

// UndeleteProduct takes back a scheduled deletion that is not yet due.
func (c *Client) UndeleteProduct(ctx context.Context, id string) (Product, error) {
	var pr Product
	return pr, c.do(ctx, "POST", p("products", id, "undelete"), nil, &pr)
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

// RevokeMachine refuses one installation, named by its ID or its key;
// RestoreMachine undoes it.
func (c *Client) RevokeMachine(ctx context.Context, product, machine, note string) error {
	return c.do(ctx, "POST", p("products", product, "revoke"), map[string]string{"machine": machine, "note": note}, nil)
}

func (c *Client) RestoreMachine(ctx context.Context, product, machine string) error {
	return c.do(ctx, "POST", p("products", product, "restore"), map[string]string{"machine": machine}, nil)
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

// Requests returns the product's requests, newest first: those of the
// status given ("pending", "approved", "declined"), or all with "".
func (c *Client) Requests(ctx context.Context, product, status string) ([]Request, error) {
	var rs []Request
	return rs, c.do(ctx, "GET", p("products", product, "requests")+"?status="+url.QueryEscape(status), nil, &rs)
}

// Approve grants a request's modules, or those of them in a, and tells
// the user; Decline tells them no.
func (c *Client) Approve(ctx context.Context, product, id string, a Answer) (Request, error) {
	var r Request
	return r, c.do(ctx, "POST", p("products", product, "requests", id, "approve"), a, &r)
}

func (c *Client) Decline(ctx context.Context, product, id, note string) (Request, error) {
	var r Request
	return r, c.do(ctx, "POST", p("products", product, "requests", id, "decline"), Answer{Note: note}, &r)
}

// Usage sums the product's usage over the last days, 30 if days is 0.
func (c *Client) Usage(ctx context.Context, product string, days int) (UsageReport, error) {
	var u UsageReport
	return u, c.do(ctx, "GET", p("products", product, "usage")+"?days="+strconv.Itoa(days), nil, &u)
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
