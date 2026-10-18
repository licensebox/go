// Package cli is the licensebox command: products, keys, admins, users,
// grants and revocations over the admin API, for admins signed in by
// email. It is a package so that it can be tested against a server.
package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"licensebox.dev/admin"
	"licensebox.dev/policy"
)

const usage = `usage: licensebox [-json] command [arguments]

Signing in:
  login [EMAIL]                       sign in with a code mailed to you
  logout                              sign out on this machine
  whoami                              who you are signed in as
  version                             this program's release

Products:
  products                            the products you manage
  create ID -modules a,b [settings]   create a product and its signing key
  product ID                          a product's settings, keys and admins
  product ID [settings]               change settings; those not given are kept
      settings: -name, -modules a,b, -free a, -trial b, -trial-days N,
                -lease-hours N, -machine-limit N, -allow-areas AREAS, -block-areas AREAS,
                -terms N, -terms-url URL, -contact EMAIL
      -describe "module: what it is for" (again for each), -hidden a,
                -usage on|off (collect counts of the commands apps run)
  key add ID                          a new signing key, current from now
  key retire ID KID                   remove an old key
  admin add ID EMAIL                  let someone manage the product
  admin remove ID EMAIL

Users:
  users ID [-q text]                  the product's users
  user ID EMAIL                       a user's grants and machines
  grant ID EMAIL MODULE... [-until 2027-01-31 | -days N] [-note text]
  ungrant ID EMAIL MODULE...
  revoke ID EMAIL [-note text]        refuse the user's apps from their next check
  revoke ID -machine KEY              refuse one machine
  restore ID EMAIL | -machine KEY
  requests ID [-all]                  requests for modules, waiting or all
  approve ID REQUEST [MODULE...]      grant what was asked, or the modules given
                                      [-until 2027-01-31 | -days N] [-note text]
  decline ID REQUEST [-note text]     say no, telling them why
  events ID [-n 50]                   the latest activity
  stats ID                            users and machines
  usage ID [-days 30]                 commands run, by command, user and version

Operators:
  allowed | allow EMAIL | disallow EMAIL   who may create products

The server is $LICENSEBOX_SERVER, or https://licensebox.dev. The session
is kept in licensebox/admin-token in your configuration folder, or given
as $LICENSEBOX_TOKEN.`

// Env is what the command runs with.
type Env struct {
	In     io.Reader
	Out    io.Writer
	Getenv func(string) string
	HTTP   *http.Client
	// TokenFile is where the session is kept; empty means
	// licensebox/admin-token in the user's configuration folder.
	TokenFile string
	// Version is the command's release.
	Version string
}

func (e Env) tokenFile() (string, error) {
	if e.TokenFile != "" {
		return e.TokenFile, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "licensebox", "admin-token"), nil
}

func (e Env) client() (*admin.Client, error) {
	c := &admin.Client{Server: e.Getenv("LICENSEBOX_SERVER"), Token: e.Getenv("LICENSEBOX_TOKEN"), HTTP: e.HTTP}
	if c.Token == "" {
		f, err := e.tokenFile()
		if err != nil {
			return nil, err
		}
		b, err := os.ReadFile(f)
		if err == nil {
			c.Token = strings.TrimSpace(string(b))
		}
	}
	return c, nil
}

// Run runs the command with the arguments after its name.
func Run(ctx context.Context, args []string, env Env) error {
	top := flag.NewFlagSet("licensebox", flag.ContinueOnError)
	top.SetOutput(io.Discard)
	asJSON := top.Bool("json", false, "print the server's answers as JSON")
	if err := top.Parse(args); err != nil || top.NArg() == 0 || top.Arg(0) == "help" {
		fmt.Fprintln(env.Out, usage)
		if err != nil {
			return err
		}
		return nil
	}
	c, err := env.client()
	if err != nil {
		return err
	}
	r := runner{ctx: ctx, c: c, env: env, json: *asJSON, tw: tabwriter.NewWriter(env.Out, 0, 4, 2, ' ', 0)}
	defer r.tw.Flush()
	cmd, rest := top.Arg(0), top.Args()[1:]
	if cmd == "version" {
		fmt.Fprintln(env.Out, "licensebox", dash(env.Version))
		return nil
	}
	if cmd != "login" && c.Token == "" {
		return errors.New("not signed in: run licensebox login")
	}
	switch cmd {
	case "login":
		return r.login(rest)
	case "logout":
		return r.logout()
	case "whoami":
		me, err := c.Me(ctx)
		return r.show(me, err, func() {
			fmt.Fprintf(r.tw, "%s", dash(me.Email))
			if me.Operator {
				fmt.Fprint(r.tw, ", operator")
			}
			if me.MayCreate {
				fmt.Fprint(r.tw, "; may create products")
			}
			fmt.Fprintln(r.tw)
		})
	case "products":
		ps, err := c.Products(ctx)
		return r.show(ps, err, func() {
			fmt.Fprintln(r.tw, "ID\tNAME\tMODULES\tFREE\tTRIAL\tOFFLINE")
			for _, p := range ps {
				fmt.Fprintf(r.tw, "%s\t%s\t%s\t%s\t%s\t%dh\n", p.ID, p.Name, list(p.Modules), list(p.Free), trial(p.Settings), hours(p.LeaseHours))
			}
		})
	case "create":
		return r.create(rest)
	case "product":
		return r.product(rest)
	case "key":
		return r.key(rest)
	case "admin":
		return r.admin(rest)
	case "users":
		fs := flags("users")
		q := fs.String("q", "", "only users whose email or purpose contains this")
		pos, err := parse(fs, rest, 1, "users ID [-q text]")
		if err != nil {
			return err
		}
		us, err := c.Users(ctx, pos[0], *q)
		return r.show(us, err, func() {
			fmt.Fprintln(r.tw, "EMAIL\tSINCE\tUSES IT FOR\tMACHINES\tGRANTED\tSTATE")
			for _, u := range us {
				fmt.Fprintf(r.tw, "%s\t%s\t%s\t%d\t%s\t%s\n", u.Email, date(u.Created), dash(u.Purpose), len(u.Machines), granted(u.Grants), state(u.Revoked))
			}
		})
	case "user":
		pos, err := parse(flags("user"), rest, 2, "user ID EMAIL")
		if err != nil {
			return err
		}
		u, err := c.User(ctx, pos[0], pos[1])
		return r.show(u, err, func() { r.user(u) })
	case "grant", "ungrant":
		return r.grant(cmd, rest)
	case "revoke", "restore":
		return r.revoke(cmd, rest)
	case "events":
		fs := flags("events")
		n := fs.Int("n", 50, "how many")
		pos, err := parse(fs, rest, 1, "events ID [-n N]")
		if err != nil {
			return err
		}
		es, err := c.Events(ctx, pos[0], *n)
		return r.show(es, err, func() {
			fmt.Fprintln(r.tw, "TIME (UTC)\tWHAT\tDETAIL\tBY")
			for _, e := range es {
				fmt.Fprintf(r.tw, "%s\t%s\t%s\t%s\n", e.Time.UTC().Format("2006-01-02 15:04"), e.Kind, e.Detail, e.By)
			}
		})
	case "stats":
		pos, err := parse(flags("stats"), rest, 1, "stats ID")
		if err != nil {
			return err
		}
		st, err := c.Stats(ctx, pos[0])
		return r.show(st, err, func() {
			fmt.Fprintf(r.tw, "users\t%d (%d revoked)\n", st.Users, st.Revoked)
			fmt.Fprintf(r.tw, "machines\t%d, %d active in the last 30 days\n", st.Machines, st.Active)
			vs := make([]string, 0, len(st.Versions))
			for v := range st.Versions {
				vs = append(vs, v)
			}
			slices.Sort(vs)
			for _, v := range vs {
				fmt.Fprintf(r.tw, "  version %s\t%d\n", dash(v), st.Versions[v])
			}
		})
	case "requests":
		fs := flags("requests")
		all := fs.Bool("all", false, "answered ones too")
		pos, err := parse(fs, rest, 1, "requests ID [-all]")
		if err != nil {
			return err
		}
		status := "pending"
		if *all {
			status = ""
		}
		rs, err := c.Requests(ctx, pos[0], status)
		return r.show(rs, err, func() {
			if len(rs) == 0 {
				fmt.Fprintln(r.tw, "No requests waiting.")
				return
			}
			fmt.Fprintln(r.tw, "REQUEST\tEMAIL\tMODULES\tASKED\tSTATUS\tNOTE")
			for _, q := range rs {
				fmt.Fprintf(r.tw, "%s\t%s\t%s\t%s\t%s\t%s\n", q.ID, q.Email, list(q.Modules), date(q.Created), q.Status, oneLine(q.Note))
			}
		})
	case "approve", "decline":
		fs := flags(cmd)
		untilFlag := fs.String("until", "", "the last day, as 2027-01-31")
		days := fs.Int("days", 0, "for this many days from now")
		note := fs.String("note", "", "a note sent to the user")
		use := cmd + " ID REQUEST [MODULE...]"
		pos, err := parse(fs, rest, -2, use)
		if err != nil {
			return err
		}
		var q admin.Request
		if cmd == "decline" {
			q, err = c.Decline(ctx, pos[0], pos[1], *note)
		} else {
			a := admin.Answer{Modules: pos[2:], Note: *note}
			switch {
			case *untilFlag != "" && *days != 0:
				return errors.New("give -until or -days, not both")
			case *untilFlag != "":
				d, err := time.Parse(time.DateOnly, *untilFlag)
				if err != nil {
					return errors.New("-until: a date, as 2027-01-31")
				}
				a.Until = d.AddDate(0, 0, 1)
			case *days > 0:
				a.Until = time.Now().AddDate(0, 0, *days)
			}
			q, err = c.Approve(ctx, pos[0], pos[1], a)
		}
		return r.show(q, err, func() {
			if q.Status == "approved" {
				fmt.Fprintf(r.tw, "Approved: %s has %s %s, and was told by email.\n", q.Email, list(q.Granted), until(q.Until))
			} else {
				fmt.Fprintf(r.tw, "Declined: %s was told by email.\n", q.Email)
			}
		})
	case "usage":
		fs := flags("usage")
		days := fs.Int("days", 30, "how many days back")
		pos, err := parse(fs, rest, 1, "usage ID [-days 30]")
		if err != nil {
			return err
		}
		u, err := c.Usage(ctx, pos[0], *days)
		return r.show(u, err, func() {
			fmt.Fprintf(r.tw, "Since %s: %d runs, %d failed.\n\n", u.Since, u.Runs, u.Failed)
			for _, part := range []struct {
				title string
				lines []admin.UsageLine
			}{{"COMMAND", u.Commands}, {"USER", u.Users}, {"VERSION", u.Versions}} {
				if len(part.lines) == 0 {
					continue
				}
				fmt.Fprintf(r.tw, "%s\tRUNS\tFAILED\tUSERS\tMEAN TIME\n", part.title)
				for _, l := range part.lines {
					fmt.Fprintf(r.tw, "%s\t%d\t%d\t%d\t%.1f s\n", dash(l.Name), l.Runs, l.Failed, l.Users, float64(l.Millis)/1000)
				}
				fmt.Fprintln(r.tw)
			}
		})
	case "allowed":
		as, err := c.Allowed(ctx)
		return r.show(as, err, func() {
			fmt.Fprintln(r.tw, "MAY CREATE PRODUCTS\tSINCE")
			for _, a := range as {
				fmt.Fprintf(r.tw, "%s\t%s\n", a.Email, date(a.Created))
			}
		})
	case "allow", "disallow":
		pos, err := parse(flags(cmd), rest, 1, cmd+" EMAIL")
		if err != nil {
			return err
		}
		if cmd == "allow" {
			err = c.Allow(ctx, pos[0])
		} else {
			err = c.Disallow(ctx, pos[0])
		}
		return r.done(err, "%s: %s", cmd+"ed", pos[0])
	}
	fmt.Fprintln(env.Out, usage)
	return fmt.Errorf("unknown command %q", cmd)
}

type runner struct {
	ctx  context.Context
	c    *admin.Client
	env  Env
	json bool
	tw   *tabwriter.Writer
}

// show prints v as JSON with -json, else with print.
func (r runner) show(v any, err error, print func()) error {
	if err != nil {
		return err
	}
	if r.json {
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Fprintln(r.env.Out, string(b))
		return nil
	}
	print()
	return nil
}

func (r runner) done(err error, format string, args ...any) error {
	if err != nil {
		return err
	}
	if !r.json {
		fmt.Fprintf(r.tw, format+"\n", args...)
	}
	return nil
}

func (r runner) login(args []string) error {
	pos, err := parse(flags("login"), args, -1, "login [EMAIL]")
	if err != nil {
		return err
	}
	in := bufio.NewReader(r.env.In)
	email := ""
	if len(pos) > 0 {
		email = pos[0]
	} else {
		fmt.Fprint(r.env.Out, "Email: ")
		email, _ = in.ReadString('\n')
	}
	email = strings.TrimSpace(email)
	if err := r.c.StartLogin(r.ctx, email); err != nil {
		return err
	}
	fmt.Fprintf(r.env.Out, "If %s manages a product, a six-digit code was sent to it.\nCode: ", email)
	code, _ := in.ReadString('\n')
	s, err := r.c.FinishLogin(r.ctx, email, strings.TrimSpace(code))
	if err != nil {
		return err
	}
	f, err := r.env.tokenFile()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(f, []byte(s.Token+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(r.env.Out, "Signed in as %s until %s.\n", s.Email, s.Expires.Local().Format("2 Jan 2006"))
	return nil
}

func (r runner) logout() error {
	err := r.c.Logout(r.ctx)
	if f, ferr := r.env.tokenFile(); ferr == nil {
		os.Remove(f)
	}
	return r.done(err, "Signed out.")
}

// settings defines the product settings' flags on fs, and returns a
// function applying those given to s.
func settings(fs *flag.FlagSet) func(s *admin.Settings) {
	name := fs.String("name", "", "the name users see")
	modules := fs.String("modules", "", "all its modules, comma-separated")
	free := fs.String("free", "", "the modules everyone may run")
	trialMods := fs.String("trial", "", "the modules each new user may try")
	trialDays := fs.Int("trial-days", 0, "how long the trial lasts")
	leaseHours := fs.Int("lease-hours", 0, "how long apps run offline (24 if 0)")
	heartbeatInterval := fs.Int("heartbeat-interval", 0, "optional heartbeat interval in seconds; 0 disables")
	heartbeatGrace := fs.Int("heartbeat-grace", 0, "maximum seconds without successful contact for heartbeat products")
	machineLimit := fs.Int("machine-limit", 0, "machine seats per user; 0 means unrestricted; new sign-ins transfer the oldest seat")
	var allowAreas, blockAreas []policy.Area
	fs.Func("allow-areas", "allowed countries, cities or radii, separated by semicolons", func(text string) error { var err error; allowAreas, err = policy.ParseAreas(text); return err })
	fs.Func("block-areas", "blocked countries, cities or radii, separated by semicolons", func(text string) error { var err error; blockAreas, err = policy.ParseAreas(text); return err })
	terms := fs.Int("terms", 0, "the version of the terms users accept")
	termsURL := fs.String("terms-url", "", "where the terms are")
	contact := fs.String("contact", "", "shown where users are refused")
	var describe []string
	fs.Func("describe", `what a module is for, as "export: export to STEP"`, func(v string) error {
		if !strings.Contains(v, ":") {
			return errors.New(`want "module: what it is for"`)
		}
		describe = append(describe, v)
		return nil
	})
	hidden := fs.String("hidden", "", "modules users don't see nor can ask for, comma-separated")
	usage := fs.String("usage", "", "on or off: collect counts of the commands apps run")
	return func(s *admin.Settings) {
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "name":
				s.Name = *name
			case "modules":
				s.Modules = split(*modules)
			case "free":
				s.Free = split(*free)
			case "trial":
				s.TrialModules = split(*trialMods)
			case "trial-days":
				s.TrialDays = *trialDays
			case "lease-hours":
				s.LeaseHours = *leaseHours
			case "heartbeat-interval":
				s.Heartbeat.IntervalSeconds = *heartbeatInterval
				if *heartbeatInterval == 0 {
					s.Heartbeat.GraceSeconds = 0
				}
			case "heartbeat-grace":
				s.Heartbeat.GraceSeconds = *heartbeatGrace
			case "machine-limit":
				s.MachineLimit = *machineLimit
			case "allow-areas":
				s.Locations.Allow = allowAreas
			case "block-areas":
				s.Locations.Block = blockAreas
			case "terms":
				s.Terms = *terms
			case "terms-url":
				s.TermsURL = *termsURL
			case "contact":
				s.Contact = *contact
			case "describe":
				if s.Descriptions == nil {
					s.Descriptions = map[string]string{}
				}
				for _, d := range describe {
					m, text, _ := strings.Cut(d, ":")
					if text = strings.TrimSpace(text); text == "" {
						delete(s.Descriptions, strings.TrimSpace(m))
					} else {
						s.Descriptions[strings.TrimSpace(m)] = text
					}
				}
			case "hidden":
				s.Hidden = split(*hidden)
			case "usage":
				s.Usage = *usage == "on"
			}
		})
	}
}

func (r runner) create(args []string) error {
	fs := flags("create")
	apply := settings(fs)
	pos, err := parse(fs, args, 1, "create ID -modules a,b [settings]")
	if err != nil {
		return err
	}
	s := admin.Settings{Terms: 1, MachineLimit: 1}
	apply(&s)
	cr, err := r.c.CreateProduct(r.ctx, pos[0], s)
	return r.show(cr, err, func() {
		r.settings(cr.Product)
		fmt.Fprintf(r.tw, "\nBuild this into your app:\n\n")
		r.tw.Flush()
		r.config(cr.Product.ID, []admin.Key{cr.Key})
	})
}

func (r runner) product(args []string) error {
	fs := flags("product")
	apply := settings(fs)
	pos, err := parse(fs, args, 1, "product ID [settings]")
	if err != nil {
		return err
	}
	pr, err := r.c.Product(r.ctx, pos[0])
	if err != nil {
		return err
	}
	changed := false
	fs.Visit(func(*flag.Flag) { changed = true })
	if changed {
		apply(&pr.Settings)
		if pr, err = r.c.UpdateProduct(r.ctx, pr.ID, pr.Settings); err != nil {
			return err
		}
	}
	ks, err := r.c.Keys(r.ctx, pr.ID)
	return r.show(map[string]any{"product": pr, "keys": ks}, err, func() {
		r.settings(pr)
		fmt.Fprintf(r.tw, "admins\t%s\n\n", list(pr.Admins))
		r.tw.Flush()
		r.config(pr.ID, ks)
	})
}

func (r runner) settings(p admin.Product) {
	fmt.Fprintf(r.tw, "id\t%s\nname\t%s\nmodules\t%s\nfree\t%s\nhidden\t%s\ntrial\t%s\noffline\t%d hours\nterms\t%s\ncontact\t%s\nusage\t%s\n",
		p.ID, p.Name, list(p.Modules), list(p.Free), list(p.Hidden), trial(p.Settings), hours(p.LeaseHours), terms(p.Settings), dash(p.Contact), onOff(p.Usage))
	fmt.Fprintf(r.tw, "machine seats\t%d (0 is unrestricted)\nallowed areas\t%s\nblocked areas\t%s\n", p.MachineLimit, strings.ReplaceAll(policy.FormatAreas(p.Locations.Allow), "\n", "; "), strings.ReplaceAll(policy.FormatAreas(p.Locations.Block), "\n", "; "))
	for _, m := range p.Modules {
		if d := p.Descriptions[m]; d != "" {
			fmt.Fprintf(r.tw, "  %s\t%s\n", m, d)
		}
	}
	if p.Heartbeat.Enabled() {
		fmt.Fprintf(r.tw, "heartbeat interval\t%ds\ncontact grace\t%ds\n", p.Heartbeat.IntervalSeconds, p.Heartbeat.GraceSeconds)
	} else {
		fmt.Fprintln(r.tw, "heartbeat\tdisabled")
	}
}

func onOff(b bool) string {
	if b {
		return "collected"
	}
	return "off"
}

// config prints the client configuration an app carries.
func (r runner) config(product string, keys []admin.Key) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "client.Config{\n\tProduct: %q,\n\tKeys: lease.Keys{\n", product)
	for _, k := range keys {
		cur := ""
		if k.Current {
			cur = " // current"
		}
		fmt.Fprintf(&b, "\t\t%q: lease.MustKey(%q),%s\n", k.KID, k.Public, cur)
	}
	fmt.Fprint(&b, "\t},\n}\n")
	r.env.Out.Write(b.Bytes())
}

func (r runner) key(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: licensebox key add ID | key retire ID KID")
	}
	switch args[0] {
	case "add":
		pos, err := parse(flags("key add"), args[1:], 1, "key add ID")
		if err != nil {
			return err
		}
		k, err := r.c.AddKey(r.ctx, pos[0])
		return r.show(k, err, func() {
			fmt.Fprintf(r.tw, "New leases are signed with %s from now. Ship app versions that carry it:\n\t%q: lease.MustKey(%q),\nthen retire the old key.\n", k.KID, k.KID, k.Public)
		})
	case "retire":
		pos, err := parse(flags("key retire"), args[1:], 2, "key retire ID KID")
		if err != nil {
			return err
		}
		return r.done(r.c.RetireKey(r.ctx, pos[0], pos[1]), "Retired %s: apps holding leases signed with it sign in again.", pos[1])
	}
	return errors.New("usage: licensebox key add ID | key retire ID KID")
}

func (r runner) admin(args []string) error {
	if len(args) == 0 || (args[0] != "add" && args[0] != "remove") {
		return errors.New("usage: licensebox admin add|remove ID EMAIL")
	}
	pos, err := parse(flags("admin"), args[1:], 2, "admin "+args[0]+" ID EMAIL")
	if err != nil {
		return err
	}
	var pr admin.Product
	if args[0] == "add" {
		pr, err = r.c.AddAdmin(r.ctx, pos[0], pos[1])
	} else {
		pr, err = r.c.RemoveAdmin(r.ctx, pos[0], pos[1])
	}
	return r.show(pr, err, func() { fmt.Fprintf(r.tw, "%s admins: %s\n", pr.ID, list(pr.Admins)) })
}

func (r runner) user(u admin.User) {
	fmt.Fprintf(r.tw, "%s\t%s, user since %s\n", u.Email, state(u.Revoked), date(u.Created))
	fmt.Fprintf(r.tw, "uses it for\t%s\n", dash(u.Purpose))
	if u.Note != "" {
		fmt.Fprintf(r.tw, "note\t%s\n", u.Note)
	}
	r.tw.Flush()
	fmt.Fprintln(r.env.Out)
	fmt.Fprintln(r.tw, "GRANT\tUNTIL\tNOTE")
	for _, g := range u.Grants {
		fmt.Fprintf(r.tw, "%s\t%s\t%s\n", g.Module, until(g.Until), g.Note)
	}
	r.tw.Flush()
	fmt.Fprintln(r.env.Out)
	fmt.Fprintln(r.tw, "MACHINE\tSYSTEM\tVERSION\tLAST CHECK\tSTATE")
	for _, m := range u.Machines {
		seatState := "seat transferred"
		if m.Allocated {
			seatState = "allocated"
		}
		if m.Revoked {
			seatState = "revoked"
		}
		fmt.Fprintf(r.tw, "%s\t%s/%s\t%s\t%s\t%s\n", m.Key, m.OS, m.Arch, dash(m.Version), m.Last.UTC().Format("2006-01-02 15:04"), seatState)
	}
}

func (r runner) grant(cmd string, args []string) error {
	fs := flags(cmd)
	untilFlag := fs.String("until", "", "the last day, as 2027-01-31")
	days := fs.Int("days", 0, "for this many days from now")
	note := fs.String("note", "", "why, for the record")
	pos, err := parse(fs, args, -3, cmd+" ID EMAIL MODULE...")
	if err != nil {
		return err
	}
	var gs []admin.Grant
	if cmd == "ungrant" {
		gs, err = r.c.Ungrant(r.ctx, pos[0], pos[1], pos[2:]...)
	} else {
		g := admin.GrantRequest{Email: pos[1], Modules: pos[2:], Note: *note}
		switch {
		case *untilFlag != "" && *days != 0:
			return errors.New("give -until or -days, not both")
		case *untilFlag != "":
			d, err := time.Parse(time.DateOnly, *untilFlag)
			if err != nil {
				return errors.New("-until: a date, as 2027-01-31")
			}
			g.Until = d.AddDate(0, 0, 1) // to the end of that day, UTC
		case *days > 0:
			g.Until = time.Now().AddDate(0, 0, *days)
		}
		gs, err = r.c.Grant(r.ctx, pos[0], g)
	}
	return r.show(gs, err, func() {
		fmt.Fprintf(r.tw, "%s has, in %s:\n", pos[1], pos[0])
		if len(gs) == 0 {
			fmt.Fprintln(r.tw, "  no grants")
		}
		for _, g := range gs {
			fmt.Fprintf(r.tw, "  %s\t%s\t%s\n", g.Module, until(g.Until), g.Note)
		}
	})
}

func (r runner) revoke(cmd string, args []string) error {
	fs := flags(cmd)
	machine := fs.String("machine", "", "a machine's key, instead of a user")
	note := fs.String("note", "", "why, for the record")
	use := cmd + " ID EMAIL | " + cmd + " ID -machine KEY"
	pos, err := parse(fs, args, -1, use)
	if err != nil {
		return err
	}
	id := pos[0]
	switch {
	case *machine == "" && len(pos) == 2 && cmd == "revoke":
		err = r.c.Revoke(r.ctx, id, pos[1], *note)
	case *machine == "" && len(pos) == 2:
		err = r.c.Restore(r.ctx, id, pos[1])
	case *machine != "" && len(pos) == 1 && cmd == "revoke":
		err = r.c.RevokeMachine(r.ctx, id, *machine, *note)
	case *machine != "" && len(pos) == 1:
		err = r.c.RestoreMachine(r.ctx, id, *machine)
	default:
		return errors.New("usage: licensebox " + use)
	}
	what := *machine
	if what == "" {
		what = pos[1]
	}
	if cmd == "revoke" {
		return r.done(err, "Revoked %s: refused at the next check.", what)
	}
	return r.done(err, "Restored %s.", what)
}

func flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parse parses flags given anywhere among the arguments and returns the
// others: exactly n of them, or with n negative at least -n.
func parse(fs *flag.FlagSet, args []string, n int, use string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, fmt.Errorf("%v\nusage: licensebox %s", err, use)
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	if n >= 0 && len(pos) != n || n < 0 && len(pos) < -n {
		return nil, errors.New("usage: licensebox " + use)
	}
	return pos, nil
}

func split(s string) []string {
	out := []string{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		out = append(out, f)
	}
	return out
}

func list(s []string) string { return dash(strings.Join(s, ",")) }

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 60 {
		s = s[:57] + "..."
	}
	return s
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func hours(h int) int {
	if h == 0 {
		return 24
	}
	return h
}

func trial(s admin.Settings) string {
	if len(s.TrialModules) == 0 || s.TrialDays == 0 {
		return "-"
	}
	return fmt.Sprintf("%s for %d days", list(s.TrialModules), s.TrialDays)
}

func terms(s admin.Settings) string {
	if s.TermsURL == "" {
		return fmt.Sprintf("version %d", s.Terms)
	}
	return fmt.Sprintf("version %d, %s", s.Terms, s.TermsURL)
}

func granted(gs []admin.Grant) string {
	var ms []string
	for _, g := range gs {
		if g.Active(time.Now()) {
			ms = append(ms, g.Module)
		}
	}
	return list(ms)
}

func date(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.DateOnly)
}

func until(t time.Time) string {
	if t.IsZero() {
		return "for good"
	}
	return "until " + t.UTC().Add(-time.Second).Format(time.DateOnly)
}

func state(revoked bool) string {
	if revoked {
		return "revoked"
	}
	return "active"
}
