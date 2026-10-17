# licensebox for Go

The Go client for [licensebox](https://licensebox.dev): your app signs the
user in once, by email, then checks a signed lease offline on every run and
renews it by itself.

```
go get licensebox.dev/client
```

```go
lic, err := client.New(client.Config{
	Product: "myapp",
	Keys:    lease.Keys{"myapp-2026a": lease.MustKey("K3T9…")},
	Version: version,
})
if err != nil {
	return err
}
if _, err := lic.Require(ctx, "export"); err != nil {
	return err // says which module is missing, and for whom
}
```

- `client`: sign-in, storage of the lease and the installation's key,
  offline checks, renewal.
- `lease`: the lease format, for checking leases without the client.
- `cmd/signin`: signs in to a product and prints the lease, for trying a
  product's set-up.

Standard library only. The full guide, and the HTTP API for other
languages, is at [licensebox.dev/docs](https://licensebox.dev/docs).

MIT licence.
