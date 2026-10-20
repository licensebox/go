// Command signin signs in to a product with the client, as an app would,
// and prints the lease: for trying a deployment.
//
//	go run ./cmd/signin -product edgewise -key edgewise-2026=K3T9...
//
// The lease and the installation key are kept in a folder of their own,
// so the tool does not disturb an app's.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"licensebox.dev/client"
	"licensebox.dev/lease"
)

func main() {
	product := flag.String("product", "", "the product's id")
	key := flag.String("key", "", "its public key, as kid=ed25519-mldsa65:base64url")
	server := flag.String("server", client.DefaultServer, "the server")
	module := flag.String("require", "", "a module to require after signing in")
	logout := flag.Bool("logout", false, "remove the lease first, to sign in again")
	flag.Parse()
	kid, pub, ok := strings.Cut(*key, "=")
	if *product == "" || !ok {
		log.Fatal("signin: -product and -key kid=ed25519-mldsa65:base64url are required")
	}
	pk, err := lease.DecodeKey(pub)
	if err != nil {
		log.Fatal("signin: ", err)
	}
	base, _ := os.UserConfigDir()
	c, err := client.New(client.Config{
		Product: *product, Keys: lease.Keys{kid: pk}, Server: *server, Version: "signin",
		Dir: filepath.Join(base, "licensebox", "signin", *product),
	})
	if err != nil {
		log.Fatal(err)
	}
	if *logout {
		c.Logout()
	}
	ctx := context.Background()
	l, err := c.Lease(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("product %s, user %s (%s)\nmodules %v\nissued %s, expires %s\n", l.Product, l.Email, l.User, l.Modules, l.Issued.Local().Format("2006-01-02 15:04"), l.Expires.Local().Format("2006-01-02 15:04"))
	if *module != "" {
		if _, err := c.Require(ctx, *module); err != nil {
			fmt.Println("require:", err)
		} else {
			fmt.Printf("require %s: ok\n", *module)
		}
	}
}
