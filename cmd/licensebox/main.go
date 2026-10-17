// Command licensebox manages products on licensebox: their settings,
// signing keys and admins, and their users' grants and revocations.
//
//	go install licensebox.dev/cmd/licensebox@latest
//	licensebox login
//	licensebox help
package main

import (
	"context"
	"fmt"
	"os"

	"licensebox.dev/admin/cli"
)

// version is the release, set when it is built.
var version = "dev"

func main() {
	env := cli.Env{In: os.Stdin, Out: os.Stdout, Getenv: os.Getenv, Version: version}
	if err := cli.Run(context.Background(), os.Args[1:], env); err != nil {
		fmt.Fprintln(os.Stderr, "licensebox:", err)
		os.Exit(1)
	}
}
