//go:build !devenclave

// Command devstack runs a local development stack (see devstack.go). It
// exists only in devenclave builds; without the tag it links nothing but
// this message (`make check-tcb`).
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "devstack is a development tool: build or run it with -tags devenclave, e.g.\n"+
		"  go run -tags devenclave github.com/vettid/vettid-vault/cmd/devstack@<commit>")
	os.Exit(2)
}
