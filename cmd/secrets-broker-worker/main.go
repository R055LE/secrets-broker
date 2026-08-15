// Command secrets-broker-worker is the fixed, credential-bearing half of the
// broker. Its no-argument protocol is intended to be invoked only through the
// installed sudoers rule as the dedicated secrets-broker user. The check
// command is reserved for deployment administration.
package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/R055LE/secrets-broker/internal/worker"
)

func main() {
	os.Exit(run(os.Args[1:], worker.NewServer(), os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, server *worker.Server, in io.Reader, out, errOut io.Writer) int {
	switch len(args) {
	case 0:
		if err := server.Serve(context.Background(), in, out); err != nil {
			return 1
		}
		return 0
	case 1:
		if args[0] == "check" {
			result, err := server.Check()
			if err != nil {
				_, _ = fmt.Fprintf(errOut, "secrets-broker-worker: check failed: %v\n", err)
				return 1
			}
			if _, err := fmt.Fprintf(out, "Worker semantic check passed: %d project(s), token metadata valid (%d bytes).\n", result.Projects, result.TokenBytes); err != nil {
				return 1
			}
			return 0
		}
	}
	_, _ = fmt.Fprintln(errOut, "usage: secrets-broker-worker [check]")
	return 2
}
