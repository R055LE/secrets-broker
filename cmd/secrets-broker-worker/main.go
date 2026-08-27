// Command secrets-broker-worker is the fixed, credential-bearing half of the
// broker. Its no-argument protocol is intended to be invoked only through the
// installed sudoers rule as the dedicated secrets-broker user. The check and
// access-check commands are reserved for deployment administration.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/R055LE/secrets-broker/internal/accessdiag"
	"github.com/R055LE/secrets-broker/internal/worker"
)

func main() {
	os.Exit(run(os.Args[1:], worker.NewServer(), os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, server *worker.Server, in io.Reader, out, errOut io.Writer) int {
	if len(args) >= 1 && len(args) <= 2 && args[0] == "access-check" {
		alias := ""
		if len(args) == 2 {
			alias = args[1]
		}
		result, err := server.CheckAccess(context.Background(), alias)
		if err != nil {
			_, _ = fmt.Fprintln(errOut, "secrets-broker-worker: access check failed")
			return 2
		}
		if err := json.NewEncoder(out).Encode(result); err != nil {
			_, _ = fmt.Fprintln(errOut, "secrets-broker-worker: access check output failed")
			return 2
		}
		if result.Outcome != accessdiag.OutcomeAllAccessible {
			return 1
		}
		return 0
	}

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
	_, _ = fmt.Fprintln(errOut, "usage: secrets-broker-worker [check | access-check [ALIAS]]")
	return 2
}
