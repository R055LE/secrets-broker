// Package cli is unprivileged cobra plumbing. It only constructs a bounded
// request for the fixed isolated worker; no policy or adapter selection lives
// in the caller's process.
package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is set via -ldflags at build time (see Taskfile.yml).
var Version = "dev"

// Execute runs the CLI and returns the process exit code. It never calls
// os.Exit itself, so main.go stays a one-line composition root.
func Execute() int {
	exitCode := 0

	root := &cobra.Command{
		Use:           "secrets-broker",
		Short:         "A custody broker between AI coding agents and Bitwarden Secrets Manager",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newRunCmd(&exitCode))
	root.AddCommand(newVersionCmd())

	if err := root.ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "secrets-broker:", err)
		return 2 // usage/parsing error — distinct from the broker's own 125/126
	}
	return exitCode
}
