// Package runner executes an approved command with secrets injected, via
// `bws run`.
package runner

import (
	"context"
	"io"

	"github.com/R055LE/secrets-broker/internal/token"
)

// RunSpec describes one approved command execution.
type RunSpec struct {
	ProjectID  string
	Token      token.Token
	WorkingDir string
	Argv       []string // the wrapped command and its arguments, e.g. ["git", "push"]

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Result is the outcome of a command that was actually executed. It's only
// ever returned for commands the broker decided to run — a broker-side
// denial never reaches a Runner at all.
type Result struct {
	ExitCode int
}

// Runner executes an approved command with the resolved token made
// available to it, without the token ever passing through this process's
// own long-lived environment.
type Runner interface {
	Run(ctx context.Context, spec RunSpec) (Result, error)
}
