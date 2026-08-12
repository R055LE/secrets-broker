// Package execx is the single seam between the broker's adapter packages and
// os/exec. Adapters (token/secretservice.go, approval/kdialog.go, runner/bws.go)
// depend on the Runner interface here, not on os/exec directly, so their
// tests can inject a fake instead of shelling out to real binaries.
package execx

import (
	"bytes"
	"context"
	"io"
	"os/exec"
)

// Result is the outcome of running a command to completion.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Runner runs commands on behalf of adapter packages.
type Runner interface {
	// Run captures output for adapters that need to inspect a small result
	// (a Secret Service read, a kdialog decision).
	Run(ctx context.Context, name string, args []string, env []string) (Result, error)

	// RunPassthrough connects stdin/stdout/stderr directly to the given
	// streams instead of buffering — used by runner/bws.go so the wrapped
	// command behaves like it was invoked directly, and so the broker never
	// holds the wrapped command's output (which may itself be sensitive) in
	// its own memory.
	RunPassthrough(ctx context.Context, name string, args []string, env []string, dir string, stdin io.Reader, stdout, stderr io.Writer) (exitCode int, err error)
}

// OSRunner is the real Runner, backed by os/exec.
type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, name string, args []string, env []string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if env != nil {
		cmd.Env = env
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := Result{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}
	if err != nil {
		return result, err
	}

	return result, nil
}

func (OSRunner) RunPassthrough(ctx context.Context, name string, args []string, env []string, dir string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()

	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}

	return 0, nil
}
