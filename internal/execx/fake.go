package execx

import (
	"context"
	"io"
)

// FakeRunner is a scripted Runner for adapter unit tests — no real
// subprocess is ever spawned.
type FakeRunner struct {
	// RunResult/RunErr are returned by Run, regardless of arguments.
	RunResult Result
	RunErr    error

	// PassthroughExitCode/PassthroughErr are returned by RunPassthrough. If
	// PassthroughStdout/PassthroughStderr are set, they're written to the
	// caller's stdout/stderr writers to simulate wrapped-command output.
	PassthroughExitCode int
	PassthroughErr      error
	PassthroughStdout   string
	PassthroughStderr   string

	// Calls records every invocation for assertions.
	Calls []Call
}

// Call records a single invocation of the fake, for test assertions.
type Call struct {
	Method string // "Run" or "RunPassthrough"
	Name   string
	Args   []string
	Env    []string
	Dir    string
}

func (f *FakeRunner) Run(ctx context.Context, name string, args []string, env []string) (Result, error) {
	f.Calls = append(f.Calls, Call{Method: "Run", Name: name, Args: args, Env: env})
	return f.RunResult, f.RunErr
}

func (f *FakeRunner) RunPassthrough(ctx context.Context, name string, args []string, env []string, dir string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	f.Calls = append(f.Calls, Call{Method: "RunPassthrough", Name: name, Args: args, Env: env, Dir: dir})
	if f.PassthroughStdout != "" {
		_, _ = io.WriteString(stdout, f.PassthroughStdout)
	}
	if f.PassthroughStderr != "" {
		_, _ = io.WriteString(stderr, f.PassthroughStderr)
	}
	return f.PassthroughExitCode, f.PassthroughErr
}
