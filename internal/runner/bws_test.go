package runner

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/R055LE/secrets-broker/internal/execx"
	"github.com/R055LE/secrets-broker/internal/token"
)

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"push":           "'push'",
		"fix: something": "'fix: something'",
		"":               "''",
		"it's":           `'it'\''s'`,
		"$(rm -rf /)":    "'$(rm -rf /)'",
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildEnv_OnlyPassthroughVarsAndToken(t *testing.T) {
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("HOME", "/home/test")
	t.Setenv("LANG", "en_US.UTF-8")
	t.Setenv("SOME_UNRELATED_SECRET", "should-not-appear")

	env := buildEnv("my-token")

	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "SOME_UNRELATED_SECRET") {
		t.Fatalf("buildEnv leaked an unrelated env var: %v", env)
	}
	if !strings.Contains(joined, "BWS_ACCESS_TOKEN=my-token") {
		t.Fatalf("buildEnv missing token: %v", env)
	}
	if !strings.Contains(joined, "PATH=/usr/bin") || !strings.Contains(joined, "HOME=/home/test") {
		t.Fatalf("buildEnv missing expected passthrough vars: %v", env)
	}
}

func TestBWSRunner_Run_PassesQuotedArgvAndScopedEnv(t *testing.T) {
	fake := &execx.FakeRunner{PassthroughExitCode: 0}
	r := NewBWSRunner(fake)

	spec := RunSpec{
		ProjectID: "proj-1",
		Token:     token.New("s3cr3t"),
		Argv:      []string{"git", "commit", "-m", "fix: something"},
		Stdin:     &bytes.Buffer{},
		Stdout:    &bytes.Buffer{},
		Stderr:    &bytes.Buffer{},
	}

	result, err := r.Run(context.Background(), spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("got exit code %d, want 0", result.ExitCode)
	}

	if len(fake.Calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(fake.Calls))
	}
	call := fake.Calls[0]
	if call.Method != "RunPassthrough" {
		t.Fatalf("expected RunPassthrough, got %s", call.Method)
	}
	if call.Name != "bws" {
		t.Fatalf("expected bws binary, got %s", call.Name)
	}

	wantArgs := []string{"run", "--project-id", "proj-1", "--", "'git'", "'commit'", "'-m'", "'fix: something'"}
	if strings.Join(call.Args, "|") != strings.Join(wantArgs, "|") {
		t.Fatalf("got args %v, want %v", call.Args, wantArgs)
	}

	found := false
	for _, e := range call.Env {
		if e == "BWS_ACCESS_TOKEN=s3cr3t" {
			found = true
		}
	}
	if !found {
		t.Fatalf("token not present in env passed to bws: %v", call.Env)
	}
}

func TestBWSRunner_Run_RejectsEmptyArgv(t *testing.T) {
	fake := &execx.FakeRunner{}
	r := NewBWSRunner(fake)

	_, err := r.Run(context.Background(), RunSpec{ProjectID: "proj-1", Token: token.New("t")})
	if err == nil {
		t.Fatal("expected an error for empty argv")
	}
	if len(fake.Calls) != 0 {
		t.Fatal("bws must never be invoked for an empty command")
	}
}

func TestBWSRunner_Run_RejectsEmptyToken(t *testing.T) {
	fake := &execx.FakeRunner{}
	r := NewBWSRunner(fake)

	_, err := r.Run(context.Background(), RunSpec{ProjectID: "proj-1", Argv: []string{"echo"}})
	if err == nil {
		t.Fatal("expected an error for an empty token")
	}
	if len(fake.Calls) != 0 {
		t.Fatal("bws must never be invoked without a resolved token")
	}
}

func TestBWSRunner_Run_PropagatesNonZeroExit(t *testing.T) {
	fake := &execx.FakeRunner{PassthroughExitCode: 7}
	r := NewBWSRunner(fake)

	result, err := r.Run(context.Background(), RunSpec{
		ProjectID: "proj-1",
		Token:     token.New("t"),
		Argv:      []string{"false"},
	})
	if err != nil {
		t.Fatalf("a nonzero wrapped-command exit is not a Runner error: %v", err)
	}
	if result.ExitCode != 7 {
		t.Fatalf("got exit code %d, want 7", result.ExitCode)
	}
}
