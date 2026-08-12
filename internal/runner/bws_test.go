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

func TestBuildEnv_UsesTrustedRuntimeValuesAndToken(t *testing.T) {
	env := buildEnv("my-token", "/usr/bin:/bin", "/var/lib/secrets-broker")

	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "SOME_UNRELATED_SECRET") {
		t.Fatalf("buildEnv leaked an unrelated env var: %v", env)
	}
	if !strings.Contains(joined, "BWS_ACCESS_TOKEN=my-token") {
		t.Fatalf("buildEnv missing token: %v", env)
	}
	if !strings.Contains(joined, "PATH=/usr/bin:/bin") || !strings.Contains(joined, "HOME=/var/lib/secrets-broker") {
		t.Fatalf("buildEnv missing expected passthrough vars: %v", env)
	}
}

func TestBWSRunner_Run_PassesQuotedArgvAndScopedEnv(t *testing.T) {
	fake := &execx.FakeRunner{PassthroughExitCode: 0}
	r := NewBWSRunner(fake, "/usr/local/bin/bws", "/usr/bin:/bin", "/var/lib/secrets-broker")

	spec := RunSpec{
		ProjectID:  "proj-1",
		Token:      token.New("s3cr3t"),
		WorkingDir: "/tmp",
		Argv:       []string{"git", "commit", "-m", "fix: something"},
		Stdin:      &bytes.Buffer{},
		Stdout:     &bytes.Buffer{},
		Stderr:     &bytes.Buffer{},
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
	if call.Name != "/usr/local/bin/bws" {
		t.Fatalf("expected fixed bws binary, got %s", call.Name)
	}
	if call.Dir != "/tmp" {
		t.Fatalf("got working directory %q, want /tmp", call.Dir)
	}

	wantArgs := []string{
		"run", "--project-id", "proj-1", "--no-inherit-env", "--",
		"'/usr/bin/sudo'", "'-n'", "'-H'", "'-u'", "'secrets-broker-runner'", "'--'",
		"'git'", "'commit'", "'-m'", "'fix: something'",
	}
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
	r := NewBWSRunner(fake, "/usr/local/bin/bws", "/usr/bin:/bin", "/var/lib/secrets-broker")

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
	r := NewBWSRunner(fake, "/usr/local/bin/bws", "/usr/bin:/bin", "/var/lib/secrets-broker")

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
	r := NewBWSRunner(fake, "/usr/local/bin/bws", "/usr/bin:/bin", "/var/lib/secrets-broker")

	result, err := r.Run(context.Background(), RunSpec{
		ProjectID:  "proj-1",
		Token:      token.New("t"),
		WorkingDir: "/tmp",
		Argv:       []string{"false"},
	})
	if err != nil {
		t.Fatalf("a nonzero wrapped-command exit is not a Runner error: %v", err)
	}
	if result.ExitCode != 7 {
		t.Fatalf("got exit code %d, want 7", result.ExitCode)
	}
}
