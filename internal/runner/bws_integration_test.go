//go:build integration

package runner_test

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/R055LE/secrets-broker/internal/execx"
	"github.com/R055LE/secrets-broker/internal/runner"
	"github.com/R055LE/secrets-broker/internal/token"
)

// Real bws, real Secret Service resolution, real Bitwarden Secrets Manager
// project — the actual end-to-end path, not fakes. Requires
// SECRETS_BROKER_TEST_PROJECT_ID / _TOKEN_ENTRY / _SECRET_NAME to point at
// a real project with a machine account and a throwaway test secret;
// SECRETS_BROKER_TEST_SECRET_VALUE is optional, for asserting the exact
// value rather than just "non-empty."
func TestBWSRunner_Integration_RealSecretInjection(t *testing.T) {
	projectID := os.Getenv("SECRETS_BROKER_TEST_PROJECT_ID")
	tokenEntry := os.Getenv("SECRETS_BROKER_TEST_TOKEN_ENTRY")
	secretName := os.Getenv("SECRETS_BROKER_TEST_SECRET_NAME")
	if projectID == "" || tokenEntry == "" || secretName == "" {
		t.Skip("SECRETS_BROKER_TEST_PROJECT_ID / _TOKEN_ENTRY / _SECRET_NAME not set — skipping integration test against real bws")
	}

	resolver := token.NewSecretServiceResolver(execx.OSRunner{})
	tok, err := resolver.Resolve(context.Background(), tokenEntry)
	if err != nil {
		t.Fatalf("resolving token: %v", err)
	}

	r := runner.NewBWSRunner(execx.OSRunner{})
	var stdout bytes.Buffer
	result, err := r.Run(context.Background(), runner.RunSpec{
		ProjectID: projectID,
		Token:     tok,
		Argv:      []string{"printenv", secretName},
		Stdin:     &bytes.Buffer{},
		Stdout:    &stdout,
		Stderr:    &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("got exit code %d, want 0 (stdout: %q)", result.ExitCode, stdout.String())
	}

	got := strings.TrimSpace(stdout.String())
	if got == "" {
		t.Fatal("secret value came back empty")
	}
	if want := os.Getenv("SECRETS_BROKER_TEST_SECRET_VALUE"); want != "" && got != want {
		t.Fatalf("got secret value %q, want %q", got, want)
	}
}

func TestBWSRunner_Integration_BadProjectIDFailsCleanly(t *testing.T) {
	tokenEntry := os.Getenv("SECRETS_BROKER_TEST_TOKEN_ENTRY")
	if tokenEntry == "" {
		t.Skip("SECRETS_BROKER_TEST_TOKEN_ENTRY not set — skipping")
	}

	resolver := token.NewSecretServiceResolver(execx.OSRunner{})
	tok, err := resolver.Resolve(context.Background(), tokenEntry)
	if err != nil {
		t.Fatalf("resolving token: %v", err)
	}

	r := runner.NewBWSRunner(execx.OSRunner{})
	result, err := r.Run(context.Background(), runner.RunSpec{
		ProjectID: "00000000-0000-0000-0000-000000000000",
		Token:     tok,
		Argv:      []string{"echo", "should-not-print"},
		Stdin:     &bytes.Buffer{},
		Stdout:    &bytes.Buffer{},
		Stderr:    &bytes.Buffer{},
	})
	// bws itself starts fine and exits nonzero (404 from the API) — this is
	// a Runner-level "executed with a nonzero exit," not a Go error. See
	// decisions/0004 for why the broker can't distinguish this from the
	// wrapped command's own failure.
	if err != nil {
		t.Fatalf("unexpected Go-level error: %v", err)
	}
	if result.ExitCode == 0 {
		t.Fatal("expected a nonzero exit code for a nonexistent project ID")
	}
}
