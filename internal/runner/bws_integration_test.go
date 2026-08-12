//go:build integration

package runner_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/R055LE/secrets-broker/internal/execx"
	"github.com/R055LE/secrets-broker/internal/runner"
	"github.com/R055LE/secrets-broker/internal/token"
)

// Real bws, real file resolution, the deployed runner sudo hop, and a real
// Bitwarden Secrets Manager project. Run this as the secrets-broker worker
// account after installing deploy/secrets-broker.sudoers. The token file must
// be owned by that account and mode 0600 or tighter.
func TestBWSRunner_Integration_RealSecretInjection(t *testing.T) {
	projectID := os.Getenv("SECRETS_BROKER_TEST_PROJECT_ID")
	tokenPath := os.Getenv("SECRETS_BROKER_TEST_TOKEN_FILE")
	secretName := os.Getenv("SECRETS_BROKER_TEST_SECRET_NAME")
	if projectID == "" || tokenPath == "" || secretName == "" {
		t.Skip("SECRETS_BROKER_TEST_PROJECT_ID / _TOKEN_FILE / _SECRET_NAME not set; skipping integration test against real bws")
	}

	resolver := token.NewFileResolver(tokenPath)
	tok, err := resolver.Resolve(context.Background(), "")
	if err != nil {
		t.Fatalf("resolving token: %v", err)
	}

	bwsBinary, err := exec.LookPath("bws")
	if err != nil {
		t.Fatalf("finding bws: %v", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("resolving home: %v", err)
	}
	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("resolving working directory: %v", err)
	}
	r := runner.NewBWSRunner(execx.OSRunner{}, bwsBinary, os.Getenv("PATH"), home)
	var stdout bytes.Buffer
	result, err := r.Run(context.Background(), runner.RunSpec{
		ProjectID:  projectID,
		Token:      tok,
		WorkingDir: workingDir,
		Argv:       []string{"printenv", secretName},
		Stdin:      &bytes.Buffer{},
		Stdout:     &stdout,
		Stderr:     &bytes.Buffer{},
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
	tokenPath := os.Getenv("SECRETS_BROKER_TEST_TOKEN_FILE")
	if tokenPath == "" {
		t.Skip("SECRETS_BROKER_TEST_TOKEN_FILE not set; skipping")
	}

	resolver := token.NewFileResolver(tokenPath)
	tok, err := resolver.Resolve(context.Background(), "")
	if err != nil {
		t.Fatalf("resolving token: %v", err)
	}

	bwsBinary, err := exec.LookPath("bws")
	if err != nil {
		t.Fatalf("finding bws: %v", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("resolving home: %v", err)
	}
	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("resolving working directory: %v", err)
	}
	r := runner.NewBWSRunner(execx.OSRunner{}, bwsBinary, os.Getenv("PATH"), home)
	result, err := r.Run(context.Background(), runner.RunSpec{
		ProjectID:  "00000000-0000-0000-0000-000000000000",
		Token:      tok,
		WorkingDir: workingDir,
		Argv:       []string{"echo", "should-not-print"},
		Stdin:      &bytes.Buffer{},
		Stdout:     &bytes.Buffer{},
		Stderr:     &bytes.Buffer{},
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
