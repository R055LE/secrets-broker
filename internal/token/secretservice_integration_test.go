//go:build integration

package token_test

import (
	"context"
	"os"
	"testing"

	"github.com/R055LE/secrets-broker/internal/execx"
	"github.com/R055LE/secrets-broker/internal/token"
)

// Real secret-tool, real Secret Service keyring, no fakes. Skips cleanly
// when the environment isn't configured, so `go test ./...` (CI's default,
// no -tags=integration) never even compiles this file, and a contributor
// without a live Bitwarden setup gets a skip, not a failure.
func TestSecretServiceResolver_Integration_RealEntry(t *testing.T) {
	entry := os.Getenv("SECRETS_BROKER_TEST_TOKEN_ENTRY")
	if entry == "" {
		t.Skip("SECRETS_BROKER_TEST_TOKEN_ENTRY not set — skipping integration test against a real Secret Service entry")
	}

	r := token.NewSecretServiceResolver(execx.OSRunner{})
	tok, err := r.Resolve(context.Background(), entry)
	if err != nil {
		t.Fatalf("failed to resolve real entry %q: %v", entry, err)
	}
	if tok.Empty() {
		t.Fatal("resolved token is empty")
	}
}

func TestSecretServiceResolver_Integration_UnknownEntryFails(t *testing.T) {
	if os.Getenv("SECRETS_BROKER_TEST_TOKEN_ENTRY") == "" {
		t.Skip("SECRETS_BROKER_TEST_TOKEN_ENTRY not set — skipping (only run when Secret Service is confirmed reachable)")
	}

	r := token.NewSecretServiceResolver(execx.OSRunner{})
	_, err := r.Resolve(context.Background(), "secrets-broker-integration-test-entry-that-should-not-exist")
	if err == nil {
		t.Fatal("expected an error resolving a deliberately nonexistent entry")
	}
}
