package token_test

import (
	"context"
	"testing"

	"github.com/R055LE/secrets-broker/internal/token"
)

func TestEnvResolver_Success(t *testing.T) {
	t.Setenv("SECRETS_BROKER_TEST_VAR", "s3cr3t-token")
	r := token.NewEnvResolver("SECRETS_BROKER_TEST_VAR")

	tok, err := r.Resolve(context.Background(), "ignored-entry")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.Value() != "s3cr3t-token" {
		t.Fatalf("got %q, want %q", tok.Value(), "s3cr3t-token")
	}
}

func TestEnvResolver_Unset(t *testing.T) {
	r := token.NewEnvResolver("SECRETS_BROKER_TEST_VAR_DEFINITELY_UNSET")
	_, err := r.Resolve(context.Background(), "entry")
	if err == nil {
		t.Fatal("expected an error for an unset env var")
	}
}

func TestEnvResolver_Empty(t *testing.T) {
	t.Setenv("SECRETS_BROKER_TEST_VAR_EMPTY", "")
	r := token.NewEnvResolver("SECRETS_BROKER_TEST_VAR_EMPTY")
	_, err := r.Resolve(context.Background(), "entry")
	if err == nil {
		t.Fatal("expected an error for an empty env var")
	}
}

func TestEnvResolver_IgnoresEntry(t *testing.T) {
	t.Setenv("SECRETS_BROKER_TEST_VAR", "s3cr3t-token")
	r := token.NewEnvResolver("SECRETS_BROKER_TEST_VAR")

	tok1, err := r.Resolve(context.Background(), "entry-one")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tok2, err := r.Resolve(context.Background(), "entry-two")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok1.Value() != tok2.Value() {
		t.Fatalf("expected the same value regardless of entry, got %q and %q", tok1.Value(), tok2.Value())
	}
}
