package cli

import (
	"testing"

	"github.com/R055LE/secrets-broker/internal/config"
	"github.com/R055LE/secrets-broker/internal/execx"
	"github.com/R055LE/secrets-broker/internal/token"
)

func TestNewResolver_SecretService(t *testing.T) {
	r, err := newResolver(config.TokenSource{Backend: config.BackendSecretService}, execx.OSRunner{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := r.(*token.SecretServiceResolver); !ok {
		t.Fatalf("got %T, want *token.SecretServiceResolver", r)
	}
}

func TestNewResolver_Env(t *testing.T) {
	r, err := newResolver(config.TokenSource{
		Backend: config.BackendEnv,
		Env:     config.EnvSource{Var: "SOME_VAR"},
	}, execx.OSRunner{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := r.(*token.EnvResolver); !ok {
		t.Fatalf("got %T, want *token.EnvResolver", r)
	}
}

func TestNewResolver_File(t *testing.T) {
	r, err := newResolver(config.TokenSource{
		Backend: config.BackendFile,
		File:    config.FileSource{Path: "/some/path"},
	}, execx.OSRunner{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := r.(*token.FileResolver); !ok {
		t.Fatalf("got %T, want *token.FileResolver", r)
	}
}

func TestNewResolver_UnknownBackend(t *testing.T) {
	_, err := newResolver(config.TokenSource{Backend: "carrier-pigeon"}, execx.OSRunner{})
	if err == nil {
		t.Fatal("expected an error for an unsupported backend")
	}
}
