package cli

import (
	"testing"

	"github.com/R055LE/secrets-broker/internal/approval"
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

func TestNewApprover_KDialog(t *testing.T) {
	a, err := newApprover(config.ApprovalSource{Backend: config.ApprovalBackendKDialog}, execx.OSRunner{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := a.(*approval.KDialogApprover); !ok {
		t.Fatalf("got %T, want *approval.KDialogApprover", a)
	}
}

func TestNewApprover_TailscaleRelay(t *testing.T) {
	a, err := newApprover(config.ApprovalSource{
		Backend: config.ApprovalBackendTailscaleRelay,
		TailscaleRelay: config.TailscaleRelaySource{
			ControlURL:          "http://100.64.0.1:7620",
			PollIntervalSeconds: 2,
			TimeoutSeconds:      300,
		},
	}, execx.OSRunner{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := a.(*approval.TailscaleApprover); !ok {
		t.Fatalf("got %T, want *approval.TailscaleApprover", a)
	}
}

func TestNewApprover_UnknownBackend(t *testing.T) {
	_, err := newApprover(config.ApprovalSource{Backend: "carrier-pigeon"}, execx.OSRunner{})
	if err == nil {
		t.Fatal("expected an error for an unsupported backend")
	}
}
