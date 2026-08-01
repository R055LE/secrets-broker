package token_test

import (
	"context"
	"strings"
	"testing"

	"github.com/R055LE/secrets-broker/internal/execx"
	"github.com/R055LE/secrets-broker/internal/token"
)

func TestSecretServiceResolver_Success(t *testing.T) {
	fake := &execx.FakeRunner{
		RunResult: execx.Result{ExitCode: 0, Stdout: "s3cr3t-token"},
	}
	r := token.NewSecretServiceResolver(fake)

	tok, err := r.Resolve(context.Background(), "claude-code-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.Value() != "s3cr3t-token" {
		t.Fatalf("got token value %q, want %q", tok.Value(), "s3cr3t-token")
	}

	if len(fake.Calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(fake.Calls))
	}
	call := fake.Calls[0]
	if call.Name != "secret-tool" {
		t.Fatalf("expected secret-tool, got %s", call.Name)
	}
	wantArgs := []string{"lookup", "service", "secrets-broker", "entry", "claude-code-agent"}
	if strings.Join(call.Args, " ") != strings.Join(wantArgs, " ") {
		t.Fatalf("got args %v, want %v", call.Args, wantArgs)
	}
}

func TestSecretServiceResolver_TrimsTrailingNewline(t *testing.T) {
	fake := &execx.FakeRunner{
		RunResult: execx.Result{ExitCode: 0, Stdout: "s3cr3t-token\n"},
	}
	r := token.NewSecretServiceResolver(fake)

	tok, err := r.Resolve(context.Background(), "claude-code-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.Value() != "s3cr3t-token" {
		t.Fatalf("got token value %q, want trailing newline trimmed", tok.Value())
	}
}

func TestSecretServiceResolver_NotFound(t *testing.T) {
	fake := &execx.FakeRunner{
		RunResult: execx.Result{ExitCode: 1, Stdout: "", Stderr: ""},
	}
	r := token.NewSecretServiceResolver(fake)

	_, err := r.Resolve(context.Background(), "claude-code-agent")
	if err == nil {
		t.Fatal("expected an error when the entry isn't found")
	}
}

func TestSecretServiceResolver_EmptyValue(t *testing.T) {
	fake := &execx.FakeRunner{
		RunResult: execx.Result{ExitCode: 0, Stdout: ""},
	}
	r := token.NewSecretServiceResolver(fake)

	_, err := r.Resolve(context.Background(), "claude-code-agent")
	if err == nil {
		t.Fatal("expected an error on empty value")
	}
}

func TestSecretServiceResolver_RunnerError(t *testing.T) {
	fake := &execx.FakeRunner{
		RunErr: context.DeadlineExceeded,
	}
	r := token.NewSecretServiceResolver(fake)

	_, err := r.Resolve(context.Background(), "claude-code-agent")
	if err == nil {
		t.Fatal("expected an error when the runner itself fails")
	}
}
