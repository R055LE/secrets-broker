// Package token resolves the bootstrap Bitwarden Secrets Manager access
// token from wherever it's stored, and carries it as a value that can't be
// accidentally logged.
package token

import (
	"context"
	"log/slog"
)

// Token wraps a resolved BWS_ACCESS_TOKEN value. String and LogValue are
// deliberately redacted so an accidental fmt.Printf/slog.Info on a Token
// can't leak the value into diagnostics — Value is the one explicit,
// deliberate way to get it out.
type Token struct {
	value string
}

func New(value string) Token { return Token{value: value} }

func (t Token) Value() string { return t.value }

func (t Token) Empty() bool { return t.value == "" }

func (t Token) String() string { return "[REDACTED]" }

func (t Token) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Resolver resolves a bootstrap access token from a backend-specific store.
// entry names the credential within that store (for the Secret Service
// backend, the "entry" attribute value used to look it up; a future
// container-oriented backend might treat entry as an env var name or a
// secret-mount filename). Backends that need shared, non-per-project
// configuration bind it at construction time, not
// through this method.
type Resolver interface {
	Resolve(ctx context.Context, entry string) (Token, error)
}
