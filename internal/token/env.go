package token

import (
	"context"
	"fmt"
	"os"
)

// EnvResolver resolves the bootstrap token from a single configured
// environment variable — for headless deployments (systemd unit,
// container) where the token is injected at process start rather than
// pulled from a desktop keyring.
//
// It ignores entry: a deployment using this backend is assumed
// single-tenant — one broker process, one token, matching how a container
// or systemd unit typically receives exactly one secret. A deployment
// needing more than one resolvable credential at runtime should use the
// Secret Service backend, or FileResolver per-project if that's ever built.
type EnvResolver struct {
	varName string
}

func NewEnvResolver(varName string) *EnvResolver {
	return &EnvResolver{varName: varName}
}

func (r *EnvResolver) Resolve(ctx context.Context, entry string) (Token, error) {
	value, ok := os.LookupEnv(r.varName)
	if !ok {
		return Token{}, fmt.Errorf("environment variable %q is not set", r.varName)
	}
	if value == "" {
		return Token{}, fmt.Errorf("environment variable %q is empty", r.varName)
	}
	return New(value), nil
}
