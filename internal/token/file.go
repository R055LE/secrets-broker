package token

import (
	"context"
	"fmt"
	"strings"

	"github.com/R055LE/secrets-broker/internal/securefile"
)

// FileResolver resolves the bootstrap token from a single configured file
// path — the Docker-secrets/Kubernetes-Secret-volume convention, usually
// tmpfs-backed so the value isn't actually persisted to disk. Like
// EnvResolver, it ignores entry (single-tenant assumption — see env.go).
type FileResolver struct {
	path string
}

func NewFileResolver(path string) *FileResolver {
	return &FileResolver{path: path}
}

func (r *FileResolver) Resolve(ctx context.Context, entry string) (Token, error) {
	data, err := securefile.Read(r.path, 64<<10, 0o077, false)
	if err != nil {
		return Token{}, fmt.Errorf("reading token file %q: %w", r.path, err)
	}

	value := strings.TrimRight(string(data), "\n")
	if value == "" {
		return Token{}, fmt.Errorf("token file %q is empty", r.path)
	}

	return New(value), nil
}
