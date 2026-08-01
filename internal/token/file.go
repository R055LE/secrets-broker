package token

import (
	"context"
	"fmt"
	"os"
	"strings"
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
	info, err := os.Stat(r.path)
	if err != nil {
		return Token{}, fmt.Errorf("stating token file %q: %w", r.path, err)
	}

	// Refuse a file readable/writable by group or other — a common, cheap
	// -to-catch misconfiguration. Secret Service has a daemon mediating
	// access; a plain file has only filesystem permissions, so this
	// backend has to enforce that itself rather than trust the caller got
	// it right.
	if info.Mode().Perm()&0o077 != 0 {
		return Token{}, fmt.Errorf("token file %q permissions are too open (%v) — must not be readable or writable by group or other", r.path, info.Mode().Perm())
	}

	data, err := os.ReadFile(r.path)
	if err != nil {
		return Token{}, fmt.Errorf("reading token file %q: %w", r.path, err)
	}

	value := strings.TrimRight(string(data), "\n")
	if value == "" {
		return Token{}, fmt.Errorf("token file %q is empty", r.path)
	}

	return New(value), nil
}
