package token_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/R055LE/secrets-broker/internal/token"
)

func writeTestFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("writing test file: %v", err)
	}
	return path
}

func TestFileResolver_Success(t *testing.T) {
	path := writeTestFile(t, "s3cr3t-token\n", 0o600)

	r := token.NewFileResolver(path)
	tok, err := r.Resolve(context.Background(), "ignored-entry")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.Value() != "s3cr3t-token" {
		t.Fatalf("got %q, want trailing newline trimmed to %q", tok.Value(), "s3cr3t-token")
	}
}

func TestFileResolver_MissingFile(t *testing.T) {
	r := token.NewFileResolver("/nonexistent/path/to/token")
	_, err := r.Resolve(context.Background(), "entry")
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestFileResolver_EmptyFile(t *testing.T) {
	path := writeTestFile(t, "", 0o600)

	r := token.NewFileResolver(path)
	_, err := r.Resolve(context.Background(), "entry")
	if err == nil {
		t.Fatal("expected an error for an empty file")
	}
}

func TestFileResolver_RejectsGroupReadablePermissions(t *testing.T) {
	path := writeTestFile(t, "s3cr3t-token", 0o640)

	r := token.NewFileResolver(path)
	_, err := r.Resolve(context.Background(), "entry")
	if err == nil {
		t.Fatal("expected an error for a group-readable token file")
	}
}

func TestFileResolver_RejectsWorldReadablePermissions(t *testing.T) {
	path := writeTestFile(t, "s3cr3t-token", 0o644)

	r := token.NewFileResolver(path)
	_, err := r.Resolve(context.Background(), "entry")
	if err == nil {
		t.Fatal("expected an error for a world-readable token file")
	}
}

func TestFileResolver_IgnoresEntry(t *testing.T) {
	path := writeTestFile(t, "s3cr3t-token", 0o600)

	r := token.NewFileResolver(path)
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
