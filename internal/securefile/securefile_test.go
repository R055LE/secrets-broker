package securefile

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writeFixture(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("setting fixture permissions: %v", err)
	}
}

func TestReadValidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	writeFixture(t, path, "secret", 0o600)

	data, err := Read(path, 64, 0o077, false)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(data) != "secret" {
		t.Fatalf("got %q", data)
	}
}

func TestReadRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid")
	writeFixture(t, valid, "secret", 0o600)
	symlink := filepath.Join(dir, "symlink")
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatalf("creating symlink: %v", err)
	}
	tooOpen := filepath.Join(dir, "too-open")
	writeFixture(t, tooOpen, "secret", 0o640)
	oversized := filepath.Join(dir, "oversized")
	writeFixture(t, oversized, "too long", 0o600)

	tests := []struct {
		name     string
		path     string
		maxBytes int64
	}{
		{name: "symlink", path: symlink, maxBytes: 64},
		{name: "permissions", path: tooOpen, maxBytes: 64},
		{name: "oversized", path: oversized, maxBytes: 3},
		{name: "directory", path: dir, maxBytes: 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Read(tt.path, tt.maxBytes, 0o077, false); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestReadRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("creating FIFO: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := Read(path, 64, 0o077, false)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("got error %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read blocked while validating a FIFO")
	}
}

func TestValidatePrivateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	writeFixture(t, path, "secret", 0o600)

	size, err := ValidatePrivateFile(path, 64)
	if err != nil {
		t.Fatalf("ValidatePrivateFile: %v", err)
	}
	if size != 6 {
		t.Fatalf("got size %d", size)
	}
	if _, err := ValidatePrivateFile(path, 3); err == nil {
		t.Fatal("expected oversized file to be rejected")
	}
	symlink := filepath.Join(dir, "symlink")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatalf("creating symlink: %v", err)
	}
	if _, err := ValidatePrivateFile(symlink, 64); err == nil {
		t.Fatal("expected symlink to be rejected")
	}
}

func TestOpenAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := OpenAppend(path, 0o600)
	if err != nil {
		t.Fatalf("OpenAppend: %v", err)
	}
	if _, err := f.WriteString("one\n"); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	f, err = OpenAppend(path, 0o600)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	if _, err := f.WriteString("two\n"); err != nil {
		t.Fatalf("appending: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading result: %v", err)
	}
	if string(data) != "one\ntwo\n" {
		t.Fatalf("got %q", data)
	}
}

func TestDirectoryValidators(t *testing.T) {
	dir := t.TempDir()
	privateDir := filepath.Join(dir, "private")
	trustedDir := filepath.Join(dir, "trusted")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatalf("creating private directory: %v", err)
	}
	if err := os.Mkdir(trustedDir, 0o755); err != nil {
		t.Fatalf("creating trusted directory: %v", err)
	}
	if err := ValidatePrivateDir(privateDir); err != nil {
		t.Fatalf("ValidatePrivateDir: %v", err)
	}
	if err := ValidateTrustedDir(trustedDir); err != nil {
		t.Fatalf("ValidateTrustedDir: %v", err)
	}
	if err := os.Chmod(privateDir, 0o750); err != nil {
		t.Fatalf("opening private directory permissions: %v", err)
	}
	if err := ValidatePrivateDir(privateDir); err == nil {
		t.Fatal("expected private directory permissions to be rejected")
	}
	if err := os.Chmod(trustedDir, 0o775); err != nil {
		t.Fatalf("opening trusted directory permissions: %v", err)
	}
	if err := ValidateTrustedDir(trustedDir); err == nil {
		t.Fatal("expected writable trusted directory to be rejected")
	}
	file := filepath.Join(dir, "file")
	writeFixture(t, file, "file", 0o600)
	if err := ValidatePrivateDir(file); err == nil {
		t.Fatal("expected file to be rejected as private directory")
	}
	if err := ValidateTrustedDir(file); err == nil {
		t.Fatal("expected file to be rejected as trusted directory")
	}
}

func TestValidateExecutable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "command")
	writeFixture(t, path, "binary", 0o700)
	if err := ValidateExecutable(path); err != nil {
		t.Fatalf("ValidateExecutable: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("removing executable bit: %v", err)
	}
	if err := ValidateExecutable(path); err == nil {
		t.Fatal("expected non-executable file to be rejected")
	}
	if err := os.Chmod(path, 0o722); err != nil {
		t.Fatalf("opening executable permissions: %v", err)
	}
	if err := ValidateExecutable(path); err == nil {
		t.Fatal("expected writable executable to be rejected")
	}
	symlink := filepath.Join(dir, "symlink")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatalf("creating symlink: %v", err)
	}
	if err := ValidateExecutable(symlink); err == nil {
		t.Fatal("expected executable symlink to be rejected")
	}
}

func TestValidateOwnerRejectsUnexpectedOwner(t *testing.T) {
	uid := uint32(os.Geteuid()) + 1
	if uid == 0 {
		uid = 1
	}
	info := fileInfo{stat: &syscall.Stat_t{Uid: uid}}
	if err := validateOwner("fixture", info, false); err == nil {
		t.Fatal("expected unexpected owner to be rejected")
	}
}

type fileInfo struct {
	stat *syscall.Stat_t
}

func (fileInfo) Name() string       { return "fixture" }
func (fileInfo) Size() int64        { return 0 }
func (fileInfo) Mode() os.FileMode  { return 0o600 }
func (fileInfo) ModTime() time.Time { return time.Time{} }
func (fileInfo) IsDir() bool        { return false }
func (i fileInfo) Sys() any         { return i.stat }
