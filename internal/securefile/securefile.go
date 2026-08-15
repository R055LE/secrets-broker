// Package securefile opens security-sensitive files without following
// symlinks and validates the opened file descriptor before use.
package securefile

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

func Read(path string, maxBytes int64, forbiddenPerms os.FileMode, allowRootOwner bool) ([]byte, error) {
	f, err := open(path, syscall.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if err := validate(f, forbiddenPerms, allowRootOwner); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%q exceeds %d bytes", path, maxBytes)
	}
	return data, nil
}

// ValidatePrivateFile checks a sensitive file's metadata without reading its
// contents. The file must be a regular file owned by the current user with no
// group or other permissions.
func ValidatePrivateFile(path string, maxBytes int64) (int64, error) {
	f, err := open(path, syscall.O_RDONLY, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	if err := validate(f, 0o077, false); err != nil {
		return 0, err
	}
	info, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("stating %q: %w", path, err)
	}
	if info.Size() > maxBytes {
		return 0, fmt.Errorf("%q exceeds %d bytes", path, maxBytes)
	}
	return info.Size(), nil
}

func OpenAppend(path string, perm os.FileMode) (*os.File, error) {
	f, err := open(path, syscall.O_APPEND|syscall.O_CREAT|syscall.O_WRONLY, perm)
	if err != nil {
		return nil, err
	}
	if err := validate(f, 0o077, false); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func ValidatePrivateDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stating directory %q: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("directory %q permissions are too open (%v)", path, info.Mode().Perm())
	}
	return validateOwner(path, info, false)
}

func ValidateTrustedDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stating directory %q: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("directory %q is writable by group or other (%v)", path, info.Mode().Perm())
	}
	return validateOwner(path, info, true)
}

func ValidateExecutable(path string) error {
	f, err := open(path, syscall.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := validate(f, 0o022, true); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stating %q: %w", path, err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%q is not executable", path)
	}
	return nil
}

func open(path string, flags int, perm os.FileMode) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, uint32(perm.Perm()))
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", path, err)
	}
	return os.NewFile(uintptr(fd), path), nil
}

func validate(f *os.File, forbiddenPerms os.FileMode, allowRootOwner bool) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stating %q: %w", f.Name(), err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", f.Name())
	}
	if info.Mode().Perm()&forbiddenPerms != 0 {
		return fmt.Errorf("%q permissions are too open (%v)", f.Name(), info.Mode().Perm())
	}
	return validateOwner(f.Name(), info, allowRootOwner)
}

func validateOwner(path string, info os.FileInfo, allowRoot bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("determining owner of %q", path)
	}
	uid := uint32(os.Geteuid())
	if stat.Uid == uid || (allowRoot && stat.Uid == 0) {
		return nil
	}
	return fmt.Errorf("%q must be owned by uid %d%s, got %d", path, uid, rootSuffix(allowRoot), stat.Uid)
}

func rootSuffix(allowRoot bool) string {
	if allowRoot {
		return " or root"
	}
	return ""
}
