package admin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"syscall"
	"time"

	"github.com/R055LE/secrets-broker/internal/securefile"
)

const (
	recoveryArtifactVersion  = 1
	maxRecoveryArtifactBytes = 2 << 20
)

var recoveryIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type RecoveryResult struct {
	Changed    bool
	RecoveryID string
}

type RecoverySummary struct {
	RecoveryID string
	Project    string
	CreatedAt  time.Time
}

type RecoveryArtifactInput struct {
	RecoveryID string
	Project    string
	Before     []byte
	After      []byte
}

type RecoveryArtifact struct {
	Version      int       `json:"version"`
	RecoveryID   string    `json:"recovery_id"`
	CreatedAt    time.Time `json:"created_at"`
	Project      string    `json:"project"`
	BeforeSHA256 string    `json:"before_sha256"`
	AfterSHA256  string    `json:"after_sha256"`
	Policy       []byte    `json:"policy"`
}

type RecoveryArtifacts interface {
	Publish(input RecoveryArtifactInput) error
	List() ([]RecoverySummary, error)
	Read(recoveryID string) (RecoveryArtifact, error)
}

type RecoveryStore struct {
	dir           string
	expectedOwner uint32
	expectedGroup uint32
	now           func() time.Time
	writeFile     func(*os.File, []byte) error
	syncFile      func(*os.File) error
	linkFile      func(string, string) error
	syncDir       func(string) error
}

func NewRecoveryStore(dir string, expectedOwner, expectedGroup uint32) *RecoveryStore {
	return &RecoveryStore{
		dir:           dir,
		expectedOwner: expectedOwner,
		expectedGroup: expectedGroup,
		now:           time.Now,
		writeFile:     writeAll,
		syncFile:      func(f *os.File) error { return f.Sync() },
		linkFile:      os.Link,
		syncDir:       syncDirectory,
	}
}

func (s *RecoveryStore) Publish(input RecoveryArtifactInput) error {
	if err := validateRecoveryID(input.RecoveryID); err != nil {
		return err
	}
	if input.Project == "" {
		return errors.New("recovery project alias is required")
	}
	if err := validateRecoveryDir(s.dir, s.expectedOwner, s.expectedGroup); err != nil {
		return err
	}

	artifact := RecoveryArtifact{
		Version:      recoveryArtifactVersion,
		RecoveryID:   input.RecoveryID,
		CreatedAt:    s.now().UTC(),
		Project:      input.Project,
		BeforeSHA256: digestBytes(input.Before),
		AfterSHA256:  digestBytes(input.After),
		Policy:       append([]byte(nil), input.Before...),
	}
	encoded, err := json.Marshal(artifact)
	if err != nil {
		return fmt.Errorf("encoding recovery artifact: %w", err)
	}
	if len(encoded) > maxRecoveryArtifactBytes {
		return fmt.Errorf("recovery artifact exceeds maximum size of %d bytes", maxRecoveryArtifactBytes)
	}

	temp, err := os.CreateTemp(s.dir, ".recovery.tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary recovery artifact: %w", err)
	}
	tempName := temp.Name()
	keepTemp := true
	defer func() {
		_ = temp.Close()
		if keepTemp {
			_ = os.Remove(tempName)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("setting recovery artifact permissions: %w", err)
	}
	if err := validateRecoveryFile(tempName, s.expectedOwner, s.expectedGroup); err != nil {
		return fmt.Errorf("validating temporary recovery artifact: %w", err)
	}
	if err := s.writeFile(temp, encoded); err != nil {
		return fmt.Errorf("writing recovery artifact: %w", err)
	}
	if err := s.syncFile(temp); err != nil {
		return fmt.Errorf("syncing recovery artifact: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("closing recovery artifact: %w", err)
	}

	finalPath := filepath.Join(s.dir, input.RecoveryID)
	if err := s.linkFile(tempName, finalPath); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("recovery artifact %q already exists", input.RecoveryID)
		}
		return fmt.Errorf("publishing recovery artifact: %w", err)
	}
	rollbackFinal := true
	defer func() {
		if rollbackFinal {
			_ = os.Remove(finalPath)
		}
	}()
	if err := os.Remove(tempName); err != nil {
		return fmt.Errorf("removing temporary recovery artifact: %w", err)
	}
	keepTemp = false
	if err := s.syncDir(s.dir); err != nil {
		_ = os.Remove(finalPath)
		_ = s.syncDir(s.dir)
		return fmt.Errorf("syncing recovery directory: %w", err)
	}
	rollbackFinal = false
	return nil
}

func (s *RecoveryStore) List() ([]RecoverySummary, error) {
	if err := validateRecoveryDir(s.dir, s.expectedOwner, s.expectedGroup); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("reading recovery directory: %w", err)
	}
	summaries := make([]RecoverySummary, 0, len(entries))
	for _, entry := range entries {
		if err := validateRecoveryID(entry.Name()); err != nil {
			return nil, fmt.Errorf("unsafe recovery artifact %q: %w", entry.Name(), err)
		}
		artifact, err := s.Read(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("reading recovery artifact %q: %w", entry.Name(), err)
		}
		summaries = append(summaries, RecoverySummary{
			RecoveryID: artifact.RecoveryID,
			Project:    artifact.Project,
			CreatedAt:  artifact.CreatedAt,
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].CreatedAt.Equal(summaries[j].CreatedAt) {
			return summaries[i].RecoveryID < summaries[j].RecoveryID
		}
		return summaries[i].CreatedAt.Before(summaries[j].CreatedAt)
	})
	return summaries, nil
}

func (s *RecoveryStore) Read(recoveryID string) (RecoveryArtifact, error) {
	if err := validateRecoveryID(recoveryID); err != nil {
		return RecoveryArtifact{}, err
	}
	if err := validateRecoveryDir(s.dir, s.expectedOwner, s.expectedGroup); err != nil {
		return RecoveryArtifact{}, err
	}
	path := filepath.Join(s.dir, recoveryID)
	if err := validateRecoveryFile(path, s.expectedOwner, s.expectedGroup); err != nil {
		return RecoveryArtifact{}, err
	}
	data, err := securefile.Read(path, maxRecoveryArtifactBytes, 0o077, false)
	if err != nil {
		return RecoveryArtifact{}, fmt.Errorf("reading recovery artifact: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var artifact RecoveryArtifact
	if err := decoder.Decode(&artifact); err != nil {
		return RecoveryArtifact{}, fmt.Errorf("decoding recovery artifact: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return RecoveryArtifact{}, err
	}
	if err := validateRecoveryArtifact(artifact, recoveryID); err != nil {
		return RecoveryArtifact{}, err
	}
	return artifact, nil
}

func validateRecoveryArtifact(artifact RecoveryArtifact, recoveryID string) error {
	if artifact.Version != recoveryArtifactVersion {
		return fmt.Errorf("unsupported recovery artifact version %d", artifact.Version)
	}
	if artifact.RecoveryID != recoveryID {
		return errors.New("recovery artifact ID does not match its filename")
	}
	if artifact.Project == "" {
		return errors.New("recovery artifact project alias is empty")
	}
	if artifact.CreatedAt.IsZero() {
		return errors.New("recovery artifact creation time is empty")
	}
	if err := validateDigest(artifact.BeforeSHA256, "pre-removal"); err != nil {
		return err
	}
	if err := validateDigest(artifact.AfterSHA256, "post-removal"); err != nil {
		return err
	}
	if digestBytes(artifact.Policy) != artifact.BeforeSHA256 {
		return errors.New("recovery artifact pre-removal digest does not match stored policy")
	}
	return nil
}

func validateRecoveryID(recoveryID string) error {
	if !recoveryIDPattern.MatchString(recoveryID) {
		return errors.New("recovery ID must be 32 lowercase hexadecimal characters")
	}
	return nil
}

func validateDigest(value, label string) error {
	if len(value) != 64 {
		return fmt.Errorf("recovery artifact %s digest is invalid", label)
	}
	for _, c := range value {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("recovery artifact %s digest is invalid", label)
		}
	}
	return nil
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func validateRecoveryDir(path string, expectedOwner, expectedGroup uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stating recovery directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("recovery path must be a non-symlink directory")
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("recovery directory must have mode 0700, got %04o", info.Mode().Perm())
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("recovery directory must not have special permission bits")
	}
	if err := validateExpectedIdentity(info, expectedOwner, expectedGroup); err != nil {
		return fmt.Errorf("recovery directory: %w", err)
	}
	return nil
}

func validateRecoveryFile(path string, expectedOwner, expectedGroup uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stating recovery artifact: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("recovery artifact must be a regular, non-symlink file")
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("recovery artifact must have mode 0600, got %04o", info.Mode().Perm())
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("recovery artifact must not have special permission bits")
	}
	if err := validateExpectedIdentity(info, expectedOwner, expectedGroup); err != nil {
		return fmt.Errorf("recovery artifact: %w", err)
	}
	if info.Size() > maxRecoveryArtifactBytes {
		return fmt.Errorf("recovery artifact exceeds maximum size of %d bytes", maxRecoveryArtifactBytes)
	}
	return nil
}

func validateExpectedIdentity(info os.FileInfo, expectedOwner, expectedGroup uint32) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("could not determine owner")
	}
	if stat.Uid != expectedOwner {
		return fmt.Errorf("must be owned by uid %d, got %d", expectedOwner, stat.Uid)
	}
	if stat.Gid != expectedGroup {
		return fmt.Errorf("must use gid %d, got %d", expectedGroup, stat.Gid)
	}
	return nil
}

func writeAll(f *os.File, data []byte) error {
	written, err := f.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("recovery artifact contains trailing JSON data")
		}
		return fmt.Errorf("decoding recovery artifact trailer: %w", err)
	}
	return nil
}
