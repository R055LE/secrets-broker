// Package admin provides the root-only policy administration operations.
package admin

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"syscall"

	"github.com/R055LE/secrets-broker/internal/config"
	"github.com/R055LE/secrets-broker/internal/securefile"
)

const maxPolicyBytes = 1 << 20

const (
	ModeAutomatic = "automatic"
	ModeConfirm   = "confirm"
)

var (
	projectHeaderPattern = regexp.MustCompile(`(?m)^[\t ]*\[\[projects\]\][\t ]*(?:#[^\r\n]*)?\r?$`)
	allowHeaderPattern   = regexp.MustCompile(`(?m)^[\t ]*\[\[projects\.allow\]\][\t ]*(?:#[^\r\n]*)?\r?$`)
	approvalPattern      = regexp.MustCompile(`(?m)^([\t ]*approval[\t ]*=[\t ]*)(?:"(?:\\.|[^"\\\r\n])*"|'[^'\r\n]*')([\t ]*(?:#[^\r\n]*)?\r?)$`)
)

type ProjectSummary struct {
	Alias    string
	Mode     string
	Behavior string
}

type Editor struct {
	path          string
	expectedOwner uint32
}

func NewEditor(path string, expectedOwner uint32) *Editor {
	return &Editor{path: path, expectedOwner: expectedOwner}
}

func (e *Editor) ListProjects() ([]ProjectSummary, error) {
	_, cfg, _, err := e.readPolicy()
	if err != nil {
		return nil, err
	}

	projects := make([]ProjectSummary, len(cfg.Projects))
	for i, project := range cfg.Projects {
		mode, behavior := displayApproval(project.Approval)
		projects[i] = ProjectSummary{Alias: project.Alias, Mode: mode, Behavior: behavior}
	}
	return projects, nil
}

func (e *Editor) SetApproval(alias, mode string) (bool, error) {
	approval, err := storedApproval(mode)
	if err != nil {
		return false, err
	}

	data, cfg, metadata, err := e.readPolicy()
	if err != nil {
		return false, err
	}

	projectIndex := -1
	for i, project := range cfg.Projects {
		if project.Alias == alias {
			projectIndex = i
			break
		}
	}
	if projectIndex < 0 {
		return false, fmt.Errorf("unknown project %q", alias)
	}
	if cfg.Projects[projectIndex].Approval == approval {
		return false, nil
	}

	updated, err := replaceApproval(data, len(cfg.Projects), projectIndex, approval)
	if err != nil {
		return false, err
	}
	updatedConfig, err := config.Parse(updated)
	if err != nil {
		return false, fmt.Errorf("validating updated policy: %w", err)
	}
	if err := updatedConfig.ValidateWorker(); err != nil {
		return false, fmt.Errorf("validating updated worker policy: %w", err)
	}

	expected := *cfg
	expected.Projects = append([]config.Project(nil), cfg.Projects...)
	expected.Projects[projectIndex].Approval = approval
	if !reflect.DeepEqual(&expected, updatedConfig) {
		return false, errors.New("updated policy changed fields outside the selected approval mode")
	}

	if err := e.writeAtomic(updated, metadata); err != nil {
		return false, err
	}
	return true, nil
}

type fileMetadata struct {
	mode     os.FileMode
	uid      uint32
	gid      uint32
	dev      uint64
	ino      uint64
	size     int64
	modified int64
}

func (e *Editor) readPolicy() ([]byte, *config.Config, fileMetadata, error) {
	dir := filepath.Dir(e.path)
	if err := securefile.ValidateTrustedDir(dir); err != nil {
		return nil, nil, fileMetadata{}, fmt.Errorf("validating policy directory: %w", err)
	}

	before, err := e.metadata()
	if err != nil {
		return nil, nil, fileMetadata{}, err
	}
	data, err := securefile.Read(e.path, maxPolicyBytes, 0o022, true)
	if err != nil {
		return nil, nil, fileMetadata{}, fmt.Errorf("reading policy: %w", err)
	}
	after, err := e.metadata()
	if err != nil {
		return nil, nil, fileMetadata{}, err
	}
	if !sameFile(before, after) {
		return nil, nil, fileMetadata{}, errors.New("policy changed while it was being read")
	}

	cfg, err := config.Parse(data)
	if err != nil {
		return nil, nil, fileMetadata{}, err
	}
	if err := cfg.ValidateWorker(); err != nil {
		return nil, nil, fileMetadata{}, fmt.Errorf("invalid worker policy: %w", err)
	}
	return data, cfg, after, nil
}

func (e *Editor) metadata() (fileMetadata, error) {
	info, err := os.Lstat(e.path)
	if err != nil {
		return fileMetadata{}, fmt.Errorf("stating policy: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fileMetadata{}, errors.New("policy must be a regular, non-symlink file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fileMetadata{}, fmt.Errorf("policy permissions are too open (%v)", info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileMetadata{}, errors.New("determining policy ownership")
	}
	if stat.Uid != e.expectedOwner {
		return fileMetadata{}, fmt.Errorf("policy must be owned by uid %d, got %d", e.expectedOwner, stat.Uid)
	}
	return fileMetadata{
		mode:     info.Mode().Perm(),
		uid:      stat.Uid,
		gid:      stat.Gid,
		dev:      uint64(stat.Dev),
		ino:      stat.Ino,
		size:     info.Size(),
		modified: info.ModTime().UnixNano(),
	}, nil
}

func (e *Editor) writeAtomic(data []byte, original fileMetadata) error {
	current, err := e.metadata()
	if err != nil {
		return err
	}
	if !sameFile(original, current) {
		return errors.New("policy changed before it could be replaced")
	}

	dir := filepath.Dir(e.path)
	temp, err := os.CreateTemp(dir, ".policy.toml.tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary policy: %w", err)
	}
	tempName := temp.Name()
	keepTemp := true
	defer func() {
		_ = temp.Close()
		if keepTemp {
			_ = os.Remove(tempName)
		}
	}()

	tempInfo, err := temp.Stat()
	if err != nil {
		return fmt.Errorf("stating temporary policy: %w", err)
	}
	tempStat, ok := tempInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("determining temporary policy ownership")
	}
	if tempStat.Uid != original.uid || tempStat.Gid != original.gid {
		if err := temp.Chown(int(original.uid), int(original.gid)); err != nil {
			return fmt.Errorf("preserving policy ownership: %w", err)
		}
	}
	if err := temp.Chmod(original.mode); err != nil {
		return fmt.Errorf("preserving policy permissions: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("writing temporary policy: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("syncing temporary policy: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("closing temporary policy: %w", err)
	}

	current, err = e.metadata()
	if err != nil {
		return err
	}
	if !sameFile(original, current) {
		return errors.New("policy changed before atomic replacement")
	}
	if err := os.Rename(tempName, e.path); err != nil {
		return fmt.Errorf("replacing policy: %w", err)
	}
	keepTemp = false

	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("opening policy directory for sync: %w", err)
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("syncing policy directory: %w", err)
	}
	return nil
}

func replaceApproval(data []byte, projectCount, projectIndex int, approval string) ([]byte, error) {
	headers := projectHeaderPattern.FindAllIndex(data, -1)
	if len(headers) != projectCount {
		return nil, errors.New("policy layout is not editable: expected one [[projects]] block per project")
	}
	if projectIndex < 0 || projectIndex >= len(headers) {
		return nil, errors.New("selected project is outside the editable policy layout")
	}

	start := headers[projectIndex][1]
	end := len(data)
	if projectIndex+1 < len(headers) {
		end = headers[projectIndex+1][0]
	}
	block := data[start:end]
	matches := approvalPattern.FindAllSubmatchIndex(block, -1)
	quoted := []byte(`"` + approval + `"`)
	if len(matches) > 1 {
		return nil, errors.New("selected project has more than one approval field")
	}
	if len(matches) == 1 {
		valueStart := start + matches[0][3]
		valueEnd := start + matches[0][4]
		updated := make([]byte, 0, len(data)-valueEnd+valueStart+len(quoted))
		updated = append(updated, data[:valueStart]...)
		updated = append(updated, quoted...)
		updated = append(updated, data[valueEnd:]...)
		return updated, nil
	}

	insertAt := end
	if allowHeader := allowHeaderPattern.FindIndex(block); allowHeader != nil {
		insertAt = start + allowHeader[0]
	}
	newline := []byte("\n")
	if bytes.Contains(data, []byte("\r\n")) {
		newline = []byte("\r\n")
	}
	line := append([]byte(`approval = "`+approval+`"`), newline...)
	if insertAt > 0 && data[insertAt-1] != '\n' {
		line = append(newline, line...)
	}
	updated := make([]byte, 0, len(data)+len(line))
	updated = append(updated, data[:insertAt]...)
	updated = append(updated, line...)
	updated = append(updated, data[insertAt:]...)
	return updated, nil
}

func storedApproval(mode string) (string, error) {
	switch mode {
	case ModeAutomatic:
		return config.ApprovalNever, nil
	case ModeConfirm:
		return config.ApprovalAllowlistedPrompt, nil
	default:
		return "", fmt.Errorf("unsupported approval mode %q (use %q or %q)", mode, ModeAutomatic, ModeConfirm)
	}
}

func displayApproval(approval string) (string, string) {
	switch approval {
	case config.ApprovalNever:
		return ModeAutomatic, "allowlisted commands run without confirmation"
	case config.ApprovalAllowlistedPrompt:
		return ModeConfirm, "allowlisted commands require confirmation"
	case config.ApprovalPrompt:
		return "prompt-unlisted", "allowlisted commands run; unlisted commands may be confirmed"
	case config.ApprovalAlways:
		return "prompt-any", "every command may be confirmed, including unlisted commands"
	default:
		return approval, "unknown"
	}
}

func sameFile(a, b fileMetadata) bool {
	return a.dev == b.dev &&
		a.ino == b.ino &&
		a.uid == b.uid &&
		a.gid == b.gid &&
		a.mode == b.mode &&
		a.size == b.size &&
		a.modified == b.modified
}
