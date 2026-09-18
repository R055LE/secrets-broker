// Package admin provides the root-only policy administration operations.
package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
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
	argvPattern          = regexp.MustCompile(`(?m)^[\t ]*argv[\t ]*=[^\r\n]*\r?$`)
)

type ProjectSummary struct {
	Alias    string
	Mode     string
	Behavior string
}

type ProjectDetail struct {
	Alias        string
	BWSProjectID string
	TokenEntry   string
	WorkingDir   string
	Mode         string
	Behavior     string
	Allow        [][]string
}

type ProjectInput struct {
	Alias        string
	BWSProjectID string
	TokenEntry   string
	WorkingDir   string
}

type Editor struct {
	path          string
	expectedOwner uint32
	recovery      RecoveryArtifacts
	beforeWrite   func()
}

func NewEditor(path string, expectedOwner uint32) *Editor {
	return &Editor{path: path, expectedOwner: expectedOwner}
}

func NewRecoveryEditor(path, recoveryDir string, expectedOwner, expectedGroup uint32) *Editor {
	return newEditorWithRecovery(
		path,
		expectedOwner,
		NewRecoveryStore(recoveryDir, expectedOwner, expectedGroup),
	)
}

func newEditorWithRecovery(path string, expectedOwner uint32, recovery RecoveryArtifacts) *Editor {
	return &Editor{path: path, expectedOwner: expectedOwner, recovery: recovery}
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

func (e *Editor) GetProject(alias string) (ProjectDetail, error) {
	_, cfg, _, err := e.readPolicy()
	if err != nil {
		return ProjectDetail{}, err
	}

	projectIndex, err := findProject(cfg, alias)
	if err != nil {
		return ProjectDetail{}, err
	}
	project := cfg.Projects[projectIndex]
	mode, behavior := displayApproval(project.Approval)
	return ProjectDetail{
		Alias:        project.Alias,
		BWSProjectID: project.BWSProjectID,
		TokenEntry:   project.TokenEntry,
		WorkingDir:   project.WorkingDir,
		Mode:         mode,
		Behavior:     behavior,
		Allow:        cloneArgv(project.Allow),
	}, nil
}

func (e *Editor) ListAllowlist(alias string) ([][]string, error) {
	_, cfg, _, err := e.readPolicy()
	if err != nil {
		return nil, err
	}

	projectIndex, err := findProject(cfg, alias)
	if err != nil {
		return nil, err
	}
	return cloneArgv(cfg.Projects[projectIndex].Allow), nil
}

func (e *Editor) CreateProject(input ProjectInput) (bool, error) {
	if err := validateProjectInput(input); err != nil {
		return false, err
	}

	data, cfg, metadata, err := e.readPolicy()
	if err != nil {
		return false, err
	}
	for _, project := range cfg.Projects {
		if project.Alias == input.Alias {
			return false, fmt.Errorf("project %q already exists", input.Alias)
		}
	}

	project := config.Project{
		Alias:        input.Alias,
		BWSProjectID: input.BWSProjectID,
		TokenEntry:   input.TokenEntry,
		WorkingDir:   input.WorkingDir,
		Approval:     config.ApprovalAllowlistedPrompt,
	}
	updated := appendProject(data, project)
	updatedConfig, err := config.Parse(updated)
	if err != nil {
		return false, fmt.Errorf("validating updated policy: %w", err)
	}
	if err := updatedConfig.ValidateWorker(); err != nil {
		return false, fmt.Errorf("validating updated worker policy: %w", err)
	}

	expected := *cfg
	expected.Projects = append(append([]config.Project(nil), cfg.Projects...), project)
	if !reflect.DeepEqual(&expected, updatedConfig) {
		return false, errors.New("updated policy changed fields outside the new project")
	}

	if err := e.writeAtomic(updated, metadata); err != nil {
		return false, err
	}
	return true, nil
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

	projectIndex, err := findProject(cfg, alias)
	if err != nil {
		return false, err
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

func (e *Editor) AddAllowlist(alias string, argv []string) (bool, error) {
	if len(argv) == 0 {
		return false, errors.New("allowlist argv must not be empty")
	}

	data, cfg, metadata, err := e.readPolicy()
	if err != nil {
		return false, err
	}
	projectIndex, err := findProject(cfg, alias)
	if err != nil {
		return false, err
	}
	for _, entry := range cfg.Projects[projectIndex].Allow {
		if slices.Equal(entry.Argv, argv) {
			return false, nil
		}
	}

	updated, err := insertAllowEntry(
		data,
		len(cfg.Projects),
		projectIndex,
		len(cfg.Projects[projectIndex].Allow),
		argv,
	)
	if err != nil {
		return false, err
	}
	want := append([]config.AllowEntry(nil), cfg.Projects[projectIndex].Allow...)
	want = append(want, config.AllowEntry{Argv: append([]string(nil), argv...)})
	if err := validateAllowlistUpdate(updated, cfg, projectIndex, want); err != nil {
		return false, err
	}
	if err := e.writeAtomic(updated, metadata); err != nil {
		return false, err
	}
	return true, nil
}

func (e *Editor) RemoveAllowlist(alias string, argv []string) (bool, error) {
	if len(argv) == 0 {
		return false, errors.New("allowlist argv must not be empty")
	}

	data, cfg, metadata, err := e.readPolicy()
	if err != nil {
		return false, err
	}
	projectIndex, err := findProject(cfg, alias)
	if err != nil {
		return false, err
	}

	allow := cfg.Projects[projectIndex].Allow
	remove := make([]int, 0, 1)
	var want []config.AllowEntry
	for i, entry := range allow {
		if slices.Equal(entry.Argv, argv) {
			remove = append(remove, i)
			continue
		}
		want = append(want, entry)
	}
	if len(remove) == 0 {
		return false, nil
	}

	updated, err := removeAllowEntries(data, len(cfg.Projects), projectIndex, len(allow), remove)
	if err != nil {
		return false, err
	}
	if err := validateAllowlistUpdate(updated, cfg, projectIndex, want); err != nil {
		return false, err
	}
	if err := e.writeAtomic(updated, metadata); err != nil {
		return false, err
	}
	return true, nil
}

func (e *Editor) RemoveProject(alias, confirmation, recoveryID string) (RecoveryResult, error) {
	if e.recovery == nil {
		return RecoveryResult{}, errors.New("project recovery is not configured")
	}
	if confirmation == "" {
		return RecoveryResult{}, errors.New("project confirmation is required")
	}
	if confirmation != alias {
		return RecoveryResult{}, errors.New("project confirmation must exactly match the selected alias")
	}
	if err := validateRecoveryID(recoveryID); err != nil {
		return RecoveryResult{}, err
	}

	data, cfg, metadata, err := e.readPolicy()
	if err != nil {
		return RecoveryResult{}, err
	}
	projectIndex, err := findProject(cfg, alias)
	if err != nil {
		return RecoveryResult{}, err
	}
	if len(cfg.Projects) == 1 {
		return RecoveryResult{}, errors.New("cannot remove the last configured project")
	}

	updated, err := removeProjectSpan(data, len(cfg.Projects), projectIndex)
	if err != nil {
		return RecoveryResult{}, err
	}
	updatedConfig, err := config.Parse(updated)
	if err != nil {
		return RecoveryResult{}, fmt.Errorf("validating updated policy: %w", err)
	}
	if err := updatedConfig.ValidateWorker(); err != nil {
		return RecoveryResult{}, fmt.Errorf("validating updated worker policy: %w", err)
	}
	expected := *cfg
	expected.Projects = append([]config.Project(nil), cfg.Projects[:projectIndex]...)
	expected.Projects = append(expected.Projects, cfg.Projects[projectIndex+1:]...)
	if !reflect.DeepEqual(&expected, updatedConfig) {
		return RecoveryResult{}, errors.New("updated policy changed fields outside the selected project")
	}

	if err := e.recovery.Publish(RecoveryArtifactInput{
		RecoveryID: recoveryID,
		Project:    alias,
		Before:     data,
		After:      updated,
	}); err != nil {
		return RecoveryResult{}, fmt.Errorf("publishing project recovery artifact: %w", err)
	}
	result := RecoveryResult{RecoveryID: recoveryID}
	if e.beforeWrite != nil {
		e.beforeWrite()
	}
	if err := e.writeAtomic(updated, metadata); err != nil {
		return result, err
	}
	result.Changed = true
	return result, nil
}

func (e *Editor) ListRecoveries() ([]RecoverySummary, error) {
	if e.recovery == nil {
		return nil, errors.New("project recovery is not configured")
	}
	return e.recovery.List()
}

func (e *Editor) RestoreProject(recoveryID, confirmation string) (RecoveryResult, error) {
	if e.recovery == nil {
		return RecoveryResult{}, errors.New("project recovery is not configured")
	}
	if confirmation == "" {
		return RecoveryResult{}, errors.New("project confirmation is required")
	}
	artifact, err := e.recovery.Read(recoveryID)
	if err != nil {
		return RecoveryResult{}, err
	}
	result := RecoveryResult{RecoveryID: recoveryID}
	if confirmation != artifact.Project {
		return result, errors.New("project confirmation must exactly match the recovery artifact alias")
	}

	currentData, currentConfig, metadata, err := e.readPolicy()
	if err != nil {
		return result, err
	}
	if digestBytes(currentData) != artifact.AfterSHA256 {
		return result, errors.New("policy changed since removal; automatic restore is not allowed")
	}

	storedConfig, err := config.Parse(artifact.Policy)
	if err != nil {
		return result, fmt.Errorf("validating stored policy: %w", err)
	}
	if err := storedConfig.ValidateWorker(); err != nil {
		return result, fmt.Errorf("validating stored worker policy: %w", err)
	}
	projectIndex, err := findProject(storedConfig, artifact.Project)
	if err != nil {
		return result, errors.New("recovery artifact does not contain the confirmed project")
	}
	expected := *storedConfig
	expected.Projects = append([]config.Project(nil), storedConfig.Projects[:projectIndex]...)
	expected.Projects = append(expected.Projects, storedConfig.Projects[projectIndex+1:]...)
	if !reflect.DeepEqual(&expected, currentConfig) {
		return result, errors.New("recovery artifact does not differ by exactly the confirmed project")
	}
	removed, err := removeProjectSpan(artifact.Policy, len(storedConfig.Projects), projectIndex)
	if err != nil {
		return result, fmt.Errorf("validating stored policy layout: %w", err)
	}
	if !bytes.Equal(removed, currentData) {
		return result, errors.New("recovery artifact does not reproduce the current policy")
	}
	if e.beforeWrite != nil {
		e.beforeWrite()
	}
	if err := e.writeAtomic(artifact.Policy, metadata); err != nil {
		return result, err
	}
	result.Changed = true
	return result, nil
}

func validateProjectInput(input ProjectInput) error {
	if input.Alias == "" {
		return errors.New("project alias is required")
	}
	if input.BWSProjectID == "" {
		return errors.New("bws project ID is required")
	}
	if input.TokenEntry == "" {
		return errors.New("token entry is required")
	}
	if input.WorkingDir == "" {
		return errors.New("working directory is required")
	}
	if !filepath.IsAbs(input.WorkingDir) {
		return errors.New("working directory must be an absolute path")
	}
	return nil
}

func appendProject(data []byte, project config.Project) []byte {
	values := make([]string, 4)
	for i, value := range []string{project.Alias, project.BWSProjectID, project.TokenEntry, project.WorkingDir} {
		encoded, _ := json.Marshal(value)
		values[i] = string(encoded)
	}

	newline := []byte("\n")
	if bytes.Contains(data, []byte("\r\n")) {
		newline = []byte("\r\n")
	}
	updated := append([]byte(nil), data...)
	if len(updated) > 0 && !bytes.HasSuffix(updated, newline) {
		updated = append(updated, newline...)
	}
	doubleNewline := append(append([]byte(nil), newline...), newline...)
	if len(updated) > 0 && !bytes.HasSuffix(updated, doubleNewline) {
		updated = append(updated, newline...)
	}
	lines := []string{
		"[[projects]]",
		"alias = " + values[0],
		"bws_project_id = " + values[1],
		"token_entry = " + values[2],
		"working_dir = " + values[3],
		`approval = "` + config.ApprovalAllowlistedPrompt + `"`,
	}
	updated = append(updated, []byte(strings.Join(lines, string(newline)))...)
	updated = append(updated, newline...)
	return updated
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
	if len(data) > maxPolicyBytes {
		return fmt.Errorf("updated policy exceeds maximum size of %d bytes", maxPolicyBytes)
	}
	lock, err := lockPolicy(e.path)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()

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

func lockPolicy(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("opening policy for mutation lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("locking policy for mutation: %w", err)
	}
	return file, nil
}

func replaceApproval(data []byte, projectCount, projectIndex int, approval string) ([]byte, error) {
	start, end, err := projectBlockBounds(data, projectCount, projectIndex)
	if err != nil {
		return nil, err
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

func insertAllowEntry(data []byte, projectCount, projectIndex, allowCount int, argv []string) ([]byte, error) {
	start, end, err := projectBlockBounds(data, projectCount, projectIndex)
	if err != nil {
		return nil, err
	}
	if got := len(allowHeaderPattern.FindAllIndex(data[start:end], -1)); got != allowCount {
		return nil, errors.New("policy layout is not editable: expected one [[projects.allow]] block per allowlist entry")
	}

	encoded, err := json.Marshal(argv)
	if err != nil {
		return nil, fmt.Errorf("encoding allowlist argv: %w", err)
	}
	newline := []byte("\n")
	if bytes.Contains(data, []byte("\r\n")) {
		newline = []byte("\r\n")
	}
	entry := make([]byte, 0, len(encoded)+64)
	if end > 0 && data[end-1] != '\n' {
		entry = append(entry, newline...)
	}
	entry = append(entry, "  [[projects.allow]]"...)
	entry = append(entry, newline...)
	entry = append(entry, "  argv = "...)
	entry = append(entry, encoded...)
	entry = append(entry, newline...)

	updated := make([]byte, 0, len(data)+len(entry))
	updated = append(updated, data[:end]...)
	updated = append(updated, entry...)
	updated = append(updated, data[end:]...)
	return updated, nil
}

type byteSpan struct {
	start int
	end   int
}

func removeAllowEntries(data []byte, projectCount, projectIndex, allowCount int, remove []int) ([]byte, error) {
	start, end, err := projectBlockBounds(data, projectCount, projectIndex)
	if err != nil {
		return nil, err
	}
	block := data[start:end]
	allowHeaders := allowHeaderPattern.FindAllIndex(block, -1)
	if len(allowHeaders) != allowCount {
		return nil, errors.New("policy layout is not editable: expected one [[projects.allow]] block per allowlist entry")
	}

	spans := make([]byteSpan, 0, len(remove)*2)
	for _, index := range remove {
		if index < 0 || index >= len(allowHeaders) {
			return nil, errors.New("selected allowlist entry is outside the editable policy layout")
		}
		sectionEnd := len(block)
		if index+1 < len(allowHeaders) {
			sectionEnd = allowHeaders[index+1][0]
		}
		sectionStart := allowHeaders[index][1]
		matches := argvPattern.FindAllIndex(block[sectionStart:sectionEnd], -1)
		if len(matches) != 1 {
			return nil, errors.New("policy layout is not editable: expected one single-line argv field per [[projects.allow]] block")
		}

		headerStart := start + allowHeaders[index][0]
		headerEnd := consumeNewline(data, start+allowHeaders[index][1])
		argvStart := start + sectionStart + matches[0][0]
		argvEnd := consumeNewline(data, start+sectionStart+matches[0][1])
		spans = append(spans, byteSpan{start: headerStart, end: headerEnd})
		spans = append(spans, byteSpan{start: argvStart, end: argvEnd})
	}

	updated := make([]byte, 0, len(data))
	cursor := 0
	for _, span := range spans {
		if span.start < cursor {
			return nil, errors.New("selected allowlist entries overlap in the editable policy layout")
		}
		updated = append(updated, data[cursor:span.start]...)
		cursor = span.end
	}
	updated = append(updated, data[cursor:]...)
	return updated, nil
}

func removeProjectSpan(data []byte, projectCount, projectIndex int) ([]byte, error) {
	headers := projectHeaderPattern.FindAllIndex(data, -1)
	if len(headers) != projectCount {
		return nil, errors.New("policy layout is not editable: expected one [[projects]] block per project")
	}
	if projectIndex < 0 || projectIndex >= len(headers) {
		return nil, errors.New("selected project is outside the editable policy layout")
	}
	end := len(data)
	if projectIndex+1 < len(headers) {
		end = headers[projectIndex+1][0]
	}
	updated := append([]byte(nil), data[:headers[projectIndex][0]]...)
	return append(updated, data[end:]...), nil
}

func projectBlockBounds(data []byte, projectCount, projectIndex int) (int, int, error) {
	headers := projectHeaderPattern.FindAllIndex(data, -1)
	if len(headers) != projectCount {
		return 0, 0, errors.New("policy layout is not editable: expected one [[projects]] block per project")
	}
	if projectIndex < 0 || projectIndex >= len(headers) {
		return 0, 0, errors.New("selected project is outside the editable policy layout")
	}
	end := len(data)
	if projectIndex+1 < len(headers) {
		end = headers[projectIndex+1][0]
	}
	return headers[projectIndex][1], end, nil
}

func consumeNewline(data []byte, index int) int {
	if index < len(data) && data[index] == '\n' {
		return index + 1
	}
	return index
}

func validateAllowlistUpdate(updated []byte, cfg *config.Config, projectIndex int, want []config.AllowEntry) error {
	updatedConfig, err := config.Parse(updated)
	if err != nil {
		return fmt.Errorf("validating updated policy: %w", err)
	}
	if err := updatedConfig.ValidateWorker(); err != nil {
		return fmt.Errorf("validating updated worker policy: %w", err)
	}

	expected := *cfg
	expected.Projects = append([]config.Project(nil), cfg.Projects...)
	expectedProject := cfg.Projects[projectIndex]
	expectedProject.Allow = want
	expected.Projects[projectIndex] = expectedProject
	if !reflect.DeepEqual(&expected, updatedConfig) {
		return errors.New("updated policy changed fields outside the selected project allowlist")
	}
	return nil
}

func findProject(cfg *config.Config, alias string) (int, error) {
	for i, project := range cfg.Projects {
		if project.Alias == alias {
			return i, nil
		}
	}
	return -1, fmt.Errorf("unknown project %q", alias)
}

func cloneArgv(entries []config.AllowEntry) [][]string {
	argv := make([][]string, len(entries))
	for i, entry := range entries {
		argv[i] = append([]string(nil), entry.Argv...)
	}
	return argv
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
