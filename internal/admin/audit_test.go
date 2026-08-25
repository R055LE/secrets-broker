package admin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var (
	errAuditUnavailable = errors.New("audit unavailable")
	errPolicyUpdate     = errors.New("policy update failed")
)

type fakeMutationEditor struct {
	changed bool
	err     error
	calls   int
}

func (f *fakeMutationEditor) ListProjects() ([]ProjectSummary, error) {
	return nil, nil
}

func (f *fakeMutationEditor) ListAllowlist(string) ([][]string, error) {
	return nil, nil
}

func (f *fakeMutationEditor) CreateProject(ProjectInput) (bool, error) {
	f.calls++
	return f.changed, f.err
}

func (f *fakeMutationEditor) SetApproval(string, string) (bool, error) {
	f.calls++
	return f.changed, f.err
}

func (f *fakeMutationEditor) AddAllowlist(string, []string) (bool, error) {
	f.calls++
	return f.changed, f.err
}

func (f *fakeMutationEditor) RemoveAllowlist(string, []string) (bool, error) {
	f.calls++
	return f.changed, f.err
}

type fakeMutationLogger struct {
	startErr  error
	finishErr error
	starts    []MutationStart
	finishes  []MutationFinish
	sequence  []string
}

func (f *fakeMutationLogger) Start(_ context.Context, rec MutationStart) (string, error) {
	f.sequence = append(f.sequence, "start")
	if f.startErr != nil {
		return "", f.startErr
	}
	f.starts = append(f.starts, rec)
	return "mutation-id", nil
}

func (f *fakeMutationLogger) Finish(_ context.Context, mutationID string, rec MutationFinish) error {
	f.sequence = append(f.sequence, "finish")
	if mutationID != "mutation-id" {
		return errors.New("unexpected mutation ID")
	}
	f.finishes = append(f.finishes, rec)
	return f.finishErr
}

func TestAuditedEditorRecordsApprovalMutation(t *testing.T) {
	editor := &fakeMutationEditor{changed: true}
	logger := &fakeMutationLogger{}
	audited := NewAuditedEditor(editor, logger, 0)

	changed, err := audited.SetApproval("omada-read", ModeAutomatic)
	if err != nil {
		t.Fatalf("SetApproval: %v", err)
	}
	if !changed || editor.calls != 1 {
		t.Fatalf("changed = %v, editor calls = %d", changed, editor.calls)
	}
	wantStart := MutationStart{
		ActorUID:     0,
		Project:      "omada-read",
		Operation:    MutationSetApproval,
		ApprovalMode: ModeAutomatic,
	}
	if !reflect.DeepEqual(logger.starts, []MutationStart{wantStart}) {
		t.Fatalf("starts = %#v, want %#v", logger.starts, []MutationStart{wantStart})
	}
	if !reflect.DeepEqual(logger.finishes, []MutationFinish{{Outcome: MutationChanged}}) {
		t.Fatalf("finishes = %#v", logger.finishes)
	}
}

func TestAuditedEditorRecordsProjectCreationWithoutDeploymentIdentifiers(t *testing.T) {
	editor := &fakeMutationEditor{changed: true}
	logger := &fakeMutationLogger{}
	audited := NewAuditedEditor(editor, logger, 0)
	input := ProjectInput{
		Alias:        "github-ops",
		BWSProjectID: "11111111-1111-1111-1111-111111111111",
		TokenEntry:   "github-ops-agent",
		WorkingDir:   "/srv/github-ops",
	}

	changed, err := audited.CreateProject(input)
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if !changed || editor.calls != 1 {
		t.Fatalf("changed = %v, editor calls = %d", changed, editor.calls)
	}
	wantStart := MutationStart{
		ActorUID:     0,
		Project:      input.Alias,
		Operation:    MutationCreateProject,
		ApprovalMode: ModeConfirm,
	}
	if !reflect.DeepEqual(logger.starts, []MutationStart{wantStart}) {
		t.Fatalf("starts = %#v, want %#v", logger.starts, []MutationStart{wantStart})
	}
	if !reflect.DeepEqual(logger.finishes, []MutationFinish{{Outcome: MutationChanged}}) {
		t.Fatalf("finishes = %#v", logger.finishes)
	}
}

func TestAuditedEditorRecordsAllowlistMutationWithoutChangingArgv(t *testing.T) {
	editor := &fakeMutationEditor{changed: true}
	logger := &fakeMutationLogger{}
	audited := NewAuditedEditor(editor, logger, 0)
	argv := []string{"/usr/bin/tool", "--flag", "hello world"}

	if _, err := audited.AddAllowlist("project", argv); err != nil {
		t.Fatalf("AddAllowlist: %v", err)
	}
	if len(logger.starts) != 1 {
		t.Fatalf("got %d starts", len(logger.starts))
	}
	start := logger.starts[0]
	if start.Operation != MutationAddAllowlist || !reflect.DeepEqual(start.Argv, argv) {
		t.Fatalf("start = %#v", start)
	}
	if &start.Argv[0] == &argv[0] {
		t.Fatal("audit record retained the caller's argv slice")
	}
}

func TestAuditedEditorBlocksMutationWhenStartAuditFails(t *testing.T) {
	editor := &fakeMutationEditor{changed: true}
	logger := &fakeMutationLogger{startErr: errAuditUnavailable}
	audited := NewAuditedEditor(editor, logger, 0)

	changed, err := audited.SetApproval("project", ModeConfirm)
	if changed || !errors.Is(err, errAuditUnavailable) {
		t.Fatalf("changed = %v, err = %v", changed, err)
	}
	if editor.calls != 0 {
		t.Fatalf("editor called %d times after audit failure", editor.calls)
	}
	if len(logger.finishes) != 0 {
		t.Fatal("finish was written without a successful start")
	}
}

func TestAuditedEditorRecordsNoChangeAndFailureOutcomes(t *testing.T) {
	tests := []struct {
		name        string
		editorError error
		wantOutcome string
	}{
		{name: "no change", wantOutcome: MutationNoChange},
		{name: "failed", editorError: errPolicyUpdate, wantOutcome: MutationFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			editor := &fakeMutationEditor{err: tt.editorError}
			logger := &fakeMutationLogger{}
			audited := NewAuditedEditor(editor, logger, 0)

			_, err := audited.RemoveAllowlist("project", []string{"/usr/bin/true"})
			if !errors.Is(err, tt.editorError) {
				t.Fatalf("err = %v, want %v", err, tt.editorError)
			}
			if got := logger.finishes[0].Outcome; got != tt.wantOutcome {
				t.Fatalf("outcome = %q, want %q", got, tt.wantOutcome)
			}
		})
	}
}

func TestAuditedEditorReportsFinishFailureAfterPolicyChange(t *testing.T) {
	editor := &fakeMutationEditor{changed: true}
	logger := &fakeMutationLogger{finishErr: errAuditUnavailable}
	audited := NewAuditedEditor(editor, logger, 0)

	changed, err := audited.SetApproval("project", ModeAutomatic)
	if !changed || !errors.Is(err, errAuditUnavailable) {
		t.Fatalf("changed = %v, err = %v", changed, err)
	}
	if !strings.Contains(err.Error(), "policy changed") {
		t.Fatalf("error does not disclose committed policy change: %v", err)
	}
}

func TestAuditedEditorDoesNotAuditReadOnlyOperations(t *testing.T) {
	logger := &fakeMutationLogger{}
	audited := NewAuditedEditor(&fakeMutationEditor{}, logger, 0)

	if _, err := audited.ListProjects(); err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if _, err := audited.ListAllowlist("project"); err != nil {
		t.Fatalf("ListAllowlist: %v", err)
	}
	if len(logger.sequence) != 0 {
		t.Fatalf("read-only operations wrote audit events: %v", logger.sequence)
	}
}

func TestMutationJSONLLoggerWritesPrivateStartAndFinishRecords(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "admin-audit")
	path := filepath.Join(dir, "audit.jsonl")
	logger := NewMutationJSONLLogger(path)

	mutationID, err := logger.Start(context.Background(), MutationStart{
		ActorUID:     os.Geteuid(),
		Project:      "github-ops",
		Operation:    MutationSetApproval,
		ApprovalMode: ModeConfirm,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := logger.Finish(context.Background(), mutationID, MutationFinish{Outcome: MutationChanged}); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat audit directory: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("directory mode = %o, want 700", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat audit file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode = %o, want 600", got)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("got %d records, want 2", len(lines))
	}
	var start, finish map[string]any
	if err := json.Unmarshal(lines[0], &start); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	if err := json.Unmarshal(lines[1], &finish); err != nil {
		t.Fatalf("decode finish: %v", err)
	}
	if start["event"] != "start" || start["project"] != "github-ops" || start["operation"] != MutationSetApproval {
		t.Fatalf("start record = %#v", start)
	}
	if start["approval_mode"] != ModeConfirm {
		t.Fatalf("start record missing approval mode: %#v", start)
	}
	if finish["event"] != "finish" || finish["outcome"] != MutationChanged {
		t.Fatalf("finish record = %#v", finish)
	}
	if start["mutation_id"] == "" || start["mutation_id"] != finish["mutation_id"] {
		t.Fatalf("mutation IDs do not correlate: %#v %#v", start, finish)
	}
	for _, forbidden := range []string{"token", "bws_project_id", "secret", "policy"} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatalf("audit contains forbidden field or value %q: %s", forbidden, data)
		}
	}
}

func TestMutationJSONLLoggerRejectsOpenAuditDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "admin-audit")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("create audit directory: %v", err)
	}
	logger := NewMutationJSONLLogger(filepath.Join(dir, "audit.jsonl"))

	if _, err := logger.Start(context.Background(), MutationStart{Project: "project"}); err == nil {
		t.Fatal("expected an open audit directory to be rejected")
	}
}

func TestMutationJSONLLoggerHashesAllowlistArgv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin-audit", "audit.jsonl")
	logger := NewMutationJSONLLogger(path)
	argv := []string{"/usr/bin/printenv", "SENSITIVE_SECRET_NAME"}

	if _, err := logger.Start(context.Background(), MutationStart{
		ActorUID:  os.Geteuid(),
		Project:   "project",
		Operation: MutationAddAllowlist,
		Argv:      argv,
	}); err != nil {
		t.Fatalf("Start: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	if bytes.Contains(data, []byte(argv[0])) || bytes.Contains(data, []byte(argv[1])) {
		t.Fatalf("audit contains raw argv: %s", data)
	}
	encoded, err := json.Marshal(argv)
	if err != nil {
		t.Fatalf("marshal argv: %v", err)
	}
	wantDigest := fmt.Sprintf("%x", sha256.Sum256(encoded))
	if !bytes.Contains(data, []byte(`"argv_sha256":"`+wantDigest+`"`)) {
		t.Fatalf("audit does not contain argv digest %q: %s", wantDigest, data)
	}
	if !bytes.Contains(data, []byte(`"argv_count":2`)) {
		t.Fatalf("audit does not contain argv count: %s", data)
	}
}
