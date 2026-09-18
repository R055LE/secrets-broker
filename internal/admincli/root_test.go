package admincli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/R055LE/secrets-broker/internal/accessdiag"
	"github.com/R055LE/secrets-broker/internal/admin"
)

type fakeProjectEditor struct {
	projects       []admin.ProjectSummary
	changed        bool
	err            error
	alias          string
	mode           string
	allow          [][]string
	argv           []string
	input          admin.ProjectInput
	recoveryResult admin.RecoveryResult
	recoveries     []admin.RecoverySummary
	recoveryID     string
	confirmation   string
	calls          int
}

type fakeAccessChecker struct {
	result  accessdiag.Result
	err     error
	aliases []string
}

func (c *fakeAccessChecker) Run(
	_ context.Context,
	alias string,
	consume func(accessdiag.Result) error,
) (accessdiag.Outcome, error) {
	c.aliases = append(c.aliases, alias)
	if c.err != nil {
		return "", c.err
	}
	if err := consume(c.result); err != nil {
		return c.result.Outcome, err
	}
	return c.result.Outcome, nil
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func (f *fakeProjectEditor) ListProjects() ([]admin.ProjectSummary, error) {
	f.calls++
	return f.projects, f.err
}

func (f *fakeProjectEditor) SetApproval(alias, mode string) (bool, error) {
	f.calls++
	f.alias = alias
	f.mode = mode
	return f.changed, f.err
}

func (f *fakeProjectEditor) CreateProject(input admin.ProjectInput) (bool, error) {
	f.calls++
	f.input = input
	return f.changed, f.err
}

func (f *fakeProjectEditor) ListAllowlist(alias string) ([][]string, error) {
	f.calls++
	f.alias = alias
	return f.allow, f.err
}

func (f *fakeProjectEditor) AddAllowlist(alias string, argv []string) (bool, error) {
	f.calls++
	f.alias = alias
	f.argv = argv
	return f.changed, f.err
}

func (f *fakeProjectEditor) RemoveAllowlist(alias string, argv []string) (bool, error) {
	f.calls++
	f.alias = alias
	f.argv = argv
	return f.changed, f.err
}

func (f *fakeProjectEditor) RemoveProject(alias, confirmation string) (admin.RecoveryResult, error) {
	f.calls++
	f.alias = alias
	f.confirmation = confirmation
	return f.recoveryResult, f.err
}

func (f *fakeProjectEditor) ListRecoveries() ([]admin.RecoverySummary, error) {
	f.calls++
	return f.recoveries, f.err
}

func (f *fakeProjectEditor) RestoreProject(recoveryID, confirmation string) (admin.RecoveryResult, error) {
	f.calls++
	f.recoveryID = recoveryID
	f.confirmation = confirmation
	return f.recoveryResult, f.err
}

func TestProjectsList(t *testing.T) {
	editor := &fakeProjectEditor{projects: []admin.ProjectSummary{
		{Alias: "omada-read", Mode: "confirm", Behavior: "allowlisted commands require confirmation"},
		{Alias: "probe", Mode: "automatic", Behavior: "allowlisted commands run without confirmation"},
	}}
	var stdout, stderr bytes.Buffer

	if code := execute(func() int { return 0 }, editor, []string{"projects", "list"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	for _, want := range []string{"ALIAS", "omada-read", "confirm", "probe", "automatic"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("output missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestProjectsAccessCheckRendersOnlyApprovedColumnsAndExitStatus(t *testing.T) {
	tests := []struct {
		name     string
		alias    string
		status   accessdiag.Status
		wantCode int
	}{
		{name: "all accessible", status: accessdiag.StatusAccessible, wantCode: 0},
		{name: "remote failure", alias: "github-ops", status: accessdiag.StatusInaccessible, wantCode: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			projects := []accessdiag.ProjectResult{{
				Alias: "github-ops", BWSProjectID: "11111111-1111-1111-1111-111111111111", Status: tt.status,
			}}
			checker := &fakeAccessChecker{result: accessdiag.Result{
				Version: accessdiag.Version, Outcome: accessdiag.Aggregate(projects), Projects: projects,
			}}
			args := []string{"projects", "access", "check"}
			if tt.alias != "" {
				args = append(args, tt.alias)
			}
			var stdout, stderr bytes.Buffer
			code := executeWithAccess(func() int { return 0 }, &fakeProjectEditor{}, checker, args, &stdout, &stderr)
			if code != tt.wantCode || stderr.Len() != 0 {
				t.Fatalf("code = %d, stderr = %q", code, stderr.String())
			}
			if !reflect.DeepEqual(checker.aliases, []string{tt.alias}) {
				t.Fatalf("aliases = %#v", checker.aliases)
			}
			lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
			if len(lines) != 2 || !reflect.DeepEqual(strings.Fields(lines[0]), []string{"ALIAS", "BWS_PROJECT_ID", "STATUS"}) {
				t.Fatalf("output = %q", stdout.String())
			}
			if !reflect.DeepEqual(strings.Fields(lines[1]), []string{"github-ops", "11111111-1111-1111-1111-111111111111", string(tt.status)}) {
				t.Fatalf("row = %q", lines[1])
			}
			for _, forbidden := range []string{"token_entry", "working_dir", "allowlist", "secret"} {
				if strings.Contains(strings.ToLower(stdout.String()), forbidden) {
					t.Fatalf("output contains %q: %s", forbidden, stdout.String())
				}
			}
		})
	}
}

func TestProjectsAccessCheckRejectsInvalidUseBeforeWorker(t *testing.T) {
	tests := []struct {
		name string
		euid int
		args []string
	}{
		{name: "non-root", euid: 1000, args: []string{"projects", "access", "check"}},
		{name: "too many aliases", euid: 0, args: []string{"projects", "access", "check", "one", "two"}},
		{name: "timeout override", euid: 0, args: []string{"projects", "access", "check", "--timeout", "1s"}},
		{name: "worker override", euid: 0, args: []string{"projects", "access", "check", "--worker", "/tmp/worker"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &fakeAccessChecker{}
			var stdout, stderr bytes.Buffer
			code := executeWithAccess(func() int { return tt.euid }, &fakeProjectEditor{}, checker, tt.args, &stdout, &stderr)
			if code != 2 || len(checker.aliases) != 0 || stdout.Len() != 0 {
				t.Fatalf("code = %d, calls = %#v, stdout = %q", code, checker.aliases, stdout.String())
			}
		})
	}
}

func TestProjectsAccessCheckReturnsTwoForLocalOrOutputFailure(t *testing.T) {
	t.Run("local", func(t *testing.T) {
		checker := &fakeAccessChecker{err: errors.New("worker access diagnostic failed")}
		var stdout, stderr bytes.Buffer
		code := executeWithAccess(
			func() int { return 0 }, &fakeProjectEditor{}, checker,
			[]string{"projects", "access", "check"}, &stdout, &stderr,
		)
		if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "access diagnostic failed") {
			t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
		}
	})

	t.Run("output", func(t *testing.T) {
		projects := []accessdiag.ProjectResult{{Alias: "project", BWSProjectID: "id", Status: accessdiag.StatusAccessible}}
		checker := &fakeAccessChecker{result: accessdiag.Result{
			Version: accessdiag.Version, Outcome: accessdiag.Aggregate(projects), Projects: projects,
		}}
		var stderr bytes.Buffer
		code := executeWithAccess(
			func() int { return 0 }, &fakeProjectEditor{}, checker,
			[]string{"projects", "access", "check"}, failingWriter{}, &stderr,
		)
		if code != 2 || !strings.Contains(stderr.String(), "writing access diagnostic") {
			t.Fatalf("code = %d, stderr = %q", code, stderr.String())
		}
	})
}

func TestProjectsSetApproval(t *testing.T) {
	editor := &fakeProjectEditor{changed: true}
	var stdout, stderr bytes.Buffer

	if code := execute(func() int { return 0 }, editor, []string{"projects", "set-approval", "omada-read", "automatic"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if editor.alias != "omada-read" || editor.mode != "automatic" {
		t.Fatalf("SetApproval called with %q %q", editor.alias, editor.mode)
	}
	if !strings.Contains(stdout.String(), "now uses automatic") {
		t.Fatalf("unexpected output: %q", stdout.String())
	}
}

func TestProjectsCreateRequiresExplicitInputsAndUsesSafeDefaults(t *testing.T) {
	editor := &fakeProjectEditor{changed: true}
	var stdout, stderr bytes.Buffer
	args := []string{
		"projects", "create", "github-ops",
		"--bws-project-id", "11111111-1111-1111-1111-111111111111",
		"--token-entry", "github-ops-agent",
		"--working-dir", "/srv/github ops",
	}

	if code := execute(func() int { return 0 }, editor, args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	want := admin.ProjectInput{
		Alias:        "github-ops",
		BWSProjectID: "11111111-1111-1111-1111-111111111111",
		TokenEntry:   "github-ops-agent",
		WorkingDir:   "/srv/github ops",
	}
	if !reflect.DeepEqual(editor.input, want) {
		t.Fatalf("CreateProject input = %#v, want %#v", editor.input, want)
	}
	if !strings.Contains(stdout.String(), `created in confirm mode with an empty allowlist`) {
		t.Fatalf("unexpected output: %q", stdout.String())
	}
}

func TestProjectsCreateRejectsMissingInputBeforeEditor(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "BWS project ID",
			args: []string{"projects", "create", "github-ops", "--token-entry", "entry", "--working-dir", "/srv/project"},
			want: "--bws-project-id is required",
		},
		{
			name: "token entry",
			args: []string{"projects", "create", "github-ops", "--bws-project-id", "id", "--working-dir", "/srv/project"},
			want: "--token-entry is required",
		},
		{
			name: "working directory",
			args: []string{"projects", "create", "github-ops", "--bws-project-id", "id", "--token-entry", "entry"},
			want: "--working-dir is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			editor := &fakeProjectEditor{}
			var stdout, stderr bytes.Buffer
			if code := execute(func() int { return 0 }, editor, tt.args, &stdout, &stderr); code == 0 {
				t.Fatal("expected command to fail")
			}
			if editor.calls != 0 {
				t.Fatalf("editor called %d times", editor.calls)
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("stderr = %q, want containing %q", stderr.String(), tt.want)
			}
		})
	}
}

func TestProjectsSetApprovalReportsNoOp(t *testing.T) {
	editor := &fakeProjectEditor{}
	var stdout, stderr bytes.Buffer

	if code := execute(func() int { return 0 }, editor, []string{"projects", "set-approval", "omada-read", "confirm"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "already uses confirm") {
		t.Fatalf("unexpected output: %q", stdout.String())
	}
}

func TestProjectsRemoveRequiresExactConfirmationAndReportsRecoveryID(t *testing.T) {
	id := strings.Repeat("a", 32)
	editor := &fakeProjectEditor{recoveryResult: admin.RecoveryResult{Changed: true, RecoveryID: id}}
	var stdout, stderr bytes.Buffer

	args := []string{"projects", "remove", "github-ops", "--confirm", "github-ops"}
	if code := execute(func() int { return 0 }, editor, args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if editor.alias != "github-ops" || editor.confirmation != "github-ops" {
		t.Fatalf("RemoveProject called with %q %q", editor.alias, editor.confirmation)
	}
	if !strings.Contains(stdout.String(), id) {
		t.Fatalf("output missing recovery ID: %q", stdout.String())
	}
}

func TestProjectsRemovePassesMissingConfirmationToAuditedEditor(t *testing.T) {
	editor := &fakeProjectEditor{err: errors.New("project confirmation is required")}
	var stdout, stderr bytes.Buffer

	if code := execute(func() int { return 0 }, editor, []string{"projects", "remove", "github-ops"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected missing confirmation to fail")
	}
	if editor.calls != 1 || editor.confirmation != "" {
		t.Fatalf("editor called %d times", editor.calls)
	}
	if !strings.Contains(stderr.String(), "project confirmation is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestProjectsRemoveReportsRecoveryIDAfterArtifactPublicationError(t *testing.T) {
	id := strings.Repeat("b", 32)
	editor := &fakeProjectEditor{
		err:            errors.New("policy changed before atomic replacement"),
		recoveryResult: admin.RecoveryResult{RecoveryID: id},
	}
	var stdout, stderr bytes.Buffer

	args := []string{"projects", "remove", "github-ops", "--confirm", "github-ops"}
	if code := execute(func() int { return 0 }, editor, args, &stdout, &stderr); code == 0 {
		t.Fatal("expected removal to fail")
	}
	if !strings.Contains(stderr.String(), id) {
		t.Fatalf("stderr missing recovery ID: %q", stderr.String())
	}
}

func TestProjectsRecoveryListPrintsOnlyApprovedMetadata(t *testing.T) {
	id := strings.Repeat("c", 32)
	created := time.Date(2026, time.August, 25, 12, 30, 0, 0, time.UTC)
	editor := &fakeProjectEditor{recoveries: []admin.RecoverySummary{{
		RecoveryID: id,
		Project:    "github-ops",
		CreatedAt:  created,
	}}}
	var stdout, stderr bytes.Buffer

	if code := execute(func() int { return 0 }, editor, []string{"projects", "recovery", "list"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	for _, want := range []string{"RECOVERY_ID", "ALIAS", "CREATED_AT", id, "github-ops", created.Format(time.RFC3339Nano)} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("output missing %q: %s", want, stdout.String())
		}
	}
	for _, forbidden := range []string{"sha256", "policy", "working_dir", "token_entry", "argv"} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("output contains forbidden field %q: %s", forbidden, stdout.String())
		}
	}
}

func TestProjectsRecoveryRestorePassesIDAndConfirmation(t *testing.T) {
	id := strings.Repeat("d", 32)
	editor := &fakeProjectEditor{recoveryResult: admin.RecoveryResult{Changed: true, RecoveryID: id}}
	var stdout, stderr bytes.Buffer

	args := []string{"projects", "recovery", "restore", id, "--confirm", "github-ops"}
	if code := execute(func() int { return 0 }, editor, args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if editor.recoveryID != id || editor.confirmation != "github-ops" {
		t.Fatalf("RestoreProject called with %q %q", editor.recoveryID, editor.confirmation)
	}
	if !strings.Contains(stdout.String(), `Project "github-ops" restored`) {
		t.Fatalf("unexpected output: %q", stdout.String())
	}
}

func TestProjectsRecoveryRestorePassesMissingConfirmationToAuditedEditor(t *testing.T) {
	id := strings.Repeat("e", 32)
	editor := &fakeProjectEditor{err: errors.New("project confirmation is required")}
	var stdout, stderr bytes.Buffer

	args := []string{"projects", "recovery", "restore", id}
	if code := execute(func() int { return 0 }, editor, args, &stdout, &stderr); code == 0 {
		t.Fatal("expected missing confirmation to fail")
	}
	if editor.calls != 1 || editor.recoveryID != id || editor.confirmation != "" {
		t.Fatalf(
			"RestoreProject called %d times with %q %q",
			editor.calls,
			editor.recoveryID,
			editor.confirmation,
		)
	}
	if !strings.Contains(stderr.String(), "project confirmation is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestProjectsAllowlistList(t *testing.T) {
	editor := &fakeProjectEditor{allow: [][]string{
		{"/usr/bin/true"},
		{"/usr/bin/printf", "hello world"},
	}}
	var stdout, stderr bytes.Buffer

	if code := execute(func() int { return 0 }, editor, []string{"projects", "allowlist", "list", "omada-read"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if editor.alias != "omada-read" {
		t.Fatalf("ListAllowlist called with %q", editor.alias)
	}
	for _, want := range []string{"INDEX", `["/usr/bin/true"]`, `["/usr/bin/printf","hello world"]`} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("output missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestProjectsAllowlistAddPreservesArgvAfterSeparator(t *testing.T) {
	editor := &fakeProjectEditor{changed: true}
	var stdout, stderr bytes.Buffer
	args := []string{"projects", "allowlist", "add", "omada-read", "--", "/usr/bin/tool", "--flag", "hello world", ""}

	if code := execute(func() int { return 0 }, editor, args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	want := []string{"/usr/bin/tool", "--flag", "hello world", ""}
	if !reflect.DeepEqual(editor.argv, want) {
		t.Fatalf("AddAllowlist argv = %#v, want %#v", editor.argv, want)
	}
	if !strings.Contains(stdout.String(), `now allows ["/usr/bin/tool","--flag","hello world",""]`) {
		t.Fatalf("unexpected output: %q", stdout.String())
	}
}

func TestProjectsAllowlistRemoveReportsNoOp(t *testing.T) {
	editor := &fakeProjectEditor{}
	var stdout, stderr bytes.Buffer

	if code := execute(func() int { return 0 }, editor, []string{"projects", "allowlist", "remove", "omada-read", "--", "/usr/bin/true"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `did not allow ["/usr/bin/true"]`) {
		t.Fatalf("unexpected output: %q", stdout.String())
	}
}

func TestAdminCommandsRequireRoot(t *testing.T) {
	editor := &fakeProjectEditor{}
	var stdout, stderr bytes.Buffer

	if code := execute(func() int { return 1000 }, editor, []string{"projects", "list"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected non-root invocation to fail")
	}
	if editor.calls != 0 {
		t.Fatal("editor was called before root check")
	}
	if !strings.Contains(stderr.String(), "must run as root") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestEditorErrorsAreSanitizedByCommandPrefix(t *testing.T) {
	editor := &fakeProjectEditor{err: errors.New("policy unavailable")}
	var stdout, stderr bytes.Buffer

	if code := execute(func() int { return 0 }, editor, []string{"projects", "list"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected editor error")
	}
	if got := stderr.String(); !strings.Contains(got, "secrets-broker-admin: policy unavailable") {
		t.Fatalf("unexpected stderr: %q", got)
	}
}

func TestAdminDoesNotExposePolicyPathOverride(t *testing.T) {
	root := newRootCommand(func() int { return 0 }, &fakeProjectEditor{}, &bytes.Buffer{})
	for _, name := range []string{"policy", "config"} {
		if root.Flags().Lookup(name) != nil || root.PersistentFlags().Lookup(name) != nil {
			t.Fatalf("admin command must not expose --%s", name)
		}
	}
}

func TestProjectsCreateDoesNotExposeUnsafeDefaults(t *testing.T) {
	root := newRootCommand(func() int { return 0 }, &fakeProjectEditor{}, &bytes.Buffer{})
	projects, _, err := root.Find([]string{"projects"})
	if err != nil {
		t.Fatalf("finding projects command: %v", err)
	}
	create, _, err := projects.Find([]string{"create"})
	if err != nil {
		t.Fatalf("finding create command: %v", err)
	}
	for _, name := range []string{"approval", "allow", "allowlist", "secret", "policy", "config"} {
		if create.Flags().Lookup(name) != nil || create.PersistentFlags().Lookup(name) != nil {
			t.Fatalf("project creation must not expose --%s", name)
		}
	}
}

func TestTokenEntryUsageSurfacesResolverBackendCaveat(t *testing.T) {
	root := newRootCommand(func() int { return 0 }, &fakeProjectEditor{}, &bytes.Buffer{})
	projects, _, err := root.Find([]string{"projects"})
	if err != nil {
		t.Fatalf("finding projects command: %v", err)
	}
	create, _, err := projects.Find([]string{"create"})
	if err != nil {
		t.Fatalf("finding create command: %v", err)
	}
	flag := create.Flags().Lookup("token-entry")
	if flag == nil {
		t.Fatal("projects create must expose --token-entry")
	}
	for _, phrase := range []string{"resolver backend", "advisory only"} {
		if !strings.Contains(flag.Usage, phrase) {
			t.Fatalf("--token-entry usage must mention %q, got: %q", phrase, flag.Usage)
		}
	}
}

func TestProjectRecoveryDoesNotExposeUnsafeOverrides(t *testing.T) {
	root := newRootCommand(func() int { return 0 }, &fakeProjectEditor{}, &bytes.Buffer{})
	for _, path := range [][]string{{"projects", "remove"}, {"projects", "recovery", "restore"}} {
		command, _, err := root.Find(path)
		if err != nil {
			t.Fatalf("finding %v: %v", path, err)
		}
		for _, name := range []string{"yes", "force", "policy", "config", "recovery-dir", "path"} {
			if command.Flags().Lookup(name) != nil || command.PersistentFlags().Lookup(name) != nil {
				t.Fatalf("%v must not expose --%s", path, name)
			}
		}
	}
}
