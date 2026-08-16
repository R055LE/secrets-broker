package admincli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/R055LE/secrets-broker/internal/admin"
)

type fakeProjectEditor struct {
	projects []admin.ProjectSummary
	changed  bool
	err      error
	alias    string
	mode     string
	calls    int
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
