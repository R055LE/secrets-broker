package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/R055LE/secrets-broker/internal/config"
)

func TestListProjectsUsesOperatorFacingModes(t *testing.T) {
	path := writePolicy(t, policyWithProjects(
		projectBlock("automatic-project", `approval = "never"`),
		projectBlock("confirm-project", `approval = "allowlisted-prompt"`),
		projectBlock("advanced-prompt", `approval = "prompt"`),
		projectBlock("advanced-always", `approval = "always"`),
	))

	projects, err := NewEditor(path, uint32(os.Geteuid())).ListProjects()
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	wantModes := []string{"automatic", "confirm", "prompt-unlisted", "prompt-any"}
	if len(projects) != len(wantModes) {
		t.Fatalf("got %d projects, want %d", len(projects), len(wantModes))
	}
	for i, want := range wantModes {
		if projects[i].Mode != want {
			t.Errorf("project %d mode = %q, want %q", i, projects[i].Mode, want)
		}
		if projects[i].Behavior == "" {
			t.Errorf("project %d has no behavior description", i)
		}
	}
}

func TestSetApprovalChangesOnlySelectedValueAndPreservesMetadata(t *testing.T) {
	contents := policyWithProjects(
		projectBlock("alpha", `approval = "allowlisted-prompt"`),
		projectBlock("beta", `approval = "allowlisted-prompt" # keep this comment`),
	)
	path := writePolicy(t, contents)
	before := statFile(t, path)

	changed, err := NewEditor(path, uint32(os.Geteuid())).SetApproval("beta", ModeAutomatic)
	if err != nil {
		t.Fatalf("SetApproval: %v", err)
	}
	if !changed {
		t.Fatal("expected policy to change")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading policy: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, `approval = "never" # keep this comment`) {
		t.Fatalf("updated approval did not preserve comment:\n%s", got)
	}
	if strings.Count(got, `approval = "allowlisted-prompt"`) != 1 {
		t.Fatalf("unselected project changed:\n%s", got)
	}

	after := statFile(t, path)
	if before.Uid != after.Uid || before.Gid != after.Gid {
		t.Fatalf("ownership changed from %d:%d to %d:%d", before.Uid, before.Gid, after.Uid, after.Gid)
	}
	if os.FileMode(before.Mode).Perm() != os.FileMode(after.Mode).Perm() {
		t.Fatalf("mode changed from %v to %v", os.FileMode(before.Mode).Perm(), os.FileMode(after.Mode).Perm())
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("loading updated policy: %v", err)
	}
	if cfg.Projects[1].Approval != config.ApprovalNever {
		t.Fatalf("stored approval = %q, want %q", cfg.Projects[1].Approval, config.ApprovalNever)
	}
}

func TestSetApprovalInsertsExplicitModeWhenFieldIsMissing(t *testing.T) {
	path := writePolicy(t, policyWithProjects(projectBlock("alpha", "")))

	changed, err := NewEditor(path, uint32(os.Geteuid())).SetApproval("alpha", ModeConfirm)
	if err != nil {
		t.Fatalf("SetApproval: %v", err)
	}
	if !changed {
		t.Fatal("expected policy to change")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading policy: %v", err)
	}
	got := string(data)
	approvalIndex := strings.Index(got, `approval = "allowlisted-prompt"`)
	allowIndex := strings.Index(got, "[[projects.allow]]")
	if approvalIndex < 0 || approvalIndex > allowIndex {
		t.Fatalf("approval was not inserted before the allowlist:\n%s", got)
	}
}

func TestSetApprovalNoOpDoesNotRewrite(t *testing.T) {
	path := writePolicy(t, policyWithProjects(projectBlock("alpha", `approval = "never"`)))
	before := statFile(t, path)

	changed, err := NewEditor(path, uint32(os.Geteuid())).SetApproval("alpha", ModeAutomatic)
	if err != nil {
		t.Fatalf("SetApproval: %v", err)
	}
	if changed {
		t.Fatal("expected unchanged policy")
	}
	after := statFile(t, path)
	if before.Ino != after.Ino {
		t.Fatal("no-op replaced the policy file")
	}
}

func TestSetApprovalRejectsUnknownProjectAndModeWithoutWriting(t *testing.T) {
	path := writePolicy(t, policyWithProjects(projectBlock("alpha", `approval = "never"`)))
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	editor := NewEditor(path, uint32(os.Geteuid()))

	if _, err := editor.SetApproval("missing", ModeConfirm); err == nil || !strings.Contains(err.Error(), "unknown project") {
		t.Fatalf("unknown project error = %v", err)
	}
	if _, err := editor.SetApproval("alpha", "always"); err == nil || !strings.Contains(err.Error(), "unsupported approval mode") {
		t.Fatalf("unsafe mode error = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading result: %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("rejected update changed the policy")
	}
}

func TestEditorRejectsSymlinkAndUnexpectedOwner(t *testing.T) {
	path := writePolicy(t, policyWithProjects(projectBlock("alpha", `approval = "never"`)))
	symlink := filepath.Join(filepath.Dir(path), "policy-link.toml")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatalf("creating symlink: %v", err)
	}
	if _, err := NewEditor(symlink, uint32(os.Geteuid())).ListProjects(); err == nil {
		t.Fatal("expected symlink to be rejected")
	}

	unexpected := uint32(os.Geteuid()) + 1
	if unexpected == 0 {
		unexpected = 1
	}
	if _, err := NewEditor(path, unexpected).ListProjects(); err == nil || !strings.Contains(err.Error(), "must be owned") {
		t.Fatalf("owner error = %v", err)
	}
}

func TestReplaceApprovalRejectsUnsupportedLayout(t *testing.T) {
	if _, err := replaceApproval([]byte("projects = []\n"), 1, 0, config.ApprovalNever); err == nil {
		t.Fatal("expected unsupported layout to be rejected")
	}
}

func writePolicy(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("setting policy directory mode: %v", err)
	}
	path := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(path, []byte(contents), 0o640); err != nil {
		t.Fatalf("writing policy: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("setting policy mode: %v", err)
	}
	return path
}

func statFile(t *testing.T, path string) *syscall.Stat_t {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stating %s: %v", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("file stat has unexpected type")
	}
	return stat
}

func policyWithProjects(projects ...string) string {
	return `[runtime]
bws_binary = "/usr/local/bin/bws"
command_path = "/usr/bin:/bin"
home = "/var/lib/secrets-broker"

[token_source]
backend = "file"

[token_source.file]
path = "/var/lib/secrets-broker/bws-access-token"

[approval_source]
backend = "tailscale-relay"

[approval_source.tailscale_relay]
control_url = "http://100.100.100.100:7620"
poll_interval_seconds = 2
timeout_seconds = 300

` + strings.Join(projects, "\n")
}

func projectBlock(alias, approvalLine string) string {
	approval := ""
	if approvalLine != "" {
		approval = approvalLine + "\n"
	}
	return fmt.Sprintf(`[[projects]]
alias = %q
bws_project_id = "00000000-0000-0000-0000-000000000000"
token_entry = %q
working_dir = "/tmp"
%s
  [[projects.allow]]
  argv = ["/usr/bin/true"]
`, alias, alias, approval)
}
