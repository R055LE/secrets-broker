package admin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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

func TestListAllowlistReturnsExactArgv(t *testing.T) {
	path := writePolicy(t, policyWithProjects(projectBlockWithAllow(
		"alpha",
		`approval = "allowlisted-prompt"`,
		[]string{"/usr/bin/true"},
		[]string{"/usr/bin/printf", "hello world", ""},
	)))

	got, err := NewEditor(path, uint32(os.Geteuid())).ListAllowlist("alpha")
	if err != nil {
		t.Fatalf("ListAllowlist: %v", err)
	}
	want := [][]string{{"/usr/bin/true"}, {"/usr/bin/printf", "hello world", ""}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allowlist = %#v, want %#v", got, want)
	}
	if _, err := NewEditor(path, uint32(os.Geteuid())).ListAllowlist("missing"); err == nil || !strings.Contains(err.Error(), "unknown project") {
		t.Fatalf("unknown project error = %v", err)
	}
}

func TestAddAllowlistChangesOnlySelectedProjectAndPreservesMetadata(t *testing.T) {
	contents := policyWithProjects(
		projectBlockWithAllow("alpha", `approval = "allowlisted-prompt"`, []string{"/usr/bin/true"}),
		projectBlockWithAllow("beta", `approval = "never"`, []string{"/usr/bin/false"}),
	) + "# keep trailing comment\n"
	path := writePolicy(t, contents)
	before := statFile(t, path)
	argv := []string{"/usr/bin/printf", "hello world", `quote"and\\slash`}

	changed, err := NewEditor(path, uint32(os.Geteuid())).AddAllowlist("alpha", argv)
	if err != nil {
		t.Fatalf("AddAllowlist: %v", err)
	}
	if !changed {
		t.Fatal("expected policy to change")
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("loading updated policy: %v", err)
	}
	if got, want := cfg.Projects[0].AllowArgv(), [][]string{{"/usr/bin/true"}, argv}; !reflect.DeepEqual(got, want) {
		t.Fatalf("alpha allowlist = %#v, want %#v", got, want)
	}
	if got, want := cfg.Projects[1].AllowArgv(), [][]string{{"/usr/bin/false"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("beta allowlist = %#v, want %#v", got, want)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading updated policy: %v", err)
	}
	if !strings.Contains(string(data), "# keep trailing comment") {
		t.Fatal("unrelated comment was not preserved")
	}
	assertMetadataPreserved(t, before, statFile(t, path))
}

func TestAddAllowlistDuplicateDoesNotRewrite(t *testing.T) {
	path := writePolicy(t, policyWithProjects(projectBlock("alpha", `approval = "never"`)))
	before := statFile(t, path)

	changed, err := NewEditor(path, uint32(os.Geteuid())).AddAllowlist("alpha", []string{"/usr/bin/true"})
	if err != nil {
		t.Fatalf("AddAllowlist: %v", err)
	}
	if changed {
		t.Fatal("expected unchanged policy")
	}
	if after := statFile(t, path); before.Ino != after.Ino {
		t.Fatal("duplicate add replaced the policy file")
	}
}

func TestRemoveAllowlistRemovesEveryExactDuplicateOnly(t *testing.T) {
	target := []string{"/usr/bin/tool", "read"}
	contents := policyWithProjects(
		projectBlockWithAllow(
			"alpha",
			`approval = "allowlisted-prompt"`,
			target,
			[]string{"/usr/bin/tool", "read", "--verbose"},
			target,
		),
		projectBlockWithAllow("beta", `approval = "never"`, target),
	)
	contents = strings.Replace(contents, "  [[projects.allow]]\n", "  # keep allowlist note\n  [[projects.allow]]\n", 1)
	path := writePolicy(t, contents)
	before := statFile(t, path)

	changed, err := NewEditor(path, uint32(os.Geteuid())).RemoveAllowlist("alpha", target)
	if err != nil {
		t.Fatalf("RemoveAllowlist: %v", err)
	}
	if !changed {
		t.Fatal("expected policy to change")
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("loading updated policy: %v", err)
	}
	if got, want := cfg.Projects[0].AllowArgv(), [][]string{{"/usr/bin/tool", "read", "--verbose"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("alpha allowlist = %#v, want %#v", got, want)
	}
	if got, want := cfg.Projects[1].AllowArgv(), [][]string{target}; !reflect.DeepEqual(got, want) {
		t.Fatalf("beta allowlist = %#v, want %#v", got, want)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading updated policy: %v", err)
	}
	if !strings.Contains(string(data), "# keep allowlist note") {
		t.Fatal("allowlist comment was not preserved")
	}
	assertMetadataPreserved(t, before, statFile(t, path))
}

func TestRemoveAllowlistMissingEntryDoesNotRewrite(t *testing.T) {
	path := writePolicy(t, policyWithProjects(projectBlock("alpha", `approval = "never"`)))
	before := statFile(t, path)

	changed, err := NewEditor(path, uint32(os.Geteuid())).RemoveAllowlist("alpha", []string{"/usr/bin/false"})
	if err != nil {
		t.Fatalf("RemoveAllowlist: %v", err)
	}
	if changed {
		t.Fatal("expected unchanged policy")
	}
	if after := statFile(t, path); before.Ino != after.Ino {
		t.Fatal("missing remove replaced the policy file")
	}
}

func TestRemoveAllowlistSupportsEmptyResult(t *testing.T) {
	path := writePolicy(t, policyWithProjects(projectBlock("alpha", `approval = "never"`)))

	changed, err := NewEditor(path, uint32(os.Geteuid())).RemoveAllowlist("alpha", []string{"/usr/bin/true"})
	if err != nil {
		t.Fatalf("RemoveAllowlist: %v", err)
	}
	if !changed {
		t.Fatal("expected policy to change")
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("loading updated policy: %v", err)
	}
	if len(cfg.Projects[0].Allow) != 0 {
		t.Fatalf("allowlist = %#v, want empty", cfg.Projects[0].AllowArgv())
	}
}

func TestAllowlistMutationsRejectEmptyArgv(t *testing.T) {
	editor := NewEditor("unused", uint32(os.Geteuid()))
	if _, err := editor.AddAllowlist("alpha", nil); err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("AddAllowlist error = %v", err)
	}
	if _, err := editor.RemoveAllowlist("alpha", nil); err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("RemoveAllowlist error = %v", err)
	}
}

func TestRemoveAllowlistRejectsUnsupportedLayoutWithoutWriting(t *testing.T) {
	contents := policyWithProjects(projectBlock("alpha", `approval = "never"`))
	contents = strings.Replace(contents, `argv = ["/usr/bin/true"]`, "argv = [\n    \"/usr/bin/true\",\n  ]", 1)
	path := writePolicy(t, contents)

	_, err := NewEditor(path, uint32(os.Geteuid())).RemoveAllowlist("alpha", []string{"/usr/bin/true"})
	if err == nil {
		t.Fatal("expected unsupported layout to be rejected")
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("reading policy: %v", readErr)
	}
	if string(data) != contents {
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

func assertMetadataPreserved(t *testing.T, before, after *syscall.Stat_t) {
	t.Helper()
	if before.Uid != after.Uid || before.Gid != after.Gid {
		t.Fatalf("ownership changed from %d:%d to %d:%d", before.Uid, before.Gid, after.Uid, after.Gid)
	}
	if os.FileMode(before.Mode).Perm() != os.FileMode(after.Mode).Perm() {
		t.Fatalf("mode changed from %v to %v", os.FileMode(before.Mode).Perm(), os.FileMode(after.Mode).Perm())
	}
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
	return projectBlockWithAllow(alias, approvalLine, []string{"/usr/bin/true"})
}

func projectBlockWithAllow(alias, approvalLine string, entries ...[]string) string {
	approval := ""
	if approvalLine != "" {
		approval = approvalLine + "\n"
	}
	block := fmt.Sprintf(`[[projects]]
alias = %q
bws_project_id = "00000000-0000-0000-0000-000000000000"
token_entry = %q
working_dir = "/tmp"
%s`, alias, alias, approval)
	for _, argv := range entries {
		encoded, err := json.Marshal(argv)
		if err != nil {
			panic(err)
		}
		block += fmt.Sprintf("\n  [[projects.allow]]\n  argv = %s\n", encoded)
	}
	return block
}
