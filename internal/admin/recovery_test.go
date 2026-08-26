package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/R055LE/secrets-broker/internal/config"
)

func TestEditorRemovesCanonicalProjectAndPublishesRecovery(t *testing.T) {
	tests := []struct {
		name  string
		alias string
	}{
		{name: "first", alias: "alpha"},
		{name: "middle", alias: "beta"},
		{name: "last", alias: "gamma"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocks := []string{
				projectBlockWithAllow("alpha", `approval = "never"`, []string{"/usr/bin/true"}),
				projectBlockWithAllow("beta", `approval = "allowlisted-prompt"`, []string{"/usr/bin/printf", "quoted value"}),
				projectBlockWithAllow("gamma", `approval = "never"`, []string{"/usr/bin/false"}),
			}
			blocks[1] = strings.Replace(blocks[1], "[[projects]]", "[[projects]] # selected block\n# selected comment", 1)
			original := policyWithProjects(blocks...)
			path := writePolicy(t, original)
			recoveryDir := writeRecoveryDir(t)
			editor := NewRecoveryEditor(path, recoveryDir, uint32(os.Geteuid()), uint32(os.Getegid()))
			before := statFile(t, path)

			result, err := editor.RemoveProject(tt.alias, tt.alias, strings.Repeat("a", 32))
			if err != nil {
				t.Fatalf("RemoveProject: %v", err)
			}
			if !result.Changed || result.RecoveryID != strings.Repeat("a", 32) {
				t.Fatalf("result = %#v", result)
			}

			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read policy: %v", err)
			}
			want := removeProjectBytesForTest(t, []byte(original), tt.alias)
			if !bytes.Equal(got, want) {
				t.Fatalf("updated policy differs\ngot:\n%s\nwant:\n%s", got, want)
			}
			assertMetadataPreserved(t, before, statFile(t, path))

			artifact, err := NewRecoveryStore(
				recoveryDir,
				uint32(os.Geteuid()),
				uint32(os.Getegid()),
			).Read(result.RecoveryID)
			if err != nil {
				t.Fatalf("Read recovery: %v", err)
			}
			if artifact.Project != tt.alias || !bytes.Equal(artifact.Policy, []byte(original)) {
				t.Fatalf("artifact = %#v", artifact)
			}
			if artifact.BeforeSHA256 != digestBytes([]byte(original)) || artifact.AfterSHA256 != digestBytes(want) {
				t.Fatalf("artifact digests = %q %q", artifact.BeforeSHA256, artifact.AfterSHA256)
			}
			info, err := os.Lstat(filepath.Join(recoveryDir, result.RecoveryID))
			if err != nil {
				t.Fatalf("stat artifact: %v", err)
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatalf("artifact mode = %v", info.Mode())
			}
		})
	}
}

func TestEditorRemovalPreservesLineEndingsAndFinalNewline(t *testing.T) {
	for _, tt := range []struct {
		name      string
		transform func(string) string
	}{
		{name: "LF", transform: func(s string) string { return s }},
		{name: "CRLF", transform: func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }},
		{name: "no final newline", transform: func(s string) string { return strings.TrimSuffix(s, "\n") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			alpha := projectBlock("alpha", `approval = "never"`)
			beta := projectBlock("beta", `approval = "never"`)
			original := tt.transform(policyWithProjects(alpha, beta))
			want := tt.transform(policyWithProjects(beta))
			path := writePolicy(t, original)
			editor := NewRecoveryEditor(
				path,
				writeRecoveryDir(t),
				uint32(os.Geteuid()),
				uint32(os.Getegid()),
			)

			if _, err := editor.RemoveProject("alpha", "alpha", strings.Repeat("b", 32)); err != nil {
				t.Fatalf("RemoveProject: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read policy: %v", err)
			}
			if !bytes.Equal(got, []byte(want)) {
				t.Fatalf("policy bytes differ\ngot: %q\nwant: %q", got, want)
			}
		})
	}
}

func TestEditorRemovalRejectsWithoutArtifactOrPolicyChange(t *testing.T) {
	tests := []struct {
		name         string
		alias        string
		confirmation string
		contents     string
		want         string
	}{
		{
			name:         "missing confirmation",
			alias:        "alpha",
			confirmation: "",
			contents: policyWithProjects(
				projectBlock("alpha", `approval = "never"`),
				projectBlock("beta", `approval = "never"`),
			),
			want: "confirmation is required",
		},
		{
			name:         "mismatched confirmation",
			alias:        "alpha",
			confirmation: "beta",
			contents:     policyWithProjects(projectBlock("alpha", `approval = "never"`), projectBlock("beta", `approval = "never"`)),
			want:         "confirmation",
		},
		{
			name:         "unknown alias",
			alias:        "missing",
			confirmation: "missing",
			contents:     policyWithProjects(projectBlock("alpha", `approval = "never"`), projectBlock("beta", `approval = "never"`)),
			want:         "unknown project",
		},
		{
			name:         "last project",
			alias:        "alpha",
			confirmation: "alpha",
			contents:     policyWithProjects(projectBlock("alpha", `approval = "never"`)),
			want:         "last configured project",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writePolicy(t, tt.contents)
			recoveryDir := writeRecoveryDir(t)
			editor := NewRecoveryEditor(path, recoveryDir, uint32(os.Geteuid()), uint32(os.Getegid()))

			result, err := editor.RemoveProject(tt.alias, tt.confirmation, strings.Repeat("c", 32))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("result = %#v, error = %v, want containing %q", result, err, tt.want)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatalf("read policy: %v", readErr)
			}
			if string(got) != tt.contents {
				t.Fatal("policy changed after rejected removal")
			}
			entries, readErr := os.ReadDir(recoveryDir)
			if readErr != nil {
				t.Fatalf("read recovery directory: %v", readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("recovery artifacts created: %v", entries)
			}
		})
	}
}

func TestEditorRestoreRejectsMissingConfirmationBeforeRecoveryRead(t *testing.T) {
	path := writePolicy(t, policyWithProjects(projectBlock("alpha", `approval = "never"`)))
	editor := newEditorWithRecovery(path, uint32(os.Geteuid()), &barrierRecoveryStore{})

	if _, err := editor.RestoreProject(strings.Repeat("a", 32), ""); err == nil ||
		!strings.Contains(err.Error(), "confirmation is required") {
		t.Fatalf("missing confirmation error = %v", err)
	}
}

func TestEditorRestoreRequiresExactPostRemovalPolicy(t *testing.T) {
	original := policyWithProjects(
		projectBlock("alpha", `approval = "never"`),
		projectBlock("beta", `approval = "allowlisted-prompt"`),
	)
	path := writePolicy(t, original)
	recoveryDir := writeRecoveryDir(t)
	editor := NewRecoveryEditor(path, recoveryDir, uint32(os.Geteuid()), uint32(os.Getegid()))
	id := strings.Repeat("d", 32)
	if _, err := editor.RemoveProject("beta", "beta", id); err != nil {
		t.Fatalf("RemoveProject: %v", err)
	}
	removed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read removed policy: %v", err)
	}
	before := statFile(t, path)

	result, err := editor.RestoreProject(id, "beta")
	if err != nil {
		t.Fatalf("RestoreProject: %v", err)
	}
	if !result.Changed || result.RecoveryID != id {
		t.Fatalf("result = %#v", result)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read restored policy: %v", err)
	}
	if !bytes.Equal(got, []byte(original)) {
		t.Fatalf("restored policy differs\ngot:\n%s\nwant:\n%s", got, original)
	}
	assertMetadataPreserved(t, before, statFile(t, path))
	if _, err := os.Stat(filepath.Join(recoveryDir, id)); err != nil {
		t.Fatalf("artifact was not retained: %v", err)
	}

	if err := os.WriteFile(path, append(removed, []byte("# later edit\n")...), 0o640); err != nil {
		t.Fatalf("mutate policy: %v", err)
	}
	if _, err := editor.RestoreProject(id, "beta"); err == nil || !strings.Contains(err.Error(), "changed since removal") {
		t.Fatalf("mutation restore error = %v", err)
	}
}

func TestRecoveryStoreRejectsUnsafeArtifactsAndCollisions(t *testing.T) {
	dir := writeRecoveryDir(t)
	store := NewRecoveryStore(dir, uint32(os.Geteuid()), uint32(os.Getegid()))
	id := strings.Repeat("e", 32)
	input := RecoveryArtifactInput{
		RecoveryID: id,
		Project:    "beta",
		Before:     []byte("before"),
		After:      []byte("after"),
	}
	if err := store.Publish(input); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	original, err := os.ReadFile(filepath.Join(dir, id))
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	if err := store.Publish(input); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("collision error = %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, id))
	if err != nil {
		t.Fatalf("read artifact after collision: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("collision overwrote artifact")
	}

	if _, err := store.Read("../policy.toml"); err == nil {
		t.Fatal("path traversal ID was accepted")
	}
	unsafeID := strings.Repeat("f", 32)
	if err := os.Symlink(filepath.Join(dir, id), filepath.Join(dir, unsafeID)); err != nil {
		t.Fatalf("create artifact symlink: %v", err)
	}
	if _, err := store.Read(unsafeID); err == nil {
		t.Fatal("artifact symlink was accepted")
	}
}

func TestRecoveryStorePublishesExactPrivateVersionedArtifact(t *testing.T) {
	dir := writeRecoveryDir(t)
	store := NewRecoveryStore(dir, uint32(os.Geteuid()), uint32(os.Getegid()))
	store.now = fixedRecoveryTime
	id := strings.Repeat("0", 32)
	input := RecoveryArtifactInput{
		RecoveryID: id,
		Project:    "beta",
		Before:     []byte("private policy bytes"),
		After:      []byte("remaining policy bytes"),
	}
	if err := store.Publish(input); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	path := filepath.Join(dir, id)
	uid, gid, mode := recoveryFileMetadata(t, path)
	if uid != uint32(os.Geteuid()) || gid != uint32(os.Getegid()) || mode != 0o600 {
		t.Fatalf("artifact metadata = %d:%d:%o", uid, gid, mode)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	if bytes.Contains(raw, input.Before) {
		t.Fatalf("artifact policy was not JSON base64 encoded: %s", raw)
	}
	var artifact RecoveryArtifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatalf("decode artifact: %v", err)
	}
	if artifact.Version != recoveryArtifactVersion || artifact.CreatedAt != fixedRecoveryTime() {
		t.Fatalf("artifact version or time = %#v", artifact)
	}

	summaries, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []RecoverySummary{{RecoveryID: id, Project: "beta", CreatedAt: fixedRecoveryTime()}}
	if !reflect.DeepEqual(summaries, want) {
		t.Fatalf("summaries = %#v, want %#v", summaries, want)
	}
}

func TestRecoveryStorePublishFailuresLeaveNoArtifact(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RecoveryStore)
	}{
		{
			name: "short write",
			mutate: func(store *RecoveryStore) {
				store.writeFile = func(*os.File, []byte) error { return io.ErrShortWrite }
			},
		},
		{
			name: "file sync",
			mutate: func(store *RecoveryStore) {
				store.syncFile = func(*os.File) error { return errors.New("sync failed") }
			},
		},
		{
			name: "directory sync",
			mutate: func(store *RecoveryStore) {
				store.syncDir = func(string) error { return errors.New("sync failed") }
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeRecoveryDir(t)
			store := NewRecoveryStore(dir, uint32(os.Geteuid()), uint32(os.Getegid()))
			tt.mutate(store)
			err := store.Publish(RecoveryArtifactInput{
				RecoveryID: strings.Repeat("1", 32),
				Project:    "beta",
				Before:     []byte("before"),
				After:      []byte("after"),
			})
			if err == nil {
				t.Fatal("expected publication to fail")
			}
			entries, readErr := os.ReadDir(dir)
			if readErr != nil {
				t.Fatalf("read recovery directory: %v", readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("failed publication left files: %v", entries)
			}
		})
	}
}

func TestEditorArtifactFailureLeavesPolicyUnchanged(t *testing.T) {
	original := policyWithProjects(
		projectBlock("alpha", `approval = "never"`),
		projectBlock("beta", `approval = "never"`),
	)
	path := writePolicy(t, original)
	dir := writeRecoveryDir(t)
	store := NewRecoveryStore(dir, uint32(os.Geteuid()), uint32(os.Getegid()))
	store.syncFile = func(*os.File) error { return errors.New("sync failed") }
	editor := newEditorWithRecovery(path, uint32(os.Geteuid()), store)

	result, err := editor.RemoveProject("beta", "beta", strings.Repeat("8", 32))
	if err == nil || result != (RecoveryResult{}) {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read policy: %v", readErr)
	}
	if string(got) != original {
		t.Fatal("artifact failure changed policy")
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("read recovery directory: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("artifact failure left files: %v", entries)
	}
}

func TestEditorRestoreRejectsInvalidOrOverbroadSnapshot(t *testing.T) {
	current := []byte(policyWithProjects(projectBlock("alpha", `approval = "never"`)))
	tests := []struct {
		name    string
		project string
		before  []byte
		want    string
	}{
		{
			name:    "invalid stored policy",
			project: "beta",
			before:  []byte("not a policy"),
			want:    "validating stored policy",
		},
		{
			name:    "more than one project difference",
			project: "beta",
			before: []byte(policyWithProjects(
				projectBlock("alpha", `approval = "never"`),
				projectBlock("beta", `approval = "never"`),
				projectBlock("gamma", `approval = "never"`),
			)),
			want: "does not differ by exactly",
		},
	}
	for index, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writePolicy(t, string(current))
			dir := writeRecoveryDir(t)
			store := NewRecoveryStore(dir, uint32(os.Geteuid()), uint32(os.Getegid()))
			id := strings.Repeat([]string{"9", "a"}[index], 32)
			if err := store.Publish(RecoveryArtifactInput{
				RecoveryID: id,
				Project:    tt.project,
				Before:     tt.before,
				After:      current,
			}); err != nil {
				t.Fatalf("Publish: %v", err)
			}
			editor := newEditorWithRecovery(path, uint32(os.Geteuid()), store)

			if _, err := editor.RestoreProject(id, tt.project); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("restore error = %v, want containing %q", err, tt.want)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatalf("read policy: %v", readErr)
			}
			if !bytes.Equal(got, current) {
				t.Fatal("rejected recovery changed policy")
			}
		})
	}
}

func TestRecoveryStoreRejectsUnsafeDirectoryAndMalformedListing(t *testing.T) {
	dir := writeRecoveryDir(t)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("open recovery directory: %v", err)
	}
	store := NewRecoveryStore(dir, uint32(os.Geteuid()), uint32(os.Getegid()))
	if err := store.Publish(RecoveryArtifactInput{RecoveryID: strings.Repeat("2", 32), Project: "beta"}); err == nil {
		t.Fatal("open recovery directory was accepted")
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("restore recovery directory mode: %v", err)
	}
	malformedID := strings.Repeat("3", 32)
	if err := os.WriteFile(filepath.Join(dir, malformedID), []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write malformed artifact: %v", err)
	}
	if _, err := store.List(); err == nil {
		t.Fatal("malformed artifact was silently ignored")
	}
}

func TestEditorRemovalRejectsAlternateValidProjectLayout(t *testing.T) {
	contents := `projects = [
  { alias = "alpha", bws_project_id = "00000000-0000-0000-0000-000000000000", token_entry = "alpha", working_dir = "/tmp", approval = "never" },
  { alias = "beta", bws_project_id = "11111111-1111-1111-1111-111111111111", token_entry = "beta", working_dir = "/tmp", approval = "never" },
]

[runtime]
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
`
	path := writePolicy(t, contents)
	recoveryDir := writeRecoveryDir(t)
	editor := NewRecoveryEditor(path, recoveryDir, uint32(os.Geteuid()), uint32(os.Getegid()))

	if _, err := editor.RemoveProject("alpha", "alpha", strings.Repeat("4", 32)); err == nil ||
		!strings.Contains(err.Error(), "layout is not editable") {
		t.Fatalf("alternate layout error = %v", err)
	}
	entries, err := os.ReadDir(recoveryDir)
	if err != nil {
		t.Fatalf("read recovery directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("alternate layout created artifacts: %v", entries)
	}
}

func TestRemovalConcurrentReplacementWinsAndLeavesPreparedArtifact(t *testing.T) {
	original := policyWithProjects(
		projectBlock("alpha", `approval = "never"`),
		projectBlock("beta", `approval = "never"`),
	)
	concurrent := policyWithProjects(
		projectBlock("alpha", `approval = "allowlisted-prompt"`),
		projectBlock("beta", `approval = "never"`),
	)
	path := writePolicy(t, original)
	recoveryDir := writeRecoveryDir(t)
	editor := NewRecoveryEditor(path, recoveryDir, uint32(os.Geteuid()), uint32(os.Getegid()))
	editor.beforeWrite = func() { replacePolicyForTest(t, path, concurrent) }
	id := strings.Repeat("5", 32)

	result, err := editor.RemoveProject("beta", "beta", id)
	if err == nil || result.Changed || result.RecoveryID != id {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read policy: %v", readErr)
	}
	if string(got) != concurrent {
		t.Fatal("removal overwrote the concurrent policy")
	}
	if _, readErr := os.Stat(filepath.Join(recoveryDir, id)); readErr != nil {
		t.Fatalf("prepared artifact missing: %v", readErr)
	}
}

func TestRestoreConcurrentReplacementWins(t *testing.T) {
	original := policyWithProjects(
		projectBlock("alpha", `approval = "never"`),
		projectBlock("beta", `approval = "never"`),
	)
	concurrent := policyWithProjects(projectBlock("alpha", `approval = "allowlisted-prompt"`))
	path := writePolicy(t, original)
	recoveryDir := writeRecoveryDir(t)
	editor := NewRecoveryEditor(path, recoveryDir, uint32(os.Geteuid()), uint32(os.Getegid()))
	id := strings.Repeat("6", 32)
	if _, err := editor.RemoveProject("beta", "beta", id); err != nil {
		t.Fatalf("RemoveProject: %v", err)
	}
	editor.beforeWrite = func() { replacePolicyForTest(t, path, concurrent) }

	result, err := editor.RestoreProject(id, "beta")
	if err == nil || result.Changed {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read policy: %v", readErr)
	}
	if string(got) != concurrent {
		t.Fatal("restore overwrote the concurrent policy")
	}
}

func TestConcurrentRemovalsPublishDistinctArtifactsButOnePolicyWins(t *testing.T) {
	original := policyWithProjects(
		projectBlock("alpha", `approval = "never"`),
		projectBlock("beta", `approval = "never"`),
		projectBlock("gamma", `approval = "never"`),
	)
	path := writePolicy(t, original)
	store := &barrierRecoveryStore{waitFor: 2, ready: make(chan struct{})}
	editor := newEditorWithRecovery(path, uint32(os.Geteuid()), store)

	type outcome struct {
		result RecoveryResult
		err    error
	}
	outcomes := make(chan outcome, 2)
	var wg sync.WaitGroup
	for i, alias := range []string{"alpha", "beta"} {
		wg.Add(1)
		go func(index int, project string) {
			defer wg.Done()
			result, err := editor.RemoveProject(project, project, strings.Repeat(string(rune('1'+index)), 32))
			outcomes <- outcome{result: result, err: err}
		}(i, alias)
	}
	wg.Wait()
	close(outcomes)

	changed := 0
	failed := 0
	for outcome := range outcomes {
		if outcome.result.Changed {
			changed++
		} else if outcome.err != nil {
			failed++
		}
	}
	if changed != 1 || failed != 1 {
		t.Fatalf("changed = %d, failed = %d", changed, failed)
	}
	if got := store.publishedIDs(); !reflect.DeepEqual(got, []string{strings.Repeat("1", 32), strings.Repeat("2", 32)}) {
		t.Fatalf("published IDs = %v", got)
	}
}

func TestConcurrentRestoresAllowOnePolicyReplacement(t *testing.T) {
	original := []byte(policyWithProjects(
		projectBlock("alpha", `approval = "never"`),
		projectBlock("beta", `approval = "never"`),
	))
	removed := removeProjectBytesForTest(t, original, "beta")
	id := strings.Repeat("7", 32)
	store := &barrierReadRecoveryStore{
		artifact: RecoveryArtifact{
			Version:      recoveryArtifactVersion,
			RecoveryID:   id,
			CreatedAt:    fixedRecoveryTime(),
			Project:      "beta",
			BeforeSHA256: digestBytes(original),
			AfterSHA256:  digestBytes(removed),
			Policy:       original,
		},
		waitFor: 2,
		ready:   make(chan struct{}),
	}
	path := writePolicy(t, string(removed))
	editor := newEditorWithRecovery(path, uint32(os.Geteuid()), store)

	type outcome struct {
		result RecoveryResult
		err    error
	}
	outcomes := make(chan outcome, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := editor.RestoreProject(id, "beta")
			outcomes <- outcome{result: result, err: err}
		}()
	}
	wg.Wait()
	close(outcomes)

	changed := 0
	failed := 0
	for outcome := range outcomes {
		if outcome.result.Changed {
			changed++
		} else if outcome.err != nil {
			failed++
		}
	}
	if changed != 1 || failed != 1 {
		t.Fatalf("changed = %d, failed = %d", changed, failed)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("concurrent restore did not leave the exact original policy")
	}
}

type barrierRecoveryStore struct {
	mu      sync.Mutex
	inputs  []RecoveryArtifactInput
	waitFor int
	ready   chan struct{}
}

type barrierReadRecoveryStore struct {
	mu       sync.Mutex
	artifact RecoveryArtifact
	reads    int
	waitFor  int
	ready    chan struct{}
}

func (s *barrierReadRecoveryStore) Publish(RecoveryArtifactInput) error {
	return errors.New("unexpected Publish call")
}

func (s *barrierReadRecoveryStore) List() ([]RecoverySummary, error) {
	return nil, errors.New("unexpected List call")
}

func (s *barrierReadRecoveryStore) Read(string) (RecoveryArtifact, error) {
	s.mu.Lock()
	s.reads++
	if s.reads == s.waitFor {
		close(s.ready)
	}
	s.mu.Unlock()
	<-s.ready
	return s.artifact, nil
}

func (s *barrierRecoveryStore) Publish(input RecoveryArtifactInput) error {
	s.mu.Lock()
	s.inputs = append(s.inputs, input)
	if len(s.inputs) == s.waitFor {
		close(s.ready)
	}
	s.mu.Unlock()
	<-s.ready
	return nil
}

func (s *barrierRecoveryStore) List() ([]RecoverySummary, error) {
	return nil, errors.New("unexpected List call")
}

func (s *barrierRecoveryStore) Read(string) (RecoveryArtifact, error) {
	return RecoveryArtifact{}, errors.New("unexpected Read call")
}

func (s *barrierRecoveryStore) publishedIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, len(s.inputs))
	for i, input := range s.inputs {
		ids[i] = input.RecoveryID
	}
	sort.Strings(ids)
	return ids
}

func writeRecoveryDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "recovery")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("create recovery directory: %v", err)
	}
	return dir
}

func recoveryFileMetadata(t *testing.T, path string) (uint32, uint32, os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat recovery artifact: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("unexpected recovery stat type")
	}
	return stat.Uid, stat.Gid, info.Mode().Perm()
}

func fixedRecoveryTime() time.Time {
	return time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
}

func removeProjectBytesForTest(t *testing.T, data []byte, alias string) []byte {
	t.Helper()
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatalf("parse test policy: %v", err)
	}
	index, err := findProject(cfg, alias)
	if err != nil {
		t.Fatalf("find test project: %v", err)
	}
	headers := projectHeaderPattern.FindAllIndex(data, -1)
	end := len(data)
	if index+1 < len(headers) {
		end = headers[index+1][0]
	}
	result := append([]byte(nil), data[:headers[index][0]]...)
	return append(result, data[end:]...)
}

func replacePolicyForTest(t *testing.T, path, contents string) {
	t.Helper()
	temp, err := os.CreateTemp(filepath.Dir(path), ".concurrent-policy-*")
	if err != nil {
		t.Fatalf("create concurrent policy: %v", err)
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if err := temp.Chmod(0o640); err != nil {
		t.Fatalf("chmod concurrent policy: %v", err)
	}
	if _, err := temp.WriteString(contents); err != nil {
		t.Fatalf("write concurrent policy: %v", err)
	}
	if err := temp.Close(); err != nil {
		t.Fatalf("close concurrent policy: %v", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		t.Fatalf("replace concurrent policy: %v", err)
	}
}
