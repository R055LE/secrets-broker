package adminweb

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/R055LE/secrets-broker/internal/accessdiag"
	"github.com/R055LE/secrets-broker/internal/admin"
	"github.com/R055LE/secrets-broker/internal/projectlist"
)

const webTestPolicy = `[runtime]
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
[[projects]]
alias = "existing"
bws_project_id = "existing-id"
token_entry = "token-id"
working_dir = "/work/existing"
approval = "allowlisted-prompt"
`

func controlHarness(t *testing.T) (*Server, *admin.Editor, *pageLogger) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(path, []byte(webTestPolicy), 0o640); err != nil {
		t.Fatal(err)
	}
	editor := admin.NewEditor(path, uint32(os.Getuid()))
	s, _, _, logger := pageHarness()
	s.reader, s.revision = editor, editor.Revision
	s.edit = func(revision string) policyMutator {
		return admin.NewAuditedEditor(editor.WithRevision(revision), s.logger, 0)
	}
	s.available = []projectlist.Project{{ID: "project-id", Name: "Example project"}}
	s.availableUntil = time.Now().Add(10 * time.Minute)
	return s, editor, logger
}

func reviewForm(t *testing.T, s *Server, kind string, fields url.Values) *httptest.ResponseRecorder {
	t.Helper()
	revision, err := s.revision()
	if err != nil {
		t.Fatal(err)
	}
	target := fields.Get("alias")
	if kind == "create" {
		target = ""
	}
	token, err := s.issueTargetToken(kind, revision, target)
	if err != nil {
		t.Fatal(err)
	}
	fields.Set("csrf", token)
	return response(s, request("POST", "/projects/"+kind, fields.Encode()))
}

var csrfPattern = regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`)

func commitForm(t *testing.T, s *Server, review *httptest.ResponseRecorder, alias string, confirm bool) *httptest.ResponseRecorder {
	t.Helper()
	match := csrfPattern.FindStringSubmatch(review.Body.String())
	if review.Code != 200 || len(match) != 2 {
		t.Fatalf("review failed: %d %s", review.Code, review.Body.String())
	}
	fields := url.Values{"csrf": {match[1]}, "alias": {alias}}
	if confirm {
		fields.Set("confirm", "yes")
	}
	return response(s, request("POST", "/projects/commit", fields.Encode()))
}

func createFields() url.Values {
	return url.Values{"alias": {"demo"}, "project_id": {"project-id"}, "token_entry": {"token-id"}, "working_dir": {"/work/demo"}}
}

func createWebProject(t *testing.T, s *Server) {
	t.Helper()
	if w := commitForm(t, s, reviewForm(t, s, "create", createFields()), "demo", false); w.Code != 200 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
}

func TestGuidedCreateUsesSafeDefaultsAndReviewedValues(t *testing.T) {
	s, editor, logger := controlHarness(t)
	review := reviewForm(t, s, "create", createFields())
	if logger.starts != 0 || !strings.Contains(review.Body.String(), "confirm mode with an empty allowlist") {
		t.Fatal("review mutated policy or omitted defaults")
	}
	w := commitForm(t, s, review, "demo", false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Local project created") {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	detail, err := editor.GetProject("demo")
	if err != nil || detail.Mode != admin.ModeConfirm || len(detail.Allow) != 0 || detail.BWSProjectID != "project-id" {
		t.Fatalf("unsafe create: %#v %v", detail, err)
	}
	if logger.start.Operation != admin.MutationCreateProject || logger.start.ActorLogin != testConfig.Login || logger.finish.ActorLogin != testConfig.Login {
		t.Fatal("creation attribution missing")
	}
	if w := commitForm(t, s, review, "demo", false); w.Code != 403 || logger.starts != 1 {
		t.Fatal("replayed create ran again")
	}
	if w := reviewForm(t, s, "create", createFields()); w.Code != 400 {
		t.Fatal("duplicate alias accepted")
	}
}

func TestCreateRejectsIncompleteUnavailableAndOverriddenInputs(t *testing.T) {
	for _, invalid := range []string{"alias", "token_entry", "working_dir", "project_id", "relative", "override", "expired"} {
		s, editor, logger := controlHarness(t)
		fields := createFields()
		switch invalid {
		case "relative":
			fields.Set("working_dir", "relative")
		case "override":
			fields.Set("mode", "automatic")
		case "expired":
			s.availableUntil = time.Time{}
		default:
			fields.Set(invalid, "")
		}
		if w := reviewForm(t, s, "create", fields); w.Code < 400 {
			t.Fatalf("accepted %s", invalid)
		}
		projects, _ := editor.ListProjects()
		if len(projects) != 1 || logger.starts != 0 {
			t.Fatal("invalid create changed policy")
		}
	}
}

func TestMetadataAndApprovalRequireReviewAndConfirmation(t *testing.T) {
	s, editor, logger := controlHarness(t)
	createWebProject(t, s)
	fields := createFields()
	fields.Set("working_dir", "/work/changed")
	review := reviewForm(t, s, "metadata", fields)
	if !strings.Contains(review.Body.String(), "/work/demo") || !strings.Contains(review.Body.String(), "/work/changed") {
		t.Fatal("current and proposed metadata missing")
	}
	if w := commitForm(t, s, review, "demo", false); w.Code != 400 {
		t.Fatal("metadata changed without confirmation")
	}
	review = reviewForm(t, s, "metadata", fields)
	if w := commitForm(t, s, review, "demo", true); w.Code != 200 {
		t.Fatalf("metadata failed: %d %s", w.Code, w.Body.String())
	}
	detail, _ := editor.GetProject("demo")
	if detail.WorkingDir != "/work/changed" || detail.TokenEntry != "token-id" || detail.Mode != admin.ModeConfirm || !slices.Equal(logger.start.Fields, []string{"working_dir"}) {
		t.Fatal("metadata changed unrelated fields")
	}
	mode := url.Values{"alias": {"demo"}, "mode": {"automatic"}}
	if w := commitForm(t, s, reviewForm(t, s, "mode", mode), "demo", false); w.Code != 400 {
		t.Fatal("automatic mode changed without confirmation")
	}
	if w := commitForm(t, s, reviewForm(t, s, "mode", mode), "demo", true); w.Code != 200 {
		t.Fatal("confirmed automatic mode failed")
	}
	detail, _ = editor.GetProject("demo")
	if detail.Mode != admin.ModeAutomatic {
		t.Fatal("mode not saved")
	}
	if w := commitForm(t, s, reviewForm(t, s, "mode", mode), "demo", false); w.Code != 200 || logger.finish.Outcome != admin.MutationNoChange {
		t.Fatal("mode no-op failed")
	}
}

func TestExactArgumentsPreserveSpacesQuotesEmptyAndRemoval(t *testing.T) {
	s, editor, logger := controlHarness(t)
	createWebProject(t, s)
	argv := []string{"/usr/bin/tool", "two words", `"literal quotes"`, "", "$(literal)"}
	fields := url.Values{"alias": {"demo"}, "argv": argv}
	if w := commitForm(t, s, reviewForm(t, s, "add", fields), "demo", false); w.Code != 400 {
		t.Fatal("added command without confirmation")
	}
	if w := commitForm(t, s, reviewForm(t, s, "add", fields), "demo", true); w.Code != 200 {
		t.Fatalf("add failed: %d %s", w.Code, w.Body.String())
	}
	detail, _ := editor.GetProject("demo")
	if len(detail.Allow) != 1 || !slices.Equal(detail.Allow[0], argv) {
		t.Fatalf("arguments changed: %#v", detail.Allow)
	}
	if w := commitForm(t, s, reviewForm(t, s, "add", fields), "demo", true); w.Code != 200 || logger.finish.Outcome != admin.MutationNoChange {
		t.Fatal("duplicate argv was not a no-op")
	}
	if w := reviewForm(t, s, "add", url.Values{"alias": {"demo"}}); w.Code != 400 {
		t.Fatal("missing argv accepted")
	}
	if w := commitForm(t, s, reviewForm(t, s, "remove", url.Values{"alias": {"demo"}, "entry": {"0"}}), "demo", false); w.Code != 200 {
		t.Fatal("removal failed")
	}
	detail, _ = editor.GetProject("demo")
	if len(detail.Allow) != 0 {
		t.Fatal("exact entry remained")
	}
	if w := reviewForm(t, s, "remove", url.Values{"alias": {"demo"}, "entry": {"0"}}); w.Code != 400 {
		t.Fatal("missing entry accepted")
	}
}

func TestCommitRejectsPolicyChangeEvenAfterHTTPRevisionCheck(t *testing.T) {
	s, editor, logger := controlHarness(t)
	createWebProject(t, s)
	review := reviewForm(t, s, "add", url.Values{"alias": {"demo"}, "argv": {"/usr/bin/tool"}})
	originalFactory := s.edit
	s.edit = func(revision string) policyMutator {
		if _, err := editor.SetApproval("demo", "automatic"); err != nil {
			t.Fatal(err)
		}
		return originalFactory(revision)
	}
	w := commitForm(t, s, review, "demo", true)
	detail, _ := editor.GetProject("demo")
	if w.Code != 409 || len(detail.Allow) != 0 || logger.finish.Outcome != admin.MutationFailed {
		t.Fatal("stale edit reached newer policy")
	}
}

func TestMutationAuditFailureNeverClaimsSuccess(t *testing.T) {
	for _, failure := range []string{"start", "finish"} {
		s, editor, logger := controlHarness(t)
		review := reviewForm(t, s, "create", createFields())
		if failure == "start" {
			logger.startErr = errors.New("private-audit-error")
		} else {
			logger.finishErr = errors.New("private-audit-error")
		}
		w := commitForm(t, s, review, "demo", false)
		projects, _ := editor.ListProjects()
		if w.Code != 503 || strings.Contains(w.Body.String(), "private-audit-error") || strings.Contains(w.Body.String(), "Local project created") {
			t.Fatal("audit failure claimed success or exposed error")
		}
		if failure == "start" && len(projects) != 1 {
			t.Fatal("write followed audit-start failure")
		}
		if failure == "finish" && (len(projects) != 2 || !strings.Contains(w.Body.String(), "Policy changed, but audit completion failed")) {
			t.Fatal("changed policy not disclosed")
		}
	}
}

func TestPolicyViewCannotBindOldValuesToNewRevision(t *testing.T) {
	s, _, _ := controlHarness(t)
	calls := 0
	s.revision = func() (string, error) {
		calls++
		if calls == 1 {
			return "old", nil
		}
		return "new", nil
	}
	if w := response(s, request("GET", "/", "")); w.Code != 503 || len(s.tokens) != 0 {
		t.Fatal("inconsistent policy view issued a form")
	}
}

// This fixture uses disposable policy and fake Bitwarden metadata for browser acceptance.
func TestBrowserFixture(t *testing.T) {
	if os.Getenv("SECRETS_BROKER_BROWSER_FIXTURE") != "1" {
		t.Skip("interactive browser fixture")
	}
	s, _, _ := controlHarness(t)
	s.available = nil
	checker := &pageChecker{list: projectlist.Result{Version: 1, Projects: []projectlist.Project{{ID: "project-id", Name: "Example project"}}}, access: accessdiag.Result{Version: 1, Outcome: accessdiag.OutcomeInaccessible, Projects: []accessdiag.ProjectResult{{Alias: "demo", BWSProjectID: "project-id", Status: accessdiag.StatusInaccessible}}}}
	s.access = admin.NewAuditedAccessDiagnostic(checker, s.logger, 0)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Tailscale-User-Login", testConfig.Login)
		s.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), peerKey{}, true)))
	}))
	s.cfg.Host = server.Listener.Addr().String()
	server.StartTLS()
	defer server.Close()
	t.Logf("Browser fixture: %s", server.URL)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(stop)
	<-stop
}
