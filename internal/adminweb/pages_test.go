package adminweb

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/R055LE/secrets-broker/internal/accessdiag"
	"github.com/R055LE/secrets-broker/internal/admin"
	"github.com/R055LE/secrets-broker/internal/projectlist"
)

type pageReader struct {
	detail     admin.ProjectDetail
	path       admin.PathCheckResult
	err        error
	pathCalls  int
	beforePath func()
}

func (p *pageReader) ListProjects() ([]admin.ProjectSummary, error) {
	if p.detail.Alias == "" {
		return nil, p.err
	}
	return []admin.ProjectSummary{{Alias: p.detail.Alias, Mode: p.detail.Mode, Behavior: p.detail.Behavior}}, p.err
}
func (p *pageReader) GetProject(string) (admin.ProjectDetail, error) { return p.detail, p.err }
func (p *pageReader) CheckProjectPath(context.Context, string) (admin.PathCheckResult, error) {
	if p.beforePath != nil {
		p.beforePath()
	}
	p.pathCalls++
	return p.path, p.err
}

type pageChecker struct {
	list   projectlist.Result
	access accessdiag.Result
	err    error
	calls  int
}

func (p *pageChecker) ListAvailable(context.Context) (projectlist.Result, error) {
	p.calls++
	return p.list, p.err
}
func (p *pageChecker) CheckAccess(context.Context, string) (accessdiag.Result, error) {
	p.calls++
	return p.access, p.err
}

type pageLogger struct {
	recordLogger
	startErr, finishErr error
	starts, finishes    int
}

func (l *pageLogger) Start(ctx context.Context, record admin.MutationStart) (string, error) {
	l.starts++
	id, _ := l.recordLogger.Start(ctx, record)
	return id, l.startErr
}
func (l *pageLogger) Finish(ctx context.Context, id string, record admin.MutationFinish) error {
	l.finishes++
	_ = l.recordLogger.Finish(ctx, id, record)
	return l.finishErr
}

func pageHarness() (*Server, *pageReader, *pageChecker, *pageLogger) {
	s := NewServer(testConfig)
	s.revision = func() (string, error) { return "current", nil }
	reader := &pageReader{detail: admin.ProjectDetail{Alias: "demo/<script>", BWSProjectID: "project-id", TokenEntry: "token-id", WorkingDir: "/work/<script>", Mode: "confirm", Behavior: "requires approval", Allow: [][]string{{"/usr/bin/tool", "two words", "<script>"}}}, path: admin.PathCheckResult{Resolution: admin.PathResolved, WorkerCanEnter: true, RunnerCanEnter: true}}
	checker := &pageChecker{list: projectlist.Result{Version: projectlist.Version, Projects: []projectlist.Project{{ID: "project-id", Name: "<script>project</script>"}}}}
	logger := &pageLogger{}
	s.reader = reader
	s.logger = actorLogger{logger: logger, login: testConfig.Login}
	s.access = admin.NewAuditedAccessDiagnostic(checker, s.logger, 0)
	return s, reader, checker, logger
}

func formRequest(t *testing.T, s *Server, action, alias string) *http.Request {
	t.Helper()
	token, err := s.issueTargetToken(action, "current", alias)
	if err != nil {
		t.Fatal(err)
	}
	return request("POST", "/projects/"+action, url.Values{"csrf": {token}, "alias": {alias}}.Encode())
}

func TestPagesShowEscapedMetadataWithoutDiagnostics(t *testing.T) {
	s, reader, checker, logger := pageHarness()
	s.cfg.ApprovalURL = "http://relay.example.ts.net:7621"
	for _, path := range []string{"/", "/projects/0", "/style.css"} {
		w := response(s, request("GET", path, ""))
		if w.Code != 200 || strings.Contains(w.Body.String(), "<script>") {
			t.Fatalf("unsafe page %s: %d %s", path, w.Code, w.Body.String())
		}
		if path == "/projects/0" {
			for _, text := range []string{"project-id", "token-id", "&lt;script&gt;", "<li><code>two words</code></li>", s.cfg.ApprovalURL} {
				if !strings.Contains(w.Body.String(), text) {
					t.Fatalf("missing %q", text)
				}
			}
		}
	}
	if checker.calls != 0 || reader.pathCalls != 0 || logger.starts != 0 {
		t.Fatal("GET performed a diagnostic")
	}
	for _, path := range []string{"/projects/-1", "/projects/1", "/projects/alias"} {
		if w := response(s, request("GET", path, "")); w.Code != 404 {
			t.Fatalf("bad index %s: %d", path, w.Code)
		}
	}
}

func TestDiscoveryIsAuditedEscapedAndExpires(t *testing.T) {
	s, _, checker, logger := pageHarness()
	now := time.Now()
	s.now = func() time.Time { return now }
	w := response(s, formRequest(t, s, "discover", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "&lt;script&gt;project") || strings.Contains(w.Body.String(), "<script>") {
		t.Fatalf("bad discovery: %d %s", w.Code, w.Body.String())
	}
	if checker.calls != 1 || logger.start.ActorUID != 0 || logger.start.ActorLogin != testConfig.Login || logger.finish.ActorLogin != testConfig.Login || logger.finish.Outcome != "listed" {
		t.Fatal("discovery attribution lost")
	}
	response(s, request("GET", "/", ""))
	if checker.calls != 1 {
		t.Fatal("GET repeated discovery")
	}
	now = now.Add(10 * time.Minute)
	if w := response(s, request("GET", "/", "")); strings.Contains(w.Body.String(), "&lt;script&gt;project") {
		t.Fatal("expired discovery shown")
	}
	checker.err = errors.New("private-error")
	w = response(s, formRequest(t, s, "discover", ""))
	if w.Code != 503 || len(s.available) != 0 || strings.Contains(w.Body.String(), "private-error") {
		t.Fatal("failed refresh exposed error or kept discovery")
	}
}

func TestPathCheckRequiresTargetAndSuccessfulAudit(t *testing.T) {
	for _, failure := range []string{"", "start", "finish"} {
		t.Run(failure, func(t *testing.T) {
			s, reader, _, logger := pageHarness()
			reader.beforePath = func() {
				if logger.starts != 1 {
					t.Fatal("path check preceded audit")
				}
			}
			if failure == "start" {
				logger.startErr = errors.New("private-error")
			}
			if failure == "finish" {
				logger.finishErr = errors.New("private-error")
			}
			w := response(s, formRequest(t, s, "path", reader.detail.Alias))
			if failure == "" {
				if w.Code != 200 || reader.pathCalls != 1 || logger.finish.Outcome != "ready" {
					t.Fatal("path result missing")
				}
			} else if w.Code != 503 || strings.Contains(w.Body.String(), "private-error") || strings.Contains(w.Body.String(), "Path resolution") {
				t.Fatal("audit failure reported success")
			}
			if failure == "start" && (reader.pathCalls != 0 || logger.finishes != 0) {
				t.Fatal("check continued after start failure")
			}
		})
	}
	s, reader, _, logger := pageHarness()
	r := formRequest(t, s, "path", reader.detail.Alias)
	_ = r.ParseForm()
	r.PostForm.Set("alias", "other")
	if w := response(s, r); w.Code != 403 || logger.starts != 0 {
		t.Fatal("token target changed")
	}
}

func TestAccessDistinguishesGrantDenialFromCheckFailure(t *testing.T) {
	for _, failure := range []string{"", "worker", "audit", "wrong project"} {
		s, reader, checker, logger := pageHarness()
		checker.access = accessdiag.Result{Version: accessdiag.Version, Outcome: accessdiag.OutcomeInaccessible, Projects: []accessdiag.ProjectResult{{Alias: reader.detail.Alias, BWSProjectID: "project-id", Status: accessdiag.StatusInaccessible}}}
		switch failure {
		case "worker":
			checker.err = errors.New("private-error")
		case "audit":
			logger.finishErr = errors.New("private-error")
		case "wrong project":
			checker.access.Projects[0].Alias = "other"
		}
		w := response(s, formRequest(t, s, "access", reader.detail.Alias))
		if failure == "" {
			if w.Code != 200 || !strings.Contains(w.Body.String(), "Review the machine account") || logger.finish.Outcome != "inaccessible" {
				t.Fatal("grant denial not explained")
			}
		} else if w.Code != 503 || strings.Contains(w.Body.String(), "Grant status:") || strings.Contains(w.Body.String(), "private-error") {
			t.Fatalf("failed %s check exposed result", failure)
		}
	}
}

func TestDiscoveryRejectsUnboundedResult(t *testing.T) {
	s, _, checker, _ := pageHarness()
	checker.list.Projects = make([]projectlist.Project, projectlist.MaxProjects+1)
	if w := response(s, formRequest(t, s, "discover", "")); w.Code != 503 || len(s.available) != 0 {
		t.Fatal("oversized discovery accepted")
	}
}
