package worker

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/R055LE/secrets-broker/internal/accessdiag"
	"github.com/R055LE/secrets-broker/internal/execx"
	"github.com/R055LE/secrets-broker/internal/token"
)

type accessResponse struct {
	exitCode int
	stdout   string
	stderr   string
	err      error
	wait     bool
}

type accessRunner struct {
	responses []accessResponse
	calls     []execx.Call
}

func (r *accessRunner) Run(context.Context, string, []string, []string) (execx.Result, error) {
	return execx.Result{}, errors.New("unexpected buffered execution")
}

func (r *accessRunner) RunPassthrough(
	ctx context.Context,
	name string,
	args, env []string,
	dir string,
	_ io.Reader,
	stdout, stderr io.Writer,
) (int, error) {
	r.calls = append(r.calls, execx.Call{
		Method: "RunPassthrough", Name: name, Args: append([]string(nil), args...),
		Env: append([]string(nil), env...), Dir: dir,
	})
	response := r.responses[len(r.calls)-1]
	if response.wait {
		<-ctx.Done()
		return -1, ctx.Err()
	}
	_, _ = io.WriteString(stdout, response.stdout)
	_, _ = io.WriteString(stderr, response.stderr)
	return response.exitCode, response.err
}

type recordingResolver struct {
	token   token.Token
	err     error
	entries []string
}

func (r *recordingResolver) Resolve(_ context.Context, entry string) (token.Token, error) {
	r.entries = append(r.entries, entry)
	return r.token, r.err
}

func appendAccessProject(t *testing.T, configPath, alias, projectID, workingDir string) {
	t.Helper()
	file, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("opening config: %v", err)
	}
	defer func() { _ = file.Close() }()
	_, err = file.WriteString(`
[[projects]]
alias = "` + alias + `"
bws_project_id = "` + projectID + `"
token_entry = "sentinel-entry"
working_dir = "` + workingDir + `"
approval = "never"
  [[projects.allow]]
  argv = ["false"]
`)
	if err != nil {
		t.Fatalf("appending config: %v", err)
	}
}

func TestCheckAccessUsesFixedSerialBoundaryAndReadsTokenOnce(t *testing.T) {
	workingDir := t.TempDir()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("unused-token-file"), 0o600); err != nil {
		t.Fatalf("writing token: %v", err)
	}
	configPath, bwsPath := writeWorkerConfig(t, workingDir, tokenPath)
	appendAccessProject(t, configPath, "second", "second-project-id", workingDir)
	runner := &accessRunner{responses: []accessResponse{
		{exitCode: 0, stdout: "sentinel-secret-output"},
		{exitCode: 1, stderr: "Received error message from server: [404 Not Found] sentinel-response-body"},
	}}
	resolver := &recordingResolver{token: token.New("sentinel-access-token")}
	auditPath := filepath.Join(t.TempDir(), "worker-audit", "audit.jsonl")
	resolvedPath := ""
	server := &Server{
		ConfigPath: configPath, AuditLogPath: auditPath, ExecRunner: runner,
		newTokenResolver: func(path string) token.Resolver {
			resolvedPath = path
			return resolver
		},
	}

	result, err := server.CheckAccess(context.Background(), "")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	wantProjects := []accessdiag.ProjectResult{
		{Alias: "test", BWSProjectID: "project-id", Status: accessdiag.StatusAccessible},
		{Alias: "second", BWSProjectID: "second-project-id", Status: accessdiag.StatusInaccessible},
	}
	if result.Version != accessdiag.Version || result.Outcome != accessdiag.OutcomeInaccessible || !reflect.DeepEqual(result.Projects, wantProjects) {
		t.Fatalf("result = %#v", result)
	}
	if resolvedPath != tokenPath || !reflect.DeepEqual(resolver.entries, []string{""}) {
		t.Fatalf("token path = %q, entries = %#v", resolvedPath, resolver.entries)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("calls = %#v", runner.calls)
	}
	for i, call := range runner.calls {
		projectID := wantProjects[i].BWSProjectID
		if call.Name != bwsPath || call.Dir == workingDir {
			t.Fatalf("call %d used an untrusted path: %#v", i, call)
		}
		wantArgs := []string{"project", "get", projectID, "--output", "none", "--color", "no"}
		if !reflect.DeepEqual(call.Args, wantArgs) {
			t.Fatalf("call %d args = %#v, want %#v", i, call.Args, wantArgs)
		}
		wantEnv := []string{
			"PATH=" + filepath.Dir(filepath.Join(filepath.Dir(bwsPath), "bin", "unused")),
			"HOME=" + filepath.Join(filepath.Dir(bwsPath), "home"),
			"LANG=C.UTF-8",
			"BWS_ACCESS_TOKEN=sentinel-access-token",
		}
		if !reflect.DeepEqual(call.Env, wantEnv) {
			t.Fatalf("call %d env = %#v, want %#v", i, call.Env, wantEnv)
		}
		joined := call.Name + strings.Join(call.Args, " ") + call.Dir
		if strings.Contains(joined, "sentinel-access-token") {
			t.Fatalf("call %d placed token outside environment: %#v", i, call)
		}
	}
	encoded := result.Projects[0].Alias + result.Projects[1].Alias
	if strings.Contains(encoded, "sentinel-secret-output") || strings.Contains(encoded, "sentinel-response-body") {
		t.Fatal("raw BWS output reached the result")
	}
	if _, err := os.Stat(auditPath); !os.IsNotExist(err) {
		t.Fatalf("access diagnostic created worker execution audit: %v", err)
	}
}

func TestCheckAccessSelectsOneProjectAndRejectsUnknownAliasBeforeToken(t *testing.T) {
	workingDir := t.TempDir()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("unused-token-file"), 0o600); err != nil {
		t.Fatalf("writing token: %v", err)
	}
	configPath, _ := writeWorkerConfig(t, workingDir, tokenPath)
	appendAccessProject(t, configPath, "second", "second-project-id", workingDir)
	runner := &accessRunner{responses: []accessResponse{{exitCode: 0}}}
	resolver := &recordingResolver{token: token.New("token")}
	server := &Server{
		ConfigPath: configPath,
		ExecRunner: runner,
		newTokenResolver: func(string) token.Resolver {
			return resolver
		},
	}

	result, err := server.CheckAccess(context.Background(), "second")
	if err != nil || len(result.Projects) != 1 || result.Projects[0].Alias != "second" {
		t.Fatalf("single result = %#v, %v", result, err)
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(runner.calls[0].Args, []string{"project", "get", "second-project-id", "--output", "none", "--color", "no"}) {
		t.Fatalf("calls = %#v", runner.calls)
	}

	runner.calls = nil
	resolver.entries = nil
	if _, err := server.CheckAccess(context.Background(), "missing"); err == nil {
		t.Fatal("unknown alias succeeded")
	}
	if len(resolver.entries) != 0 || len(runner.calls) != 0 {
		t.Fatalf("unknown alias touched token or bws: token=%#v bws=%#v", resolver.entries, runner.calls)
	}
}

func TestClassifyAccessUsesReviewedBWSForms(t *testing.T) {
	tests := []struct {
		name     string
		exitCode int
		stderr   string
		want     accessdiag.Status
	}{
		{name: "success", exitCode: 0, stderr: "ignored", want: accessdiag.StatusAccessible},
		{name: "not found", exitCode: 1, stderr: `Received error message from server: [404 Not Found] {"message":"Resource not found."}`, want: accessdiag.StatusInaccessible},
		{name: "unauthorized", exitCode: 1, stderr: "[401 Unauthorized]", want: accessdiag.StatusAuthenticationError},
		{name: "forbidden", exitCode: 1, stderr: "[403 Forbidden]", want: accessdiag.StatusAuthenticationError},
		{name: "invalid token", exitCode: 1, stderr: "Invalid access token", want: accessdiag.StatusAuthenticationError},
		{name: "DNS", exitCode: 1, stderr: "dns error: temporary failure in name resolution", want: accessdiag.StatusNetworkError},
		{name: "connection", exitCode: 1, stderr: "tcp connect error: connection refused", want: accessdiag.StatusNetworkError},
		{name: "request timeout", exitCode: 1, stderr: "request timed out", want: accessdiag.StatusNetworkError},
		{name: "TLS", exitCode: 1, stderr: "TLS error: certificate verify failed", want: accessdiag.StatusNetworkError},
		{name: "rate limit", exitCode: 1, stderr: "[429 Too Many Requests]", want: accessdiag.StatusAPIError},
		{name: "server", exitCode: 1, stderr: "[503 Service Unavailable]", want: accessdiag.StatusAPIError},
		{name: "server before transport text", exitCode: 1, stderr: "[503 Service Unavailable] connection refused", want: accessdiag.StatusAPIError},
		{name: "changed form", exitCode: 1, stderr: "sentinel future BWS error", want: accessdiag.StatusUnknownError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyAccess(tt.exitCode, tt.stderr); got != tt.want {
				t.Fatalf("classifyAccess() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCheckAccessTreatsTimeoutAsNetworkAndOversizedStderrAsLocalFailure(t *testing.T) {
	workingDir := t.TempDir()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("unused"), 0o600); err != nil {
		t.Fatalf("writing token: %v", err)
	}
	configPath, _ := writeWorkerConfig(t, workingDir, tokenPath)
	resolver := &recordingResolver{token: token.New("token")}

	t.Run("timeout", func(t *testing.T) {
		server := &Server{
			ConfigPath:       configPath,
			ExecRunner:       &accessRunner{responses: []accessResponse{{wait: true}}},
			accessTimeout:    time.Millisecond,
			newTokenResolver: func(string) token.Resolver { return resolver },
		}
		result, err := server.CheckAccess(context.Background(), "test")
		if err != nil || result.Projects[0].Status != accessdiag.StatusNetworkError {
			t.Fatalf("result = %#v, err = %v", result, err)
		}
	})

	t.Run("oversized stderr", func(t *testing.T) {
		server := &Server{
			ConfigPath: configPath,
			ExecRunner: &accessRunner{responses: []accessResponse{{
				exitCode: 1, stderr: strings.Repeat("sentinel-secret", accessStderrLimit),
			}}},
			newTokenResolver: func(string) token.Resolver { return resolver },
		}
		result, err := server.CheckAccess(context.Background(), "test")
		if err == nil || len(result.Projects) != 0 || strings.Contains(err.Error(), "sentinel-secret") {
			t.Fatalf("result = %#v, err = %v", result, err)
		}
	})
}
