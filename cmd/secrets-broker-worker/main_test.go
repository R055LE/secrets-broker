package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/R055LE/secrets-broker/internal/accessdiag"
	"github.com/R055LE/secrets-broker/internal/execx"
	"github.com/R055LE/secrets-broker/internal/worker"
)

func TestRunRejectsArguments(t *testing.T) {
	for _, args := range [][]string{{"unknown"}, {"access-check", "one", "two"}} {
		var stderr bytes.Buffer
		status := run(args, worker.NewServer(), strings.NewReader(""), &bytes.Buffer{}, &stderr)
		if status != 2 {
			t.Fatalf("args = %#v, status = %d", args, status)
		}
		if !strings.Contains(stderr.String(), "usage:") {
			t.Fatalf("args = %#v, stderr = %q", args, stderr.String())
		}
	}
}

func TestRunCheckFailureDoesNotCreateAuditLog(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	server := &worker.Server{
		ConfigPath:   filepath.Join(t.TempDir(), "missing-policy.toml"),
		AuditLogPath: auditPath,
	}
	var stderr bytes.Buffer
	status := run([]string{"check"}, server, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if status != 1 {
		t.Fatalf("got status %d", status)
	}
	if !strings.Contains(stderr.String(), "check failed") {
		t.Fatalf("got stderr %q", stderr.String())
	}
	if _, err := os.Stat(auditPath); !os.IsNotExist(err) {
		t.Fatalf("check created an audit log: %v", err)
	}
}

func TestRunAccessCheckEmitsOneSanitizedVersionedResult(t *testing.T) {
	server := accessCheckServer(t, &execx.FakeRunner{
		PassthroughExitCode: 1,
		PassthroughStdout:   "sentinel-secret-value",
		PassthroughStderr:   "Received error message from server: [404 Not Found] sentinel-response-body",
	})
	var stdout, stderr bytes.Buffer
	status := run([]string{"access-check", "test"}, server, strings.NewReader(""), &stdout, &stderr)
	if status != 1 || stderr.Len() != 0 {
		t.Fatalf("status = %d, stderr = %q", status, stderr.String())
	}
	var result accessdiag.Result
	decoder := json.NewDecoder(&stdout)
	if err := decoder.Decode(&result); err != nil {
		t.Fatalf("decoding result: %v", err)
	}
	if result.Version != accessdiag.Version || result.Outcome != accessdiag.OutcomeInaccessible || len(result.Projects) != 1 {
		t.Fatalf("result = %#v", result)
	}
	raw := fmt.Sprintf("%#v", result)
	for _, forbidden := range []string{"sentinel-secret-value", "sentinel-response-body", "token-entry", "working-dir"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("result contains %q: %s", forbidden, raw)
		}
	}
}

func TestRunAccessCheckSanitizesLocalFailure(t *testing.T) {
	server := &worker.Server{ConfigPath: "/sentinel-private-policy"}
	var stdout, stderr bytes.Buffer
	status := run([]string{"access-check"}, server, strings.NewReader(""), &stdout, &stderr)
	if status != 2 || stdout.Len() != 0 {
		t.Fatalf("status = %d, stdout = %q", status, stdout.String())
	}
	if got := stderr.String(); got != "secrets-broker-worker: access check failed\n" {
		t.Fatalf("stderr = %q", got)
	}
	if strings.Contains(stderr.String(), "sentinel-private-policy") {
		t.Fatal("stderr exposed the policy path")
	}
}

func accessCheckServer(t *testing.T, runner *execx.FakeRunner) *worker.Server {
	t.Helper()
	runtimeDir := t.TempDir()
	home := filepath.Join(runtimeDir, "home")
	commandDir := filepath.Join(runtimeDir, "bin")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatalf("creating home: %v", err)
	}
	if err := os.Mkdir(commandDir, 0o700); err != nil {
		t.Fatalf("creating command path: %v", err)
	}
	bwsPath := filepath.Join(runtimeDir, "bws")
	if err := os.WriteFile(bwsPath, []byte("test binary"), 0o700); err != nil {
		t.Fatalf("writing bws: %v", err)
	}
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("sentinel-access-token"), 0o600); err != nil {
		t.Fatalf("writing token: %v", err)
	}
	workingDir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "policy.toml")
	body := fmt.Sprintf(`
[runtime]
bws_binary = %q
command_path = %q
home = %q

[token_source]
backend = "file"
[token_source.file]
path = %q

[approval_source]
backend = "tailscale-relay"
[approval_source.tailscale_relay]
control_url = "http://100.64.0.1:7620"
poll_interval_seconds = 1
timeout_seconds = 5

[[projects]]
alias = "test"
bws_project_id = "project-id"
token_entry = "token-entry"
working_dir = %q
approval = "never"
  [[projects.allow]]
  argv = ["sentinel-command"]
`, bwsPath, commandDir, home, tokenPath, workingDir)
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatalf("writing policy: %v", err)
	}
	return &worker.Server{ConfigPath: configPath, ExecRunner: runner}
}
