package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/R055LE/secrets-broker/internal/config"
	"github.com/R055LE/secrets-broker/internal/execx"
)

func writeWorkerConfig(t *testing.T, workingDir, tokenPath string) (string, string) {
	t.Helper()
	runtimeDir := t.TempDir()
	home := filepath.Join(runtimeDir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatalf("creating worker home: %v", err)
	}
	commandDir := filepath.Join(runtimeDir, "bin")
	if err := os.Mkdir(commandDir, 0o700); err != nil {
		t.Fatalf("creating command path: %v", err)
	}
	bwsPath := filepath.Join(runtimeDir, "bws")
	if err := os.WriteFile(bwsPath, []byte("test binary"), 0o700); err != nil {
		t.Fatalf("creating bws fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "policy.toml")
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
token_entry = "ignored"
working_dir = %q
approval = "never"
  [[projects.allow]]
  argv = ["true"]
`, bwsPath, commandDir, home, tokenPath, workingDir)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path, bwsPath
}

func TestServerExecutesAllowedRequestThroughFixedConfiguration(t *testing.T) {
	workingDir := t.TempDir()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0o600); err != nil {
		t.Fatalf("writing token: %v", err)
	}
	fakeExec := &execx.FakeRunner{PassthroughStdout: "ok\n"}
	configPath, bwsPath := writeWorkerConfig(t, workingDir, tokenPath)
	server := &Server{
		ConfigPath:   configPath,
		AuditLogPath: filepath.Join(t.TempDir(), "private", "audit.jsonl"),
		ExecRunner:   fakeExec,
	}

	requestBody, _ := json.Marshal(Request{Project: "test", WorkingDir: workingDir, Argv: []string{"true"}})
	var response bytes.Buffer
	if err := server.Serve(context.Background(), bytes.NewReader(requestBody), &response); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	rawResponse := response.String()
	decoder := json.NewDecoder(strings.NewReader(rawResponse))
	var stdout string
	var result *Result
	for {
		var f frame
		if err := decoder.Decode(&f); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decoding frame: %v", err)
		}
		if f.Type == frameStdout {
			stdout += string(f.Data)
		}
		if f.Type == frameResult {
			result = f.Result
		}
	}
	if stdout != "ok\n" {
		t.Fatalf("got stdout %q; frames: %s", stdout, rawResponse)
	}
	if result == nil || result.Denied || result.ExitCode != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(fakeExec.Calls) != 1 || fakeExec.Calls[0].Name != bwsPath {
		t.Fatalf("worker did not use configured absolute bws binary: %+v", fakeExec.Calls)
	}
}

func TestServerCheckValidatesDeploymentWithoutSideEffects(t *testing.T) {
	workingDir := t.TempDir()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0o600); err != nil {
		t.Fatalf("writing token: %v", err)
	}
	fakeExec := &execx.FakeRunner{}
	configPath, _ := writeWorkerConfig(t, workingDir, tokenPath)
	auditPath := filepath.Join(t.TempDir(), "private", "audit.jsonl")
	server := &Server{ConfigPath: configPath, AuditLogPath: auditPath, ExecRunner: fakeExec}

	result, err := server.Check()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result.Projects != 1 || result.TokenBytes != int64(len("test-token")) {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(fakeExec.Calls) != 0 {
		t.Fatalf("check executed a command: %+v", fakeExec.Calls)
	}
	if _, err := os.Stat(auditPath); !os.IsNotExist(err) {
		t.Fatalf("check created an audit log: %v", err)
	}
}

func TestServerCheckRejectsInvalidDeploymentState(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, workingDir, tokenPath string)
		want   string
	}{
		{
			name: "empty token",
			mutate: func(t *testing.T, _, tokenPath string) {
				if err := os.WriteFile(tokenPath, nil, 0o600); err != nil {
					t.Fatalf("emptying token: %v", err)
				}
			},
			want: "is empty",
		},
		{
			name: "unsafe token permissions",
			mutate: func(t *testing.T, _, tokenPath string) {
				if err := os.Chmod(tokenPath, 0o640); err != nil {
					t.Fatalf("opening token permissions: %v", err)
				}
			},
			want: "permissions are too open",
		},
		{
			name: "missing working directory",
			mutate: func(t *testing.T, workingDir, _ string) {
				if err := os.Remove(workingDir); err != nil {
					t.Fatalf("removing working directory: %v", err)
				}
			},
			want: "resolving working directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workingDir := t.TempDir()
			tokenPath := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(tokenPath, []byte("test-token"), 0o600); err != nil {
				t.Fatalf("writing token: %v", err)
			}
			configPath, _ := writeWorkerConfig(t, workingDir, tokenPath)
			tt.mutate(t, workingDir, tokenPath)

			_, err := (&Server{ConfigPath: configPath, ExecRunner: &execx.FakeRunner{}}).Check()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got error %v; want %q", err, tt.want)
			}
		})
	}
}

func TestServerAuditsInvalidConfiguration(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "policy.toml")
	if err := os.WriteFile(configPath, []byte("not valid toml = ["), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	auditPath := filepath.Join(t.TempDir(), "private", "audit.jsonl")
	server := &Server{ConfigPath: configPath, AuditLogPath: auditPath, ExecRunner: &execx.FakeRunner{}}
	requestBody, _ := json.Marshal(Request{Project: "test", WorkingDir: "/tmp", Argv: []string{"true"}})

	var response bytes.Buffer
	if err := server.Serve(context.Background(), bytes.NewReader(requestBody), &response); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if !strings.Contains(response.String(), `"type":"error"`) {
		t.Fatalf("expected error frame, got %s", response.String())
	}
	auditData, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	if !strings.Contains(string(auditData), "denied:config_unavailable") {
		t.Fatalf("config failure was not audited: %s", auditData)
	}
}

func TestServerAuditsInvalidRequest(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "private", "audit.jsonl")
	server := &Server{ConfigPath: "/unused", AuditLogPath: auditPath, ExecRunner: &execx.FakeRunner{}}

	var response bytes.Buffer
	if err := server.Serve(context.Background(), strings.NewReader(`{"project":`), &response); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if !strings.Contains(response.String(), `"type":"error"`) {
		t.Fatalf("expected error frame, got %s", response.String())
	}
	auditData, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	if !strings.Contains(string(auditData), "denied:invalid_request") {
		t.Fatalf("invalid request was not audited: %s", auditData)
	}
}

func TestValidateRuntimeRejectsWritableWorkerHome(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o777); err != nil {
		t.Fatalf("opening home permissions: %v", err)
	}
	bwsPath := filepath.Join(t.TempDir(), "bws")
	if err := os.WriteFile(bwsPath, []byte("binary"), 0o700); err != nil {
		t.Fatalf("writing bws fixture: %v", err)
	}

	err := validateRuntime(config.Runtime{
		BWSBinary: bwsPath, CommandPath: "/usr/bin:/bin", Home: home,
	})
	if err == nil {
		t.Fatal("expected a writable worker home to be rejected")
	}
}
