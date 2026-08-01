package config_test

import (
	"testing"

	"github.com/R055LE/secrets-broker/internal/config"
)

func TestLoad_Valid(t *testing.T) {
	cfg, err := config.Load("testdata/valid.toml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	p, ok := cfg.Project("claude-code")
	if !ok {
		t.Fatal("expected project claude-code to be found")
	}
	if p.Approval != config.ApprovalPrompt {
		t.Fatalf("got approval %q, want %q", p.Approval, config.ApprovalPrompt)
	}
	allow := p.AllowArgv()
	if len(allow) != 2 || allow[0][0] != "git" || allow[0][1] != "push" {
		t.Fatalf("unexpected allowlist: %v", allow)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := config.Load("testdata/does-not-exist.toml")
	if err == nil {
		t.Fatal("expected an error for a missing config file")
	}
}

func TestLoad_ApprovalDefaultsToNever(t *testing.T) {
	cfg, err := config.Load("testdata/defaults_approval.toml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p, ok := cfg.Project("no-approval-set")
	if !ok {
		t.Fatal("expected project to be found")
	}
	if p.Approval != config.ApprovalNever {
		t.Fatalf("got approval %q, want default %q", p.Approval, config.ApprovalNever)
	}
}

func TestLoad_DuplicateAliasRejected(t *testing.T) {
	_, err := config.Load("testdata/duplicate_alias.toml")
	if err == nil {
		t.Fatal("expected an error for a duplicate project alias")
	}
}

func TestLoad_BadApprovalValueRejected(t *testing.T) {
	_, err := config.Load("testdata/bad_approval.toml")
	if err == nil {
		t.Fatal("expected an error for an invalid approval value")
	}
}

func TestLoad_EnvBackendValid(t *testing.T) {
	cfg, err := config.Load("testdata/env_backend.toml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TokenSource.Backend != config.BackendEnv {
		t.Fatalf("got backend %q, want %q", cfg.TokenSource.Backend, config.BackendEnv)
	}
	if cfg.TokenSource.Env.Var != "SECRETS_BROKER_BOOTSTRAP_TOKEN" {
		t.Fatalf("got env var %q", cfg.TokenSource.Env.Var)
	}
}

func TestLoad_EnvBackendMissingVarRejected(t *testing.T) {
	_, err := config.Load("testdata/env_backend_missing_var.toml")
	if err == nil {
		t.Fatal("expected an error when backend=env and env.var is unset")
	}
}

func TestLoad_FileBackendValid(t *testing.T) {
	cfg, err := config.Load("testdata/file_backend.toml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TokenSource.Backend != config.BackendFile {
		t.Fatalf("got backend %q, want %q", cfg.TokenSource.Backend, config.BackendFile)
	}
	if cfg.TokenSource.File.Path != "/run/secrets/bws-token" {
		t.Fatalf("got file path %q", cfg.TokenSource.File.Path)
	}
}

func TestLoad_FileBackendMissingPathRejected(t *testing.T) {
	_, err := config.Load("testdata/file_backend_missing_path.toml")
	if err == nil {
		t.Fatal("expected an error when backend=file and file.path is unset")
	}
}

func TestLoad_UnknownBackendRejected(t *testing.T) {
	_, err := config.Load("testdata/unknown_backend.toml")
	if err == nil {
		t.Fatal("expected an error for an unsupported token_source.backend")
	}
}

func TestLoad_ApprovalSourceDefaultsToKDialog(t *testing.T) {
	cfg, err := config.Load("testdata/approval_kdialog_default.toml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ApprovalSource.Backend != config.ApprovalBackendKDialog {
		t.Fatalf("got approval_source.backend %q, want default %q", cfg.ApprovalSource.Backend, config.ApprovalBackendKDialog)
	}
}

func TestLoad_ApprovalTailscaleRelayValid(t *testing.T) {
	cfg, err := config.Load("testdata/approval_tailscale_relay.toml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ApprovalSource.Backend != config.ApprovalBackendTailscaleRelay {
		t.Fatalf("got backend %q, want %q", cfg.ApprovalSource.Backend, config.ApprovalBackendTailscaleRelay)
	}
	if cfg.ApprovalSource.TailscaleRelay.ControlURL != "http://100.64.0.1:7620" {
		t.Fatalf("got control_url %q", cfg.ApprovalSource.TailscaleRelay.ControlURL)
	}
	// Poll interval / timeout omitted in the fixture — must get defaults.
	if cfg.ApprovalSource.TailscaleRelay.PollIntervalSeconds != 2 {
		t.Fatalf("got poll interval %d, want default 2", cfg.ApprovalSource.TailscaleRelay.PollIntervalSeconds)
	}
	if cfg.ApprovalSource.TailscaleRelay.TimeoutSeconds != 300 {
		t.Fatalf("got timeout %d, want default 300", cfg.ApprovalSource.TailscaleRelay.TimeoutSeconds)
	}
}

func TestLoad_ApprovalTailscaleRelayMissingURLRejected(t *testing.T) {
	_, err := config.Load("testdata/approval_tailscale_relay_missing_url.toml")
	if err == nil {
		t.Fatal("expected an error when backend=tailscale-relay and control_url is unset")
	}
}

func TestLoad_ApprovalUnknownBackendRejected(t *testing.T) {
	_, err := config.Load("testdata/approval_unknown_backend.toml")
	if err == nil {
		t.Fatal("expected an error for an unsupported approval_source.backend")
	}
}

func TestProject_UnknownAlias(t *testing.T) {
	cfg, err := config.Load("testdata/valid.toml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, ok := cfg.Project("nonexistent")
	if ok {
		t.Fatal("expected unknown alias to not be found")
	}
}

func TestDefaultPath_HonorsXDGConfigHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdgtest")
	path, err := config.DefaultPath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "/tmp/xdgtest/secrets-broker/policy.toml"
	if path != want {
		t.Fatalf("got %q, want %q", path, want)
	}
}

func TestDefaultAuditLogPath_HonorsXDGStateHome(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/tmp/xdgstate")
	path, err := config.DefaultAuditLogPath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "/tmp/xdgstate/secrets-broker/audit.jsonl"
	if path != want {
		t.Fatalf("got %q, want %q", path, want)
	}
}
