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
