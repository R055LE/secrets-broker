package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/R055LE/secrets-broker/internal/worker"
)

func TestRunRejectsArguments(t *testing.T) {
	var stderr bytes.Buffer
	status := run([]string{"unknown"}, worker.NewServer(), strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if status != 2 {
		t.Fatalf("got status %d", status)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("got stderr %q", stderr.String())
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
