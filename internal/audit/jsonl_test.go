package audit_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/R055LE/secrets-broker/internal/audit"
)

func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening audit log: %v", err)
	}
	defer func() { _ = f.Close() }()

	var lines []map[string]any
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(text), &m); err != nil {
			t.Fatalf("unmarshaling audit line %q: %v", text, err)
		}
		lines = append(lines, m)
	}
	return lines
}

func TestJSONLLogger_StartThenFinishAppendsTwoLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "audit.jsonl")

	logger, err := audit.NewJSONLLogger(path)
	if err != nil {
		t.Fatalf("NewJSONLLogger: %v", err)
	}

	runID, err := logger.Start(context.Background(), audit.StartRecord{
		Project: "claude-code",
		Argv:    []string{"git", "push"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if runID == "" {
		t.Fatal("Start returned an empty run ID")
	}

	exitCode := 0
	if err := logger.Finish(context.Background(), runID, audit.FinishRecord{
		Outcome:  "executed",
		ExitCode: &exitCode,
	}); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2 (start + finish)", len(lines))
	}
	if lines[0]["event"] != "start" || lines[1]["event"] != "finish" {
		t.Fatalf("unexpected event order: %v, %v", lines[0]["event"], lines[1]["event"])
	}
	if lines[0]["run_id"] != lines[1]["run_id"] {
		t.Fatalf("start/finish run_id mismatch: %v vs %v", lines[0]["run_id"], lines[1]["run_id"])
	}
	if lines[0]["project"] != "claude-code" {
		t.Fatalf("start record missing project: %v", lines[0])
	}
	if lines[1]["outcome"] != "executed" {
		t.Fatalf("finish record missing outcome: %v", lines[1])
	}
}

func TestJSONLLogger_MultipleRunsGetDistinctIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	logger, err := audit.NewJSONLLogger(path)
	if err != nil {
		t.Fatalf("NewJSONLLogger: %v", err)
	}

	id1, _ := logger.Start(context.Background(), audit.StartRecord{Project: "p", Argv: []string{"a"}})
	id2, _ := logger.Start(context.Background(), audit.StartRecord{Project: "p", Argv: []string{"b"}})
	if id1 == id2 {
		t.Fatalf("expected distinct run IDs, got %q twice", id1)
	}
}
