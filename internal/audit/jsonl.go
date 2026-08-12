package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/R055LE/secrets-broker/internal/securefile"
)

// record is the on-disk shape of one JSONL line. Start and Finish each
// write one record, sharing RunID; Event distinguishes them.
type record struct {
	RunID      string    `json:"run_id"`
	Timestamp  time.Time `json:"timestamp"`
	Event      string    `json:"event"` // "start" | "finish"
	Project    string    `json:"project,omitempty"`
	WorkingDir string    `json:"working_dir,omitempty"`
	Argv       []string  `json:"argv,omitempty"`
	Outcome    string    `json:"outcome,omitempty"`
	ExitCode   *int      `json:"exit_code,omitempty"`
}

// JSONLLogger appends one JSON object per line to a local file. O_APPEND keeps
// concurrent worker processes from racing the file offset; the mutex keeps
// goroutines sharing one logger from overlapping writes.
type JSONLLogger struct {
	mu   sync.Mutex
	path string
}

func NewJSONLLogger(path string) (*JSONLLogger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating audit log directory: %w", err)
	}
	if err := securefile.ValidatePrivateDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("validating audit log directory: %w", err)
	}
	return &JSONLLogger{path: path}, nil
}

func (l *JSONLLogger) Start(ctx context.Context, rec StartRecord) (string, error) {
	runID, err := newRunID()
	if err != nil {
		return "", fmt.Errorf("generating run ID: %w", err)
	}

	err = l.append(record{
		RunID:      runID,
		Timestamp:  time.Now().UTC(),
		Event:      "start",
		Project:    rec.Project,
		WorkingDir: rec.WorkingDir,
		Argv:       rec.Argv,
	})
	if err != nil {
		return "", err
	}
	return runID, nil
}

func (l *JSONLLogger) Finish(ctx context.Context, runID string, rec FinishRecord) error {
	return l.append(record{
		RunID:     runID,
		Timestamp: time.Now().UTC(),
		Event:     "finish",
		Outcome:   rec.Outcome,
		ExitCode:  rec.ExitCode,
	})
}

func (l *JSONLLogger) append(rec record) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := securefile.OpenAppend(l.path, 0o600)
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}
	defer func() { _ = f.Close() }()

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshaling audit record: %w", err)
	}
	line = append(line, '\n')

	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("writing audit record: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("syncing audit record: %w", err)
	}
	return nil
}

func newRunID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
