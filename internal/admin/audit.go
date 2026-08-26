package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/R055LE/secrets-broker/internal/securefile"
)

const (
	MutationCreateProject   = "create_project"
	MutationSetApproval     = "set_approval"
	MutationAddAllowlist    = "add_allowlist"
	MutationRemoveAllowlist = "remove_allowlist"
	MutationRemoveProject   = "remove_project"
	MutationRestoreProject  = "restore_project"

	MutationChanged  = "changed"
	MutationNoChange = "no_change"
	MutationFailed   = "failed"
)

type ProjectEditor interface {
	ListProjects() ([]ProjectSummary, error)
	ListAllowlist(alias string) ([][]string, error)
	CreateProject(input ProjectInput) (bool, error)
	SetApproval(alias, mode string) (bool, error)
	AddAllowlist(alias string, argv []string) (bool, error)
	RemoveAllowlist(alias string, argv []string) (bool, error)
	RemoveProject(alias, confirmation, recoveryID string) (RecoveryResult, error)
	ListRecoveries() ([]RecoverySummary, error)
	RestoreProject(recoveryID, confirmation string) (RecoveryResult, error)
}

type MutationStart struct {
	ActorUID     int
	Project      string
	Operation    string
	ApprovalMode string
	Argv         []string
	RecoveryID   string
}

type MutationFinish struct {
	Outcome string
}

type MutationLogger interface {
	Start(ctx context.Context, rec MutationStart) (mutationID string, err error)
	Finish(ctx context.Context, mutationID string, rec MutationFinish) error
}

type AuditedEditor struct {
	editor        ProjectEditor
	logger        MutationLogger
	actorUID      int
	newRecoveryID func() (string, error)
}

func NewAuditedEditor(editor ProjectEditor, logger MutationLogger, actorUID int) *AuditedEditor {
	return newAuditedEditor(editor, logger, actorUID, newRecoveryID)
}

func newAuditedEditor(
	editor ProjectEditor,
	logger MutationLogger,
	actorUID int,
	recoveryIDGenerator func() (string, error),
) *AuditedEditor {
	return &AuditedEditor{
		editor:        editor,
		logger:        logger,
		actorUID:      actorUID,
		newRecoveryID: recoveryIDGenerator,
	}
}

func (e *AuditedEditor) ListProjects() ([]ProjectSummary, error) {
	return e.editor.ListProjects()
}

func (e *AuditedEditor) ListAllowlist(alias string) ([][]string, error) {
	return e.editor.ListAllowlist(alias)
}

func (e *AuditedEditor) ListRecoveries() ([]RecoverySummary, error) {
	return e.editor.ListRecoveries()
}

func (e *AuditedEditor) CreateProject(input ProjectInput) (bool, error) {
	return e.mutate(MutationStart{
		ActorUID:     e.actorUID,
		Project:      input.Alias,
		Operation:    MutationCreateProject,
		ApprovalMode: ModeConfirm,
	}, func() (bool, error) {
		return e.editor.CreateProject(input)
	})
}

func (e *AuditedEditor) SetApproval(alias, mode string) (bool, error) {
	return e.mutate(MutationStart{
		ActorUID:     e.actorUID,
		Project:      alias,
		Operation:    MutationSetApproval,
		ApprovalMode: mode,
	}, func() (bool, error) {
		return e.editor.SetApproval(alias, mode)
	})
}

func (e *AuditedEditor) AddAllowlist(alias string, argv []string) (bool, error) {
	return e.mutate(MutationStart{
		ActorUID:  e.actorUID,
		Project:   alias,
		Operation: MutationAddAllowlist,
		Argv:      append([]string(nil), argv...),
	}, func() (bool, error) {
		return e.editor.AddAllowlist(alias, argv)
	})
}

func (e *AuditedEditor) RemoveAllowlist(alias string, argv []string) (bool, error) {
	return e.mutate(MutationStart{
		ActorUID:  e.actorUID,
		Project:   alias,
		Operation: MutationRemoveAllowlist,
		Argv:      append([]string(nil), argv...),
	}, func() (bool, error) {
		return e.editor.RemoveAllowlist(alias, argv)
	})
}

func (e *AuditedEditor) RemoveProject(alias, confirmation string) (RecoveryResult, error) {
	recoveryID, err := e.newRecoveryID()
	if err != nil {
		return RecoveryResult{}, fmt.Errorf("generating recovery ID: %w", err)
	}
	return e.mutateRecovery(MutationStart{
		ActorUID:   e.actorUID,
		Project:    alias,
		Operation:  MutationRemoveProject,
		RecoveryID: recoveryID,
	}, func() (RecoveryResult, error) {
		return e.editor.RemoveProject(alias, confirmation, recoveryID)
	})
}

func (e *AuditedEditor) RestoreProject(recoveryID, confirmation string) (RecoveryResult, error) {
	return e.mutateRecovery(MutationStart{
		ActorUID:   e.actorUID,
		Project:    confirmation,
		Operation:  MutationRestoreProject,
		RecoveryID: recoveryID,
	}, func() (RecoveryResult, error) {
		return e.editor.RestoreProject(recoveryID, confirmation)
	})
}

func (e *AuditedEditor) mutate(start MutationStart, update func() (bool, error)) (bool, error) {
	ctx := context.Background()
	mutationID, err := e.logger.Start(ctx, start)
	if err != nil {
		return false, fmt.Errorf("starting administrator audit: %w", err)
	}

	changed, updateErr := update()
	outcome := MutationNoChange
	if updateErr != nil {
		outcome = MutationFailed
	} else if changed {
		outcome = MutationChanged
	}

	finishErr := e.logger.Finish(ctx, mutationID, MutationFinish{Outcome: outcome})
	if finishErr != nil {
		if changed {
			finishErr = fmt.Errorf("policy changed but administrator audit completion failed: %w", finishErr)
		} else {
			finishErr = fmt.Errorf("finishing administrator audit: %w", finishErr)
		}
		return changed, errors.Join(updateErr, finishErr)
	}
	return changed, updateErr
}

func (e *AuditedEditor) mutateRecovery(
	start MutationStart,
	update func() (RecoveryResult, error),
) (RecoveryResult, error) {
	ctx := context.Background()
	mutationID, err := e.logger.Start(ctx, start)
	if err != nil {
		return RecoveryResult{}, fmt.Errorf("starting administrator audit: %w", err)
	}

	result, updateErr := update()
	outcome := MutationNoChange
	if updateErr != nil {
		outcome = MutationFailed
	} else if result.Changed {
		outcome = MutationChanged
	}

	finishErr := e.logger.Finish(ctx, mutationID, MutationFinish{Outcome: outcome})
	if finishErr != nil {
		if result.Changed {
			finishErr = fmt.Errorf("policy changed but administrator audit completion failed: %w", finishErr)
		} else {
			finishErr = fmt.Errorf("finishing administrator audit: %w", finishErr)
		}
		return result, errors.Join(updateErr, finishErr)
	}
	return result, updateErr
}

type MutationJSONLLogger struct {
	mu   sync.Mutex
	path string
}

func NewMutationJSONLLogger(path string) *MutationJSONLLogger {
	return &MutationJSONLLogger{path: path}
}

type mutationRecord struct {
	MutationID   string    `json:"mutation_id"`
	Timestamp    time.Time `json:"timestamp"`
	Event        string    `json:"event"`
	ActorUID     *int      `json:"actor_uid,omitempty"`
	Project      string    `json:"project,omitempty"`
	Operation    string    `json:"operation,omitempty"`
	ApprovalMode string    `json:"approval_mode,omitempty"`
	ArgvSHA256   string    `json:"argv_sha256,omitempty"`
	ArgvCount    int       `json:"argv_count,omitempty"`
	RecoveryID   string    `json:"recovery_id,omitempty"`
	Outcome      string    `json:"outcome,omitempty"`
}

func (l *MutationJSONLLogger) Start(_ context.Context, rec MutationStart) (string, error) {
	mutationID, err := newMutationID()
	if err != nil {
		return "", fmt.Errorf("generating mutation ID: %w", err)
	}
	actorUID := rec.ActorUID
	argvSHA256 := ""
	if len(rec.Argv) > 0 {
		argvSHA256 = digestArgv(rec.Argv)
	}
	err = l.append(mutationRecord{
		MutationID:   mutationID,
		Timestamp:    time.Now().UTC(),
		Event:        "start",
		ActorUID:     &actorUID,
		Project:      rec.Project,
		Operation:    rec.Operation,
		ApprovalMode: rec.ApprovalMode,
		ArgvSHA256:   argvSHA256,
		ArgvCount:    len(rec.Argv),
		RecoveryID:   rec.RecoveryID,
	})
	if err != nil {
		return "", err
	}
	return mutationID, nil
}

func digestArgv(argv []string) string {
	encoded, _ := json.Marshal(argv)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (l *MutationJSONLLogger) Finish(_ context.Context, mutationID string, rec MutationFinish) error {
	return l.append(mutationRecord{
		MutationID: mutationID,
		Timestamp:  time.Now().UTC(),
		Event:      "finish",
		Outcome:    rec.Outcome,
	})
}

func (l *MutationJSONLLogger) append(rec mutationRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	dir := filepath.Dir(l.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating administrator audit directory: %w", err)
	}
	if err := securefile.ValidatePrivateDir(dir); err != nil {
		return fmt.Errorf("validating administrator audit directory: %w", err)
	}

	f, err := securefile.OpenAppend(l.path, 0o600)
	if err != nil {
		return fmt.Errorf("opening administrator audit log: %w", err)
	}
	defer func() { _ = f.Close() }()

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshaling administrator audit record: %w", err)
	}
	line = append(line, '\n')
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("writing administrator audit record: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("syncing administrator audit record: %w", err)
	}
	return nil
}

func newMutationID() (string, error) {
	return newRandomHexID(8)
}

func newRecoveryID() (string, error) {
	return newRandomHexID(16)
}

func newRandomHexID(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
