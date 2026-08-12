package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/R055LE/secrets-broker/internal/approval"
	"github.com/R055LE/secrets-broker/internal/audit"
	"github.com/R055LE/secrets-broker/internal/broker"
	"github.com/R055LE/secrets-broker/internal/config"
	"github.com/R055LE/secrets-broker/internal/execx"
	"github.com/R055LE/secrets-broker/internal/runner"
	"github.com/R055LE/secrets-broker/internal/securefile"
	"github.com/R055LE/secrets-broker/internal/token"
)

const (
	DefaultConfigPath   = "/etc/secrets-broker/policy.toml"
	DefaultAuditLogPath = "/var/log/secrets-broker/audit.jsonl"
)

type Server struct {
	ConfigPath   string
	AuditLogPath string
	ExecRunner   execx.Runner
}

func NewServer() *Server {
	return &Server{
		ConfigPath:   DefaultConfigPath,
		AuditLogPath: DefaultAuditLogPath,
		ExecRunner:   execx.OSRunner{},
	}
}

func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	encoder := json.NewEncoder(out)
	logger, err := audit.NewJSONLLogger(s.AuditLogPath)
	if err != nil {
		return writeWorkerError(encoder, err)
	}
	req, err := decodeRequest(in)
	if err != nil {
		return writeAuditedWorkerError(ctx, encoder, logger, Request{}, "invalid_request", err)
	}
	cfg, err := config.LoadWorker(s.ConfigPath)
	if err != nil {
		return writeAuditedWorkerError(ctx, encoder, logger, req, "config_unavailable", err)
	}
	if err := cfg.ValidateWorker(); err != nil {
		return writeAuditedWorkerError(ctx, encoder, logger, req, "config_unavailable", fmt.Errorf("invalid worker config: %w", err))
	}
	if err := validateRuntime(cfg.Runtime); err != nil {
		return writeAuditedWorkerError(ctx, encoder, logger, req, "config_unavailable", fmt.Errorf("invalid worker runtime: %w", err))
	}

	relayClient := approval.NewHTTPRelayClient(cfg.ApprovalSource.TailscaleRelay.ControlURL, nil)
	approver := approval.NewTailscaleApprover(
		relayClient,
		time.Duration(cfg.ApprovalSource.TailscaleRelay.PollIntervalSeconds)*time.Second,
		time.Duration(cfg.ApprovalSource.TailscaleRelay.TimeoutSeconds)*time.Second,
	)
	b := broker.New(
		cfg,
		token.NewFileResolver(cfg.TokenSource.File.Path),
		approver,
		runner.NewBWSRunner(s.ExecRunner, cfg.Runtime.BWSBinary, cfg.Runtime.CommandPath, cfg.Runtime.Home),
		logger,
	)

	if req.DryRun {
		dry := b.DryRun(req.Project, req.WorkingDir, req.Argv)
		result := Result{Reason: dry.Reason}
		switch dry.Verdict {
		case broker.VerdictAllow:
			result.ExitCode = 0
		case broker.VerdictPrompt:
			result.ExitCode = 0
		default:
			result.Denied = true
			result.ExitCode = 125
		}
		return encoder.Encode(frame{Type: frameResult, Result: &result})
	}

	mu := &sync.Mutex{}
	outcome := b.Run(ctx, broker.RunRequest{
		Project:    req.Project,
		WorkingDir: req.WorkingDir,
		Argv:       req.Argv,
		Stdout:     &frameWriter{mu: mu, encoder: encoder, stream: frameStdout},
		Stderr:     &frameWriter{mu: mu, encoder: encoder, stream: frameStderr},
	})
	if outcome.AuditIncomplete {
		_, _ = (&frameWriter{mu: mu, encoder: encoder, stream: frameStderr}).Write([]byte("secrets-broker: warning: audit finish record could not be written\n"))
	}
	result := Result{Denied: outcome.Denied, Reason: outcome.Reason, ExitCode: outcome.ExitCode}
	if outcome.Denied {
		result.ExitCode = 125
		if outcome.Reason == broker.ReasonRunnerStartFailed {
			result.ExitCode = 126
		}
	}
	mu.Lock()
	err = encoder.Encode(frame{Type: frameResult, Result: &result})
	mu.Unlock()
	return err
}

func validateRuntime(runtime config.Runtime) error {
	if err := securefile.ValidateExecutable(runtime.BWSBinary); err != nil {
		return fmt.Errorf("validating bws binary: %w", err)
	}
	if err := securefile.ValidatePrivateDir(runtime.Home); err != nil {
		return fmt.Errorf("validating worker home: %w", err)
	}
	for _, dir := range strings.Split(runtime.CommandPath, string(filepath.ListSeparator)) {
		if err := securefile.ValidateTrustedDir(dir); err != nil {
			return fmt.Errorf("validating command path: %w", err)
		}
	}
	return nil
}

type frameWriter struct {
	mu      *sync.Mutex
	encoder *json.Encoder
	stream  string
}

func (w *frameWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.encoder.Encode(frame{Type: w.stream, Data: p}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func writeWorkerError(encoder *json.Encoder, err error) error {
	return encoder.Encode(frame{Type: frameError, Message: err.Error()})
}

func writeAuditedWorkerError(ctx context.Context, encoder *json.Encoder, logger audit.Logger, req Request, outcome string, workerErr error) error {
	if auditErr := auditDenied(ctx, logger, req, outcome); auditErr != nil {
		workerErr = fmt.Errorf("%w; audit failure: %v", workerErr, auditErr)
	}
	return writeWorkerError(encoder, workerErr)
}

func auditDenied(ctx context.Context, logger audit.Logger, req Request, outcome string) error {
	runID, err := logger.Start(ctx, audit.StartRecord{
		Project: req.Project, WorkingDir: req.WorkingDir, Argv: req.Argv,
	})
	if err != nil {
		return err
	}
	return logger.Finish(ctx, runID, audit.FinishRecord{Outcome: "denied:" + outcome})
}
