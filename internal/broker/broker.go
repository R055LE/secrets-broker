// Package broker is the orchestrator: the single place the whole
// deny-by-default decision matrix lives. It depends only on the
// token.Resolver / approval.Approver / runner.Runner / audit.Logger
// interfaces — never on a concrete adapter (secretservice.go, kdialog.go,
// bws.go) — so a future container-native Resolver/Approver pair is a pure
// addition, not a rewrite of this file.
package broker

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/R055LE/secrets-broker/internal/approval"
	"github.com/R055LE/secrets-broker/internal/audit"
	"github.com/R055LE/secrets-broker/internal/config"
	"github.com/R055LE/secrets-broker/internal/policy"
	"github.com/R055LE/secrets-broker/internal/runner"
	"github.com/R055LE/secrets-broker/internal/token"
)

// Denial reasons. Every path that refuses to run a command maps to exactly
// one of these — nothing falls through to an unmodeled "other" case.
const (
	ReasonUnknownProject             = "unknown_project"
	ReasonNotAllowlisted             = "not_allowlisted"
	ReasonApprovalRejected           = "approval_rejected"
	ReasonTokenResolutionFailed      = "token_resolution_failed"
	ReasonRunnerStartFailed          = "runner_start_failed"
	ReasonAuditUnavailable           = "audit_unavailable"
	ReasonWorkingDirectoryNotAllowed = "working_directory_not_allowed"
)

// Verdict is the pure policy decision for a project+argv pair, before any
// I/O (token resolution, approval, execution) happens.
type Verdict int

const (
	VerdictDeny Verdict = iota
	VerdictAllow
	VerdictPrompt
)

// Broker wires the four domain interfaces together. Construct one real
// instance in cmd/secrets-broker/main.go with real adapters; tests
// construct it with fakes.
type Broker struct {
	cfg       *config.Config
	resolver  token.Resolver
	approver  approval.Approver
	cmdRunner runner.Runner
	logger    audit.Logger
}

func New(cfg *config.Config, resolver token.Resolver, approver approval.Approver, cmdRunner runner.Runner, logger audit.Logger) *Broker {
	return &Broker{cfg: cfg, resolver: resolver, approver: approver, cmdRunner: cmdRunner, logger: logger}
}

// RunRequest is one invocation of `secrets-broker run`.
type RunRequest struct {
	Project    string
	WorkingDir string
	Argv       []string

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// RunOutcome is the result of Run. Denied and ExitCode are mutually
// exclusive in practice: a denial never reaches the runner, so ExitCode is
// only meaningful when Denied is false.
type RunOutcome struct {
	Denied          bool
	Reason          string // set when Denied — one of the Reason* constants
	ExitCode        int
	AuditIncomplete bool
}

// Run executes req against the full deny-by-default matrix, auditing every
// invocation (the audit record is written before the allowlist/approval/
// token/exec steps even begin, and finalized once a verdict is reached).
func (b *Broker) Run(ctx context.Context, req RunRequest) RunOutcome {
	runID, err := b.logger.Start(ctx, audit.StartRecord{Project: req.Project, WorkingDir: req.WorkingDir, Argv: req.Argv})
	if err != nil {
		// If the broker can't even write the audit record, it must not
		// proceed — an unaudited secret-injecting command is exactly the
		// failure mode this whole project exists to prevent.
		return RunOutcome{Denied: true, Reason: ReasonAuditUnavailable}
	}

	deny := func(reason string) RunOutcome {
		finishErr := b.logger.Finish(ctx, runID, audit.FinishRecord{Outcome: "denied:" + reason})
		return RunOutcome{Denied: true, Reason: reason, AuditIncomplete: finishErr != nil}
	}

	project, ok := b.cfg.Project(req.Project)
	if !ok {
		return deny(ReasonUnknownProject)
	}
	if project.WorkingDir != "" && !sameWorkingDir(project.WorkingDir, req.WorkingDir) {
		return deny(ReasonWorkingDirectoryNotAllowed)
	}

	switch b.decide(project, req.Argv) {
	case VerdictDeny:
		return deny(ReasonNotAllowlisted)

	case VerdictPrompt:
		prompt := formatPrompt(req.Project, req.WorkingDir, req.Argv)
		decision, approveErr := b.approver.Approve(ctx, prompt)
		if approveErr != nil || decision != approval.Approved {
			return deny(ReasonApprovalRejected)
		}
		// approved — fall through to execution below

	case VerdictAllow:
		// allowlisted — fall through to execution below
	}

	tok, err := b.resolver.Resolve(ctx, project.TokenEntry)
	if err != nil {
		return deny(ReasonTokenResolutionFailed)
	}

	result, err := b.cmdRunner.Run(ctx, runner.RunSpec{
		ProjectID:  project.BWSProjectID,
		Token:      tok,
		WorkingDir: req.WorkingDir,
		Argv:       req.Argv,
		Stdin:      req.Stdin,
		Stdout:     req.Stdout,
		Stderr:     req.Stderr,
	})
	if err != nil {
		return deny(ReasonRunnerStartFailed)
	}

	exitCode := result.ExitCode
	finishErr := b.logger.Finish(ctx, runID, audit.FinishRecord{Outcome: "executed", ExitCode: &exitCode})
	return RunOutcome{Denied: false, ExitCode: result.ExitCode, AuditIncomplete: finishErr != nil}
}

func sameWorkingDir(allowed, requested string) bool {
	if requested == "" {
		return false
	}
	allowedPath, err := filepath.EvalSymlinks(allowed)
	if err != nil {
		return false
	}
	requestedPath, err := filepath.EvalSymlinks(requested)
	if err != nil {
		return false
	}
	return filepath.Clean(allowedPath) == filepath.Clean(requestedPath)
}

func formatPrompt(project, workingDir string, argv []string) string {
	lines := make([]string, len(argv))
	for i, arg := range argv {
		lines[i] = fmt.Sprintf("  argv[%d] = %s", i, strconv.QuoteToASCII(arg))
	}
	return fmt.Sprintf(
		"secrets-broker: allow project %q to run:\n\nworking directory: %s\n%s",
		project,
		strconv.QuoteToASCII(workingDir),
		strings.Join(lines, "\n"),
	)
}

// DryRunResult is the outcome of a policy check that never touches the
// token resolver, the approver, the runner, or the audit log.
type DryRunResult struct {
	Verdict Verdict
	Reason  string // human-readable explanation
}

// DryRun resolves the same policy decision Run would reach, without any of
// Run's side effects — for preflighting a command.
func (b *Broker) DryRun(project, workingDir string, argv []string) DryRunResult {
	p, ok := b.cfg.Project(project)
	if !ok {
		return DryRunResult{Verdict: VerdictDeny, Reason: "unknown project"}
	}
	if p.WorkingDir != "" && !sameWorkingDir(p.WorkingDir, workingDir) {
		return DryRunResult{Verdict: VerdictDeny, Reason: "working directory not allowed"}
	}

	switch b.decide(p, argv) {
	case VerdictAllow:
		return DryRunResult{Verdict: VerdictAllow, Reason: "allowlisted"}
	case VerdictPrompt:
		return DryRunResult{Verdict: VerdictPrompt, Reason: fmt.Sprintf("would prompt for approval (project approval=%q)", p.Approval)}
	default:
		return DryRunResult{Verdict: VerdictDeny, Reason: fmt.Sprintf("not allowlisted and project approval=%q", p.Approval)}
	}
}

// decide is the pure policy core, shared by Run and DryRun.
func (b *Broker) decide(project config.Project, argv []string) Verdict {
	if project.Approval == config.ApprovalAlways {
		return VerdictPrompt
	}
	allowlisted := policy.Match(project.AllowArgv(), argv)
	if allowlisted && project.Approval == config.ApprovalAllowlistedPrompt {
		return VerdictPrompt
	}
	if allowlisted {
		return VerdictAllow
	}
	if project.Approval == config.ApprovalPrompt {
		return VerdictPrompt
	}
	return VerdictDeny
}
