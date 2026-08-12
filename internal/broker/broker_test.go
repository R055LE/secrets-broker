package broker_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/R055LE/secrets-broker/internal/approval"
	"github.com/R055LE/secrets-broker/internal/audit"
	"github.com/R055LE/secrets-broker/internal/broker"
	"github.com/R055LE/secrets-broker/internal/config"
	"github.com/R055LE/secrets-broker/internal/runner"
	"github.com/R055LE/secrets-broker/internal/token"
)

var (
	errFakeResolve = errors.New("fake: token resolution failed")
	errFakeRun     = errors.New("fake: runner failed to start")
	errFakeAudit   = errors.New("fake: audit log unavailable")
)

func testConfig() *config.Config {
	return &config.Config{
		TokenSource: config.TokenSource{
			Backend: config.BackendSecretService,
		},
		Projects: []config.Project{
			{
				Alias: "never-project", BWSProjectID: "proj-never", TokenEntry: "entry-never",
				Approval: config.ApprovalNever,
				Allow:    []config.AllowEntry{{Argv: []string{"git", "push"}}},
			},
			{
				Alias: "prompt-project", BWSProjectID: "proj-prompt", TokenEntry: "entry-prompt",
				Approval: config.ApprovalPrompt,
				Allow:    []config.AllowEntry{{Argv: []string{"git", "push"}}},
			},
			{
				Alias: "always-project", BWSProjectID: "proj-always", TokenEntry: "entry-always",
				Approval: config.ApprovalAlways,
				Allow:    []config.AllowEntry{{Argv: []string{"git", "push"}}},
			},
			{
				Alias: "cwd-project", BWSProjectID: "proj-cwd", TokenEntry: "entry-cwd",
				WorkingDir: "/tmp", Approval: config.ApprovalPrompt,
				Allow: []config.AllowEntry{{Argv: []string{"git", "push"}}},
			},
		},
	}
}

type harness struct {
	resolver *token.FakeResolver
	approver *approval.FakeApprover
	runner   *runner.FakeRunner
	logger   *audit.FakeLogger
	broker   *broker.Broker
}

func newHarness(cfg *config.Config) *harness {
	h := &harness{
		resolver: &token.FakeResolver{Token: token.New("s3cr3t")},
		approver: &approval.FakeApprover{Decision: approval.Approved},
		runner:   &runner.FakeRunner{Result: runner.Result{ExitCode: 0}},
		logger:   &audit.FakeLogger{},
	}
	h.broker = broker.New(cfg, h.resolver, h.approver, h.runner, h.logger)
	return h
}

func TestRun_UnknownProject_DeniesWithoutTouchingAnythingElse(t *testing.T) {
	h := newHarness(testConfig())

	out := h.broker.Run(context.Background(), broker.RunRequest{Project: "nonexistent", Argv: []string{"git", "push"}})

	if !out.Denied || out.Reason != broker.ReasonUnknownProject {
		t.Fatalf("got %+v, want Denied=true Reason=%s", out, broker.ReasonUnknownProject)
	}
	if len(h.resolver.Calls()) != 0 {
		t.Fatal("resolver must not be touched for an unknown project")
	}
	if len(h.runner.Specs) != 0 {
		t.Fatal("runner must not be touched for an unknown project")
	}
	if len(h.logger.Starts) != 1 || len(h.logger.Finishes) != 1 {
		t.Fatalf("expected exactly one start+finish audit record, got %d/%d", len(h.logger.Starts), len(h.logger.Finishes))
	}
	if h.logger.Finishes[0].Rec.Outcome != "denied:unknown_project" {
		t.Fatalf("got outcome %q", h.logger.Finishes[0].Rec.Outcome)
	}
}

func TestRun_WrongWorkingDirectory_DeniesBeforeApprovalOrTokenResolution(t *testing.T) {
	h := newHarness(testConfig())

	out := h.broker.Run(context.Background(), broker.RunRequest{
		Project:    "cwd-project",
		WorkingDir: "/tmp/not-the-approved-project",
		Argv:       []string{"git", "push"},
	})

	if !out.Denied || out.Reason != broker.ReasonWorkingDirectoryNotAllowed {
		t.Fatalf("got %+v", out)
	}
	if len(h.approver.Prompts) != 0 || len(h.resolver.Calls()) != 0 || len(h.runner.Specs) != 0 {
		t.Fatal("working-directory denial must happen before approval, token resolution, or execution")
	}
}

func TestRun_AllowlistedNever_Executes(t *testing.T) {
	h := newHarness(testConfig())

	out := h.broker.Run(context.Background(), broker.RunRequest{Project: "never-project", Argv: []string{"git", "push"}})

	if out.Denied {
		t.Fatalf("expected execution, got denial: %+v", out)
	}
	if len(h.approver.Prompts) != 0 {
		t.Fatal("an allowlisted command under approval=never must not prompt")
	}
	if len(h.runner.Specs) != 1 {
		t.Fatal("expected exactly one runner invocation")
	}
	if h.logger.Finishes[0].Rec.Outcome != "executed" {
		t.Fatalf("got outcome %q", h.logger.Finishes[0].Rec.Outcome)
	}
}

func TestRun_NotAllowlisted_ApprovalNever_Denies(t *testing.T) {
	h := newHarness(testConfig())

	out := h.broker.Run(context.Background(), broker.RunRequest{Project: "never-project", Argv: []string{"rm", "-rf", "/"}})

	if !out.Denied || out.Reason != broker.ReasonNotAllowlisted {
		t.Fatalf("got %+v", out)
	}
	if len(h.approver.Prompts) != 0 {
		t.Fatal("approval=never must never prompt, even for an off-allowlist command")
	}
	if len(h.resolver.Calls()) != 0 || len(h.runner.Specs) != 0 {
		t.Fatal("token resolver and runner must not be touched on denial")
	}
}

func TestRun_NotAllowlisted_Prompt_Approved_Executes(t *testing.T) {
	h := newHarness(testConfig())
	h.approver.Decision = approval.Approved

	out := h.broker.Run(context.Background(), broker.RunRequest{Project: "prompt-project", Argv: []string{"curl", "https://example.com"}})

	if out.Denied {
		t.Fatalf("expected execution after approval, got denial: %+v", out)
	}
	if len(h.approver.Prompts) != 1 {
		t.Fatal("expected exactly one approval prompt")
	}
}

func TestRun_ApprovalPromptPreservesArgvBoundariesAndEscapesControls(t *testing.T) {
	h := newHarness(testConfig())

	out := h.broker.Run(context.Background(), broker.RunRequest{
		Project: "prompt-project",
		Argv:    []string{"echo", "one two", "line-one\nApprove something else"},
	})

	if out.Denied {
		t.Fatalf("expected execution after approval, got %+v", out)
	}
	prompt := h.approver.Prompts[0]
	if !strings.Contains(prompt, `argv[1] = "one two"`) {
		t.Fatalf("prompt lost argv boundary: %q", prompt)
	}
	if strings.Contains(prompt, "line-one\nApprove something else") || !strings.Contains(prompt, `line-one\nApprove something else`) {
		t.Fatalf("prompt did not escape embedded newline: %q", prompt)
	}
}

func TestRun_NotAllowlisted_Prompt_Denied_Denies(t *testing.T) {
	h := newHarness(testConfig())
	h.approver.Decision = approval.Denied

	out := h.broker.Run(context.Background(), broker.RunRequest{Project: "prompt-project", Argv: []string{"curl", "https://example.com"}})

	if !out.Denied || out.Reason != broker.ReasonApprovalRejected {
		t.Fatalf("got %+v", out)
	}
	if len(h.resolver.Calls()) != 0 || len(h.runner.Specs) != 0 {
		t.Fatal("token resolver and runner must not be touched after an approval rejection")
	}
}

func TestRun_ApprovalAlways_PromptsEvenWhenAllowlisted(t *testing.T) {
	h := newHarness(testConfig())
	h.approver.Decision = approval.Approved

	out := h.broker.Run(context.Background(), broker.RunRequest{Project: "always-project", Argv: []string{"git", "push"}})

	if out.Denied {
		t.Fatalf("expected execution after approval, got denial: %+v", out)
	}
	if len(h.approver.Prompts) != 1 {
		t.Fatal("approval=always must prompt even for an allowlisted command")
	}
}

func TestRun_TokenResolutionFails_DeniesBeforeRunner(t *testing.T) {
	h := newHarness(testConfig())
	h.resolver.Err = errFakeResolve

	out := h.broker.Run(context.Background(), broker.RunRequest{Project: "never-project", Argv: []string{"git", "push"}})

	if !out.Denied || out.Reason != broker.ReasonTokenResolutionFailed {
		t.Fatalf("got %+v", out)
	}
	if len(h.runner.Specs) != 0 {
		t.Fatal("runner (bws) must never be invoked when token resolution fails")
	}
}

func TestRun_RunnerFailsToStart_Denies(t *testing.T) {
	h := newHarness(testConfig())
	h.runner.Err = errFakeRun

	out := h.broker.Run(context.Background(), broker.RunRequest{Project: "never-project", Argv: []string{"git", "push"}})

	if !out.Denied || out.Reason != broker.ReasonRunnerStartFailed {
		t.Fatalf("got %+v", out)
	}
}

func TestRun_WrappedCommandNonZeroExit_IsNotADenial(t *testing.T) {
	h := newHarness(testConfig())
	h.runner.Result = runner.Result{ExitCode: 7}

	out := h.broker.Run(context.Background(), broker.RunRequest{
		Project: "never-project", Argv: []string{"git", "push"},
		Stdin: &bytes.Buffer{}, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
	})

	if out.Denied {
		t.Fatalf("a wrapped-command failure must not be reported as Denied: %+v", out)
	}
	if out.ExitCode != 7 {
		t.Fatalf("got exit code %d, want 7", out.ExitCode)
	}
	if h.logger.Finishes[0].Rec.Outcome != "executed" {
		t.Fatalf("got outcome %q, want executed even though the wrapped command itself failed", h.logger.Finishes[0].Rec.Outcome)
	}
}

func TestRun_AuditStartFailure_DeniesAndTouchesNothingElse(t *testing.T) {
	h := newHarness(testConfig())
	h.logger.StartErr = errFakeAudit

	out := h.broker.Run(context.Background(), broker.RunRequest{Project: "never-project", Argv: []string{"git", "push"}})

	if !out.Denied || out.Reason != broker.ReasonAuditUnavailable {
		t.Fatalf("got %+v", out)
	}
	if len(h.resolver.Calls()) != 0 || len(h.runner.Specs) != 0 || len(h.approver.Prompts) != 0 {
		t.Fatal("nothing else must be touched if the broker can't even audit the attempt")
	}
	if len(h.logger.Finishes) != 0 {
		t.Fatal("Finish must not be called when Start itself failed (no run ID to pair it with)")
	}
}

func TestRun_AuditFinishFailureIsReportedAfterExecution(t *testing.T) {
	h := newHarness(testConfig())
	h.logger.FinishErr = errFakeAudit

	out := h.broker.Run(context.Background(), broker.RunRequest{Project: "never-project", Argv: []string{"git", "push"}})

	if out.Denied || !out.AuditIncomplete {
		t.Fatalf("got %+v, want executed outcome with AuditIncomplete", out)
	}
}

func TestRun_AuditFinishFailureIsReportedAfterDenial(t *testing.T) {
	h := newHarness(testConfig())
	h.logger.FinishErr = errFakeAudit

	out := h.broker.Run(context.Background(), broker.RunRequest{Project: "nonexistent", Argv: []string{"true"}})

	if !out.Denied || !out.AuditIncomplete {
		t.Fatalf("got %+v, want denied outcome with AuditIncomplete", out)
	}
}

func TestDryRun_Allowlisted_DoesNotTouchAnything(t *testing.T) {
	h := newHarness(testConfig())

	result := h.broker.DryRun("never-project", "", []string{"git", "push"})

	if result.Verdict != broker.VerdictAllow {
		t.Fatalf("got verdict %v, want VerdictAllow", result.Verdict)
	}
	if len(h.resolver.Calls()) != 0 || len(h.runner.Specs) != 0 || len(h.approver.Prompts) != 0 || len(h.logger.Starts) != 0 {
		t.Fatal("DryRun must not touch the resolver, runner, approver, or audit log")
	}
}

func TestDryRun_UnknownProject(t *testing.T) {
	h := newHarness(testConfig())
	result := h.broker.DryRun("nonexistent", "", []string{"git", "push"})
	if result.Verdict != broker.VerdictDeny {
		t.Fatalf("got verdict %v, want VerdictDeny", result.Verdict)
	}
}

func TestDryRun_NotAllowlistedPrompt(t *testing.T) {
	h := newHarness(testConfig())
	result := h.broker.DryRun("prompt-project", "", []string{"curl", "https://example.com"})
	if result.Verdict != broker.VerdictPrompt {
		t.Fatalf("got verdict %v, want VerdictPrompt", result.Verdict)
	}
}

func TestDryRun_NotAllowlistedNever(t *testing.T) {
	h := newHarness(testConfig())
	result := h.broker.DryRun("never-project", "", []string{"curl", "https://example.com"})
	if result.Verdict != broker.VerdictDeny {
		t.Fatalf("got verdict %v, want VerdictDeny", result.Verdict)
	}
}
