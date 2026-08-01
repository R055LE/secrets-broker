// Package audit writes an append-only record of every command the broker
// was asked to run, before it runs (Start) and after it's decided/finished
// (Finish) — mirroring agentic-platform-lab's audit-before-forwarding
// pattern so a crash mid-command leaves a detectable orphaned Start record
// rather than silence.
package audit

import "context"

// StartRecord is written before the broker does anything else for this
// invocation — before touching the token resolver, before checking the
// allowlist, before any approval prompt.
type StartRecord struct {
	Project string
	Argv    []string // the requested command, never secret values
}

// FinishRecord is written once the broker has reached a final outcome.
// Outcome is a short machine-readable string, e.g. "executed",
// "denied:unknown_project", "denied:not_allowlisted",
// "denied:approval_rejected", "denied:token_resolution_failed",
// "denied:runner_error". ExitCode is nil for any broker-side denial — it's
// only set when the wrapped command actually ran.
type FinishRecord struct {
	Outcome  string
	ExitCode *int
}

// Logger writes the audit trail. Start and Finish are always called in
// pairs by internal/broker, with the runID from Start passed to the
// matching Finish — but they're separate append operations, not an
// in-place update, so the log stays append-only.
type Logger interface {
	Start(ctx context.Context, rec StartRecord) (runID string, err error)
	Finish(ctx context.Context, runID string, rec FinishRecord) error
}
