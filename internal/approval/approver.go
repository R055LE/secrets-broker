// Package approval gates commands selected by a project's approval mode
// behind a human decision.
package approval

import "context"

// Decision is the outcome of an approval request. The zero value is Denied
// — a Decision left unset by a bug defaults to the safe outcome, not the
// unsafe one.
type Decision int

const (
	Denied Decision = iota
	Approved
)

// Cause is a sanitized, human-readable explanation of why an Approver
// reported Denied, suitable for surfacing to the agent-facing CLI. Causes
// are fixed strings — never errors, request identifiers, or relay details
// — because they cross the trust boundary to the untrusted caller.
type Cause string

const (
	CauseRejected    Cause = "rejected"    // a human explicitly declined
	CauseExpired     Cause = "expired"     // the request was never answered in time
	CauseUnreachable Cause = "unreachable" // the approval mechanism could not be reached
	CauseUnavailable Cause = "unavailable" // the approval mechanism failed locally
)

// CauseProvider is an optional Approver extension: an Approver that can
// explain its last denial. Callers must treat every non-Approved decision
// identically regardless of cause — the cause is diagnostic only.
type CauseProvider interface {
	ApproveCause() Cause
}

// Approver asks a human whether a command may run. Any error, and any
// non-Approved Decision, must be treated identically by callers: a hard
// deny. There is no "unsure" outcome.
type Approver interface {
	Approve(ctx context.Context, prompt string) (Decision, error)
}
