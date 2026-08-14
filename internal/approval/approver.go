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

// Approver asks a human whether a command may run. Any error, and any
// non-Approved Decision, must be treated identically by callers: a hard
// deny. There is no "unsure" outcome.
type Approver interface {
	Approve(ctx context.Context, prompt string) (Decision, error)
}
