package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// TailscaleApprover asks a relay running on a separate device (see
// decisions/0008) to gate a decision, polling until it's answered or the
// timeout expires. The relay enforces nothing about identity — Tailscale
// ACLs restricting who can reach the relay's decision port are what make
// this safe (decisions/0009). This type is deliberately just an HTTP
// polling loop with no authentication logic of its own; it doesn't need
// any, and shouldn't grow any.
type TailscaleApprover struct {
	client       RelayClient
	pollInterval time.Duration
	timeout      time.Duration

	// cause records the sanitized reason for the most recent denial.
	// An instance is created per broker request (see the worker server),
	// so there is no concurrent-approval race; if one were ever reused,
	// only the cause of the latest call would be observable.
	cause Cause
}

func NewTailscaleApprover(client RelayClient, pollInterval, timeout time.Duration) *TailscaleApprover {
	return &TailscaleApprover{client: client, pollInterval: pollInterval, timeout: timeout}
}

// ApproveCause reports the sanitized cause of the most recent denial. It
// is diagnostic only; every denial is still fail-closed.
func (a *TailscaleApprover) ApproveCause() Cause {
	if a.cause == "" {
		return CauseExpired
	}
	return a.cause
}

func (a *TailscaleApprover) Approve(ctx context.Context, prompt string) (Decision, error) {
	a.cause = CauseExpired
	id, err := newRequestID()
	if err != nil {
		return Denied, fmt.Errorf("generating request id: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	if err := a.client.Register(ctx, id, prompt); err != nil {
		a.cause = CauseUnreachable
		return Denied, fmt.Errorf("registering with relay: %w", err)
	}

	ticker := time.NewTicker(a.pollInterval)
	defer ticker.Stop()

	pollFailures := 0
	pollSucceeded := false
	for {
		select {
		case <-ctx.Done():
			// Timeout, same as an explicit "no" — a legitimate outcome
			// for a remote approver waiting on a human, not a
			// malfunction. broker.go treats any non-Approved decision
			// identically regardless, so there's nothing for a
			// distinguishing error here to communicate that matters.
			// The cause does distinguish an unanswered request from a
			// relay that never responded to polling at all.
			if pollFailures > 0 && !pollSucceeded {
				a.cause = CauseUnreachable
			}
			return Denied, nil

		case <-ticker.C:
			status, err := a.client.Poll(ctx, id)
			if err != nil {
				// Poll itself may return the approval context's deadline.
				// That is the unanswered-request timeout, not evidence that
				// the relay was unreachable.
				if ctx.Err() == nil {
					pollFailures++
				}
				// A transient poll failure doesn't fail the request
				// immediately — keep trying until the timeout bounds it.
				// If the relay is genuinely unreachable, this just means
				// every poll fails until timeout, landing on the same
				// fail-closed Denied outcome, a beat slower.
				continue
			}
			pollSucceeded = true
			switch status {
			case RelayStatusApproved:
				return Approved, nil
			case RelayStatusDenied:
				a.cause = CauseRejected
				return Denied, nil
			case RelayStatusExpired:
				a.cause = CauseExpired
				return Denied, nil
			default:
				// RelayStatusPending, or anything unrecognized — keep polling.
			}
		}
	}
}

func newRequestID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
