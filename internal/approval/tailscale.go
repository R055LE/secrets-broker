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
}

func NewTailscaleApprover(client RelayClient, pollInterval, timeout time.Duration) *TailscaleApprover {
	return &TailscaleApprover{client: client, pollInterval: pollInterval, timeout: timeout}
}

func (a *TailscaleApprover) Approve(ctx context.Context, prompt string) (Decision, error) {
	id, err := newRequestID()
	if err != nil {
		return Denied, fmt.Errorf("generating request id: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	if err := a.client.Register(ctx, id, prompt); err != nil {
		return Denied, fmt.Errorf("registering with relay: %w", err)
	}

	ticker := time.NewTicker(a.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Timeout, same as an explicit "no" — a legitimate outcome
			// for a remote approver waiting on a human, not a
			// malfunction. broker.go treats any non-Approved decision
			// identically regardless, so there's nothing for a
			// distinguishing error here to communicate that matters.
			return Denied, nil

		case <-ticker.C:
			status, err := a.client.Poll(ctx, id)
			if err != nil {
				// A transient poll failure doesn't fail the request
				// immediately — keep trying until the timeout bounds it.
				// If the relay is genuinely unreachable, this just means
				// every poll fails until timeout, landing on the same
				// fail-closed Denied outcome, a beat slower.
				continue
			}
			switch status {
			case RelayStatusApproved:
				return Approved, nil
			case RelayStatusDenied, RelayStatusExpired:
				return Denied, nil
			default:
				// RelayStatusPending, or anything unrecognized — keep polling.
			}
		}
	}
}

func newRequestID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
