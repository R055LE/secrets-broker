package approval

import "context"

// FakeApprover is a scripted Approver for broker unit tests.
type FakeApprover struct {
	Decision Decision
	Err      error

	// Prompts records every prompt text passed to Approve, for assertions.
	Prompts []string
}

func (f *FakeApprover) Approve(ctx context.Context, prompt string) (Decision, error) {
	f.Prompts = append(f.Prompts, prompt)
	return f.Decision, f.Err
}

// FakeRelayClient is a scripted RelayClient for TailscaleApprover unit
// tests — no real HTTP server involved.
type FakeRelayClient struct {
	RegisterErr error

	// PollSequence is returned one status per Poll call, in order; the
	// last entry repeats once exhausted. PollErr, if set, is returned
	// instead on every call.
	PollSequence []RelayStatus
	PollErr      error

	Registered []struct{ ID, Prompt string }
	pollCalls  int
}

func (f *FakeRelayClient) Register(ctx context.Context, id, prompt string) error {
	f.Registered = append(f.Registered, struct{ ID, Prompt string }{id, prompt})
	return f.RegisterErr
}

func (f *FakeRelayClient) Poll(ctx context.Context, id string) (RelayStatus, error) {
	if f.PollErr != nil {
		return "", f.PollErr
	}
	if len(f.PollSequence) == 0 {
		return RelayStatusPending, nil
	}
	idx := f.pollCalls
	if idx >= len(f.PollSequence) {
		idx = len(f.PollSequence) - 1
	}
	f.pollCalls++
	return f.PollSequence[idx], nil
}
