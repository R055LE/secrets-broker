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
