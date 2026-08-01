package approval

import (
	"context"
	"fmt"

	"github.com/R055LE/secrets-broker/internal/execx"
)

// KDialogApprover prompts via KDE's kdialog --yesno. It's v1's only
// Approver implementation, because it's what this project's first
// deployment target (an interactive KDE desktop session) has. It requires
// an active desktop session — there's no fallback to a terminal prompt,
// because the broker is typically invoked non-interactively by an agent
// with no attached TTY to prompt on; a headless/remote deployment needs a
// different Approver (e.g. a webhook or chat-bot prompt), which is a new
// implementation of this interface, not a change to callers.
type KDialogApprover struct {
	runner execx.Runner
}

func NewKDialogApprover(runner execx.Runner) *KDialogApprover {
	return &KDialogApprover{runner: runner}
}

func (a *KDialogApprover) Approve(ctx context.Context, prompt string) (Decision, error) {
	result, err := a.runner.Run(ctx, "kdialog", []string{"--yesno", prompt}, nil)
	if err != nil {
		return Denied, fmt.Errorf("running kdialog: %w", err)
	}

	// kdialog --yesno exits 0 for Yes and 1 for No. Any other exit code
	// (missing binary, no display, killed) is also treated as Denied — the
	// caller can't tell "the human said no" from "the prompt mechanism
	// broke" from the exit code alone, and both must fail closed the same
	// way.
	if result.ExitCode == 0 {
		return Approved, nil
	}
	return Denied, nil
}
