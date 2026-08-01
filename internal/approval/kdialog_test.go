package approval_test

import (
	"context"
	"testing"

	"github.com/R055LE/secrets-broker/internal/approval"
	"github.com/R055LE/secrets-broker/internal/execx"
)

func TestKDialogApprover_Yes(t *testing.T) {
	fake := &execx.FakeRunner{RunResult: execx.Result{ExitCode: 0}}
	a := approval.NewKDialogApprover(fake)

	decision, err := a.Approve(context.Background(), "run git push?")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != approval.Approved {
		t.Fatalf("got %v, want Approved", decision)
	}
}

func TestKDialogApprover_No(t *testing.T) {
	fake := &execx.FakeRunner{RunResult: execx.Result{ExitCode: 1}}
	a := approval.NewKDialogApprover(fake)

	decision, err := a.Approve(context.Background(), "run rm -rf /tmp/x?")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != approval.Denied {
		t.Fatalf("got %v, want Denied", decision)
	}
}

func TestKDialogApprover_UnexpectedExitCodeIsDenied(t *testing.T) {
	// e.g. no display available — must not be silently treated as approval.
	fake := &execx.FakeRunner{RunResult: execx.Result{ExitCode: 255}}
	a := approval.NewKDialogApprover(fake)

	decision, err := a.Approve(context.Background(), "run something?")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != approval.Denied {
		t.Fatalf("got %v, want Denied", decision)
	}
}

func TestKDialogApprover_RunnerErrorIsDenied(t *testing.T) {
	fake := &execx.FakeRunner{RunErr: context.DeadlineExceeded}
	a := approval.NewKDialogApprover(fake)

	decision, err := a.Approve(context.Background(), "run something?")
	if err == nil {
		t.Fatal("expected an error when the runner itself fails")
	}
	if decision != approval.Denied {
		t.Fatalf("got %v, want Denied even on error", decision)
	}
}
