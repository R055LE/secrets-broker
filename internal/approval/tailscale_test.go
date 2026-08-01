package approval_test

import (
	"context"
	"testing"
	"time"

	"github.com/R055LE/secrets-broker/internal/approval"
)

func TestTailscaleApprover_ApprovedAfterPolling(t *testing.T) {
	client := &approval.FakeRelayClient{
		PollSequence: []approval.RelayStatus{approval.RelayStatusPending, approval.RelayStatusPending, approval.RelayStatusApproved},
	}
	a := approval.NewTailscaleApprover(client, 5*time.Millisecond, 2*time.Second)

	decision, err := a.Approve(context.Background(), "run git push?")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != approval.Approved {
		t.Fatalf("got %v, want Approved", decision)
	}
	if len(client.Registered) != 1 || client.Registered[0].Prompt != "run git push?" {
		t.Fatalf("expected exactly one registration with the prompt, got %v", client.Registered)
	}
}

func TestTailscaleApprover_Denied(t *testing.T) {
	client := &approval.FakeRelayClient{
		PollSequence: []approval.RelayStatus{approval.RelayStatusPending, approval.RelayStatusDenied},
	}
	a := approval.NewTailscaleApprover(client, 5*time.Millisecond, 2*time.Second)

	decision, err := a.Approve(context.Background(), "prompt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != approval.Denied {
		t.Fatalf("got %v, want Denied", decision)
	}
}

func TestTailscaleApprover_ExpiredIsDenied(t *testing.T) {
	client := &approval.FakeRelayClient{
		PollSequence: []approval.RelayStatus{approval.RelayStatusExpired},
	}
	a := approval.NewTailscaleApprover(client, 5*time.Millisecond, 2*time.Second)

	decision, err := a.Approve(context.Background(), "prompt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != approval.Denied {
		t.Fatalf("got %v, want Denied", decision)
	}
}

func TestTailscaleApprover_TimeoutIsDenied(t *testing.T) {
	client := &approval.FakeRelayClient{} // always reports Pending
	a := approval.NewTailscaleApprover(client, 5*time.Millisecond, 30*time.Millisecond)

	start := time.Now()
	decision, err := a.Approve(context.Background(), "prompt")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("a timeout must not be reported as an error: %v", err)
	}
	if decision != approval.Denied {
		t.Fatalf("got %v, want Denied on timeout", decision)
	}
	if elapsed < 30*time.Millisecond {
		t.Fatalf("returned after %v, before the configured timeout elapsed", elapsed)
	}
}

func TestTailscaleApprover_RegisterErrorIsDenied(t *testing.T) {
	client := &approval.FakeRelayClient{RegisterErr: context.DeadlineExceeded}
	a := approval.NewTailscaleApprover(client, 5*time.Millisecond, time.Second)

	decision, err := a.Approve(context.Background(), "prompt")
	if err == nil {
		t.Fatal("expected an error when registration fails")
	}
	if decision != approval.Denied {
		t.Fatalf("got %v, want Denied even on error", decision)
	}
}

func TestTailscaleApprover_TransientPollErrorsAreRetried(t *testing.T) {
	// PollErr forces every Poll call to fail — this proves a run of
	// transient failures doesn't return early, only the timeout does.
	client := &approval.FakeRelayClient{PollErr: context.DeadlineExceeded}
	a := approval.NewTailscaleApprover(client, 5*time.Millisecond, 30*time.Millisecond)

	decision, err := a.Approve(context.Background(), "prompt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != approval.Denied {
		t.Fatalf("got %v, want Denied after exhausting the timeout on poll errors", decision)
	}
}
