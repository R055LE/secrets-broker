package approval_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/R055LE/secrets-broker/internal/approval"
	"github.com/R055LE/secrets-broker/internal/relay"
)

// These exercise HTTPRelayClient against a real internal/relay control
// handler (via httptest) — the actual wire format, not a fake.

func TestHTTPRelayClient_RegisterThenPoll(t *testing.T) {
	store := relay.NewStore()
	srv := httptest.NewServer(relay.NewControlHandler(store, time.Minute))
	defer srv.Close()

	client := approval.NewHTTPRelayClient(srv.URL, nil)

	if err := client.Register(context.Background(), "req-1", "run git push?"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	status, err := client.Poll(context.Background(), "req-1")
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if status != approval.RelayStatusPending {
		t.Fatalf("got status %v, want pending", status)
	}
}

func TestHTTPRelayClient_PollReflectsDecision(t *testing.T) {
	store := relay.NewStore()
	srv := httptest.NewServer(relay.NewControlHandler(store, time.Minute))
	defer srv.Close()

	client := approval.NewHTTPRelayClient(srv.URL, nil)
	_ = client.Register(context.Background(), "req-1", "prompt")

	if err := store.Decide("req-1", true); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	status, err := client.Poll(context.Background(), "req-1")
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if status != approval.RelayStatusApproved {
		t.Fatalf("got status %v, want approved", status)
	}
}

func TestHTTPRelayClient_RegisterDuplicateFails(t *testing.T) {
	store := relay.NewStore()
	srv := httptest.NewServer(relay.NewControlHandler(store, time.Minute))
	defer srv.Close()

	client := approval.NewHTTPRelayClient(srv.URL, nil)
	_ = client.Register(context.Background(), "req-1", "prompt")

	if err := client.Register(context.Background(), "req-1", "prompt again"); err == nil {
		t.Fatal("expected an error registering a duplicate id")
	}
}

func TestHTTPRelayClient_PollUnknownIDFails(t *testing.T) {
	store := relay.NewStore()
	srv := httptest.NewServer(relay.NewControlHandler(store, time.Minute))
	defer srv.Close()

	client := approval.NewHTTPRelayClient(srv.URL, nil)

	_, err := client.Poll(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected an error polling an unknown id")
	}
}

func TestHTTPRelayClient_UnreachableServerFails(t *testing.T) {
	client := approval.NewHTTPRelayClient("http://127.0.0.1:1", nil) // port 1: nothing listens there
	err := client.Register(context.Background(), "req-1", "prompt")
	if err == nil {
		t.Fatal("expected an error registering against an unreachable relay")
	}
}
