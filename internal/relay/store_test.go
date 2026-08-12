package relay_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/R055LE/secrets-broker/internal/relay"
)

func TestStore_CreateThenGet(t *testing.T) {
	s := relay.NewStore()
	if err := s.Create("req-1", "run git push?", time.Minute); err != nil {
		t.Fatalf("Create: %v", err)
	}

	req, err := s.Get("req-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if req.Status != relay.StatusPending {
		t.Fatalf("got status %v, want pending", req.Status)
	}
	if req.Prompt != "run git push?" {
		t.Fatalf("got prompt %q", req.Prompt)
	}
}

func TestStore_CreateDuplicateIDFails(t *testing.T) {
	s := relay.NewStore()
	if err := s.Create("req-1", "prompt", time.Minute); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if err := s.Create("req-1", "different prompt", time.Minute); err == nil {
		t.Fatal("expected an error creating a duplicate id")
	}
}

func TestStore_CapacityLimit(t *testing.T) {
	s := relay.NewStoreWithLimit(1)
	if err := s.Create("req-1", "prompt", time.Minute); err != nil {
		t.Fatalf("creating first request: %v", err)
	}
	if err := s.Create("req-2", "prompt", time.Minute); err == nil {
		t.Fatal("expected a full store to reject another request")
	}
}

func TestStore_GetUnknownID(t *testing.T) {
	s := relay.NewStore()
	_, err := s.Get("nonexistent")
	if !errors.Is(err, relay.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestStore_DecideApprove(t *testing.T) {
	s := relay.NewStore()
	_ = s.Create("req-1", "prompt", time.Minute)

	if err := s.Decide("req-1", true); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	req, _ := s.Get("req-1")
	if req.Status != relay.StatusApproved {
		t.Fatalf("got status %v, want approved", req.Status)
	}
}

func TestStore_DecideDeny(t *testing.T) {
	s := relay.NewStore()
	_ = s.Create("req-1", "prompt", time.Minute)

	if err := s.Decide("req-1", false); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	req, _ := s.Get("req-1")
	if req.Status != relay.StatusDenied {
		t.Fatalf("got status %v, want denied", req.Status)
	}
}

func TestStore_DecideUnknownID(t *testing.T) {
	s := relay.NewStore()
	err := s.Decide("nonexistent", true)
	if !errors.Is(err, relay.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestStore_DecideTwiceFails(t *testing.T) {
	s := relay.NewStore()
	_ = s.Create("req-1", "prompt", time.Minute)
	_ = s.Decide("req-1", true)

	if err := s.Decide("req-1", false); err == nil {
		t.Fatal("expected an error deciding an already-decided request")
	}
	// The first decision must stick — a second call must not flip it.
	req, _ := s.Get("req-1")
	if req.Status != relay.StatusApproved {
		t.Fatalf("got status %v, want the original decision (approved) preserved", req.Status)
	}
}

func TestStore_GetAfterDeadlineReportsExpired(t *testing.T) {
	s := relay.NewStore()
	_ = s.Create("req-1", "prompt", -time.Second) // already past deadline

	req, err := s.Get("req-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if req.Status != relay.StatusExpired {
		t.Fatalf("got status %v, want expired", req.Status)
	}
}

func TestStore_DecideAfterDeadlineFails(t *testing.T) {
	s := relay.NewStore()
	_ = s.Create("req-1", "prompt", -time.Second) // already past deadline

	if err := s.Decide("req-1", true); err == nil {
		t.Fatal("expected an error deciding an expired request")
	}
	// A late decision must not overwrite the expired status.
	req, _ := s.Get("req-1")
	if req.Status != relay.StatusExpired {
		t.Fatalf("got status %v, want expired (late decision must not count)", req.Status)
	}
}

func TestStore_Sweep(t *testing.T) {
	s := relay.NewStore()
	_ = s.Create("old", "prompt", -2*time.Hour)
	_ = s.Create("recent", "prompt", time.Minute)

	removed := s.Sweep(time.Hour)
	if removed != 1 {
		t.Fatalf("got %d removed, want 1", removed)
	}

	if _, err := s.Get("old"); !errors.Is(err, relay.ErrNotFound) {
		t.Fatal("expected the swept request to be gone")
	}
	if _, err := s.Get("recent"); err != nil {
		t.Fatalf("recent request should still exist: %v", err)
	}
}

func TestStore_ConcurrentAccess(t *testing.T) {
	s := relay.NewStore()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := "req-" + string(rune('a'+n%26)) + string(rune('0'+n/26))
			_ = s.Create(id, "prompt", time.Minute)
			_, _ = s.Get(id)
			_ = s.Decide(id, n%2 == 0)
		}(i)
	}
	wg.Wait()
	// No assertion beyond "the race detector doesn't complain" — this
	// test exists to run under `go test -race`.
}
