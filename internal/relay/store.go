// Package relay implements the secrets-broker-relay server: an in-memory,
// expiring store of pending approval requests, reachable over two distinct
// ports (see server.go) so Tailscale ACLs alone can separate "can register
// a request" from "can decide one" — no application-level auth token. See
// decisions/0008 and decisions/0009 in the main repo for why.
package relay

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	// StatusExpired is never stored — it's computed on read once a
	// request's deadline has passed with no decision, so a slow Decide
	// arriving after expiry is rejected rather than silently accepted.
	StatusExpired Status = "expired"
)

var ErrNotFound = errors.New("request not found")

type Request struct {
	ID        string
	Prompt    string
	Status    Status
	CreatedAt time.Time
	Deadline  time.Time
}

// Store is a thread-safe, in-memory table of pending approval requests.
// Deliberately not persisted: a relay restart loses in-flight requests,
// which just makes them time out on the broker side — an acceptable
// fail-closed loss for a single-user, low-volume relay, not a reason to
// bring in a database.
type Store struct {
	mu       sync.Mutex
	requests map[string]*Request
	limit    int
}

func NewStore() *Store {
	return NewStoreWithLimit(1024)
}

func NewStoreWithLimit(limit int) *Store {
	return &Store{requests: make(map[string]*Request), limit: limit}
}

// Create registers a new pending request. Returns an error if id is
// already in use — colliding is a caller bug (IDs are generated with
// enough entropy that this should never legitimately happen), not a
// benign race to paper over.
func (s *Store) Create(id, prompt string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.requests[id]; exists {
		return fmt.Errorf("request %q already exists", id)
	}
	if len(s.requests) >= s.limit {
		return errors.New("request store is full")
	}

	now := time.Now()
	s.requests[id] = &Request{
		ID:        id,
		Prompt:    prompt,
		Status:    StatusPending,
		CreatedAt: now,
		Deadline:  now.Add(ttl),
	}
	return nil
}

// Get returns the current state of id. A pending request past its
// deadline is reported as StatusExpired without mutating the stored
// record, so a Decide racing in right at expiry is judged against the
// same deadline Get already saw.
func (s *Store) Get(id string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok {
		return Request{}, ErrNotFound
	}

	out := *req
	if out.Status == StatusPending && time.Now().After(out.Deadline) {
		out.Status = StatusExpired
	}
	return out, nil
}

// Pending returns a deadline-ordered snapshot of requests that can still
// be decided. Returning copies keeps callers from mutating store state.
func (s *Store) Pending() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	pending := make([]Request, 0, len(s.requests))
	for _, req := range s.requests {
		if req.Status == StatusPending && !now.After(req.Deadline) {
			pending = append(pending, *req)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		if pending[i].Deadline.Equal(pending[j].Deadline) {
			return pending[i].ID < pending[j].ID
		}
		return pending[i].Deadline.Before(pending[j].Deadline)
	})
	return pending
}

// Decide records a decision for id. Only the first decision to arrive
// before the deadline counts — a second call, a call after expiry, or a
// call for an unknown id all fail rather than silently overwriting or
// reviving a closed request.
func (s *Store) Decide(id string, approve bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok {
		return ErrNotFound
	}
	if time.Now().After(req.Deadline) {
		return fmt.Errorf("request %q has expired", id)
	}
	if req.Status != StatusPending {
		return fmt.Errorf("request %q was already decided (%s)", id, req.Status)
	}

	if approve {
		req.Status = StatusApproved
	} else {
		req.Status = StatusDenied
	}
	return nil
}

// Sweep removes requests whose deadline passed more than olderThan ago,
// so a long-running relay doesn't accumulate closed requests forever. Not
// called automatically — the composition root (cmd/secrets-broker-relay)
// owns scheduling it on a ticker, keeping this package free of goroutine
// lifecycle concerns.
func (s *Store) Sweep(olderThan time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)
	removed := 0
	for id, req := range s.requests {
		if req.Deadline.Before(cutoff) {
			delete(s.requests, id)
			removed++
		}
	}
	return removed
}
