package relay

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type createRequestBody struct {
	Prompt string `json:"prompt"`
}

type requestView struct {
	ID       string `json:"id"`
	Status   Status `json:"status"`
	Deadline string `json:"deadline"`
}

// NewControlHandler serves the broker-facing side: registering a pending
// request and polling its status. Bind this to a port only the broker
// host's tailnet identity can reach — see server_test.go for behavior,
// and decisions/0009 in the main repo for why this is a separate port
// from NewDecisionHandler rather than the same one.
func NewControlHandler(store *Store, ttl time.Duration) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		var body createRequestBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Prompt == "" {
			http.Error(w, "invalid request body: prompt is required", http.StatusBadRequest)
			return
		}

		if err := store.Create(id, body.Prompt, ttl); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}

		req, _ := store.Get(id)
		writeJSON(w, http.StatusCreated, viewOf(req))
	})

	mux.HandleFunc("GET /requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		req, err := store.Get(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, viewOf(req))
	})

	return mux
}

type decideRequestBody struct {
	Decision string `json:"decision"` // "approve" | "deny"
}

// NewDecisionHandler serves the approver-facing side: submitting a
// decision for a pending request. Bind this to a port only the approving
// device's tailnet identity can reach. This handler enforces nothing
// about *who* is calling it — that's Tailscale ACLs' job, applied at the
// network layer before a connection ever reaches here. No app-level
// token is checked on purpose; see decisions/0008.
func NewDecisionHandler(store *Store) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /requests/{id}/decide", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		var body decideRequestBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		var approve bool
		switch body.Decision {
		case "approve":
			approve = true
		case "deny":
			approve = false
		default:
			http.Error(w, `decision must be "approve" or "deny"`, http.StatusBadRequest)
			return
		}

		if err := store.Decide(id, approve); err != nil {
			if errors.Is(err, ErrNotFound) {
				http.Error(w, err.Error(), http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusConflict)
			}
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	return mux
}

func viewOf(req Request) requestView {
	return requestView{
		ID:       req.ID,
		Status:   req.Status,
		Deadline: req.Deadline.UTC().Format(time.RFC3339),
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
