package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strings"
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

// NewDecisionHandler serves the approver-facing side: viewing a pending
// request and submitting a decision for it. Bind this to a port only the
// approving device's tailnet identity can reach. This handler enforces
// nothing about *who* is calling it — that's Tailscale ACLs' job, applied
// at the network layer before a connection ever reaches here. No app-level
// token is checked on purpose; see decisions/0008.
//
// GET /requests/{id} renders a minimal tap-to-approve HTML page — no app
// or scripting needed on the approving device, just a browser. POST
// /requests/{id}/decide accepts either that page's plain HTML form
// submission or a JSON body ({"decision":"approve"|"deny"}) for scripted
// use, so both a phone tapping a button and a script curling the endpoint
// work against the same route.
func NewDecisionHandler(store *Store) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		req, err := store.Get(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if req.Status != StatusPending {
			writeApprovalPage(w, id, "", string(req.Status), false)
			return
		}
		writeApprovalPage(w, id, req.Prompt, "", true)
	})

	mux.HandleFunc("POST /requests/{id}/decide", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		decision, err := readDecision(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var approve bool
		switch decision {
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

		if isBrowserForm(r) {
			writeApprovalPage(w, id, "", decision, false)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	return mux
}

// readDecision accepts either a JSON body ({"decision":"..."}) for
// scripted callers or a application/x-www-form-urlencoded body (what a
// plain HTML <form> submits) for the tap-to-approve page — the same
// endpoint serves both without either caller needing to know about the
// other.
func readDecision(r *http.Request) (string, error) {
	if isBrowserForm(r) {
		if err := r.ParseForm(); err != nil {
			return "", fmt.Errorf("invalid form body")
		}
		return r.PostFormValue("decision"), nil
	}

	var body decideRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("invalid request body")
	}
	return body.Decision, nil
}

func isBrowserForm(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded")
}

// writeApprovalPage renders the tap-to-approve page. Deliberately no CSS
// framework, no JS, no external resources — a single static-looking page
// that works identically on any mobile browser and has nothing to fetch
// but itself. prompt/status/showButtons together select which of the
// three states (pending-with-buttons, already-decided, or a
// just-submitted confirmation) to show.
func writeApprovalPage(w http.ResponseWriter, id, prompt, status string, showButtons bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	var body string
	switch {
	case showButtons:
		body = fmt.Sprintf(`
			<p>secrets-broker is asking to run:</p>
			<pre>%s</pre>
			<form method="POST" action="/requests/%s/decide" style="display:inline">
				<input type="hidden" name="decision" value="approve">
				<button type="submit" style="font-size:1.5em;padding:0.5em 1em;">Approve</button>
			</form>
			<form method="POST" action="/requests/%s/decide" style="display:inline">
				<input type="hidden" name="decision" value="deny">
				<button type="submit" style="font-size:1.5em;padding:0.5em 1em;">Deny</button>
			</form>`,
			html.EscapeString(prompt), html.EscapeString(id), html.EscapeString(id))
	case status == "approve" || status == "deny":
		verb := map[string]string{"approve": "Approved", "deny": "Denied"}[status]
		body = fmt.Sprintf("<p>%s.</p>", verb)
	default:
		body = fmt.Sprintf("<p>This request is no longer pending (status: %s).</p>", html.EscapeString(status))
	}

	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>secrets-broker</title></head><body style="font-family:sans-serif;max-width:32em;margin:2em auto;padding:0 1em;">%s</body></html>`, body)
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
