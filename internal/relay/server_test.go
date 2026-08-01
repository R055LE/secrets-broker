package relay_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/R055LE/secrets-broker/internal/relay"
)

func postJSON(t *testing.T, handler http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encoding request body: %v", err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, path, &buf)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func getJSON(t *testing.T, handler http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestControlHandler_RegisterThenPoll(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)

	rec := postJSON(t, control, "/requests/req-1", map[string]string{"prompt": "run git push?"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("got status %d, want 201: %s", rec.Code, rec.Body.String())
	}

	rec = getJSON(t, control, "/requests/req-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var view map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if view["status"] != "pending" {
		t.Fatalf("got status %q, want pending", view["status"])
	}
}

func TestControlHandler_RegisterEmptyPromptRejected(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)

	rec := postJSON(t, control, "/requests/req-1", map[string]string{"prompt": ""})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", rec.Code)
	}
}

func TestControlHandler_RegisterDuplicateRejected(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)

	postJSON(t, control, "/requests/req-1", map[string]string{"prompt": "first"})
	rec := postJSON(t, control, "/requests/req-1", map[string]string{"prompt": "second"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("got status %d, want 409", rec.Code)
	}
}

func TestControlHandler_PollUnknownID(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)

	rec := getJSON(t, control, "/requests/nonexistent")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got status %d, want 404", rec.Code)
	}
}

func TestDecisionHandler_ApproveThenReflectedViaControl(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)
	decision := relay.NewDecisionHandler(store)

	postJSON(t, control, "/requests/req-1", map[string]string{"prompt": "prompt"})

	rec := postJSON(t, decision, "/requests/req-1/decide", map[string]string{"decision": "approve"})
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200: %s", rec.Code, rec.Body.String())
	}

	rec = getJSON(t, control, "/requests/req-1")
	var view map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if view["status"] != "approved" {
		t.Fatalf("got status %q, want approved", view["status"])
	}
}

func TestDecisionHandler_DenyThenReflectedViaControl(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)
	decision := relay.NewDecisionHandler(store)

	postJSON(t, control, "/requests/req-1", map[string]string{"prompt": "prompt"})

	rec := postJSON(t, decision, "/requests/req-1/decide", map[string]string{"decision": "deny"})
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200: %s", rec.Code, rec.Body.String())
	}

	rec = getJSON(t, control, "/requests/req-1")
	var view map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if view["status"] != "denied" {
		t.Fatalf("got status %q, want denied", view["status"])
	}
}

func TestDecisionHandler_UnknownIDRejected(t *testing.T) {
	store := relay.NewStore()
	decision := relay.NewDecisionHandler(store)

	rec := postJSON(t, decision, "/requests/nonexistent/decide", map[string]string{"decision": "approve"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got status %d, want 404", rec.Code)
	}
}

func TestDecisionHandler_AlreadyDecidedRejected(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)
	decision := relay.NewDecisionHandler(store)

	postJSON(t, control, "/requests/req-1", map[string]string{"prompt": "prompt"})
	postJSON(t, decision, "/requests/req-1/decide", map[string]string{"decision": "approve"})

	rec := postJSON(t, decision, "/requests/req-1/decide", map[string]string{"decision": "deny"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("got status %d, want 409", rec.Code)
	}
}

func TestDecisionHandler_InvalidDecisionValueRejected(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)
	decision := relay.NewDecisionHandler(store)

	postJSON(t, control, "/requests/req-1", map[string]string{"prompt": "prompt"})

	rec := postJSON(t, decision, "/requests/req-1/decide", map[string]string{"decision": "maybe"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", rec.Code)
	}
}
