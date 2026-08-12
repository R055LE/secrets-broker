package relay_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

// postForm simulates what a plain HTML <form method="POST"> submits from
// a mobile browser — the tap-to-approve page's actual request shape,
// distinct from postJSON's scripted-caller shape.
func postForm(t *testing.T, handler http.Handler, path string, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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

func TestControlHandler_RejectsOversizedPrompt(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)

	rec := postJSON(t, control, "/requests/req-1", map[string]string{"prompt": strings.Repeat("x", 17<<10)})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", rec.Code)
	}
}

func TestControlHandler_RejectsInvalidRequestID(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)

	rec := postJSON(t, control, "/requests/bad$id", map[string]string{"prompt": "prompt"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", rec.Code)
	}
}

func TestControlHandler_RejectsNonASCIIRequestID(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)

	rec := postJSON(t, control, "/requests/request-é", map[string]string{"prompt": "prompt"})
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

func TestDecisionHandler_ApprovalPageShowsPromptAndButtons(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)
	decision := relay.NewDecisionHandler(store)

	postJSON(t, control, "/requests/req-1", map[string]string{"prompt": "run git push?"})

	rec := getJSON(t, decision, "/requests/req-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "run git push?") {
		t.Fatalf("page missing the prompt text: %s", body)
	}
	if !strings.Contains(body, `value="approve"`) || !strings.Contains(body, `value="deny"`) {
		t.Fatalf("page missing approve/deny form controls: %s", body)
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("approval page must deny framing, got %q", rec.Header().Get("X-Frame-Options"))
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("approval page missing CSP frame protection: %q", rec.Header().Get("Content-Security-Policy"))
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("approval page must not be cached, got %q", rec.Header().Get("Cache-Control"))
	}
}

func TestDecisionHandler_ApprovalPageUnknownID(t *testing.T) {
	store := relay.NewStore()
	decision := relay.NewDecisionHandler(store)

	rec := getJSON(t, decision, "/requests/nonexistent")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got status %d, want 404", rec.Code)
	}
}

func TestDecisionHandler_ApprovalPageAlreadyDecided(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)
	decision := relay.NewDecisionHandler(store)

	postJSON(t, control, "/requests/req-1", map[string]string{"prompt": "prompt"})
	postJSON(t, decision, "/requests/req-1/decide", map[string]string{"decision": "approve"})

	rec := getJSON(t, decision, "/requests/req-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, `value="approve"`) {
		t.Fatalf("an already-decided request must not still show the approve button: %s", body)
	}
	if !strings.Contains(body, "approved") {
		t.Fatalf("page should mention the request is already approved: %s", body)
	}
}

func TestDecisionHandler_FormApproveThenReflectedViaControl(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)
	decision := relay.NewDecisionHandler(store)

	postJSON(t, control, "/requests/req-1", map[string]string{"prompt": "prompt"})

	rec := postForm(t, decision, "/requests/req-1/decide", url.Values{"decision": {"approve"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Approved") {
		t.Fatalf("form submission should render a confirmation page, got: %s", rec.Body.String())
	}

	pollRec := getJSON(t, control, "/requests/req-1")
	var view map[string]string
	_ = json.Unmarshal(pollRec.Body.Bytes(), &view)
	if view["status"] != "approved" {
		t.Fatalf("got status %q, want approved", view["status"])
	}
}

func TestDecisionHandler_FormDenyThenReflectedViaControl(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)
	decision := relay.NewDecisionHandler(store)

	postJSON(t, control, "/requests/req-1", map[string]string{"prompt": "prompt"})

	rec := postForm(t, decision, "/requests/req-1/decide", url.Values{"decision": {"deny"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Denied") {
		t.Fatalf("form submission should render a confirmation page, got: %s", rec.Body.String())
	}

	pollRec := getJSON(t, control, "/requests/req-1")
	var view map[string]string
	_ = json.Unmarshal(pollRec.Body.Bytes(), &view)
	if view["status"] != "denied" {
		t.Fatalf("got status %q, want denied", view["status"])
	}
}

func TestDecisionHandler_PromptTextIsEscaped(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)
	decision := relay.NewDecisionHandler(store)

	postJSON(t, control, "/requests/req-1", map[string]string{"prompt": `<script>alert(1)</script>`})

	rec := getJSON(t, decision, "/requests/req-1")
	body := rec.Body.String()
	if strings.Contains(body, "<script>") {
		t.Fatalf("prompt text must be HTML-escaped, got unescaped script tag: %s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("expected the escaped form of the prompt in the page: %s", body)
	}
}

func TestDecisionHandler_CrossOriginFormRejected(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)
	decision := relay.NewDecisionHandler(store)

	postJSON(t, control, "/requests/req-1", map[string]string{"prompt": "prompt"})

	req := httptest.NewRequest(http.MethodPost, "/requests/req-1/decide", strings.NewReader("decision=approve"))
	req.Host = "relay.example"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://attacker.example")
	rec := httptest.NewRecorder()
	decision.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got status %d, want 403 for a cross-origin form POST", rec.Code)
	}

	// Confirm the decision genuinely didn't take effect.
	pollRec := getJSON(t, control, "/requests/req-1")
	var view map[string]string
	_ = json.Unmarshal(pollRec.Body.Bytes(), &view)
	if view["status"] != "pending" {
		t.Fatalf("got status %q, want pending — the rejected cross-origin request must not have decided anything", view["status"])
	}
}

func TestDecisionHandler_SameOriginFormAccepted(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)
	decision := relay.NewDecisionHandler(store)

	postJSON(t, control, "/requests/req-1", map[string]string{"prompt": "prompt"})

	req := httptest.NewRequest(http.MethodPost, "/requests/req-1/decide", strings.NewReader("decision=approve"))
	req.Host = "relay.example"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://relay.example")
	rec := httptest.NewRecorder()
	decision.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 for a same-origin form POST: %s", rec.Code, rec.Body.String())
	}
}

func TestDecisionHandler_MismatchedRefererRejected(t *testing.T) {
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)
	decision := relay.NewDecisionHandler(store)

	postJSON(t, control, "/requests/req-1", map[string]string{"prompt": "prompt"})

	req := httptest.NewRequest(http.MethodPost, "/requests/req-1/decide", strings.NewReader("decision=approve"))
	req.Host = "relay.example"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://attacker.example/evil-page")
	rec := httptest.NewRecorder()
	decision.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got status %d, want 403 for a mismatched Referer", rec.Code)
	}
}

func TestDecisionHandler_NoOriginOrRefererAllowed(t *testing.T) {
	// The documented scripted/JSON API path — no browser, no Origin/Referer
	// at all. Must not be broken by the CSRF defense, which only targets
	// browser-driven requests.
	store := relay.NewStore()
	control := relay.NewControlHandler(store, time.Minute)
	decision := relay.NewDecisionHandler(store)

	postJSON(t, control, "/requests/req-1", map[string]string{"prompt": "prompt"})

	rec := postJSON(t, decision, "/requests/req-1/decide", map[string]string{"decision": "approve"})
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 for a header-less scripted call: %s", rec.Code, rec.Body.String())
	}
}
