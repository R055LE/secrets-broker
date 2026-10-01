package adminweb

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func request(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = testConfig.Host
	r.Header.Set("Tailscale-User-Login", testConfig.Login)
	r.Header.Set("Origin", "https://"+testConfig.Host)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r.WithContext(context.WithValue(r.Context(), peerKey{}, true))
}

func response(s *Server, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestAuthorizationPrecedesAllRoutes(t *testing.T) {
	s := NewServer(testConfig)
	calls := 0
	s.mux.HandleFunc("/probe", func(http.ResponseWriter, *http.Request) { calls++ })
	for _, method := range []string{"GET", "POST"} {
		for _, change := range []func(*http.Request) *http.Request{
			func(r *http.Request) *http.Request { return r.WithContext(context.Background()) },
			func(r *http.Request) *http.Request { r.Header.Del("Tailscale-User-Login"); return r },
			func(r *http.Request) *http.Request { r.Header.Set("Tailscale-User-Login", "forged"); return r },
			func(r *http.Request) *http.Request { r.Header.Add("Tailscale-User-Login", testConfig.Login); return r },
			func(r *http.Request) *http.Request { r.Host = "other.example.ts.net"; return r },
			func(r *http.Request) *http.Request { r.URL.Host = testConfig.Host; return r },
		} {
			w := response(s, change(request(method, "/probe", "")))
			if w.Code != http.StatusForbidden || calls != 0 {
				t.Fatalf("unauthorized route: status %d, calls %d", w.Code, calls)
			}
		}
	}
	if w := response(s, request("DELETE", "/probe", "")); w.Code != http.StatusMethodNotAllowed || calls != 0 {
		t.Fatal("unsupported method reached route")
	}
}

func TestHomeEscapesIdentityAndHasSafeHeaders(t *testing.T) {
	cfg := testConfig
	cfg.Login = "<script>alert(1)</script>@example.invalid"
	s := NewServer(cfg)
	r := request("GET", "/", "")
	r.Header.Set("Tailscale-User-Login", cfg.Login)
	w := response(s, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "<script>") || !strings.Contains(w.Body.String(), "&lt;script&gt;") {
		t.Fatalf("unsafe HTML: %s", w.Body.String())
	}
	for name, value := range map[string]string{
		"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
		"Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
	} {
		if w.Header().Get(name) != value {
			t.Fatalf("missing header %s", name)
		}
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") || len(s.tokens) != 0 {
		t.Fatal("unsafe policy or GET token side effect")
	}
}

func postHarness(t *testing.T) (*Server, *int, string) {
	t.Helper()
	s := NewServer(testConfig)
	s.revision = func() (string, error) { return "current", nil }
	calls := new(int)
	s.mux.HandleFunc("POST /change", s.protectPost("/change", func(w http.ResponseWriter, r *http.Request) {
		*calls++
		if r.Context().Err() != nil {
			t.Error("operation inherited browser cancellation")
		}
		if _, ok := r.Context().Deadline(); !ok {
			t.Error("operation has no deadline")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	token, err := s.issueToken("/change", "current")
	if err != nil {
		t.Fatal(err)
	}
	return s, calls, "csrf=" + url.QueryEscape(token)
}

func TestPostRejectsOriginContentTypeTokensAndOversize(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"missing origin":   func(r *http.Request) { r.Header.Del("Origin") },
		"cross origin":     func(r *http.Request) { r.Header.Set("Origin", "https://other.example.ts.net") },
		"duplicate origin": func(r *http.Request) { r.Header.Add("Origin", "https://"+testConfig.Host) },
		"json":             func(r *http.Request) { r.Header.Set("Content-Type", "application/json") },
		"query token":      func(r *http.Request) { r.URL.RawQuery = "csrf=token" },
	} {
		t.Run(name, func(t *testing.T) {
			s, calls, body := postHarness(t)
			r := request("POST", "/change", body)
			change(r)
			if w := response(s, r); w.Code < 400 || *calls != 0 {
				t.Fatalf("unsafe POST status=%d calls=%d", w.Code, *calls)
			}
		})
	}
	for _, body := range []string{"", "csrf=forged", "csrf=one&csrf=two", "csrf=x&data=" + strings.Repeat("x", 64<<10)} {
		s, calls, _ := postHarness(t)
		if w := response(s, request("POST", "/change", body)); w.Code < 400 || *calls != 0 {
			t.Fatalf("accepted invalid or oversized form: %d", w.Code)
		}
	}
}

func TestSingleUseStaleAndCancelledPosts(t *testing.T) {
	s, calls, body := postHarness(t)
	if w := response(s, request("GET", "/change", "")); w.Code != 405 || *calls != 0 {
		t.Fatal("GET performed a POST action")
	}
	r := request("POST", "/change", body)
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	if w := response(s, r.WithContext(ctx)); w.Code != 204 || *calls != 1 {
		t.Fatalf("valid disconnected operation failed: %d", w.Code)
	}
	if w := response(s, request("POST", "/change", body)); w.Code != 403 || *calls != 1 {
		t.Fatal("form replay performed another operation")
	}
	s, calls, body = postHarness(t)
	s.revision = func() (string, error) { return "newer", nil }
	if w := response(s, request("POST", "/change", body)); w.Code != 409 || *calls != 0 {
		t.Fatal("stale form performed operation")
	}
	s, calls, body = postHarness(t)
	s.revision = func() (string, error) { return "", errors.New("private-path") }
	if w := response(s, request("POST", "/change", body)); w.Code != 503 || *calls != 0 || strings.Contains(w.Body.String(), "private-path") {
		t.Fatal("policy read failure was not safe")
	}
}

func TestTokensExpireAreActionBoundAndBounded(t *testing.T) {
	s := NewServer(testConfig)
	now := time.Now()
	s.now = func() time.Time { return now }
	token, _ := s.issueToken("one", "")
	if _, ok := s.takeToken(token, "two"); ok {
		t.Fatal("token accepted for different action")
	}
	for range 128 {
		if _, err := s.issueToken("one", ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.issueToken("one", ""); err == nil {
		t.Fatal("unbounded token state")
	}
	now = now.Add(10 * time.Minute)
	if _, ok := s.takeToken(token, "one"); ok {
		t.Fatal("expired token accepted")
	}
	if _, err := s.issueToken("one", ""); err != nil || len(s.tokens) != 1 {
		t.Fatal("expired forms were not removed")
	}
}
