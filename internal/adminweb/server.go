package adminweb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"html/template"
	"mime"
	"net/http"
	"sync"
	"time"

	"github.com/R055LE/secrets-broker/internal/admin"
)

type peerKey struct{}

type formToken struct {
	action, login, revision string
	expires                 time.Time
}

type Server struct {
	cfg      Config
	mux      *http.ServeMux
	mu       sync.Mutex
	tokens   map[string]formToken
	now      func() time.Time
	revision func() (string, error)
}

func NewServer(cfg Config) *Server {
	s := &Server{
		cfg: cfg, mux: http.NewServeMux(), tokens: make(map[string]formToken),
		now: time.Now, revision: policyRevision,
	}
	s.mux.HandleFunc("GET /{$}", s.home)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	peer, _ := r.Context().Value(peerKey{}).(bool)
	login := r.Header.Values("Tailscale-User-Login")
	if !peer || len(login) != 1 || login[0] != s.cfg.Login || r.Host != s.cfg.Host || r.URL.Host != "" {
		http.Error(w, "Administrator access denied.", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	s.mux.ServeHTTP(w, r)
}

var homeTemplate = template.Must(template.New("home").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Secrets Broker</title></head>
<body><h1>Secrets Broker</h1><p>Administrator connection ready.</p><p>Signed in as {{.}}</p></body></html>`))

func (s *Server) home(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = homeTemplate.Execute(w, s.cfg.Login)
}

func (s *Server) issueToken(action, revision string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneTokens()
	if len(s.tokens) >= 128 {
		return "", errors.New("too many open administrator forms")
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	token := hex.EncodeToString(random[:])
	s.tokens[token] = formToken{action: action, login: s.cfg.Login, revision: revision, expires: s.now().Add(10 * time.Minute)}
	return token, nil
}

func (s *Server) pruneTokens() {
	for token, entry := range s.tokens {
		if !s.now().Before(entry.expires) {
			delete(s.tokens, token)
		}
	}
}

func (s *Server) takeToken(token, action string) (formToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneTokens()
	entry, ok := s.tokens[token]
	delete(s.tokens, token)
	return entry, ok && entry.action == action && entry.login == s.cfg.Login
}

func (s *Server) protectPost(action string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
			return
		}
		origins := r.Header.Values("Origin")
		if len(origins) != 1 || origins[0] != "https://"+s.cfg.Host {
			http.Error(w, "Form origin denied.", http.StatusForbidden)
			return
		}
		kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || kind != "application/x-www-form-urlencoded" {
			http.Error(w, "Unsupported form type.", http.StatusUnsupportedMediaType)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid or oversized form.", http.StatusBadRequest)
			return
		}
		if r.URL.RawQuery != "" || len(r.PostForm["csrf"]) != 1 {
			http.Error(w, "Invalid form token.", http.StatusForbidden)
			return
		}
		entry, ok := s.takeToken(r.PostForm.Get("csrf"), action)
		if !ok {
			http.Error(w, "Form expired or already submitted. Reload the page.", http.StatusForbidden)
			return
		}
		if entry.revision != "" {
			revision, err := s.revision()
			if err != nil {
				http.Error(w, "Policy cannot be read.", http.StatusServiceUnavailable)
				return
			}
			if revision != entry.revision {
				http.Error(w, "Policy changed. Reload the page before submitting.", http.StatusConflict)
				return
			}
		}
		// Complete audited work after a browser disconnects, with a finite operation deadline.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
		defer cancel()
		next(w, r.WithContext(ctx))
	}
}

func policyRevision() (string, error) {
	return admin.NewEditor(PolicyPath, 0).Revision()
}

type actorLogger struct {
	logger admin.MutationLogger
	login  string
}

func (l actorLogger) Start(ctx context.Context, record admin.MutationStart) (string, error) {
	record.ActorLogin = l.login
	return l.logger.Start(ctx, record)
}

func (l actorLogger) Finish(ctx context.Context, id string, record admin.MutationFinish) error {
	record.ActorLogin = l.login
	return l.logger.Finish(ctx, id, record)
}
