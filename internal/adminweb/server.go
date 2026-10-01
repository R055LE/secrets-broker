package adminweb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"mime"
	"net/http"
	"sync"
	"time"

	"github.com/R055LE/secrets-broker/internal/admin"
	"github.com/R055LE/secrets-broker/internal/execx"
	"github.com/R055LE/secrets-broker/internal/projectlist"
)

type peerKey struct{}
type revisionKey struct{}
type changeKey struct{}

type formToken struct {
	action, login, revision, target string
	expires                         time.Time
	change                          *policyChange
}

type Server struct {
	cfg            Config
	mux            *http.ServeMux
	mu             sync.Mutex
	tokens         map[string]formToken
	now            func() time.Time
	revision       func() (string, error)
	reader         projectReader
	logger         admin.MutationLogger
	access         admin.AccessDiagnostic
	available      []projectlist.Project
	availableUntil time.Time
	edit           func(string) policyMutator
	checks         map[string]projectChecks
}

func NewServer(cfg Config) *Server {
	s := &Server{
		cfg: cfg, mux: http.NewServeMux(), tokens: make(map[string]formToken), checks: make(map[string]projectChecks),
		now: time.Now, revision: policyRevision,
	}
	s.reader = admin.NewEditor(PolicyPath, 0)
	s.logger = actorLogger{logger: admin.NewMutationJSONLLogger("/var/log/secrets-broker-admin/audit.jsonl"), login: cfg.Login}
	s.access = admin.NewAuditedAccessDiagnostic(admin.NewWorkerAccessChecker(execx.OSRunner{}), s.logger, 0)
	s.edit = func(revision string) policyMutator {
		return admin.NewAuditedEditor(admin.NewEditor(PolicyPath, 0).WithRevision(revision), s.logger, 0)
	}
	s.registerPages()
	s.registerControls()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	peer, _ := r.Context().Value(peerKey{}).(bool)
	login := r.Header.Values("Tailscale-User-Login")
	// Serve rewrites the Unix proxy Host; its forwarded headers carry the public HTTPS origin.
	host := r.Header.Values("X-Forwarded-Host")
	proto := r.Header.Values("X-Forwarded-Proto")
	if !peer || len(login) != 1 || login[0] != s.cfg.Login || r.Host != "localhost" || r.URL.Host != "" ||
		len(host) != 1 || host[0] != s.cfg.Host || len(proto) != 1 || proto[0] != "https" {
		http.Error(w, "Administrator access denied.", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) issueToken(action, revision string) (string, error) {
	return s.issueTargetToken(action, revision, "")
}

func (s *Server) issueTargetToken(action, revision, target string) (string, error) {
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
	s.tokens[token] = formToken{action: action, login: s.cfg.Login, revision: revision, target: target, expires: s.now().Add(10 * time.Minute)}
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
		if entry.target != "" && (len(r.PostForm["alias"]) != 1 || r.PostForm.Get("alias") != entry.target) {
			http.Error(w, "Form target changed. Reload the page.", http.StatusForbidden)
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
		ctx = context.WithValue(ctx, revisionKey{}, entry.revision)
		ctx = context.WithValue(ctx, changeKey{}, entry.change)
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
