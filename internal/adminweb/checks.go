package adminweb

import (
	"net/http"
	"time"

	"github.com/R055LE/secrets-broker/internal/accessdiag"
	"github.com/R055LE/secrets-broker/internal/admin"
)

type projectChecks struct {
	revision                   string
	pathExpires, accessExpires time.Time
	path                       *admin.PathCheckResult
	access                     *accessdiag.Result
	pathMessage, accessMessage string
	pathWarning, accessWarning bool
}

func (s *Server) storeCheck(r *http.Request, path *admin.PathCheckResult, access *accessdiag.Result, message string, warning, bitwarden bool) {
	revision, _ := r.Context().Value(revisionKey{}).(string)
	alias := r.PostForm.Get("alias")
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, check := range s.checks {
		if check.revision != revision || (!s.now().Before(check.pathExpires) && !s.now().Before(check.accessExpires)) {
			delete(s.checks, key)
		}
	}
	check := s.checks[alias]
	if _, exists := s.checks[alias]; !exists && len(s.checks) >= 128 {
		for key := range s.checks {
			delete(s.checks, key)
			break
		}
	}
	check.revision = revision
	if bitwarden {
		check.accessExpires = s.now().Add(10 * time.Minute)
		check.access, check.accessMessage, check.accessWarning = access, message, warning
	} else {
		check.pathExpires = s.now().Add(10 * time.Minute)
		check.path, check.pathMessage, check.pathWarning = path, message, warning
	}
	s.checks[alias] = check
}
