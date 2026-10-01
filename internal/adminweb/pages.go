package adminweb

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/R055LE/secrets-broker/internal/accessdiag"
	"github.com/R055LE/secrets-broker/internal/admin"
	"github.com/R055LE/secrets-broker/internal/projectlist"
)

type projectReader interface {
	ListProjects() ([]admin.ProjectSummary, error)
	GetProject(string) (admin.ProjectDetail, error)
	CheckProjectPath(context.Context, string) (admin.PathCheckResult, error)
}

type projectRow struct {
	Index int
	admin.ProjectSummary
}

type pageData struct {
	Login, ApprovalURL, Message            string
	Warning                                bool
	Projects                               []projectRow
	Detail                                 *admin.ProjectDetail
	Index                                  int
	Available                              []projectlist.Project
	DiscoveryToken, PathToken, AccessToken string
	Path                                   *admin.PathCheckResult
	Access                                 *accessdiag.Result
}

func (s *Server) registerPages() {
	s.mux.HandleFunc("GET /{$}", s.home)
	s.mux.HandleFunc("GET /style.css", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write([]byte(pageCSS))
	})
	s.mux.HandleFunc("GET /projects/{index}", s.projectPage)
	s.mux.HandleFunc("POST /projects/discover", s.protectPost("discover", s.discover))
	s.mux.HandleFunc("POST /projects/path", s.protectPost("path", s.checkPath))
	s.mux.HandleFunc("POST /projects/access", s.protectPost("access", s.checkAccess))
}

func (s *Server) home(w http.ResponseWriter, _ *http.Request) {
	s.renderOverview(w, http.StatusOK, "", false)
}

func (s *Server) renderOverview(w http.ResponseWriter, status int, message string, warning bool) {
	projects, err := s.reader.ListProjects()
	if err != nil {
		http.Error(w, "Local policy cannot be read. Check the administrator CLI on the broker host.", http.StatusServiceUnavailable)
		return
	}
	revision, err := s.revision()
	if err != nil {
		http.Error(w, "Local policy cannot be read.", http.StatusServiceUnavailable)
		return
	}
	token, err := s.issueToken("discover", revision)
	if err != nil {
		http.Error(w, "Too many open forms. Wait ten minutes and reload.", http.StatusServiceUnavailable)
		return
	}
	data := pageData{Login: s.cfg.Login, ApprovalURL: s.cfg.ApprovalURL, Message: message, Warning: warning, DiscoveryToken: token}
	for index, project := range projects {
		data.Projects = append(data.Projects, projectRow{Index: index, ProjectSummary: project})
	}
	s.mu.Lock()
	if s.now().Before(s.availableUntil) {
		data.Available = append([]projectlist.Project(nil), s.available...)
	}
	s.mu.Unlock()
	renderPage(w, status, data)
}

func (s *Server) projectPage(w http.ResponseWriter, r *http.Request) {
	projects, err := s.reader.ListProjects()
	if err != nil {
		http.Error(w, "Local policy cannot be read.", http.StatusServiceUnavailable)
		return
	}
	index, err := strconv.Atoi(r.PathValue("index"))
	if err != nil || index < 0 || index >= len(projects) {
		http.NotFound(w, r)
		return
	}
	s.renderProject(w, http.StatusOK, index, projects[index].Alias, "", false, nil, nil)
}

func (s *Server) renderProject(w http.ResponseWriter, status, index int, alias, message string, warning bool, path *admin.PathCheckResult, access *accessdiag.Result) {
	detail, err := s.reader.GetProject(alias)
	if err != nil {
		http.Error(w, "Local project cannot be read. Reload the project list.", http.StatusServiceUnavailable)
		return
	}
	revision, err := s.revision()
	if err != nil {
		http.Error(w, "Local policy cannot be read.", http.StatusServiceUnavailable)
		return
	}
	pathToken, err := s.issueTargetToken("path", revision, alias)
	if err != nil {
		http.Error(w, "Too many open forms. Wait ten minutes and reload.", http.StatusServiceUnavailable)
		return
	}
	accessToken, err := s.issueTargetToken("access", revision, alias)
	if err != nil {
		http.Error(w, "Too many open forms. Wait ten minutes and reload.", http.StatusServiceUnavailable)
		return
	}
	renderPage(w, status, pageData{Login: s.cfg.Login, ApprovalURL: s.cfg.ApprovalURL,
		Detail: &detail, Index: index, Message: message, Warning: warning, Path: path, Access: access,
		PathToken: pathToken, AccessToken: accessToken})
}

func (s *Server) projectIndex(alias string) (int, error) {
	projects, err := s.reader.ListProjects()
	if err != nil {
		return 0, err
	}
	for index, project := range projects {
		if project.Alias == alias {
			return index, nil
		}
	}
	return 0, errors.New("project not configured")
}

func (s *Server) discover(w http.ResponseWriter, r *http.Request) {
	var result projectlist.Result
	err := s.access.ListAvailable(r.Context(), func(found projectlist.Result) error {
		if err := found.Validate(); err != nil {
			return err
		}
		result = found
		return nil
	})
	if err != nil {
		s.mu.Lock()
		s.available = nil
		s.availableUntil = time.Time{}
		s.mu.Unlock()
		s.renderOverview(w, http.StatusServiceUnavailable, "Bitwarden discovery did not complete. Check the worker and administrator audit with the root CLI, then retry.", true)
		return
	}
	s.mu.Lock()
	s.available = append([]projectlist.Project(nil), result.Projects...)
	s.availableUntil = s.now().Add(10 * time.Minute)
	s.mu.Unlock()
	s.renderOverview(w, http.StatusOK, "Bitwarden project list refreshed. This list expires after ten minutes.", false)
}

func (s *Server) checkPath(w http.ResponseWriter, r *http.Request) {
	alias := r.PostForm.Get("alias")
	index, err := s.projectIndex(alias)
	if err != nil {
		http.Error(w, "Project changed. Reload the project list.", http.StatusConflict)
		return
	}
	id, err := s.logger.Start(r.Context(), admin.MutationStart{ActorUID: 0, Project: alias, Operation: "check_project_path"})
	var result admin.PathCheckResult
	if err == nil {
		result, err = s.reader.CheckProjectPath(r.Context(), alias)
		outcome := admin.OutcomeFailed
		if err == nil {
			outcome = "not_ready"
			if result.Ready() {
				outcome = "ready"
			}
		}
		err = errors.Join(err, s.logger.Finish(r.Context(), id, admin.MutationFinish{Outcome: outcome}))
	}
	if err != nil {
		s.renderProject(w, http.StatusServiceUnavailable, index, alias, "Path check did not complete. Check the local accounts and administrator audit with the root CLI.", true, nil, nil)
		return
	}
	s.renderProject(w, http.StatusOK, index, alias, "Path check completed. It does not contact Bitwarden.", !result.Ready(), &result, nil)
}

func (s *Server) checkAccess(w http.ResponseWriter, r *http.Request) {
	alias := r.PostForm.Get("alias")
	index, err := s.projectIndex(alias)
	if err != nil {
		http.Error(w, "Project changed. Reload the project list.", http.StatusConflict)
		return
	}
	var result accessdiag.Result
	_, err = s.access.Run(r.Context(), alias, func(found accessdiag.Result) error {
		if err := found.Validate(); err != nil || len(found.Projects) != 1 || found.Projects[0].Alias != alias {
			return errors.New("invalid selected-project diagnostic")
		}
		result = found
		return nil
	})
	if err != nil {
		s.renderProject(w, http.StatusServiceUnavailable, index, alias, "Bitwarden check did not complete. Check the worker and administrator audit with the root CLI.", true, nil, nil)
		return
	}
	message := accessMessage(result.Outcome)
	s.renderProject(w, http.StatusOK, index, alias, message, result.Outcome != accessdiag.OutcomeAllAccessible, nil, &result)
}

func accessMessage(outcome accessdiag.Outcome) string {
	switch outcome {
	case accessdiag.OutcomeAllAccessible:
		return "The worker can access this Bitwarden project."
	case accessdiag.OutcomeInaccessible:
		return "The worker cannot access this project. Review the machine account's project grant in Bitwarden."
	case accessdiag.OutcomeAuthenticationError:
		return "Bitwarden rejected the worker token. Review it from a trusted terminal."
	case accessdiag.OutcomeNetworkError:
		return "The worker could not reach Bitwarden. Check the network, then retry."
	default:
		return "Bitwarden returned an unsuccessful check. Use the root CLI to inspect the diagnostic status."
	}
}
