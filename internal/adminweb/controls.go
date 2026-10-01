package adminweb

import (
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"unicode"
	"unicode/utf8"

	"github.com/R055LE/secrets-broker/internal/admin"
)

type policyMutator interface {
	CreateProject(admin.ProjectInput) (bool, error)
	UpdateProjectMetadata(string, admin.ProjectMetadataUpdate) (bool, error)
	SetApproval(string, string) (bool, error)
	AddAllowlist(string, []string) (bool, error)
	RemoveAllowlist(string, []string) (bool, error)
}

type policyChange struct {
	Kind, Alias, ProjectName string
	Input                    admin.ProjectInput
	Mode                     string
	Argv                     []string
	Widen                    bool
}

func (s *Server) registerControls() {
	for _, kind := range []string{"create", "metadata", "mode", "add", "remove"} {
		s.mux.HandleFunc("POST /projects/"+kind, s.protectPost(kind, func(w http.ResponseWriter, r *http.Request) { s.review(w, r, kind) }))
	}
	s.mux.HandleFunc("POST /projects/commit", s.protectPost("commit", s.commit))
	s.mux.HandleFunc("GET /forms.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write([]byte(pageJS))
	})
}

func validFields(form url.Values, names ...string) bool {
	allowed := append([]string{"csrf", "alias"}, names...)
	for name, values := range form {
		if !slices.Contains(allowed, name) || (name != "argv" && len(values) != 1) {
			return false
		}
	}
	return true
}

func printable(value string, limit int, empty bool) bool {
	if (!empty && value == "") || len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if !unicode.IsPrint(char) {
			return false
		}
	}
	return true
}

func validInput(input admin.ProjectInput) bool {
	return printable(input.Alias, 256, false) && printable(input.BWSProjectID, 128, false) &&
		printable(input.TokenEntry, 256, false) && printable(input.WorkingDir, 4096, false) && filepath.IsAbs(input.WorkingDir)
}

func (s *Server) review(w http.ResponseWriter, r *http.Request, kind string) {
	revision, _ := r.Context().Value(revisionKey{}).(string)
	change := &policyChange{Kind: kind, Alias: r.PostForm.Get("alias")}
	var current *admin.ProjectDetail
	if kind != "create" {
		detail, err := s.reader.GetProject(change.Alias)
		if err != nil {
			http.Error(w, "Project cannot be read. Reload the project list.", http.StatusServiceUnavailable)
			return
		}
		current = &detail
	}
	bad := func(message string) { http.Error(w, message+" Reload the page to try again.", http.StatusBadRequest) }
	switch kind {
	case "create", "metadata":
		if !validFields(r.PostForm, "project_id", "token_entry", "working_dir") {
			bad("Invalid project form.")
			return
		}
		change.Input = admin.ProjectInput{Alias: change.Alias, BWSProjectID: r.PostForm.Get("project_id"), TokenEntry: r.PostForm.Get("token_entry"), WorkingDir: r.PostForm.Get("working_dir")}
		if !validInput(change.Input) {
			bad("Complete every identifier and enter an absolute working directory. Use identifiers only; keep secret values in Bitwarden.")
			return
		}
		if current != nil {
			change.Widen = change.Input.BWSProjectID != current.BWSProjectID || change.Input.TokenEntry != current.TokenEntry || change.Input.WorkingDir != current.WorkingDir
		}
		if kind == "create" {
			projects, err := s.reader.ListProjects()
			if err != nil {
				http.Error(w, "Local policy cannot be read.", http.StatusServiceUnavailable)
				return
			}
			for _, project := range projects {
				if project.Alias == change.Alias {
					bad("Alias already exists.")
					return
				}
			}
			s.mu.Lock()
			if s.now().Before(s.availableUntil) {
				for _, project := range s.available {
					if project.ID == change.Input.BWSProjectID {
						change.ProjectName = project.Name
						break
					}
				}
			}
			s.mu.Unlock()
			if change.ProjectName == "" {
				http.Error(w, "Project discovery expired or the project is unavailable. Refresh Bitwarden projects and start again.", http.StatusConflict)
				return
			}
		}
	case "mode":
		if !validFields(r.PostForm, "mode") {
			bad("Invalid approval form.")
			return
		}
		change.Mode = r.PostForm.Get("mode")
		if change.Mode != admin.ModeConfirm && change.Mode != admin.ModeAutomatic {
			bad("Choose confirm or automatic mode.")
			return
		}
		change.Widen = change.Mode == admin.ModeAutomatic && current.Mode != admin.ModeAutomatic
	case "add":
		if !validFields(r.PostForm, "argv") || len(r.PostForm["argv"]) == 0 || len(r.PostForm["argv"]) > 256 {
			bad("Enter an ordered argument list.")
			return
		}
		change.Argv = append([]string(nil), r.PostForm["argv"]...)
		for index, arg := range change.Argv {
			if !printable(arg, 4096, index != 0) {
				bad("Arguments must be printable text and the first argument must be present.")
				return
			}
		}
		change.Widen = true
	case "remove":
		if !validFields(r.PostForm, "entry") {
			bad("Invalid argument removal form.")
			return
		}
		index, err := strconv.Atoi(r.PostForm.Get("entry"))
		if err != nil || index < 0 || index >= len(current.Allow) {
			bad("Choose an existing argument list.")
			return
		}
		change.Argv = append([]string(nil), current.Allow[index]...)
	}
	latest, err := s.revision()
	if err != nil {
		http.Error(w, "Local policy cannot be read.", http.StatusServiceUnavailable)
		return
	}
	if latest != revision {
		http.Error(w, "Policy changed. Reload before reviewing.", http.StatusConflict)
		return
	}
	token, err := s.issueTargetToken("commit", revision, change.Alias)
	if err != nil {
		http.Error(w, "Too many open forms. Wait ten minutes and reload.", http.StatusServiceUnavailable)
		return
	}
	s.mu.Lock()
	entry := s.tokens[token]
	entry.change = change
	s.tokens[token] = entry
	s.mu.Unlock()
	renderPage(w, http.StatusOK, pageData{Login: s.cfg.Login, ApprovalURL: s.cfg.ApprovalURL, Change: change, Current: current, CommitToken: token})
}

func metadataChange(current admin.ProjectDetail, input admin.ProjectInput) admin.ProjectMetadataUpdate {
	update := admin.ProjectMetadataUpdate{}
	if input.BWSProjectID != current.BWSProjectID {
		update.BWSProjectID = &input.BWSProjectID
	}
	if input.TokenEntry != current.TokenEntry {
		update.TokenEntry = &input.TokenEntry
	}
	if input.WorkingDir != current.WorkingDir {
		update.WorkingDir = &input.WorkingDir
	}
	if update.BWSProjectID == nil && update.TokenEntry == nil && update.WorkingDir == nil {
		update.WorkingDir = &input.WorkingDir
	}
	return update
}

func (s *Server) commit(w http.ResponseWriter, r *http.Request) {
	change, _ := r.Context().Value(changeKey{}).(*policyChange)
	if change == nil || !validFields(r.PostForm, "confirm") || (change.Widen && r.PostForm.Get("confirm") != "yes") {
		http.Error(w, "Confirm the reviewed change before saving. Reload to review it again.", http.StatusBadRequest)
		return
	}
	revision, _ := r.Context().Value(revisionKey{}).(string)
	editor := s.edit(revision)
	var changed bool
	var err error
	switch change.Kind {
	case "create":
		changed, err = editor.CreateProject(change.Input)
	case "metadata":
		current, readErr := s.reader.GetProject(change.Alias)
		if readErr != nil {
			http.Error(w, "Project cannot be read. Reload the project list.", http.StatusServiceUnavailable)
			return
		}
		changed, err = editor.UpdateProjectMetadata(change.Alias, metadataChange(current, change.Input))
	case "mode":
		changed, err = editor.SetApproval(change.Alias, change.Mode)
	case "add":
		changed, err = editor.AddAllowlist(change.Alias, change.Argv)
	case "remove":
		changed, err = editor.RemoveAllowlist(change.Alias, change.Argv)
	default:
		http.Error(w, "Invalid reviewed change.", http.StatusBadRequest)
		return
	}
	if err != nil {
		if errors.Is(err, admin.ErrPolicyBusy) {
			http.Error(w, "Another administrator is updating policy. Reload and retry.", http.StatusConflict)
			return
		}
		if errors.Is(err, admin.ErrPolicyChanged) {
			http.Error(w, "Policy changed. Reload before submitting.", http.StatusConflict)
			return
		}
		message := "Change did not complete. Inspect the current policy and administrator audit with the root CLI before retrying."
		if changed {
			message = "Policy changed, but audit completion failed. Inspect the current policy and administrator audit with the root CLI before retrying."
		}
		http.Error(w, message, http.StatusServiceUnavailable)
		return
	}
	index, err := s.projectIndex(change.Alias)
	if err != nil {
		http.Error(w, "Reload the project list to inspect the saved policy.", http.StatusServiceUnavailable)
		return
	}
	message := "Policy saved."
	if !changed {
		message = "No change needed. The policy already has these values."
	}
	if change.Kind == "create" {
		message = "Local project created in confirm mode with no allowed commands. Check its working directory and Bitwarden access, then add an exact command."
	}
	s.renderProject(w, http.StatusOK, index, change.Alias, message, false, nil, nil)
}
