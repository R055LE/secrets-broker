package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/R055LE/secrets-broker/internal/accessdiag"
	"github.com/R055LE/secrets-broker/internal/boundedio"
	"github.com/R055LE/secrets-broker/internal/config"
	"github.com/R055LE/secrets-broker/internal/token"
)

const accessStderrLimit = 64 << 10

var httpStatusPattern = regexp.MustCompile(`\[(4[0-9]{2}|5[0-9]{2}) [^\]]+\]`)

// CheckAccess asks BWS for project metadata without retrieving secrets or
// crossing into the runner account.
func (s *Server) CheckAccess(ctx context.Context, alias string) (accessdiag.Result, error) {
	cfg, err := config.LoadWorker(s.ConfigPath)
	if err != nil {
		return accessdiag.Result{}, fmt.Errorf("loading worker policy: %w", err)
	}
	if err := cfg.ValidateWorker(); err != nil {
		return accessdiag.Result{}, fmt.Errorf("validating worker policy: %w", err)
	}
	if err := validateRuntime(cfg.Runtime); err != nil {
		return accessdiag.Result{}, fmt.Errorf("validating worker runtime: %w", err)
	}

	projects, err := selectAccessProjects(cfg.Projects, alias)
	if err != nil {
		return accessdiag.Result{}, err
	}
	var tokenResolver token.Resolver = token.NewFileResolver(cfg.TokenSource.File.Path)
	if s.newTokenResolver != nil {
		tokenResolver = s.newTokenResolver(cfg.TokenSource.File.Path)
	}
	accessToken, err := tokenResolver.Resolve(ctx, "")
	if err != nil {
		return accessdiag.Result{}, fmt.Errorf("resolving worker token: %w", err)
	}

	results := make([]accessdiag.ProjectResult, 0, len(projects))
	for _, project := range projects {
		status, err := s.probeAccess(ctx, cfg.Runtime, accessToken, project.BWSProjectID)
		if err != nil {
			return accessdiag.Result{}, err
		}
		results = append(results, accessdiag.ProjectResult{
			Alias: project.Alias, BWSProjectID: project.BWSProjectID, Status: status,
		})
	}

	return accessdiag.Result{
		Version: accessdiag.Version, Outcome: accessdiag.Aggregate(results), Projects: results,
	}, nil
}

func selectAccessProjects(projects []config.Project, alias string) ([]config.Project, error) {
	if alias == "" {
		return projects, nil
	}
	for _, project := range projects {
		if project.Alias == alias {
			return []config.Project{project}, nil
		}
	}
	return nil, fmt.Errorf("unknown project alias")
}

func (s *Server) probeAccess(
	ctx context.Context,
	runtime config.Runtime,
	accessToken token.Token,
	projectID string,
) (accessdiag.Status, error) {
	timeout := s.accessTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stderr := boundedio.NewBuffer(accessStderrLimit)
	exitCode, err := s.ExecRunner.RunPassthrough(
		probeCtx,
		runtime.BWSBinary,
		[]string{"project", "get", projectID, "--output", "none", "--color", "no"},
		[]string{
			"PATH=" + runtime.CommandPath,
			"HOME=" + runtime.Home,
			"LANG=C.UTF-8",
			"BWS_ACCESS_TOKEN=" + accessToken.Value(),
		},
		runtime.Home,
		nil,
		io.Discard,
		stderr,
	)
	if stderr.Exceeded() {
		return "", fmt.Errorf("bws diagnostic error output exceeded limit")
	}
	if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
		return accessdiag.StatusNetworkError, nil
	}
	if err != nil {
		return "", fmt.Errorf("starting bws diagnostic")
	}
	return classifyAccess(exitCode, stderr.String()), nil
}

func classifyAccess(exitCode int, stderr string) accessdiag.Status {
	if exitCode == 0 {
		return accessdiag.StatusAccessible
	}
	lower := strings.ToLower(stderr)
	switch {
	case strings.Contains(lower, "[401 unauthorized]"),
		strings.Contains(lower, "[403 forbidden]"):
		return accessdiag.StatusAuthenticationError
	case strings.Contains(lower, "[404 not found]"):
		return accessdiag.StatusInaccessible
	case httpStatusPattern.MatchString(stderr):
		return accessdiag.StatusAPIError
	case strings.Contains(lower, "authentication failed"),
		strings.Contains(lower, "invalid access token"),
		strings.Contains(lower, "missing access token"):
		return accessdiag.StatusAuthenticationError
	case hasNetworkError(lower):
		return accessdiag.StatusNetworkError
	default:
		return accessdiag.StatusUnknownError
	}
}

func hasNetworkError(message string) bool {
	patterns := []string{
		"dns error",
		"failed to lookup address",
		"name or service not known",
		"temporary failure in name resolution",
		"connection refused",
		"connection reset",
		"connection timed out",
		"request timed out",
		"operation timed out",
		"deadline has elapsed",
		"error sending request",
		"tcp connect error",
		"connect error",
		"tls error",
		"certificate verify failed",
		"invalid peer certificate",
		"transport error",
	}
	for _, pattern := range patterns {
		if strings.Contains(message, pattern) {
			return true
		}
	}
	return false
}
