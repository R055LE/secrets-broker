package worker

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/R055LE/secrets-broker/internal/config"
	"github.com/R055LE/secrets-broker/internal/securefile"
	"github.com/R055LE/secrets-broker/internal/token"
)

type CheckResult struct {
	Projects   int
	TokenBytes int64
}

// Check validates the worker's policy and runtime without reading credentials,
// contacting the relay, executing bws, or opening the audit log.
func (s *Server) Check() (CheckResult, error) {
	cfg, err := config.LoadWorker(s.ConfigPath)
	if err != nil {
		return CheckResult{}, err
	}
	if err := cfg.ValidateWorker(); err != nil {
		return CheckResult{}, fmt.Errorf("invalid worker config: %w", err)
	}
	if err := validateRuntime(cfg.Runtime); err != nil {
		return CheckResult{}, fmt.Errorf("invalid worker runtime: %w", err)
	}

	tokenBytes, err := securefile.ValidatePrivateFile(cfg.TokenSource.File.Path, token.MaxFileBytes)
	if err != nil {
		return CheckResult{}, fmt.Errorf("validating token file: %w", err)
	}
	if tokenBytes == 0 {
		return CheckResult{}, fmt.Errorf("token file %q is empty", cfg.TokenSource.File.Path)
	}

	for _, project := range cfg.Projects {
		resolved, err := filepath.EvalSymlinks(project.WorkingDir)
		if err != nil {
			return CheckResult{}, fmt.Errorf("project %q: resolving working directory: %w", project.Alias, err)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return CheckResult{}, fmt.Errorf("project %q: stating working directory: %w", project.Alias, err)
		}
		if !info.IsDir() {
			return CheckResult{}, fmt.Errorf("project %q: working directory %q is not a directory", project.Alias, project.WorkingDir)
		}
	}

	return CheckResult{Projects: len(cfg.Projects), TokenBytes: tokenBytes}, nil
}
