package worker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/R055LE/secrets-broker/internal/boundedio"
	"github.com/R055LE/secrets-broker/internal/config"
	"github.com/R055LE/secrets-broker/internal/projectlist"
	"github.com/R055LE/secrets-broker/internal/token"
)

const projectListOutputLimit = 2 << 20

// ListProjects returns only project IDs and names visible to the worker token.
func (s *Server) ListProjects(ctx context.Context) (projectlist.Result, error) {
	cfg, err := config.LoadWorker(s.ConfigPath)
	if err != nil {
		return projectlist.Result{}, fmt.Errorf("loading worker policy: %w", err)
	}
	if err := cfg.ValidateWorker(); err != nil {
		return projectlist.Result{}, fmt.Errorf("validating worker policy: %w", err)
	}
	if err := validateRuntime(cfg.Runtime); err != nil {
		return projectlist.Result{}, fmt.Errorf("validating worker runtime: %w", err)
	}
	var resolver token.Resolver = token.NewFileResolver(cfg.TokenSource.File.Path)
	if s.newTokenResolver != nil {
		resolver = s.newTokenResolver(cfg.TokenSource.File.Path)
	}
	accessToken, err := resolver.Resolve(ctx, "")
	if err != nil {
		return projectlist.Result{}, fmt.Errorf("resolving worker token: %w", err)
	}

	timeout := s.accessTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	listCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stdout := boundedio.NewBuffer(projectListOutputLimit)
	stderr := boundedio.NewBuffer(accessStderrLimit)
	exitCode, err := s.ExecRunner.RunPassthrough(
		listCtx,
		cfg.Runtime.BWSBinary,
		[]string{"project", "list", "--output", "json", "--color", "no"},
		[]string{
			"PATH=" + cfg.Runtime.CommandPath,
			"HOME=" + cfg.Runtime.Home,
			"LANG=C.UTF-8",
			"BWS_ACCESS_TOKEN=" + accessToken.Value(),
		},
		cfg.Runtime.Home,
		nil,
		stdout,
		stderr,
	)
	if err != nil || exitCode != 0 || stdout.Exceeded() || stderr.Exceeded() || len(stderr.Bytes()) != 0 {
		return projectlist.Result{}, errors.New("BWS project list failed")
	}
	result, err := projectlist.FromBWS(stdout.Bytes())
	if err != nil {
		return projectlist.Result{}, errors.New("BWS project list returned invalid data")
	}
	return result, nil
}
