package admin

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/R055LE/secrets-broker/internal/execx"
)

const (
	PathResolved     = "resolved"
	PathMissing      = "missing"
	PathNotDirectory = "not_directory"
	PathUnresolvable = "unresolvable"
)

type PathCheckResult struct {
	Alias          string
	ConfiguredPath string
	ResolvedPath   string
	Resolution     string
	WorkerCanEnter bool
	RunnerCanEnter bool
	RunnerCanWrite bool
}

func (r PathCheckResult) Ready() bool {
	return r.Resolution == PathResolved && r.WorkerCanEnter && r.RunnerCanEnter
}

func (e *Editor) CheckProjectPath(ctx context.Context, alias string) (PathCheckResult, error) {
	detail, err := e.GetProject(alias)
	if err != nil {
		return PathCheckResult{}, err
	}
	return checkProjectPath(ctx, detail, execx.OSRunner{})
}

func checkProjectPath(ctx context.Context, project ProjectDetail, runner execx.Runner) (PathCheckResult, error) {
	result := PathCheckResult{Alias: project.Alias, ConfiguredPath: project.WorkingDir}
	resolved, err := filepath.EvalSymlinks(project.WorkingDir)
	if err != nil {
		result.Resolution = PathUnresolvable
		if errors.Is(err, fs.ErrNotExist) {
			result.Resolution = PathMissing
		}
		return result, nil
	}
	info, err := os.Stat(resolved)
	if err != nil {
		result.Resolution = PathUnresolvable
		if errors.Is(err, fs.ErrNotExist) {
			result.Resolution = PathMissing
		}
		return result, nil
	}
	if !info.IsDir() {
		result.Resolution = PathNotDirectory
		return result, nil
	}
	result.Resolution = PathResolved
	result.ResolvedPath = resolved

	result.WorkerCanEnter, err = probePath(ctx, runner, "secrets-broker", "-x", project.WorkingDir)
	if err != nil {
		return PathCheckResult{}, fmt.Errorf("worker path probe failed: %w", err)
	}
	result.RunnerCanEnter, err = probePath(ctx, runner, "secrets-broker-runner", "-x", project.WorkingDir)
	if err != nil {
		return PathCheckResult{}, fmt.Errorf("runner path probe failed: %w", err)
	}
	if result.RunnerCanEnter {
		result.RunnerCanWrite, err = probePath(ctx, runner, "secrets-broker-runner", "-w", project.WorkingDir)
		if err != nil {
			return PathCheckResult{}, fmt.Errorf("runner write probe failed: %w", err)
		}
	}
	return result, nil
}

func probePath(ctx context.Context, runner execx.Runner, user, check, path string) (bool, error) {
	result, err := runner.Run(
		ctx,
		accessRunuserPath,
		[]string{"-u", user, "--", "/usr/bin/test", check, path},
		[]string{"PATH=/usr/bin:/bin", "LC_ALL=C"},
	)
	if err != nil || result.Stdout != "" || result.Stderr != "" || result.ExitCode < 0 || result.ExitCode > 1 {
		return false, errors.New("identity check could not run")
	}
	return result.ExitCode == 0, nil
}
