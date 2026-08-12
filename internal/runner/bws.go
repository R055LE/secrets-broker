package runner

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/R055LE/secrets-broker/internal/execx"
)

const (
	isolatedSudoBinary = "/usr/bin/sudo"
	isolatedRunnerUser = "secrets-broker-runner"
)

// BWSRunner shells out to `bws run`. It's v1's only Runner implementation —
// the interface exists so a future backend swap doesn't touch broker.go,
// not because multiple backends are planned right now.
type BWSRunner struct {
	execRunner  execx.Runner
	bwsBinary   string
	commandPath string
	home        string
}

func NewBWSRunner(execRunner execx.Runner, bwsBinary, commandPath, home string) *BWSRunner {
	return &BWSRunner{
		execRunner:  execRunner,
		bwsBinary:   bwsBinary,
		commandPath: commandPath,
		home:        home,
	}
}

func (r *BWSRunner) Run(ctx context.Context, spec RunSpec) (Result, error) {
	if len(spec.Argv) == 0 {
		return Result{}, errors.New("runner: empty command")
	}
	if spec.ProjectID == "" {
		return Result{}, errors.New("runner: empty project ID")
	}
	if spec.Token.Empty() {
		return Result{}, errors.New("runner: empty token")
	}
	if !filepath.IsAbs(r.bwsBinary) {
		return Result{}, errors.New("runner: bws binary must be an absolute path")
	}
	if spec.WorkingDir == "" {
		return Result{}, errors.New("runner: empty working directory")
	}

	// bws starts only the fixed sudo hop as the credential-owning worker. bws
	// removes BWS_ACCESS_TOKEN before spawning its child; --no-inherit-env also
	// clears the worker's remaining runtime environment. sudo then changes to
	// the separate runner UID before the requested command executes. The
	// worker-scoped sudoers env_keep rule carries that already-cleared BWS
	// environment across the hop without relying on sudo -E, which sudo-rs
	// 0.2.x accepts but ignores.
	args := []string{
		"run", "--project-id", spec.ProjectID, "--no-inherit-env", "--",
		shellQuote(isolatedSudoBinary),
		shellQuote("-n"),
		shellQuote("-H"),
		shellQuote("-u"),
		shellQuote(isolatedRunnerUser),
		shellQuote("--"),
	}
	for _, tok := range spec.Argv {
		args = append(args, shellQuote(tok))
	}

	env := buildEnv(spec.Token.Value(), r.commandPath, r.home)

	exitCode, err := r.execRunner.RunPassthrough(ctx, r.bwsBinary, args, env, spec.WorkingDir, spec.Stdin, spec.Stdout, spec.Stderr)
	if err != nil {
		return Result{}, fmt.Errorf("running bws: %w", err)
	}

	return Result{ExitCode: exitCode}, nil
}

// shellQuote POSIX-single-quotes a token before handing it to `bws run`.
// bws joins its trailing command tokens with spaces and re-parses the
// result through `sh -c` (verified against bws 2.1.0's own source — it is
// not a raw exec of argv). Without quoting here, any token containing a
// space or shell metacharacter would be split or reinterpreted by that
// inner shell, silently breaking the argv boundaries the allowlist match
// already verified in Go before this function ever runs.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func buildEnv(tokenValue, commandPath, home string) []string {
	return []string{
		"PATH=" + commandPath,
		"HOME=" + home,
		"LANG=C.UTF-8",
		"BWS_ACCESS_TOKEN=" + tokenValue,
	}
}
