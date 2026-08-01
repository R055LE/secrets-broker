package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/R055LE/secrets-broker/internal/execx"
)

// passthroughEnvVars is the deliberate, minimal set of vars copied from the
// broker's own environment into bws's. bws needs at least these to run at
// all (PATH to find its own dependencies, HOME to resolve ~/.config/bws);
// LANG avoids locale warnings from wrapped commands. Nothing else survives
// — see decisions/0004-bws-run-for-injection-over-manual-export.md for why
// this is built explicitly rather than via bws's own --no-inherit-env flag.
var passthroughEnvVars = []string{"PATH", "HOME", "LANG"}

// BWSRunner shells out to `bws run`. It's v1's only Runner implementation —
// the interface exists so a future backend swap doesn't touch broker.go,
// not because multiple backends are planned right now.
type BWSRunner struct {
	execRunner execx.Runner
	bwsBinary  string
}

func NewBWSRunner(execRunner execx.Runner) *BWSRunner {
	return &BWSRunner{execRunner: execRunner, bwsBinary: "bws"}
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

	args := []string{"run", "--project-id", spec.ProjectID, "--"}
	for _, tok := range spec.Argv {
		args = append(args, shellQuote(tok))
	}

	env := buildEnv(spec.Token.Value())

	exitCode, err := r.execRunner.RunPassthrough(ctx, r.bwsBinary, args, env, spec.Stdin, spec.Stdout, spec.Stderr)
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

func buildEnv(tokenValue string) []string {
	env := make([]string, 0, len(passthroughEnvVars)+1)
	for _, name := range passthroughEnvVars {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	env = append(env, "BWS_ACCESS_TOKEN="+tokenValue)
	return env
}
