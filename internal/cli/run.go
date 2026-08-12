package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/R055LE/secrets-broker/internal/worker"
)

// Exit codes borrow docker run's convention: the wrapped command's own exit
// code passes through unmodified on success. exitDenied means the worker
// refused to run anything. exitRunnerStartFailed means the request was
// approved but bws itself could not start.
const (
	exitDenied            = 125
	exitRunnerStartFailed = 126
)

func newRunCmd(exitCode *int) *cobra.Command {
	var (
		projectAlias string
		dryRun       bool
	)

	cmd := &cobra.Command{
		Use:   "run --project <alias> [flags] -- <command> [args...]",
		Short: "Ask the isolated worker to run a policy-gated command",
		RunE: func(cmd *cobra.Command, argv []string) error {
			if projectAlias == "" {
				return fmt.Errorf("--project is required")
			}
			if len(argv) == 0 {
				return fmt.Errorf("no command given (usage: secrets-broker run --project <alias> -- <command> [args...])")
			}
			workingDir, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("resolving working directory: %w", err)
			}

			result, err := worker.NewClient().Run(cmd.Context(), worker.Request{
				Project:    projectAlias,
				WorkingDir: workingDir,
				Argv:       argv,
				DryRun:     dryRun,
			}, cmd.OutOrStdout(), cmd.ErrOrStderr())
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "secrets-broker: %v\n", err)
				*exitCode = exitDenied
				return nil
			}
			if dryRun {
				label := "allow"
				if result.Denied {
					label = "deny"
				} else if result.Reason != "allowlisted" {
					label = "prompt"
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", label, result.Reason)
			}
			if result.Denied {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "secrets-broker: denied (%s)\n", result.Reason)
			}
			*exitCode = result.ExitCode
			return nil
		},
	}

	cmd.Flags().StringVarP(&projectAlias, "project", "p", "", "project alias from the worker's policy.toml (required)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "ask the worker to resolve policy without approval, token access, execution, or audit")
	return cmd
}
