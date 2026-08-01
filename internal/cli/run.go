package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/R055LE/secrets-broker/internal/approval"
	"github.com/R055LE/secrets-broker/internal/audit"
	"github.com/R055LE/secrets-broker/internal/broker"
	"github.com/R055LE/secrets-broker/internal/config"
	"github.com/R055LE/secrets-broker/internal/execx"
	"github.com/R055LE/secrets-broker/internal/runner"
	"github.com/R055LE/secrets-broker/internal/token"
)

// Exit codes borrow docker run's convention: the wrapped command's own exit
// code passes through unmodified on success. exitDenied means the broker
// refused to run anything at all (unknown project, not allowlisted,
// approval rejected, token resolution failed, audit unavailable).
// exitRunnerStartFailed means the broker approved the command but bws
// itself failed to start.
//
// There is deliberately no flag on this command that lets the caller
// pre-answer or suppress the approval prompt (no --yes, no --force). The
// agent invoking this binary is exactly the untrusted party the approval
// gate exists for — a self-service bypass flag would make that gate
// theater. Do not add one.
const (
	exitDenied            = 125
	exitRunnerStartFailed = 126
)

func newRunCmd(exitCode *int) *cobra.Command {
	var (
		projectAlias string
		configPath   string
		auditLogPath string
		dryRun       bool
	)

	cmd := &cobra.Command{
		Use:   "run --project <alias> [flags] -- <command> [args...]",
		Short: "Run a command with secrets injected, gated by policy",
		RunE: func(cmd *cobra.Command, argv []string) error {
			if projectAlias == "" {
				return fmt.Errorf("--project is required")
			}
			if len(argv) == 0 {
				return fmt.Errorf("no command given (usage: secrets-broker run --project <alias> -- <command> [args...])")
			}

			cfgPath := configPath
			if cfgPath == "" {
				p, err := config.DefaultPath()
				if err != nil {
					return err
				}
				cfgPath = p
			}

			logPath := auditLogPath
			if logPath == "" {
				p, err := config.DefaultAuditLogPath()
				if err != nil {
					return err
				}
				logPath = p
			}

			cfg, err := config.Load(cfgPath)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "secrets-broker: %v\n", err)
				*exitCode = exitDenied
				return nil
			}

			logger, err := audit.NewJSONLLogger(logPath)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "secrets-broker: %v\n", err)
				*exitCode = exitDenied
				return nil
			}

			execRunner := execx.OSRunner{}

			resolver, err := newResolver(cfg.TokenSource, execRunner)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "secrets-broker: %v\n", err)
				*exitCode = exitDenied
				return nil
			}

			approver, err := newApprover(cfg.ApprovalSource, execRunner)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "secrets-broker: %v\n", err)
				*exitCode = exitDenied
				return nil
			}

			b := broker.New(
				cfg,
				resolver,
				approver,
				runner.NewBWSRunner(execRunner),
				logger,
			)

			if dryRun {
				result := b.DryRun(projectAlias, argv)
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", verdictLabel(result.Verdict), result.Reason)
				if result.Verdict == broker.VerdictDeny {
					*exitCode = exitDenied
				}
				return nil
			}

			out := b.Run(cmd.Context(), broker.RunRequest{
				Project: projectAlias,
				Argv:    argv,
				Stdin:   cmd.InOrStdin(),
				Stdout:  cmd.OutOrStdout(),
				Stderr:  cmd.ErrOrStderr(),
			})

			if out.Denied {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "secrets-broker: denied (%s)\n", out.Reason)
				if out.Reason == broker.ReasonRunnerStartFailed {
					*exitCode = exitRunnerStartFailed
				} else {
					*exitCode = exitDenied
				}
				return nil
			}

			*exitCode = out.ExitCode
			return nil
		},
	}

	cmd.Flags().StringVarP(&projectAlias, "project", "p", "", "project alias from policy.toml (required)")
	cmd.Flags().StringVar(&configPath, "config", "", "override the default policy.toml path")
	cmd.Flags().StringVar(&auditLogPath, "audit-log", "", "override the default audit log path")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "resolve the policy decision without touching Secret Service, bws, or the audit log")

	return cmd
}

// newResolver picks the Resolver implementation matching the configured
// token_source.backend. config.Load already validates that Backend is one
// of the known values before this is ever called; the default case is a
// defensive fallback for callers that construct a Config directly without
// going through Load (broker_test.go does exactly that).
func newResolver(ts config.TokenSource, execRunner execx.Runner) (token.Resolver, error) {
	switch ts.Backend {
	case config.BackendSecretService:
		return token.NewSecretServiceResolver(execRunner), nil
	case config.BackendEnv:
		return token.NewEnvResolver(ts.Env.Var), nil
	case config.BackendFile:
		return token.NewFileResolver(ts.File.Path), nil
	default:
		return nil, fmt.Errorf("unsupported token_source.backend %q", ts.Backend)
	}
}

// newApprover picks the Approver implementation matching the configured
// approval_source.backend. Same defensive-default rationale as
// newResolver above.
func newApprover(as config.ApprovalSource, execRunner execx.Runner) (approval.Approver, error) {
	switch as.Backend {
	case config.ApprovalBackendKDialog:
		return approval.NewKDialogApprover(execRunner), nil
	case config.ApprovalBackendTailscaleRelay:
		client := approval.NewHTTPRelayClient(as.TailscaleRelay.ControlURL, nil)
		return approval.NewTailscaleApprover(
			client,
			time.Duration(as.TailscaleRelay.PollIntervalSeconds)*time.Second,
			time.Duration(as.TailscaleRelay.TimeoutSeconds)*time.Second,
		), nil
	default:
		return nil, fmt.Errorf("unsupported approval_source.backend %q", as.Backend)
	}
}

func verdictLabel(v broker.Verdict) string {
	switch v {
	case broker.VerdictAllow:
		return "allow"
	case broker.VerdictPrompt:
		return "prompt"
	default:
		return "deny"
	}
}
