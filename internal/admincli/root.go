// Package admincli is the root-only policy administration command surface.
package admincli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/R055LE/secrets-broker/internal/accessdiag"
	"github.com/R055LE/secrets-broker/internal/admin"
	"github.com/R055LE/secrets-broker/internal/execx"
	"github.com/spf13/cobra"
)

const (
	policyPath     = "/etc/secrets-broker/policy.toml"
	adminAuditPath = "/var/log/secrets-broker-admin/audit.jsonl"
	recoveryPath   = "/var/lib/secrets-broker-admin/recovery"
)

type projectEditor interface {
	ListProjects() ([]admin.ProjectSummary, error)
	GetProject(alias string) (admin.ProjectDetail, error)
	ListAllowlist(alias string) ([][]string, error)
	CreateProject(input admin.ProjectInput) (bool, error)
	SetApproval(alias, mode string) (bool, error)
	AddAllowlist(alias string, argv []string) (bool, error)
	RemoveAllowlist(alias string, argv []string) (bool, error)
	RemoveProject(alias, confirmation string) (admin.RecoveryResult, error)
	ListRecoveries() ([]admin.RecoverySummary, error)
	RestoreProject(recoveryID, confirmation string) (admin.RecoveryResult, error)
}

func Execute() int {
	policyEditor := admin.NewRecoveryEditor(policyPath, recoveryPath, 0, 0)
	auditLogger := admin.NewMutationJSONLLogger(adminAuditPath)
	editor := admin.NewAuditedEditor(policyEditor, auditLogger, os.Geteuid())
	diagnostic := admin.NewAuditedAccessDiagnostic(
		admin.NewWorkerAccessChecker(execx.OSRunner{}),
		auditLogger,
		os.Geteuid(),
	)
	return executeWithAccess(os.Geteuid, editor, diagnostic, os.Args[1:], os.Stdout, os.Stderr)
}

func execute(euid func() int, editor projectEditor, args []string, stdout, stderr io.Writer) int {
	return executeWithAccess(euid, editor, unavailableAccessDiagnostic{}, args, stdout, stderr)
}

func executeWithAccess(
	euid func() int,
	editor projectEditor,
	diagnostic admin.AccessDiagnostic,
	args []string,
	stdout, stderr io.Writer,
) int {
	diagnosticFailed := false
	root := newRootCommandWithAccess(euid, editor, diagnostic, stdout, func() {
		diagnosticFailed = true
	})
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)

	if err := root.ExecuteContext(context.Background()); err != nil {
		_, _ = fmt.Fprintln(stderr, "secrets-broker-admin:", err)
		return 2
	}
	if diagnosticFailed {
		return 1
	}
	return 0
}

func newRootCommand(euid func() int, editor projectEditor, stdout io.Writer) *cobra.Command {
	return newRootCommandWithAccess(euid, editor, unavailableAccessDiagnostic{}, stdout, func() {})
}

func newRootCommandWithAccess(
	euid func() int,
	editor projectEditor,
	diagnostic admin.AccessDiagnostic,
	stdout io.Writer,
	onDiagnosticFailure func(),
) *cobra.Command {
	root := &cobra.Command{
		Use:           "secrets-broker-admin",
		Short:         "Administer the fixed Secrets Broker worker policy",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if euid() != 0 {
				return fmt.Errorf("must run as root")
			}
			return nil
		},
	}

	projects := &cobra.Command{Use: "projects", Short: "List and update configured projects"}
	projects.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List projects and their operator-facing approval modes",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			items, err := editor.ListProjects()
			if err != nil {
				return err
			}
			writer := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(writer, "ALIAS\tMODE\tBEHAVIOR")
			for _, item := range items {
				_, _ = fmt.Fprintf(writer, "%s\t%s\t%s\n", item.Alias, item.Mode, item.Behavior)
			}
			return writer.Flush()
		},
	})
	projects.AddCommand(&cobra.Command{
		Use:   "show ALIAS",
		Short: "Show one project's full configuration",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			detail, err := editor.GetProject(args[0])
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(
				stdout,
				"ALIAS: %s\nBWS_PROJECT_ID: %s\nTOKEN_ENTRY: %s\nWORKING_DIR: %s\nMODE: %s\nBEHAVIOR: %s\n",
				detail.Alias,
				detail.BWSProjectID,
				detail.TokenEntry,
				detail.WorkingDir,
				detail.Mode,
				detail.Behavior,
			)
			for _, argv := range detail.Allow {
				encoded, err := json.Marshal(argv)
				if err != nil {
					return fmt.Errorf("encoding allowlist argv: %w", err)
				}
				_, _ = fmt.Fprintf(stdout, "ALLOW: %s\n", encoded)
			}
			return nil
		},
	})
	var createBWSProjectID string
	var createTokenEntry string
	var createWorkingDir string
	create := &cobra.Command{
		Use:   "create ALIAS",
		Short: "Create a confirm-mode project with an empty allowlist",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if createBWSProjectID == "" {
				return fmt.Errorf("--bws-project-id is required")
			}
			if createTokenEntry == "" {
				return fmt.Errorf("--token-entry is required")
			}
			if createWorkingDir == "" {
				return fmt.Errorf("--working-dir is required")
			}
			changed, err := editor.CreateProject(admin.ProjectInput{
				Alias:        args[0],
				BWSProjectID: createBWSProjectID,
				TokenEntry:   createTokenEntry,
				WorkingDir:   createWorkingDir,
			})
			if err != nil {
				return err
			}
			if !changed {
				return fmt.Errorf("project %q was not created", args[0])
			}
			_, _ = fmt.Fprintf(stdout, "Project %q created in confirm mode with an empty allowlist.\n", args[0])
			return nil
		},
	}
	create.Flags().StringVar(&createBWSProjectID, "bws-project-id", "", "Bitwarden Secrets Manager project ID")
	create.Flags().StringVar(&createTokenEntry, "token-entry", "", "Bitwarden Secrets Manager access-token secret name; meaning depends on the resolver backend, advisory only under env/file (ignored at runtime)")
	create.Flags().StringVar(&createWorkingDir, "working-dir", "", "absolute allowed working directory")
	projects.AddCommand(create)
	var removeConfirmation string
	remove := &cobra.Command{
		Use:   "remove ALIAS --confirm ALIAS",
		Short: "Remove one project after publishing a recovery artifact",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			result, err := editor.RemoveProject(args[0], removeConfirmation)
			if err != nil {
				return recoveryMutationError(err, result)
			}
			if !result.Changed || result.RecoveryID == "" {
				return fmt.Errorf("project %q was not removed", args[0])
			}
			_, _ = fmt.Fprintf(stdout, "Project %q removed. Recovery ID: %s\n", args[0], result.RecoveryID)
			return nil
		},
	}
	remove.Flags().StringVar(&removeConfirmation, "confirm", "", "repeat the exact project alias")
	projects.AddCommand(remove)

	access := &cobra.Command{
		Use:   "access",
		Short: "Check Bitwarden project access through the deployed worker",
	}
	access.AddCommand(&cobra.Command{
		Use:   "check [ALIAS]",
		Short: "Check one or every configured Bitwarden project",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			alias := ""
			if len(args) == 1 {
				alias = args[0]
			}
			outcome, err := diagnostic.Run(cmd.Context(), alias, func(result accessdiag.Result) error {
				writer := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
				if _, err := fmt.Fprintln(writer, "ALIAS\tBWS_PROJECT_ID\tSTATUS"); err != nil {
					return fmt.Errorf("writing access diagnostic: %w", err)
				}
				for _, project := range result.Projects {
					if _, err := fmt.Fprintf(
						writer,
						"%s\t%s\t%s\n",
						project.Alias,
						project.BWSProjectID,
						project.Status,
					); err != nil {
						return fmt.Errorf("writing access diagnostic: %w", err)
					}
				}
				if err := writer.Flush(); err != nil {
					return fmt.Errorf("writing access diagnostic: %w", err)
				}
				return nil
			})
			if err != nil {
				return err
			}
			if outcome != accessdiag.OutcomeAllAccessible {
				onDiagnosticFailure()
			}
			return nil
		},
	})
	projects.AddCommand(access)

	recovery := &cobra.Command{
		Use:   "recovery",
		Short: "List and restore protected project recovery artifacts",
	}
	recovery.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List project recovery metadata",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			items, err := editor.ListRecoveries()
			if err != nil {
				return err
			}
			writer := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(writer, "RECOVERY_ID\tALIAS\tCREATED_AT")
			for _, item := range items {
				_, _ = fmt.Fprintf(
					writer,
					"%s\t%s\t%s\n",
					item.RecoveryID,
					item.Project,
					item.CreatedAt.UTC().Format(time.RFC3339Nano),
				)
			}
			return writer.Flush()
		},
	})
	var restoreConfirmation string
	restore := &cobra.Command{
		Use:   "restore RECOVERY_ID --confirm ALIAS",
		Short: "Restore exact policy bytes when policy is unchanged since removal",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			result, err := editor.RestoreProject(args[0], restoreConfirmation)
			if err != nil {
				return recoveryMutationError(err, result)
			}
			if !result.Changed {
				return fmt.Errorf("recovery artifact %q was not restored", args[0])
			}
			_, _ = fmt.Fprintf(
				stdout,
				"Project %q restored from recovery ID %s.\n",
				restoreConfirmation,
				args[0],
			)
			return nil
		},
	}
	restore.Flags().StringVar(&restoreConfirmation, "confirm", "", "repeat the exact recovered project alias")
	recovery.AddCommand(restore)
	projects.AddCommand(recovery)
	projects.AddCommand(&cobra.Command{
		Use:   "set-approval ALIAS MODE",
		Short: "Set a project to automatic or confirm mode",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			changed, err := editor.SetApproval(args[0], args[1])
			if err != nil {
				return err
			}
			if changed {
				_, _ = fmt.Fprintf(stdout, "Project %q now uses %s approval.\n", args[0], args[1])
			} else {
				_, _ = fmt.Fprintf(stdout, "Project %q already uses %s approval.\n", args[0], args[1])
			}
			return nil
		},
	})

	allowlist := &cobra.Command{
		Use:   "allowlist",
		Short: "List and update exact argv allowed for a project",
	}
	allowlist.AddCommand(&cobra.Command{
		Use:   "list ALIAS",
		Short: "List a project's exact argv allowlist",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			entries, err := editor.ListAllowlist(args[0])
			if err != nil {
				return err
			}
			writer := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(writer, "INDEX\tARGV")
			for i, argv := range entries {
				encoded, err := json.Marshal(argv)
				if err != nil {
					return fmt.Errorf("encoding allowlist argv: %w", err)
				}
				_, _ = fmt.Fprintf(writer, "%d\t%s\n", i+1, encoded)
			}
			return writer.Flush()
		},
	})
	allowlist.AddCommand(&cobra.Command{
		Use:   "add ALIAS -- ARGV...",
		Short: "Add one exact argv entry to a project",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			changed, err := editor.AddAllowlist(args[0], args[1:])
			if err != nil {
				return err
			}
			encoded, err := json.Marshal(args[1:])
			if err != nil {
				return fmt.Errorf("encoding allowlist argv: %w", err)
			}
			if changed {
				_, _ = fmt.Fprintf(stdout, "Project %q now allows %s.\n", args[0], encoded)
			} else {
				_, _ = fmt.Fprintf(stdout, "Project %q already allows %s.\n", args[0], encoded)
			}
			return nil
		},
	})
	allowlist.AddCommand(&cobra.Command{
		Use:   "remove ALIAS -- ARGV...",
		Short: "Remove an exact argv entry from a project",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			changed, err := editor.RemoveAllowlist(args[0], args[1:])
			if err != nil {
				return err
			}
			encoded, err := json.Marshal(args[1:])
			if err != nil {
				return fmt.Errorf("encoding allowlist argv: %w", err)
			}
			if changed {
				_, _ = fmt.Fprintf(stdout, "Project %q no longer allows %s.\n", args[0], encoded)
			} else {
				_, _ = fmt.Fprintf(stdout, "Project %q did not allow %s.\n", args[0], encoded)
			}
			return nil
		},
	})
	projects.AddCommand(allowlist)
	root.AddCommand(projects)
	return root
}

type unavailableAccessDiagnostic struct{}

func (unavailableAccessDiagnostic) Run(
	context.Context,
	string,
	func(accessdiag.Result) error,
) (accessdiag.Outcome, error) {
	return "", fmt.Errorf("access diagnostic unavailable")
}

func recoveryMutationError(err error, result admin.RecoveryResult) error {
	if result.RecoveryID == "" {
		return err
	}
	return fmt.Errorf("%w; recovery ID: %s", err, result.RecoveryID)
}
