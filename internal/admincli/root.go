// Package admincli is the root-only policy administration command surface.
package admincli

import (
	"context"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/R055LE/secrets-broker/internal/admin"
	"github.com/spf13/cobra"
)

const policyPath = "/etc/secrets-broker/policy.toml"

type projectEditor interface {
	ListProjects() ([]admin.ProjectSummary, error)
	SetApproval(alias, mode string) (bool, error)
}

func Execute() int {
	editor := admin.NewEditor(policyPath, 0)
	return execute(os.Geteuid, editor, os.Args[1:], os.Stdout, os.Stderr)
}

func execute(euid func() int, editor projectEditor, args []string, stdout, stderr io.Writer) int {
	root := newRootCommand(euid, editor, stdout)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)

	if err := root.ExecuteContext(context.Background()); err != nil {
		_, _ = fmt.Fprintln(stderr, "secrets-broker-admin:", err)
		return 2
	}
	return 0
}

func newRootCommand(euid func() int, editor projectEditor, stdout io.Writer) *cobra.Command {
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
	root.AddCommand(projects)
	return root
}
