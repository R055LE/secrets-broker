package cli

import "testing"

func TestRunCommandDoesNotExposeTrustedPathOverrides(t *testing.T) {
	cmd := newRunCmd(new(int))
	for _, name := range []string{"config", "audit-log", "worker"} {
		if cmd.Flags().Lookup(name) != nil {
			t.Fatalf("untrusted run command must not expose --%s", name)
		}
	}
}

func TestRunCommandStillHasProjectAndDryRunFlags(t *testing.T) {
	cmd := newRunCmd(new(int))
	for _, name := range []string{"project", "dry-run"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Fatalf("run command missing --%s", name)
		}
	}
}
