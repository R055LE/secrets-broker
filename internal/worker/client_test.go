package worker

import (
	"context"
	"strings"
	"testing"
)

func TestClientCommandUsesFixedAbsoluteWorkerAndSanitizedEnvironment(t *testing.T) {
	cmd := NewClient().command(context.Background())

	if cmd.Path != DefaultSudoBinary {
		t.Fatalf("got command path %q, want %q", cmd.Path, DefaultSudoBinary)
	}
	wantArgs := strings.Join([]string{DefaultSudoBinary, "-n", "-u", DefaultWorkerUser, "--", DefaultWorkerBinary}, "|")
	if got := strings.Join(cmd.Args, "|"); got != wantArgs {
		t.Fatalf("got args %q, want %q", got, wantArgs)
	}
	if got := strings.Join(cmd.Env, "|"); got != "PATH=/usr/sbin:/usr/bin:/sbin:/bin|LANG=C.UTF-8" {
		t.Fatalf("unexpected worker environment: %q", got)
	}
}
