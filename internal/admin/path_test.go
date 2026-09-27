package admin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/R055LE/secrets-broker/internal/execx"
)

type pathProbeCall struct {
	user string
	flag string
	path string
}

type fakePathRunner struct {
	calls    []pathProbeCall
	results  map[string]execx.Result
	probeErr error
}

func (f *fakePathRunner) Run(_ context.Context, name string, args, env []string) (execx.Result, error) {
	if name != accessRunuserPath || len(args) != 6 || args[0] != "-u" || args[2] != "--" || args[3] != "/usr/bin/test" || !reflect.DeepEqual(env, []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}) {
		panic("path check invoked an unexpected command or environment")
	}
	call := pathProbeCall{user: args[1], flag: args[4], path: args[5]}
	f.calls = append(f.calls, call)
	if f.probeErr != nil {
		return execx.Result{}, f.probeErr
	}
	return f.results[call.user+call.flag], nil
}

func (*fakePathRunner) RunPassthrough(context.Context, string, []string, []string, string, io.Reader, io.Writer, io.Writer) (int, error) {
	panic("path check must not run a command with inherited I/O")
}

func TestCheckProjectPathResolvesSymlinkAndReportsIdentityDifferences(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "project-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	runner := &fakePathRunner{results: map[string]execx.Result{
		"secrets-broker-x":        {ExitCode: 0},
		"secrets-broker-runner-x": {ExitCode: 0},
		"secrets-broker-runner-w": {ExitCode: 1},
	}}
	result, err := checkProjectPath(context.Background(), ProjectDetail{Alias: "alpha", WorkingDir: link}, runner)
	if err != nil {
		t.Fatalf("checkProjectPath: %v", err)
	}
	if result.Resolution != PathResolved || result.ResolvedPath != target || !result.WorkerCanEnter || !result.RunnerCanEnter || result.RunnerCanWrite || !result.Ready() {
		t.Fatalf("unexpected result: %#v", result)
	}
	wantCalls := []pathProbeCall{
		{"secrets-broker", "-x", link},
		{"secrets-broker-runner", "-x", link},
		{"secrets-broker-runner", "-w", link},
	}
	if !reflect.DeepEqual(runner.calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, wantCalls)
	}
	runner.calls = nil
	runner.results["secrets-broker-runner-x"] = execx.Result{ExitCode: 1}
	result, err = checkProjectPath(context.Background(), ProjectDetail{Alias: "alpha", WorkingDir: link}, runner)
	if err != nil || result.RunnerCanEnter || result.RunnerCanWrite || len(runner.calls) != 2 {
		t.Fatalf("runner denial result = %#v, calls = %#v, err = %v", result, runner.calls, err)
	}

	runner.results["secrets-broker-x"] = execx.Result{ExitCode: 1}
	runner.results["secrets-broker-runner-x"] = execx.Result{ExitCode: 0}
	runner.results["secrets-broker-runner-w"] = execx.Result{ExitCode: 0}
	result, err = checkProjectPath(context.Background(), ProjectDetail{Alias: "alpha", WorkingDir: link}, runner)
	if err != nil || result.Ready() || result.WorkerCanEnter || !result.RunnerCanEnter || !result.RunnerCanWrite {
		t.Fatalf("identity-specific result = %#v, err = %v", result, err)
	}
}

func TestCheckProjectPathReportsMissingAndNonDirectoryWithoutProbes(t *testing.T) {
	file := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(file, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	missingLink := filepath.Join(t.TempDir(), "dangling-link")
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), missingLink); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		path string
		want string
	}{
		{missingLink, PathMissing},
		{file, PathNotDirectory},
	} {
		runner := &fakePathRunner{}
		result, err := checkProjectPath(context.Background(), ProjectDetail{Alias: "alpha", WorkingDir: tt.path}, runner)
		if err != nil || result.Resolution != tt.want || result.Ready() || len(runner.calls) != 0 {
			t.Fatalf("path %q: result = %#v, calls = %#v, err = %v", tt.path, result, runner.calls, err)
		}
	}
}

func TestCheckProjectPathTreatsProbeExecutionFailureAsError(t *testing.T) {
	dir := t.TempDir()
	runner := &fakePathRunner{probeErr: errors.New("runner unavailable")}
	_, err := checkProjectPath(context.Background(), ProjectDetail{Alias: "alpha", WorkingDir: dir}, runner)
	if err == nil || !strings.Contains(err.Error(), "worker path probe failed") || strings.Contains(err.Error(), "runner unavailable") {
		t.Fatalf("probe error = %v", err)
	}
}

func TestCheckProjectPathWithDeployedIdentitiesAndACL(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to switch to deployed worker and runner identities")
	}
	worker, workerErr := user.Lookup("secrets-broker")
	commandRunner, runnerErr := user.Lookup("secrets-broker-runner")
	if workerErr != nil || runnerErr != nil {
		t.Skip("deployed worker and runner accounts are unavailable")
	}
	setfacl, err := exec.LookPath("setfacl")
	if err != nil {
		t.Skip("setfacl is unavailable")
	}
	for _, name := range []string{"secrets-broker", "secrets-broker-runner"} {
		command := exec.Command(accessRunuserPath, "-u", name, "--", "/usr/bin/true")
		command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
		if err := command.Run(); err != nil {
			t.Skipf("runuser cannot switch to %s: %v", name, err)
		}
	}
	dir, err := os.MkdirTemp("/tmp", "secrets-broker-path-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	acl := fmt.Sprintf("u:%s:--x,u:%s:r-x", worker.Uid, commandRunner.Uid)
	if err := exec.Command(setfacl, "-m", acl, dir).Run(); err != nil {
		t.Skipf("temporary filesystem does not support the ACL check: %v", err)
	}
	detail := ProjectDetail{Alias: "alpha", WorkingDir: dir}
	result, err := checkProjectPath(context.Background(), detail, execx.OSRunner{})
	if err != nil || !result.Ready() || result.RunnerCanWrite {
		t.Fatalf("readiness with read-only runner ACL = %#v, err = %v", result, err)
	}
	if err := exec.Command(setfacl, "-m", fmt.Sprintf("u:%s:rwx", commandRunner.Uid), dir).Run(); err != nil {
		t.Fatal(err)
	}
	result, err = checkProjectPath(context.Background(), detail, execx.OSRunner{})
	if err != nil || !result.Ready() || !result.RunnerCanWrite {
		t.Fatalf("readiness with writable runner ACL = %#v, err = %v", result, err)
	}
}
