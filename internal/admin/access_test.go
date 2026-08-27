package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/R055LE/secrets-broker/internal/accessdiag"
	"github.com/R055LE/secrets-broker/internal/execx"
)

type fakeAccessChecker struct {
	result   accessdiag.Result
	err      error
	aliases  []string
	sequence *[]string
}

type orderedAccessLogger struct {
	sequence *[]string
	starts   []MutationStart
	finishes []MutationFinish
}

func (l *orderedAccessLogger) Start(_ context.Context, rec MutationStart) (string, error) {
	*l.sequence = append(*l.sequence, "start")
	l.starts = append(l.starts, rec)
	return "diagnostic-id", nil
}

func (l *orderedAccessLogger) Finish(_ context.Context, mutationID string, rec MutationFinish) error {
	*l.sequence = append(*l.sequence, "finish")
	if mutationID != "diagnostic-id" {
		return errors.New("unexpected diagnostic ID")
	}
	l.finishes = append(l.finishes, rec)
	return nil
}

func (c *fakeAccessChecker) CheckAccess(_ context.Context, alias string) (accessdiag.Result, error) {
	c.aliases = append(c.aliases, alias)
	if c.sequence != nil {
		*c.sequence = append(*c.sequence, "worker")
	}
	return c.result, c.err
}

func validAccessResult(status accessdiag.Status) accessdiag.Result {
	projects := []accessdiag.ProjectResult{{Alias: "project", BWSProjectID: "project-id", Status: status}}
	return accessdiag.Result{
		Version: accessdiag.Version, Outcome: accessdiag.Aggregate(projects), Projects: projects,
	}
}

func TestWorkerAccessCheckerUsesFixedRunuserBoundary(t *testing.T) {
	result := validAccessResult(accessdiag.StatusAccessible)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	runner := &execx.FakeRunner{
		PassthroughExitCode: 0,
		PassthroughStdout:   string(encoded),
	}

	got, err := NewWorkerAccessChecker(runner).CheckAccess(context.Background(), "project")
	if err != nil || !reflect.DeepEqual(got, result) {
		t.Fatalf("CheckAccess() = %#v, %v", got, err)
	}
	if len(runner.Calls) != 1 {
		t.Fatalf("calls = %#v", runner.Calls)
	}
	call := runner.Calls[0]
	wantArgs := []string{"-u", "secrets-broker", "--", "/usr/local/libexec/secrets-broker-worker", "access-check", "project"}
	if call.Method != "RunPassthrough" || call.Name != "/usr/sbin/runuser" || !reflect.DeepEqual(call.Args, wantArgs) || call.Env != nil || call.Dir != "/" {
		t.Fatalf("call = %#v", call)
	}
}

func TestWorkerAccessCheckerRejectsUntrustedWorkerOutput(t *testing.T) {
	valid := validAccessResult(accessdiag.StatusAccessible)
	validJSON, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		exitCode int
		stdout   string
		stderr   string
	}{
		{name: "malformed", exitCode: 0, stdout: "sentinel-malformed"},
		{name: "trailing", exitCode: 0, stdout: string(validJSON) + `{}`},
		{name: "unknown field", exitCode: 0, stdout: `{"version":1,"outcome":"all_accessible","projects":[{"alias":"project","bws_project_id":"project-id","status":"accessible"}],"sentinel":"secret"}`},
		{name: "invalid status", exitCode: 1, stdout: `{"version":1,"outcome":"unknown_error","projects":[{"alias":"project","bws_project_id":"project-id","status":"future"}]}`},
		{name: "exit mismatch", exitCode: 1, stdout: string(validJSON)},
		{name: "worker failure", exitCode: 2, stdout: "", stderr: "sentinel-private-worker-error"},
		{name: "unexpected stderr", exitCode: 0, stdout: string(validJSON), stderr: "sentinel-private-worker-error"},
		{name: "oversized stdout", exitCode: 0, stdout: strings.Repeat("s", accessOutputLimit+1)},
		{name: "oversized stderr", exitCode: 0, stdout: string(validJSON), stderr: strings.Repeat("s", accessOutputLimit+1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &execx.FakeRunner{
				PassthroughExitCode: tt.exitCode,
				PassthroughStdout:   tt.stdout,
				PassthroughStderr:   tt.stderr,
			}
			result, err := NewWorkerAccessChecker(runner).CheckAccess(context.Background(), "")
			if err == nil || len(result.Projects) != 0 {
				t.Fatalf("result = %#v, err = %v", result, err)
			}
			for _, forbidden := range []string{"sentinel", "secret", "private"} {
				if strings.Contains(strings.ToLower(err.Error()), forbidden) {
					t.Fatalf("error exposed %q: %v", forbidden, err)
				}
			}
		})
	}
}

func TestAuditedAccessDiagnosticOrdersAuditOutputAndRecordsAggregate(t *testing.T) {
	sequence := []string{}
	checker := &fakeAccessChecker{
		result: validAccessResult(accessdiag.StatusNetworkError), sequence: &sequence,
	}
	logger := &orderedAccessLogger{sequence: &sequence}
	audited := NewAuditedAccessDiagnostic(checker, logger, 0)

	outcome, err := audited.Run(context.Background(), "project", func(accessdiag.Result) error {
		sequence = append(sequence, "output")
		return nil
	})
	if err != nil || outcome != accessdiag.OutcomeNetworkError {
		t.Fatalf("outcome = %q, err = %v", outcome, err)
	}
	if !reflect.DeepEqual(sequence, []string{"start", "worker", "output", "finish"}) || !reflect.DeepEqual(checker.aliases, []string{"project"}) {
		t.Fatalf("audit sequence = %#v, aliases = %#v", sequence, checker.aliases)
	}
	wantStart := MutationStart{ActorUID: 0, Project: "project", Operation: OperationCheckProjectAccess}
	if !reflect.DeepEqual(logger.starts, []MutationStart{wantStart}) {
		t.Fatalf("starts = %#v", logger.starts)
	}
	if !reflect.DeepEqual(logger.finishes, []MutationFinish{{Outcome: "network_error"}}) {
		t.Fatalf("finishes = %#v", logger.finishes)
	}
}

func TestAuditedAccessDiagnosticBlocksWorkerOnStartFailureAndReportsFinishFailure(t *testing.T) {
	t.Run("start", func(t *testing.T) {
		checker := &fakeAccessChecker{result: validAccessResult(accessdiag.StatusAccessible)}
		logger := &fakeMutationLogger{startErr: errAuditUnavailable}
		_, err := NewAuditedAccessDiagnostic(checker, logger, 0).Run(context.Background(), "", func(accessdiag.Result) error { return nil })
		if !errors.Is(err, errAuditUnavailable) || len(checker.aliases) != 0 || len(logger.finishes) != 0 {
			t.Fatalf("err = %v, aliases = %#v, finishes = %#v", err, checker.aliases, logger.finishes)
		}
	})

	t.Run("finish", func(t *testing.T) {
		checker := &fakeAccessChecker{result: validAccessResult(accessdiag.StatusAccessible)}
		logger := &fakeMutationLogger{finishErr: errAuditUnavailable}
		outcome, err := NewAuditedAccessDiagnostic(checker, logger, 0).Run(context.Background(), "", func(accessdiag.Result) error { return nil })
		if !errors.Is(err, errAuditUnavailable) || outcome != accessdiag.OutcomeAllAccessible || len(checker.aliases) != 1 {
			t.Fatalf("outcome = %q, err = %v, aliases = %#v", outcome, err, checker.aliases)
		}
	})
}

func TestAuditedAccessDiagnosticRecordsFailedWithoutDiagnosticData(t *testing.T) {
	checker := &fakeAccessChecker{err: errors.New("sentinel worker response with secret")}
	logger := &fakeMutationLogger{}
	_, err := NewAuditedAccessDiagnostic(checker, logger, 0).Run(context.Background(), "", func(accessdiag.Result) error { return nil })
	if err == nil {
		t.Fatal("CheckAccess() succeeded")
	}
	if !reflect.DeepEqual(logger.starts, []MutationStart{{ActorUID: 0, Operation: OperationCheckProjectAccess}}) {
		t.Fatalf("starts = %#v", logger.starts)
	}
	if !reflect.DeepEqual(logger.finishes, []MutationFinish{{Outcome: OutcomeFailed}}) {
		t.Fatalf("finishes = %#v", logger.finishes)
	}
}

func TestAuditedAccessDiagnosticRecordsOutputFailure(t *testing.T) {
	checker := &fakeAccessChecker{result: validAccessResult(accessdiag.StatusAccessible)}
	logger := &fakeMutationLogger{}
	outputErr := errors.New("output failed")
	_, err := NewAuditedAccessDiagnostic(checker, logger, 0).Run(
		context.Background(),
		"",
		func(accessdiag.Result) error { return outputErr },
	)
	if !errors.Is(err, outputErr) {
		t.Fatalf("err = %v", err)
	}
	if !reflect.DeepEqual(logger.finishes, []MutationFinish{{Outcome: OutcomeFailed}}) {
		t.Fatalf("finishes = %#v", logger.finishes)
	}
}

func TestAuditedAccessDiagnosticJSONLOmitsDiagnosticData(t *testing.T) {
	projects := []accessdiag.ProjectResult{{
		Alias:        "github-ops",
		BWSProjectID: "11111111-1111-1111-1111-111111111111",
		Status:       accessdiag.StatusAuthenticationError,
	}}
	checker := &fakeAccessChecker{result: accessdiag.Result{
		Version:  accessdiag.Version,
		Outcome:  accessdiag.Aggregate(projects),
		Projects: projects,
	}}
	auditPath := filepath.Join(t.TempDir(), "admin-audit", "audit.jsonl")
	logger := NewMutationJSONLLogger(auditPath)
	if _, err := NewAuditedAccessDiagnostic(checker, logger, os.Geteuid()).Run(
		context.Background(),
		"github-ops",
		func(accessdiag.Result) error { return nil },
	); err != nil {
		t.Fatalf("Run: %v", err)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("reading audit: %v", err)
	}
	for _, want := range []string{
		`"operation":"check_project_access"`,
		`"project":"github-ops"`,
		`"outcome":"authentication_error"`,
		`"mutation_id":`,
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Fatalf("audit missing %q: %s", want, data)
		}
	}
	for _, forbidden := range []string{
		"11111111-1111-1111-1111-111111111111",
		"bws_project_id",
		"token_entry",
		"working_dir",
		"raw stderr",
		"secret value",
	} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatalf("audit contains %q: %s", forbidden, data)
		}
	}
}
