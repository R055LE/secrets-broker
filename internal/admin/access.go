package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/R055LE/secrets-broker/internal/accessdiag"
	"github.com/R055LE/secrets-broker/internal/boundedio"
	"github.com/R055LE/secrets-broker/internal/execx"
	"github.com/R055LE/secrets-broker/internal/projectlist"
)

const (
	accessRunuserPath = "/usr/sbin/runuser"
	accessWorkerPath  = "/usr/local/libexec/secrets-broker-worker"
	accessWorkerUser  = "secrets-broker"
	accessOutputLimit = 2 << 20

	OperationCheckProjectAccess    = "check_project_access"
	OperationListAvailableProjects = "list_available_projects"
	OutcomeFailed                  = "failed"
)

type AccessChecker interface {
	CheckAccess(ctx context.Context, alias string) (accessdiag.Result, error)
	ListAvailable(ctx context.Context) (projectlist.Result, error)
}

type WorkerAccessChecker struct {
	runner execx.Runner
}

func NewWorkerAccessChecker(runner execx.Runner) *WorkerAccessChecker {
	return &WorkerAccessChecker{runner: runner}
}

func (c *WorkerAccessChecker) CheckAccess(ctx context.Context, alias string) (accessdiag.Result, error) {
	args := []string{"-u", accessWorkerUser, "--", accessWorkerPath, "access-check"}
	if alias != "" {
		args = append(args, alias)
	}
	stdout := boundedio.NewBuffer(accessOutputLimit)
	stderr := boundedio.NewBuffer(accessOutputLimit)
	exitCode, err := c.runner.RunPassthrough(
		ctx, accessRunuserPath, args, nil, "/", nil, stdout, stderr,
	)
	if err != nil || stdout.Exceeded() || stderr.Exceeded() || len(stderr.Bytes()) != 0 {
		return accessdiag.Result{}, errors.New("worker access diagnostic failed")
	}
	if exitCode != 0 && exitCode != 1 {
		return accessdiag.Result{}, errors.New("worker access diagnostic failed")
	}

	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decoder.DisallowUnknownFields()
	var result accessdiag.Result
	if err := decoder.Decode(&result); err != nil {
		return accessdiag.Result{}, errors.New("worker access diagnostic returned an invalid result")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return accessdiag.Result{}, errors.New("worker access diagnostic returned an invalid result")
	}
	if err := result.Validate(); err != nil {
		return accessdiag.Result{}, errors.New("worker access diagnostic returned an invalid result")
	}
	wantExitCode := 1
	if result.Outcome == accessdiag.OutcomeAllAccessible {
		wantExitCode = 0
	}
	if exitCode != wantExitCode {
		return accessdiag.Result{}, errors.New("worker access diagnostic returned an invalid result")
	}
	return result, nil
}

func (c *WorkerAccessChecker) ListAvailable(ctx context.Context) (projectlist.Result, error) {
	stdout := boundedio.NewBuffer(accessOutputLimit)
	stderr := boundedio.NewBuffer(accessOutputLimit)
	exitCode, err := c.runner.RunPassthrough(
		ctx,
		accessRunuserPath,
		[]string{"-u", accessWorkerUser, "--", accessWorkerPath, "projects-list"},
		nil, "/", nil, stdout, stderr,
	)
	if err != nil || exitCode != 0 || stdout.Exceeded() || stderr.Exceeded() || len(stderr.Bytes()) != 0 {
		return projectlist.Result{}, errors.New("worker project list failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decoder.DisallowUnknownFields()
	var result projectlist.Result
	if err := decoder.Decode(&result); err != nil {
		return projectlist.Result{}, errors.New("worker project list returned an invalid result")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || result.Validate() != nil {
		return projectlist.Result{}, errors.New("worker project list returned an invalid result")
	}
	return result, nil
}

type AccessDiagnostic interface {
	Run(
		ctx context.Context,
		alias string,
		consume func(accessdiag.Result) error,
	) (accessdiag.Outcome, error)
	ListAvailable(ctx context.Context, consume func(projectlist.Result) error) error
}

type AuditedAccessDiagnostic struct {
	checker  AccessChecker
	logger   MutationLogger
	actorUID int
}

func NewAuditedAccessDiagnostic(checker AccessChecker, logger MutationLogger, actorUID int) *AuditedAccessDiagnostic {
	return &AuditedAccessDiagnostic{checker: checker, logger: logger, actorUID: actorUID}
}

func (d *AuditedAccessDiagnostic) Run(
	ctx context.Context,
	alias string,
	consume func(accessdiag.Result) error,
) (accessdiag.Outcome, error) {
	mutationID, err := d.logger.Start(ctx, MutationStart{
		ActorUID:  d.actorUID,
		Project:   alias,
		Operation: OperationCheckProjectAccess,
	})
	if err != nil {
		return "", fmt.Errorf("starting administrator audit: %w", err)
	}

	result, checkErr := d.checker.CheckAccess(ctx, alias)
	var consumeErr error
	if checkErr == nil {
		consumeErr = consume(result)
	}
	outcome := OutcomeFailed
	if checkErr == nil && consumeErr == nil {
		outcome = string(result.Outcome)
	}
	finishErr := d.logger.Finish(ctx, mutationID, MutationFinish{Outcome: outcome})
	if finishErr != nil {
		finishErr = fmt.Errorf("finishing administrator audit: %w", finishErr)
	}
	return result.Outcome, errors.Join(checkErr, consumeErr, finishErr)
}

func (d *AuditedAccessDiagnostic) ListAvailable(
	ctx context.Context,
	consume func(projectlist.Result) error,
) error {
	mutationID, err := d.logger.Start(ctx, MutationStart{
		ActorUID: d.actorUID, Operation: OperationListAvailableProjects,
	})
	if err != nil {
		return fmt.Errorf("starting administrator audit: %w", err)
	}
	result, listErr := d.checker.ListAvailable(ctx)
	var consumeErr error
	if listErr == nil {
		consumeErr = consume(result)
	}
	outcome := OutcomeFailed
	if listErr == nil && consumeErr == nil {
		outcome = "listed"
	}
	finishErr := d.logger.Finish(ctx, mutationID, MutationFinish{Outcome: outcome})
	if finishErr != nil {
		finishErr = fmt.Errorf("finishing administrator audit: %w", finishErr)
	}
	return errors.Join(listErr, consumeErr, finishErr)
}
