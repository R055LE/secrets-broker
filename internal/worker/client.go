package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
)

const (
	DefaultSudoBinary   = "/usr/bin/sudo"
	DefaultWorkerBinary = "/usr/local/libexec/secrets-broker-worker"
	DefaultWorkerUser   = "secrets-broker"
)

type Client struct {
	sudoBinary   string
	workerBinary string
	workerUser   string
}

func NewClient() *Client {
	return &Client{
		sudoBinary:   DefaultSudoBinary,
		workerBinary: DefaultWorkerBinary,
		workerUser:   DefaultWorkerUser,
	}
}

func (c *Client) command(ctx context.Context) *exec.Cmd {
	cmd := exec.CommandContext(ctx, c.sudoBinary, "-n", "-u", c.workerUser, "--", c.workerBinary)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	return cmd
}

func (c *Client) Run(ctx context.Context, req Request, stdout, stderr io.Writer) (Result, error) {
	cmd := c.command(ctx)
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return Result{}, fmt.Errorf("opening worker stdin: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, fmt.Errorf("opening worker stdout: %w", err)
	}
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("starting worker: %w", err)
	}
	if err := json.NewEncoder(stdinPipe).Encode(req); err != nil {
		_ = stdinPipe.Close()
		_ = cmd.Wait()
		return Result{}, fmt.Errorf("sending worker request: %w", err)
	}
	if err := stdinPipe.Close(); err != nil {
		_ = cmd.Wait()
		return Result{}, fmt.Errorf("closing worker request: %w", err)
	}

	var result *Result
	decoder := json.NewDecoder(stdoutPipe)
	for {
		var f frame
		err := decoder.Decode(&f)
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = cmd.Wait()
			return Result{}, fmt.Errorf("decoding worker response: %w", err)
		}
		switch f.Type {
		case frameStdout:
			if _, err := stdout.Write(f.Data); err != nil {
				_ = cmd.Wait()
				return Result{}, fmt.Errorf("writing command stdout: %w", err)
			}
		case frameStderr:
			if _, err := stderr.Write(f.Data); err != nil {
				_ = cmd.Wait()
				return Result{}, fmt.Errorf("writing command stderr: %w", err)
			}
		case frameResult:
			result = f.Result
		case frameError:
			_ = cmd.Wait()
			return Result{}, fmt.Errorf("worker: %s", f.Message)
		default:
			_ = cmd.Wait()
			return Result{}, fmt.Errorf("worker returned unknown frame type %q", f.Type)
		}
	}

	waitErr := cmd.Wait()
	if result == nil {
		if waitErr != nil {
			return Result{}, fmt.Errorf("worker exited without a result: %w", waitErr)
		}
		return Result{}, errors.New("worker exited without a result")
	}
	if waitErr != nil {
		return Result{}, fmt.Errorf("worker exited after returning a result: %w", waitErr)
	}
	return *result, nil
}
