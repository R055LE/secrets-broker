package worker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const maxRequestBytes = 64 << 10

const (
	frameStdout = "stdout"
	frameStderr = "stderr"
	frameResult = "result"
	frameError  = "error"
)

type Request struct {
	Project    string   `json:"project"`
	WorkingDir string   `json:"working_dir"`
	Argv       []string `json:"argv"`
	DryRun     bool     `json:"dry_run,omitempty"`
}

type Result struct {
	Denied   bool   `json:"denied"`
	Reason   string `json:"reason,omitempty"`
	ExitCode int    `json:"exit_code"`
}

type frame struct {
	Type    string  `json:"type"`
	Data    []byte  `json:"data,omitempty"`
	Result  *Result `json:"result,omitempty"`
	Message string  `json:"message,omitempty"`
}

func decodeRequest(r io.Reader) (Request, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxRequestBytes+1))
	if err != nil {
		return Request{}, fmt.Errorf("reading request: %w", err)
	}
	if len(data) > maxRequestBytes {
		return Request{}, errors.New("request exceeds 64 KiB")
	}
	var req Request
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return Request{}, fmt.Errorf("decoding request: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Request{}, errors.New("request must contain exactly one JSON object")
	}
	if req.Project == "" {
		return Request{}, errors.New("project is required")
	}
	if req.WorkingDir == "" {
		return Request{}, errors.New("working_dir is required")
	}
	if len(req.Argv) == 0 {
		return Request{}, errors.New("argv is required")
	}
	return req, nil
}
