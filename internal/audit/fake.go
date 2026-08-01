package audit

import (
	"context"
	"strconv"
)

// FakeLogger is a scripted Logger for broker unit tests. It records every
// Start/Finish call so tests can assert on what got audited.
type FakeLogger struct {
	StartErr  error
	FinishErr error

	Starts   []StartRecord
	Finishes []struct {
		RunID string
		Rec   FinishRecord
	}

	nextRunID int
}

func (f *FakeLogger) Start(ctx context.Context, rec StartRecord) (string, error) {
	f.Starts = append(f.Starts, rec)
	if f.StartErr != nil {
		return "", f.StartErr
	}
	f.nextRunID++
	return "fake-run-" + strconv.Itoa(f.nextRunID), nil
}

func (f *FakeLogger) Finish(ctx context.Context, runID string, rec FinishRecord) error {
	f.Finishes = append(f.Finishes, struct {
		RunID string
		Rec   FinishRecord
	}{RunID: runID, Rec: rec})
	return f.FinishErr
}
