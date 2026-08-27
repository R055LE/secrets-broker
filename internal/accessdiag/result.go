// Package accessdiag defines the private worker-to-administrator diagnostic protocol.
package accessdiag

import (
	"fmt"
	"unicode"
)

const Version = 1

type Status string

const (
	StatusAccessible          Status = "accessible"
	StatusInaccessible        Status = "inaccessible"
	StatusAuthenticationError Status = "authentication_error"
	StatusNetworkError        Status = "network_error"
	StatusAPIError            Status = "api_error"
	StatusUnknownError        Status = "unknown_error"
)

type Outcome string

const (
	OutcomeAllAccessible       Outcome = "all_accessible"
	OutcomeInaccessible        Outcome = "inaccessible"
	OutcomeAuthenticationError Outcome = "authentication_error"
	OutcomeNetworkError        Outcome = "network_error"
	OutcomeAPIError            Outcome = "api_error"
	OutcomeUnknownError        Outcome = "unknown_error"
)

type ProjectResult struct {
	Alias        string `json:"alias"`
	BWSProjectID string `json:"bws_project_id"`
	Status       Status `json:"status"`
}

type Result struct {
	Version  int             `json:"version"`
	Outcome  Outcome         `json:"outcome"`
	Projects []ProjectResult `json:"projects"`
}

func Aggregate(projects []ProjectResult) Outcome {
	worst := OutcomeAllAccessible
	for _, project := range projects {
		switch project.Status {
		case StatusAuthenticationError:
			return OutcomeAuthenticationError
		case StatusNetworkError:
			if worst != OutcomeAuthenticationError {
				worst = OutcomeNetworkError
			}
		case StatusAPIError:
			if worst != OutcomeNetworkError {
				worst = OutcomeAPIError
			}
		case StatusUnknownError:
			if worst != OutcomeNetworkError && worst != OutcomeAPIError {
				worst = OutcomeUnknownError
			}
		case StatusInaccessible:
			if worst == OutcomeAllAccessible {
				worst = OutcomeInaccessible
			}
		}
	}
	return worst
}

func (r Result) Validate() error {
	if r.Version != Version {
		return fmt.Errorf("unsupported result version %d", r.Version)
	}
	if len(r.Projects) == 0 {
		return fmt.Errorf("result contains no projects")
	}
	seen := make(map[string]struct{}, len(r.Projects))
	for _, project := range r.Projects {
		if !safeIdentifier(project.Alias) || !safeIdentifier(project.BWSProjectID) {
			return fmt.Errorf("result contains an invalid project identifier")
		}
		if _, ok := seen[project.Alias]; ok {
			return fmt.Errorf("result contains duplicate alias %q", project.Alias)
		}
		seen[project.Alias] = struct{}{}
		if !project.Status.Valid() {
			return fmt.Errorf("result contains invalid status %q", project.Status)
		}
	}
	if want := Aggregate(r.Projects); r.Outcome != want {
		return fmt.Errorf("result outcome %q does not match aggregate %q", r.Outcome, want)
	}
	return nil
}

func safeIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func (s Status) Valid() bool {
	switch s {
	case StatusAccessible,
		StatusInaccessible,
		StatusAuthenticationError,
		StatusNetworkError,
		StatusAPIError,
		StatusUnknownError:
		return true
	default:
		return false
	}
}
