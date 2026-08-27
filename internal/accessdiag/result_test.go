package accessdiag

import "testing"

func TestAggregateUsesDocumentedPrecedence(t *testing.T) {
	projects := []ProjectResult{
		{Alias: "inaccessible", BWSProjectID: "1", Status: StatusInaccessible},
		{Alias: "unknown", BWSProjectID: "2", Status: StatusUnknownError},
		{Alias: "api", BWSProjectID: "3", Status: StatusAPIError},
		{Alias: "network", BWSProjectID: "4", Status: StatusNetworkError},
		{Alias: "authentication", BWSProjectID: "5", Status: StatusAuthenticationError},
	}

	if got := Aggregate(projects); got != OutcomeAuthenticationError {
		t.Fatalf("Aggregate() = %q, want %q", got, OutcomeAuthenticationError)
	}
	if got := Aggregate(projects[:4]); got != OutcomeNetworkError {
		t.Fatalf("Aggregate() without authentication = %q, want %q", got, OutcomeNetworkError)
	}
	if got := Aggregate(projects[:3]); got != OutcomeAPIError {
		t.Fatalf("Aggregate() without network = %q, want %q", got, OutcomeAPIError)
	}
	if got := Aggregate(projects[:2]); got != OutcomeUnknownError {
		t.Fatalf("Aggregate() without API = %q, want %q", got, OutcomeUnknownError)
	}
	if got := Aggregate(projects[:1]); got != OutcomeInaccessible {
		t.Fatalf("Aggregate() with inaccessible = %q, want %q", got, OutcomeInaccessible)
	}
	if got := Aggregate([]ProjectResult{{Alias: "ok", BWSProjectID: "6", Status: StatusAccessible}}); got != OutcomeAllAccessible {
		t.Fatalf("Aggregate() with accessible = %q, want %q", got, OutcomeAllAccessible)
	}
}

func TestResultValidateRejectsUntrustedProtocolData(t *testing.T) {
	valid := Result{
		Version: Version,
		Outcome: OutcomeAllAccessible,
		Projects: []ProjectResult{{
			Alias: "project", BWSProjectID: "id", Status: StatusAccessible,
		}},
	}
	tests := []struct {
		name   string
		mutate func(*Result)
	}{
		{name: "version", mutate: func(r *Result) { r.Version++ }},
		{name: "empty projects", mutate: func(r *Result) { r.Projects = nil }},
		{name: "empty alias", mutate: func(r *Result) { r.Projects[0].Alias = "" }},
		{name: "empty project ID", mutate: func(r *Result) { r.Projects[0].BWSProjectID = "" }},
		{name: "unsafe alias", mutate: func(r *Result) { r.Projects[0].Alias = "project\nSTATUS" }},
		{name: "unsafe project ID", mutate: func(r *Result) { r.Projects[0].BWSProjectID = "id\x1b[31m" }},
		{name: "invalid status", mutate: func(r *Result) { r.Projects[0].Status = "new_status" }},
		{name: "wrong aggregate", mutate: func(r *Result) { r.Outcome = OutcomeNetworkError }},
		{name: "duplicate alias", mutate: func(r *Result) { r.Projects = append(r.Projects, r.Projects[0]) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := valid
			got.Projects = append([]ProjectResult(nil), valid.Projects...)
			tt.mutate(&got)
			if err := got.Validate(); err == nil {
				t.Fatal("Validate() succeeded")
			}
		})
	}
}
