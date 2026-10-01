package projectlist

import (
	"reflect"
	"testing"
)

func TestFromBWSKeepsOnlyProjectIdentity(t *testing.T) {
	input := `[{
		"id":"project-id", "name":"Example", "organizationId":"organization-id",
		"creationDate":"2026-01-01T00:00:00Z", "revisionDate":"2026-01-01T00:00:00Z",
		"futureSensitiveField":"sentinel-secret"
	}]`
	got, err := FromBWS([]byte(input))
	want := Result{Version: Version, Projects: []Project{{ID: "project-id", Name: "Example"}}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("FromBWS() = %#v, %v", got, err)
	}
}

func TestFromBWSAcceptsLegacyProjectType(t *testing.T) {
	got, err := FromBWS([]byte(`[{"object":"project","id":"project-id","name":"Example"}]`))
	want := Result{Version: Version, Projects: []Project{{ID: "project-id", Name: "Example"}}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("FromBWS() = %#v, %v", got, err)
	}
}

func TestFromBWSRejectsUnusableProjectNames(t *testing.T) {
	for _, input := range []string{
		`null`,
		`[{"object":"secret","id":"id","name":"name"}]`,
		`[{"object":"unknown","id":"id","name":"name"}]`,
		`[{"object":"","id":"id","name":"name"}]`,
		`[{"object":null,"id":"id","name":"name"}]`,
		`[{"object":"project","id":"id","name":"line\nbreak"}]`,
		`[{"object":"project","id":"id","name":"one"},{"object":"project","id":"id","name":"two"}]`,
	} {
		if _, err := FromBWS([]byte(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}
