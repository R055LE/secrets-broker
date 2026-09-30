package projectlist

import (
	"reflect"
	"testing"
)

func TestFromBWSKeepsOnlyProjectIdentity(t *testing.T) {
	input := `[{
		"object":"project", "id":"project-id", "name":"Example",
		"organizationId":"organization-id", "futureSensitiveField":"sentinel-secret"
	}]`
	got, err := FromBWS([]byte(input))
	want := Result{Version: Version, Projects: []Project{{ID: "project-id", Name: "Example"}}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("FromBWS() = %#v, %v", got, err)
	}
}

func TestFromBWSRejectsUnusableProjectNames(t *testing.T) {
	for _, input := range []string{
		`null`,
		`[{"object":"secret","id":"id","name":"name"}]`,
		`[{"object":"project","id":"id","name":"line\nbreak"}]`,
		`[{"object":"project","id":"id","name":"one"},{"object":"project","id":"id","name":"two"}]`,
	} {
		if _, err := FromBWS([]byte(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}
