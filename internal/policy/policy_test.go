package policy_test

import (
	"testing"

	"github.com/R055LE/secrets-broker/internal/policy"
)

func TestMatch_ExactMatch(t *testing.T) {
	allow := [][]string{{"git", "push"}, {"git", "pull"}}
	if !policy.Match(allow, []string{"git", "push"}) {
		t.Fatal("expected exact match to be allowed")
	}
}

func TestMatch_NoMatch(t *testing.T) {
	allow := [][]string{{"git", "push"}}
	if policy.Match(allow, []string{"git", "fetch"}) {
		t.Fatal("expected no match")
	}
}

func TestMatch_ExtraTrailingArgsAreNotAPrefixMatch(t *testing.T) {
	// The whole point of exact matching: an allowlisted ["terraform","apply"]
	// must NOT also satisfy "terraform apply -destroy".
	allow := [][]string{{"terraform", "apply"}}
	if policy.Match(allow, []string{"terraform", "apply", "-destroy"}) {
		t.Fatal("prefix match must not be treated as allowed")
	}
}

func TestMatch_ShorterArgvIsNotAMatch(t *testing.T) {
	allow := [][]string{{"terraform", "apply", "-destroy"}}
	if policy.Match(allow, []string{"terraform", "apply"}) {
		t.Fatal("a shorter argv must not match a longer allowlist entry")
	}
}

func TestMatch_EmptyAllowlistDeniesEverything(t *testing.T) {
	if policy.Match(nil, []string{"echo", "hi"}) {
		t.Fatal("an empty allowlist must never match")
	}
}

func TestMatch_EmptyArgv(t *testing.T) {
	allow := [][]string{{"git", "push"}}
	if policy.Match(allow, nil) {
		t.Fatal("empty argv must not match a non-empty allowlist entry")
	}
}
