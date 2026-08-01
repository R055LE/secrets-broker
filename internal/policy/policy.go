// Package policy decides whether a requested command matches a project's
// allowlist. It's a pure function package — no I/O, nothing to fake in
// tests.
package policy

// Match reports whether argv exactly matches one of the entries in allow.
// Matching is exact and element-for-element — no globs, no prefixes, no
// shell parsing. See decisions/0005-exact-argv-allowlist-matching-no-globs.md
// for why: a prefix match would let an allowlisted ["terraform","apply"]
// also satisfy "terraform apply -destroy".
func Match(allow [][]string, argv []string) bool {
	for _, entry := range allow {
		if argvEqual(entry, argv) {
			return true
		}
	}
	return false
}

func argvEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
