package token

import "context"

// FakeResolver is a scripted Resolver for broker unit tests.
type FakeResolver struct {
	Token Token
	Err   error

	entries []string
}

func (f *FakeResolver) Resolve(ctx context.Context, entry string) (Token, error) {
	f.entries = append(f.entries, entry)
	return f.Token, f.Err
}

// Calls returns the entry names passed to Resolve, in order — for
// asserting the resolver was (or wasn't) touched.
func (f *FakeResolver) Calls() []string {
	return f.entries
}
