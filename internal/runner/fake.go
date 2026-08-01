package runner

import "context"

// FakeRunner is a scripted Runner for broker unit tests.
type FakeRunner struct {
	Result Result
	Err    error

	// Specs records every RunSpec passed to Run, for assertions. Note:
	// asserting against Specs[i].Token.Value() in a test is fine — it's
	// only String()/LogValue() that are redacted, to stop *accidental*
	// logging, not deliberate test assertions.
	Specs []RunSpec
}

func (f *FakeRunner) Run(ctx context.Context, spec RunSpec) (Result, error) {
	f.Specs = append(f.Specs, spec)
	return f.Result, f.Err
}
