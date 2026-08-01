package token

import (
	"context"
	"fmt"
	"strings"

	"github.com/R055LE/secrets-broker/internal/execx"
)

// secretServiceAttr namespaces every secret this tool stores or looks up,
// via the "service" attribute pair in freedesktop's Secret Service API.
// Fixed rather than configurable — it's just a namespace tag, not a
// meaningful policy knob.
const secretServiceAttr = "secrets-broker"

// SecretServiceResolver resolves tokens via `secret-tool`, the standard
// freedesktop Secret Service CLI. It's v1's Resolver implementation.
//
// This replaced an earlier KWalletResolver built on `kwallet-query -r`/`-w`
// directly. `kwallet-query -w` turned out to report success while silently
// failing to persist a new folder or entry on kwallet6 6.24.0 (verified
// against the on-disk wallet file and KWallet's own D-Bus API — not a
// misunderstanding of the tool, an actual broken write path). `secret-tool`
// talks to the same underlying wallet via the Secret Service D-Bus
// interface KWallet also implements, and both its write and read paths were
// verified to persist correctly across separate process invocations. It has
// a bonus: Secret Service is a freedesktop standard also implemented by
// GNOME Keyring, so this resolver isn't actually KDE-specific despite
// running on KWallet today — a smaller step than it looks toward the
// eventual container/headless Resolver (which is still a separate,
// not-yet-built implementation; this one still needs a live desktop
// keyring, just not necessarily KWallet specifically).
type SecretServiceResolver struct {
	runner execx.Runner
}

func NewSecretServiceResolver(runner execx.Runner) *SecretServiceResolver {
	return &SecretServiceResolver{runner: runner}
}

func (r *SecretServiceResolver) Resolve(ctx context.Context, entry string) (Token, error) {
	result, err := r.runner.Run(ctx, "secret-tool",
		[]string{"lookup", "service", secretServiceAttr, "entry", entry}, nil)
	if err != nil {
		return Token{}, fmt.Errorf("running secret-tool: %w", err)
	}

	if result.ExitCode != 0 {
		return Token{}, fmt.Errorf("secret-tool lookup exited %d for entry %q (not found, or Secret Service unavailable)", result.ExitCode, entry)
	}

	value := strings.TrimRight(result.Stdout, "\n")
	if value == "" {
		return Token{}, fmt.Errorf("secret-tool entry %q is empty", entry)
	}

	return New(value), nil
}
