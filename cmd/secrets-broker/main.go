// Command secrets-broker is the unprivileged, agent-facing client. The fixed
// worker process owns all policy, approval, token, audit, and runner adapters.
package main

import (
	"os"

	"github.com/R055LE/secrets-broker/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
