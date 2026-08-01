// Command secrets-broker is the composition root: the only place real
// adapters (Secret Service, kdialog, bws, JSONL audit log) are wired together.
package main

import (
	"os"

	"github.com/R055LE/secrets-broker/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
