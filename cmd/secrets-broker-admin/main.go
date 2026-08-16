// Command secrets-broker-admin is the root-only administrator interface for
// the worker's fixed policy file. It is not sudo-allowlisted for agent users.
package main

import (
	"os"

	"github.com/R055LE/secrets-broker/internal/admincli"
)

func main() {
	os.Exit(admincli.Execute())
}
