// Command secrets-broker-worker is the fixed, credential-bearing half of the
// broker. It takes no flags and is intended to be invoked only through the
// installed sudoers rule as the dedicated secrets-broker user.
package main

import (
	"context"
	"os"

	"github.com/R055LE/secrets-broker/internal/worker"
)

func main() {
	if err := worker.NewServer().Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		os.Exit(1)
	}
}
