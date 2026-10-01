package main

import (
	"fmt"
	"os"

	"github.com/R055LE/secrets-broker/internal/adminweb"
)

func main() {
	if err := adminweb.Run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "secrets-broker-admin-web:", err)
		os.Exit(1)
	}
}
