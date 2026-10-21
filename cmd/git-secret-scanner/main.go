package main

import (
	"context"
	"os"

	"github.com/selinashirbek/git-secret-scanner/internal/cli"
	"github.com/selinashirbek/git-secret-scanner/internal/scan"
)

func main() {
	code := cli.Run(os.Args[1:], os.Stdout, os.Stderr, func() int {
		return scan.Staged(context.Background(), ".", os.Stdout, os.Stderr)
	})
	os.Exit(code)
}
