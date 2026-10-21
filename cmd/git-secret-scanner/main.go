package main

import (
	"fmt"
	"os"

	"github.com/selinashirbek/git-secret-scanner/internal/cli"
)

func main() {
	code := cli.Run(os.Args[1:], os.Stdout, os.Stderr, func() int {
		fmt.Fprintln(os.Stderr, "staged scanning is not available")
		return 2
	})
	os.Exit(code)
}
