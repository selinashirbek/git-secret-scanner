package cli

import (
	"fmt"
	"io"
)

const usage = "usage: git-secret-scanner scan --staged\n"

// Run parses command-line arguments and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer, scanStaged func() int) int {
	if len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if len(args) == 2 && args[0] == "scan" && args[1] == "--staged" {
		return scanStaged()
	}

	fmt.Fprint(stderr, usage)
	return 2
}
