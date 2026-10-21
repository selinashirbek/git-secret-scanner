package scan

import (
	"context"
	"fmt"
	"io"

	"github.com/selinashirbek/git-secret-scanner/internal/gitindex"
	"github.com/selinashirbek/git-secret-scanner/internal/report"
	"github.com/selinashirbek/git-secret-scanner/internal/rules"
)

// Staged scans added lines in the Git index and returns a CLI exit code.
func Staged(ctx context.Context, startDir string, stdout, stderr io.Writer) int {
	lines, err := gitindex.AddedLines(ctx, startDir)
	if err != nil {
		fmt.Fprintln(stderr, "scan error: unable to read staged changes")
		return 2
	}

	hasHigh := false
	for _, line := range lines {
		for _, match := range rules.FindBuiltins(line.Content) {
			finding := report.Finding{
				Path:     line.Path,
				Line:     line.Number,
				RuleID:   match.RuleID,
				Severity: match.Severity,
				Value:    line.Content[match.Start:match.End],
			}
			output := stdout
			if match.Severity == rules.Medium {
				output = stderr
			} else if match.Severity == rules.High {
				hasHigh = true
			}
			if err := report.Write(output, []report.Finding{finding}); err != nil {
				fmt.Fprintln(stderr, "scan error: unable to write report")
				return 2
			}
		}
	}
	if hasHigh {
		return 1
	}
	return 0
}
