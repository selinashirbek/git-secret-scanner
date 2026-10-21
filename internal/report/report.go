package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/selinashirbek/git-secret-scanner/internal/rules"
)

// Finding contains only the fields allowed in scanner output.
type Finding struct {
	Path     string
	Line     int
	RuleID   string
	Severity rules.Severity
	Value    string
}

// Mask hides a value, retaining only two characters at each end when safe.
func Mask(value string) string {
	characters := []rune(value)
	if len(characters) <= 8 {
		return strings.Repeat("*", len(characters))
	}
	return string(characters[:2]) + strings.Repeat("*", len(characters)-4) + string(characters[len(characters)-2:])
}

// Write emits metadata and a masked match without source snippets.
func Write(output io.Writer, findings []Finding) error {
	for _, finding := range findings {
		if _, err := fmt.Fprintf(
			output,
			"%s:%d rule=%s severity=%s match=%s\n",
			finding.Path,
			finding.Line,
			finding.RuleID,
			finding.Severity,
			Mask(finding.Value),
		); err != nil {
			return err
		}
	}
	return nil
}
