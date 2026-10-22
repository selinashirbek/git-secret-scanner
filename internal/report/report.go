package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

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
			safePath(finding.Path, finding.Value),
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

func safePath(path, findingValue string) string {
	maskedBytes := make([]bool, len(path))
	maskSpan := func(start, end int) {
		for index := start; index < end; index++ {
			maskedBytes[index] = true
		}
	}

	for _, match := range rules.FindBuiltins(path) {
		maskSpan(match.Start, match.End)
	}
	if findingValue != "" {
		for offset := 0; offset < len(path); {
			index := strings.Index(path[offset:], findingValue)
			if index < 0 {
				break
			}
			start := offset + index
			maskSpan(start, start+len(findingValue))
			offset = start + len(findingValue)
		}
	}

	var redacted strings.Builder
	for index := 0; index < len(path); {
		if !maskedBytes[index] {
			redacted.WriteByte(path[index])
			index++
			continue
		}
		end := index + 1
		for end < len(path) && maskedBytes[end] {
			end++
		}
		redacted.WriteString(Mask(path[index:end]))
		index = end
	}

	result := redacted.String()
	if !utf8.ValidString(result) || strings.IndexFunc(result, func(character rune) bool {
		return !unicode.IsPrint(character)
	}) >= 0 {
		return strconv.Quote(result)
	}
	return result
}
