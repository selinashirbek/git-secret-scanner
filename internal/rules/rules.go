package rules

import (
	"regexp"
	"sort"
)

// Severity is the blocking risk assigned to a finding.
type Severity string

const (
	High   Severity = "HIGH"
	Medium Severity = "MEDIUM"
)

// Finding identifies the exact byte span matched by one built-in rule.
type Finding struct {
	RuleID   string
	Severity Severity
	Start    int
	End      int
}

type detector struct {
	id       string
	severity Severity
	pattern  *regexp.Regexp
	valid    func(string, int, int) bool
}

var builtins = []detector{
	{
		id:       "aws-access-key-id",
		severity: High,
		pattern:  regexp.MustCompile(`(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		valid:    boundedByAlphaNumeric,
	},
	{
		id:       "github-token",
		severity: High,
		pattern:  regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255}`),
		valid:    boundedByTokenCharacters,
	},
	{
		id:       "private-key",
		severity: High,
		pattern:  regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
	},
	{
		id:       "slack-webhook",
		severity: High,
		pattern:  regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9_-]+`),
		valid:    boundedByTokenCharacters,
	},
	{
		id:       "jwt",
		severity: Medium,
		pattern:  regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
		valid:    boundedByTokenCharacters,
	},
}

// FindBuiltins applies every built-in detector to line.
func FindBuiltins(line string) []Finding {
	var findings []Finding
	for _, rule := range builtins {
		for _, span := range rule.pattern.FindAllStringIndex(line, -1) {
			if rule.valid != nil && !rule.valid(line, span[0], span[1]) {
				continue
			}
			findings = append(findings, Finding{
				RuleID:   rule.id,
				Severity: rule.severity,
				Start:    span[0],
				End:      span[1],
			})
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].Start < findings[j].Start
	})
	return findings
}

func boundedByAlphaNumeric(line string, start, end int) bool {
	return (start == 0 || !isAlphaNumeric(line[start-1])) &&
		(end == len(line) || !isAlphaNumeric(line[end]))
}

func boundedByTokenCharacters(line string, start, end int) bool {
	return (start == 0 || !isTokenCharacter(line[start-1])) &&
		(end == len(line) || !isTokenCharacter(line[end]))
}

func isAlphaNumeric(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
}

func isTokenCharacter(char byte) bool {
	return isAlphaNumeric(char) || char == '_'
}
