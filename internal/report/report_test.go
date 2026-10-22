package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/selinashirbek/git-secret-scanner/internal/rules"
)

func TestMask(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "empty", value: "", want: ""},
		{name: "eight bytes", value: "12345678", want: "********"},
		{name: "short", value: "secret", want: "******"},
		{name: "long", value: "123456789", want: "12*****89"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Mask(tt.value); got != tt.want {
				t.Fatalf("Mask(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestWriteFindingOmitsRawValueAndSourceSnippet(t *testing.T) {
	const raw = "AKIAIOSFODNN7EXAMPLE"
	var output bytes.Buffer

	err := Write(&output, []Finding{{
		Path:     "config.txt",
		Line:     7,
		RuleID:   "aws-access-key-id",
		Severity: rules.High,
		Value:    raw,
	}})

	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	got := output.String()
	if strings.Contains(got, raw) || strings.Contains(got, "AWS_KEY=") {
		t.Fatalf("output leaked raw data: %q", got)
	}
	want := "config.txt:7 rule=aws-access-key-id severity=HIGH match=AK****************LE\n"
	if got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestWriteEscapesControlsAndRedactsSecretsInPath(t *testing.T) {
	const pathSecret = "AKIAIOSFODNN7EXAMPLE"
	var output bytes.Buffer

	err := Write(&output, []Finding{{
		Path:     "unsafe\n\t\x1b" + pathSecret + ".txt",
		Line:     3,
		RuleID:   "github-token",
		Severity: rules.High,
		Value:    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
	}})

	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	got := strings.TrimSuffix(output.String(), "\n")
	if strings.ContainsAny(got, "\n\t\x1b") {
		t.Fatalf("output contains a raw control byte: %q", got)
	}
	if strings.Contains(got, pathSecret) {
		t.Fatalf("output leaked a secret from the path: %q", got)
	}
	if !strings.Contains(got, `\n\t\x1b`) {
		t.Fatalf("output does not contain readable path escapes: %q", got)
	}
}
