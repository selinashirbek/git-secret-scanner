package rules

import "testing"

func TestBuiltinsFindExactSecretSpans(t *testing.T) {
	slackWebhook := "https://hooks.slack.com/services/" +
		"T00000000/B00000000/" +
		"abcdefghijklmnopqrstuvwx"
	tests := []struct {
		name     string
		line     string
		wantID   string
		wantRisk Severity
		want     string
	}{
		{
			name:     "AWS access key ID",
			line:     `key = "AKIAIOSFODNN7EXAMPLE"`,
			wantID:   "aws-access-key-id",
			wantRisk: High,
			want:     "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:     "GitHub classic token",
			line:     "token=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
			wantID:   "github-token",
			wantRisk: High,
			want:     "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		},
		{
			name:     "GitHub fine-grained token",
			line:     "github_pat_11AA0_example_token_material",
			wantID:   "github-token",
			wantRisk: High,
			want:     "github_pat_11AA0_example_token_material",
		},
		{
			name:     "private key header",
			line:     "  -----BEGIN OPENSSH PRIVATE KEY-----",
			wantID:   "private-key",
			wantRisk: High,
			want:     "-----BEGIN OPENSSH PRIVATE KEY-----",
		},
		{
			name:     "Slack webhook",
			line:     "url=" + slackWebhook,
			wantID:   "slack-webhook",
			wantRisk: High,
			want:     slackWebhook,
		},
		{
			name:     "JWT",
			line:     "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature_1",
			wantID:   "jwt",
			wantRisk: Medium,
			want:     "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature_1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := FindBuiltins(tt.line)
			if len(findings) != 1 {
				t.Fatalf("FindBuiltins() returned %d findings, want 1: %#v", len(findings), findings)
			}
			got := findings[0]
			if got.RuleID != tt.wantID || got.Severity != tt.wantRisk {
				t.Fatalf("finding = %#v, want rule %q severity %q", got, tt.wantID, tt.wantRisk)
			}
			if got.Start < 0 || got.End > len(tt.line) || got.Start >= got.End {
				t.Fatalf("invalid span [%d:%d] for line length %d", got.Start, got.End, len(tt.line))
			}
			if value := tt.line[got.Start:got.End]; value != tt.want {
				t.Fatalf("matched value = %q, want %q", value, tt.want)
			}
		})
	}
}

func TestBuiltinsRejectNonSecrets(t *testing.T) {
	tests := []string{
		"AKIA_TOO_SHORT",
		"XAKIAIOSFODNN7EXAMPLEZ",
		"ghx_abcdefghijklmnopqrstuvwxyz0123456789",
		"ghp_too_short",
		"github_pat_too_short",
		"-----BEGIN PUBLIC KEY-----",
		"http://hooks.slack.com/services/T00000000/B00000000/token",
		"https://example.com/services/T00000000/B00000000/token",
		"eyJheader.payload",
		"abc.def.ghi",
	}

	for _, line := range tests {
		t.Run(line, func(t *testing.T) {
			if got := FindBuiltins(line); len(got) != 0 {
				t.Fatalf("FindBuiltins(%q) = %#v, want no findings", line, got)
			}
		})
	}
}
