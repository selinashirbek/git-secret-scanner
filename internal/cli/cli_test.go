package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunHelpPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run([]string{"help"}, &stdout, &stderr, func() int { return 99 })

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "git-secret-scanner scan --staged") {
		t.Fatalf("stdout = %q, want usage", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunRoutesStagedScan(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false

	code := Run([]string{"scan", "--staged"}, &stdout, &stderr, func() int {
		called = true
		return 1
	})

	if code != 1 {
		t.Fatalf("Run() code = %d, want scanner code 1", code)
	}
	if !called {
		t.Fatal("staged scanner was not called")
	}
}

func TestRunRejectsUnsupportedInvocation(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run([]string{"scan"}, &stdout, &stderr, func() int { return 0 })

	if code != 2 {
		t.Fatalf("Run() code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("stderr = %q, want usage", stderr.String())
	}
}
