package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/selinashirbek/git-secret-scanner/internal/scan"
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

func TestRunStagedScanIntegration(t *testing.T) {
	repo := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "Test User"},
		{"config", "user.email", "test@example.com"},
	} {
		command := exec.Command("git", args...)
		command.Dir = repo
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, "secret.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("git", "add", "secret.txt")
	command.Dir = repo
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, output)
	}
	var stdout, stderr bytes.Buffer

	code := Run([]string{"scan", "--staged"}, &stdout, &stderr, func() int {
		return scan.Staged(context.Background(), repo, &stdout, &stderr)
	})

	if code != 1 || !strings.Contains(stdout.String(), "rule=aws-access-key-id severity=HIGH") {
		t.Fatalf("Run() = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
