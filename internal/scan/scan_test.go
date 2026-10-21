package scan

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestStagedBlocksHighFindingsWithoutLeakingSource(t *testing.T) {
	repo := scanRepository(t)
	const secret = "AKIAIOSFODNN7EXAMPLE"
	writeScanFile(t, repo, "config.env", "AWS_KEY="+secret+" # do not print this snippet\n")
	scanGit(t, repo, "add", "config.env")
	var stdout, stderr bytes.Buffer

	code := Staged(context.Background(), repo, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("Staged() code = %d, want 1; stderr=%q", code, stderr.String())
	}
	want := "config.env:1 rule=aws-access-key-id severity=HIGH match=AK****************LE\n"
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, secret) || strings.Contains(combined, "do not print this snippet") {
		t.Fatalf("scanner output leaked staged source: %q", combined)
	}
}

func TestStagedWarnsForJWTWithoutBlocking(t *testing.T) {
	repo := scanRepository(t)
	const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature_1"
	writeScanFile(t, repo, "token.txt", token+"\n")
	scanGit(t, repo, "add", "token.txt")
	var stdout, stderr bytes.Buffer

	code := Staged(context.Background(), repo, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Staged() code = %d, want 0", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "token.txt:1 rule=jwt severity=MEDIUM match=ey") {
		t.Fatalf("stderr = %q, want masked JWT warning", stderr.String())
	}
	if strings.Contains(stderr.String(), token) {
		t.Fatalf("stderr leaked JWT: %q", stderr.String())
	}
}

func TestStagedReturnsZeroForCleanChanges(t *testing.T) {
	repo := scanRepository(t)
	writeScanFile(t, repo, "clean.txt", "ordinary staged text\n")
	scanGit(t, repo, "add", "clean.txt")
	var stdout, stderr bytes.Buffer

	code := Staged(context.Background(), repo, &stdout, &stderr)

	if code != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("Staged() = %d, stdout=%q stderr=%q; want clean exit", code, stdout.String(), stderr.String())
	}
}

func TestStagedReturnsTwoForGitError(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Staged(context.Background(), t.TempDir(), &stdout, &stderr)

	if code != 2 {
		t.Fatalf("Staged() code = %d, want 2", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "scan error:") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func scanRepository(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	scanGit(t, repo, "init", "-q")
	scanGit(t, repo, "config", "user.name", "Test User")
	scanGit(t, repo, "config", "user.email", "test@example.com")
	return repo
}

func scanGit(t *testing.T, repo string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = repo
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}

func writeScanFile(t *testing.T, repo, name, content string) {
	t.Helper()
	path := filepath.Join(repo, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
