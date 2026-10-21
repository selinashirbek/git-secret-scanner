package gitindex

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAddedLinesReadsInitialCommitFromResolvedRoot(t *testing.T) {
	repo := newRepository(t)
	writeFile(t, repo, "nested/odd\tname.txt", "first\nsecret value\nthird\n")
	git(t, repo, "add", "nested/odd\tname.txt")

	lines, err := AddedLines(context.Background(), filepath.Join(repo, "nested"))
	if err != nil {
		t.Fatalf("AddedLines() error = %v", err)
	}
	want := []Line{
		{Path: "nested/odd\tname.txt", Number: 1, Content: "first"},
		{Path: "nested/odd\tname.txt", Number: 2, Content: "secret value"},
		{Path: "nested/odd\tname.txt", Number: 3, Content: "third"},
	}
	assertLines(t, lines, want)
}

func TestAddedLinesUsesStagedBlobForPartialStaging(t *testing.T) {
	repo := newRepository(t)
	writeFile(t, repo, "config.txt", "safe\n")
	git(t, repo, "add", "config.txt")
	git(t, repo, "commit", "-m", "base")

	writeFile(t, repo, "config.txt", "staged secret\n")
	git(t, repo, "add", "config.txt")
	writeFile(t, repo, "config.txt", "working tree replacement\n")

	lines, err := AddedLines(context.Background(), repo)
	if err != nil {
		t.Fatalf("AddedLines() error = %v", err)
	}
	assertLines(t, lines, []Line{{Path: "config.txt", Number: 1, Content: "staged secret"}})
}

func TestAddedLinesSupportsRenamedTargets(t *testing.T) {
	repo := newRepository(t)
	var base strings.Builder
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&base, "unchanged line %d\n", i)
	}
	writeFile(t, repo, "old.txt", base.String())
	git(t, repo, "add", "old.txt")
	git(t, repo, "commit", "-m", "base")

	if err := os.Rename(filepath.Join(repo, "old.txt"), filepath.Join(repo, "renamed.txt")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, repo, "renamed.txt", base.String()+"new staged line\n")
	git(t, repo, "add", "-A")

	lines, err := AddedLines(context.Background(), repo)
	if err != nil {
		t.Fatalf("AddedLines() error = %v", err)
	}
	assertLines(t, lines, []Line{{Path: "renamed.txt", Number: 21, Content: "new staged line"}})
}

func TestAddedLinesForcesTextWhenAttributesDisableDiff(t *testing.T) {
	repo := newRepository(t)
	writeFile(t, repo, ".gitattributes", "*.txt -diff\n")
	writeFile(t, repo, "hidden.txt", "visible staged line\n")
	git(t, repo, "add", ".gitattributes", "hidden.txt")

	lines, err := AddedLines(context.Background(), repo)
	if err != nil {
		t.Fatalf("AddedLines() error = %v", err)
	}
	if !containsLine(lines, Line{Path: "hidden.txt", Number: 1, Content: "visible staged line"}) {
		t.Fatalf("AddedLines() = %#v, want hidden.txt staged text", lines)
	}
}

func TestAddedLinesRejectsUnsupportedStagedBlobs(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "NUL byte",
			setup: func(t *testing.T, repo string) {
				writeBytes(t, repo, "binary.dat", []byte{'a', 0, 'b'})
				git(t, repo, "add", "binary.dat")
			},
		},
		{
			name: "over two megabytes",
			setup: func(t *testing.T, repo string) {
				writeBytes(t, repo, "large.txt", []byte(strings.Repeat("x", 2*1024*1024+1)))
				git(t, repo, "add", "large.txt")
			},
		},
		{
			name: "symlink mode",
			setup: func(t *testing.T, repo string) {
				if runtime.GOOS == "windows" {
					t.Skip("Git symlink index mode setup is platform-specific")
				}
				oid := gitInput(t, repo, "target", "hash-object", "-w", "--stdin")
				git(t, repo, "update-index", "--add", "--cacheinfo", "120000,"+oid+",link")
			},
		},
		{
			name: "submodule mode",
			setup: func(t *testing.T, repo string) {
				writeFile(t, repo, "base.txt", "base\n")
				git(t, repo, "add", "base.txt")
				git(t, repo, "commit", "-m", "base")
				head := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD"))
				git(t, repo, "update-index", "--add", "--cacheinfo", "160000,"+head+",module")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newRepository(t)
			tt.setup(t, repo)

			_, err := AddedLines(context.Background(), repo)
			var indexErr *Error
			if !errors.As(err, &indexErr) {
				t.Fatalf("AddedLines() error = %T %v, want *Error", err, err)
			}
			if indexErr.Kind != Unsupported {
				t.Fatalf("error kind = %q, want %q", indexErr.Kind, Unsupported)
			}
		})
	}
}

func TestParsePatchRejectsMalformedHunk(t *testing.T) {
	_, err := parsePatch("file.txt", []byte("@@ -0,0 +1,2 @@\n+only one\n"))
	var indexErr *Error
	if !errors.As(err, &indexErr) || indexErr.Kind != Parse {
		t.Fatalf("parsePatch() error = %T %v, want parse *Error", err, err)
	}
}

func newRepository(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	git(t, repo, "init", "-q")
	git(t, repo, "config", "user.name", "Test User")
	git(t, repo, "config", "user.email", "test@example.com")
	return repo
}

func git(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return string(output)
}

func gitInput(t *testing.T, repo, input string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func writeFile(t *testing.T, repo, name, content string) {
	t.Helper()
	writeBytes(t, repo, name, []byte(content))
}

func writeBytes(t *testing.T, repo, name string, content []byte) {
	t.Helper()
	path := filepath.Join(repo, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertLines(t *testing.T, got, want []Line) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("lines = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func containsLine(lines []Line, want Line) bool {
	for _, line := range lines {
		if line == want {
			return true
		}
	}
	return false
}
