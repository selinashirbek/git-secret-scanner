package gitindex

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

const (
	maxBlobSize          = 2 * 1024 * 1024
	maxPatchSize         = 4 * 1024 * 1024
	maxNameStatusSize    = 1 * 1024 * 1024
	maxAggregateBlobSize = 8 * 1024 * 1024
	maxAggregateLines    = 50_000
	maxStagedTargets     = 10_000
)

// ErrorKind classifies failures that must stop a staged scan.
type ErrorKind string

const (
	Git         ErrorKind = "git"
	Parse       ErrorKind = "parse"
	Unsupported ErrorKind = "unsupported"
)

// Error is a typed failure encountered while reading the Git index.
type Error struct {
	Kind ErrorKind
	Path string
	Err  error
}

func (err *Error) Error() string {
	if err.Path != "" {
		return fmt.Sprintf("%s error for %q: %v", err.Kind, err.Path, err.Err)
	}
	return fmt.Sprintf("%s error: %v", err.Kind, err.Err)
}

func (err *Error) Unwrap() error { return err.Err }

// Line is an added line from a staged regular text blob.
type Line struct {
	Path    string
	Number  int
	Content string
}

// AddedLines returns only added lines from staged regular text files.
func AddedLines(ctx context.Context, startDir string) ([]Line, error) {
	rootOutput, err := runGit(ctx, startDir, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, &Error{Kind: Git, Err: errors.New("could not resolve repository root")}
	}
	root, err := parseRepositoryRoot(rootOutput)
	if err != nil {
		return nil, err
	}

	unmerged, _, err := runGitLimited(ctx, root, 1, "ls-files", "--unmerged", "-z")
	if err != nil {
		return nil, &Error{Kind: Git, Err: errors.New("could not inspect index for unmerged entries")}
	}
	if len(unmerged) != 0 {
		return nil, &Error{Kind: Unsupported, Err: errors.New("index contains unmerged entries")}
	}

	nameStatus, tooLarge, err := runGitLimited(
		ctx,
		root,
		maxNameStatusSize,
		"diff", "--cached", "--name-status", "-z", "--diff-filter=ACMRT",
	)
	if err != nil {
		return nil, &Error{Kind: Git, Err: errors.New("could not enumerate staged paths")}
	}
	if tooLarge {
		return nil, &Error{Kind: Unsupported, Err: errors.New("staged path list exceeds 1 MB")}
	}
	targets, err := parseNameStatus(nameStatus)
	if err != nil {
		return nil, err
	}

	var lines []Line
	totalBlobSize := 0
	for _, target := range targets {
		path := target.path
		mode, oid, err := stageEntry(ctx, root, path)
		if err != nil {
			return nil, err
		}
		if mode == "120000" {
			return nil, &Error{Kind: Unsupported, Path: path, Err: errors.New("symlink is not scannable")}
		}
		if mode == "160000" {
			return nil, &Error{Kind: Unsupported, Path: path, Err: errors.New("submodule is not scannable")}
		}
		if !strings.HasPrefix(mode, "100") {
			return nil, &Error{Kind: Unsupported, Path: path, Err: errors.New("non-regular file is not scannable")}
		}

		blob, tooLarge, err := runGitLimited(ctx, root, maxBlobSize, "cat-file", "blob", oid)
		if err != nil {
			return nil, &Error{Kind: Git, Path: path, Err: errors.New("could not read staged blob")}
		}
		if tooLarge {
			return nil, &Error{Kind: Unsupported, Path: path, Err: errors.New("staged blob exceeds 2 MB")}
		}
		if len(blob) > maxAggregateBlobSize-totalBlobSize {
			return nil, &Error{Kind: Unsupported, Err: errors.New("staged blobs exceed 8 MB aggregate scan budget")}
		}
		totalBlobSize += len(blob)
		if bytes.IndexByte(blob, 0) >= 0 {
			return nil, &Error{Kind: Unsupported, Path: path, Err: errors.New("staged blob contains NUL")}
		}

		diffArgs := []string{"diff", "--cached", "--text", "--no-ext-diff", "--no-textconv", "--no-color", "--unified=0"}
		if target.diffFilter != "" {
			diffArgs = append(diffArgs, "--diff-filter="+target.diffFilter)
		}
		diffArgs = append(diffArgs, "--")
		diffArgs = append(diffArgs, target.diffPaths...)
		patch, tooLarge, err := runGitLimited(ctx, root, maxPatchSize, diffArgs...)
		if err != nil {
			return nil, &Error{Kind: Git, Path: path, Err: errors.New("could not read staged diff")}
		}
		if tooLarge {
			return nil, &Error{Kind: Unsupported, Path: path, Err: errors.New("staged patch exceeds 4 MB")}
		}
		pathLines, err := parsePatchLimited(path, patch, maxAggregateLines-len(lines))
		if err != nil {
			return nil, err
		}
		lines = append(lines, pathLines...)
	}
	return lines, nil
}

func parseRepositoryRoot(output []byte) (string, error) {
	if len(output) == 0 || output[len(output)-1] != '\n' {
		return "", &Error{Kind: Parse, Err: errors.New("Git returned a malformed repository root")}
	}
	output = output[:len(output)-1]
	if runtime.GOOS == "windows" && len(output) > 0 && output[len(output)-1] == '\r' {
		output = output[:len(output)-1]
	}
	if len(output) == 0 {
		return "", &Error{Kind: Parse, Err: errors.New("Git returned an empty repository root")}
	}
	return string(output), nil
}

type stagedTarget struct {
	path       string
	diffPaths  []string
	diffFilter string
}

func parseNameStatus(output []byte) ([]stagedTarget, error) {
	fields := bytes.Split(output, []byte{0})
	if len(fields) > 0 && len(fields[len(fields)-1]) == 0 {
		fields = fields[:len(fields)-1]
	}
	var targets []stagedTarget
	for index := 0; index < len(fields); {
		if len(targets) >= maxStagedTargets {
			return nil, &Error{Kind: Unsupported, Err: errors.New("staged path count exceeds 10000")}
		}
		status := string(fields[index])
		index++
		if status == "" {
			return nil, &Error{Kind: Parse, Err: errors.New("empty staged status")}
		}
		kind := status[0]
		if kind == 'R' || kind == 'C' {
			if index+1 >= len(fields) {
				return nil, &Error{Kind: Parse, Err: errors.New("truncated rename or copy status")}
			}
			source := string(fields[index])
			index++
			target := string(fields[index])
			targets = append(targets, stagedTarget{
				path:       target,
				diffPaths:  []string{source, target},
				diffFilter: string(kind),
			})
			index++
			continue
		}
		if !strings.ContainsRune("AMT", rune(kind)) || index >= len(fields) {
			return nil, &Error{Kind: Parse, Err: errors.New("invalid staged name-status record")}
		}
		path := string(fields[index])
		targets = append(targets, stagedTarget{path: path, diffPaths: []string{path}})
		index++
	}
	return targets, nil
}

func stageEntry(ctx context.Context, root, path string) (string, string, error) {
	output, err := runGit(ctx, root, "ls-files", "--stage", "-z", "--", path)
	if err != nil {
		return "", "", &Error{Kind: Git, Path: path, Err: errors.New("could not inspect staged entry")}
	}
	records := bytes.Split(output, []byte{0})
	if len(records) > 0 && len(records[len(records)-1]) == 0 {
		records = records[:len(records)-1]
	}
	if len(records) != 1 {
		return "", "", &Error{Kind: Parse, Path: path, Err: errors.New("expected one stage-0 entry")}
	}
	separator := bytes.IndexByte(records[0], '\t')
	if separator < 0 {
		return "", "", &Error{Kind: Parse, Path: path, Err: errors.New("malformed staged entry")}
	}
	metadata := strings.Fields(string(records[0][:separator]))
	entryPath := string(records[0][separator+1:])
	if len(metadata) != 3 || metadata[2] != "0" || entryPath != path {
		return "", "", &Error{Kind: Parse, Path: path, Err: errors.New("ambiguous staged entry")}
	}
	return metadata[0], metadata[1], nil
}

var hunkHeader = regexp.MustCompile(`^@@ -[0-9]+(?:,[0-9]+)? \+([0-9]+)(?:,([0-9]+))? @@(?: .*)?$`)

func parsePatch(path string, patch []byte) ([]Line, error) {
	return parsePatchLimited(path, patch, -1)
}

func parsePatchLimited(path string, patch []byte, lineLimit int) ([]Line, error) {
	var lines []Line
	inHunk := false
	newLine := 0
	wantNewLines := 0
	seenNewLines := 0

	finishHunk := func() error {
		if inHunk && seenNewLines != wantNewLines {
			return &Error{Kind: Parse, Path: path, Err: errors.New("staged hunk length mismatch")}
		}
		return nil
	}

	for _, rawLine := range bytes.Split(patch, []byte{'\n'}) {
		text := string(rawLine)
		if strings.HasPrefix(text, "@@") {
			if err := finishHunk(); err != nil {
				return nil, err
			}
			matches := hunkHeader.FindStringSubmatch(text)
			if matches == nil {
				return nil, &Error{Kind: Parse, Path: path, Err: errors.New("malformed staged hunk header")}
			}
			newLine, _ = strconv.Atoi(matches[1])
			wantNewLines = 1
			if matches[2] != "" {
				wantNewLines, _ = strconv.Atoi(matches[2])
			}
			seenNewLines = 0
			inHunk = true
			continue
		}
		if !inHunk {
			continue
		}
		if text == `\ No newline at end of file` {
			continue
		}
		if text == "" && seenNewLines == wantNewLines {
			continue
		}
		if text == "" {
			return nil, &Error{Kind: Parse, Path: path, Err: errors.New("unexpected empty patch record")}
		}
		switch text[0] {
		case '+':
			if lineLimit >= 0 && len(lines) >= lineLimit {
				return nil, &Error{Kind: Unsupported, Err: errors.New("added lines exceed aggregate scan budget")}
			}
			lines = append(lines, Line{Path: path, Number: newLine, Content: text[1:]})
			newLine++
			seenNewLines++
		case ' ':
			newLine++
			seenNewLines++
		case '-':
		default:
			return nil, &Error{Kind: Parse, Path: path, Err: errors.New("unexpected staged hunk record")}
		}
		if seenNewLines > wantNewLines {
			return nil, &Error{Kind: Parse, Path: path, Err: errors.New("staged hunk exceeds declared length")}
		}
	}
	if err := finishHunk(); err != nil {
		return nil, err
	}
	return lines, nil
}

func runGit(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = literalPathspecEnvironment()
	return cmd.Output()
}

func runGitLimited(ctx context.Context, dir string, limit int, args ...string) ([]byte, bool, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = literalPathspecEnvironment()
	output := &limitedBuffer{limit: limit}
	cmd.Stdout = output
	err := cmd.Run()
	if output.tooLarge {
		return output.Bytes(), true, nil
	}
	return output.Bytes(), output.tooLarge, err
}

func literalPathspecEnvironment() []string {
	environment := make([]string, 0, len(os.Environ())+1)
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "GIT_LITERAL_PATHSPECS=") {
			environment = append(environment, variable)
		}
	}
	return append(environment, "GIT_LITERAL_PATHSPECS=1")
}

type limitedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	tooLarge bool
}

var errOutputLimit = errors.New("Git output exceeds scan limit")

func (buffer *limitedBuffer) Write(data []byte) (int, error) {
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining < len(data) {
		buffer.tooLarge = true
		written := 0
		if remaining > 0 {
			written, _ = buffer.buffer.Write(data[:remaining])
		}
		return written, errOutputLimit
	}
	return buffer.buffer.Write(data)
}

func (buffer *limitedBuffer) Bytes() []byte { return buffer.buffer.Bytes() }
