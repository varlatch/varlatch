// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/findfiles"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// What `varlatch scan` reads (scanSources.ts; ADR-0038 Decision 14):
//
//   - --staged: the blobs recorded in the Git index for every path the next
//     commit adds or changes, read from the object store, never from the
//     working tree. A Secret that was staged and then edited or deleted in
//     the working tree is still found. Inside a Git hook, Git's own
//     environment (for example the temporary index of `git commit -a`) is
//     used as it is.
//   - Paths: files and directories, walked without following symbolic
//     links.
//
// Listing comes first and reads no content, so a scan with nothing to read
// never asks the server for values. Every file is read in chunks of 64
// KiB, so memory stays bounded whatever its size.

// SourceError is ScanSourceError.
type SourceError struct{ Message string }

func (e *SourceError) Error() string { return e.Message }

// readChunk is how much a read takes at once: createReadStream's
// highWaterMark.
const readChunk = 1 << 16

// Git runs git with an environment (the CLI's own, as a child process
// inherits it).
type Git struct{ Env []string }

// Command is a git command in cwd.
func (g Git) Command(cwd string, args ...string) *exec.Cmd {
	cmd := exec.Command("git", args...)
	cmd.Dir = cwd
	cmd.Env = g.Env
	return cmd
}

// startError is spawn's error, as Node.js words it: "could not run git:
// spawn git ENOENT" for a git that is not on PATH or a directory that is
// not there.
func startError(err error) error {
	code := findfiles.ErrnoName(err)
	var pathErr *os.PathError
	if errors.Is(err, exec.ErrNotFound) || errors.As(err, &pathErr) && pathErr.Op == "chdir" {
		code = "ENOENT"
	}
	return &SourceError{"could not run git: spawn git " + code}
}

// exitText is `exit ${code}`: the exit status, or null when a signal ended
// it.
func exitText(err error) string {
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() >= 0 {
		return "exit " + strconv.Itoa(exit.ExitCode())
	}
	return "exit null"
}

func trimJS(s string) string { return strings.TrimFunc(s, jsval.IsWhitespace) }

// Run runs git in cwd with input (none when nil) to its end: what it
// printed, what it said on its error stream, and its exit (an
// *exec.ExitError when it failed), or a start error as Node.js's spawn
// words it.
func (g Git) Run(cwd string, input *string, args ...string) (printed, said []byte, exit error, err error) {
	cmd := g.Command(cwd, args...)
	if input != nil {
		cmd.Stdin = strings.NewReader(*input)
	}
	answer, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	complaints, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, startError(err)
	}
	saidCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(complaints)
		saidCh <- b
	}()
	printed, _ = io.ReadAll(answer)
	said = <-saidCh
	return printed, said, cmd.Wait(), nil
}

// output is git(cwd, args, input): stdout, or an error carrying git's
// message.
func (g Git) output(cwd string, input *string, args ...string) ([]byte, error) {
	printed, said, exit, err := g.Run(cwd, input, args...)
	if err != nil {
		return nil, err
	}
	if exit != nil {
		message := trimJS(jsval.DecodeUTF8(said))
		if message == "" {
			message = exitText(exit)
		}
		return nil, &SourceError{"git " + args[0] + " failed: " + message}
	}
	return printed, nil
}

// Realpath is fs.realpath: the path with every link resolved.
func Realpath(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		var pathErr *os.PathError
		if !errors.As(err, &pathErr) && strings.Contains(err.Error(), "too many links") {
			return "", &os.PathError{Op: "realpath", Path: path, Err: syscall.ELOOP}
		}
		return "", err
	}
	return filepath.Abs(resolved)
}

// RelativePath is relativePath: abs relative to root, with `/` separators
// ("" for root itself).
func RelativePath(root, abs string) string {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		rel = abs // path.relative across Windows drives gives the target
	}
	if rel == "." {
		return ""
	}
	return filepath.ToSlash(rel)
}

// resolve is path.resolve(cwd, arg).
func resolve(cwd, arg string) string {
	if filepath.IsAbs(arg) {
		return filepath.Clean(arg)
	}
	return filepath.Join(cwd, arg)
}

// GitTopLevel is gitTopLevel: the top level of the Git working tree
// holding cwd.
func GitTopLevel(git Git, cwd string) (string, error) {
	out, err := git.output(cwd, nil, "rev-parse", "--show-toplevel")
	if err != nil {
		var e *SourceError
		if errors.As(err, &e) {
			return "", &SourceError{"--staged needs a Git working tree: " + strings.TrimPrefix(e.Message, "git rev-parse failed: ")}
		}
		return "", err
	}
	top := trimJS(jsval.DecodeUTF8(out))
	if top == "" {
		return "", &SourceError{"--staged needs a Git working tree, not a bare repository"}
	}
	return Realpath(top)
}

// StagedFile is a blob the next commit records: its display path, relative
// to the project root, its object id and its size.
type StagedFile struct {
	Path string
	SHA  string
	Size int64
}

// StagedListing is what --staged reads.
type StagedListing struct {
	Top        string
	Files      []StagedFile
	NotScanned []NotScanned
}

var (
	rawLine   = regexp.MustCompile(`^:(\d{6}) (\d{6}) ([0-9a-f]+) ([0-9a-f]+) ([A-Z])\d*$`)
	objectRow = regexp.MustCompile(`^([0-9a-f]+) (\w+) (\d+)$`)
)

func quoted(s string) string { return string(jsjson.Stringify(s)) }

// ListStaged is listStaged: every path the index adds or changes relative
// to HEAD (all of it before the first commit), with sizes from the object
// store, without reading content.
func ListStaged(git Git, cwd, projectRoot string) (*StagedListing, error) {
	top, err := GitTopLevel(git, cwd)
	if err != nil {
		return nil, err
	}
	root, err := Realpath(projectRoot)
	if err != nil {
		return nil, err
	}
	raw, err := git.output(top, nil, "diff", "--cached", "--raw", "-z", "--no-abbrev", "--no-renames", "--no-ext-diff", "--no-color")
	if err != nil {
		return nil, err
	}
	tokens := strings.Split(jsval.DecodeUTF8(raw), "\x00")
	type candidate struct{ path, sha string }
	var candidates []candidate
	listing := &StagedListing{Top: top, Files: []StagedFile{}, NotScanned: []NotScanned{}}
	for i := 0; i+1 < len(tokens); i += 2 {
		meta, gitPath := tokens[i], tokens[i+1]
		m := rawLine.FindStringSubmatch(meta)
		if m == nil {
			return nil, &SourceError{"unexpected output from git diff: " + quoted(meta)}
		}
		mode, sha, status := m[2], m[4], m[5]
		path := RelativePath(root, filepath.Join(top, gitPath))
		switch {
		case status == "D":
			continue
		case status == "U":
			listing.NotScanned = append(listing.NotScanned, NotScanned{path, "unmerged: resolve the conflict and stage the result"})
			continue
		case mode == "160000":
			listing.NotScanned = append(listing.NotScanned, NotScanned{path, "a submodule: scan it in its own repository"})
			continue
		}
		candidates = append(candidates, candidate{path, sha})
	}
	if len(candidates) == 0 {
		return listing, nil
	}
	var input strings.Builder
	for _, c := range candidates {
		input.WriteString(c.sha + "\n")
	}
	text := input.String()
	out, err := git.output(top, &text, "cat-file", "--batch-check")
	if err != nil {
		return nil, err
	}
	checked := strings.Split(jsval.DecodeUTF8(out), "\n")
	for i, c := range candidates {
		line := ""
		if i < len(checked) {
			line = checked[i]
		}
		m := objectRow.FindStringSubmatch(line)
		if m == nil || m[1] != c.sha {
			listing.NotScanned = append(listing.NotScanned, NotScanned{c.path, "the staged object is missing from the repository"})
			continue
		}
		if m[2] != "blob" {
			listing.NotScanned = append(listing.NotScanned, NotScanned{c.path, "not a file (" + m[2] + ")"})
			continue
		}
		size, _ := strconv.ParseFloat(m[3], 64)
		listing.Files = append(listing.Files, StagedFile{c.path, c.sha, int64(size)})
	}
	return listing, nil
}

// ScanStaged streams the staged blobs through the engine with one `git
// cat-file --batch`. A file is admitted against the total bound with the
// sizes of the files admitted before it counted (they are all read before
// it), so the total bound holds for the staged content as a whole; files
// the engine does not admit are never requested.
func ScanStaged(engine *Engine, git Git, listing *StagedListing) error {
	var wanted []StagedFile
	reserved := int64(0)
	for _, f := range listing.Files {
		if engine.Admit(f.Path, f.Size, reserved) {
			wanted = append(wanted, f)
			reserved += f.Size
		}
	}
	if len(wanted) == 0 {
		return nil
	}
	cmd := git.Command(listing.Top, "cat-file", "--batch")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	objects, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	complaints, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return startError(err)
	}
	said := make(chan []byte, 1)
	go func() {
		// What git says when it fails, read as it goes so git never waits
		// on it.
		b, _ := io.ReadAll(complaints)
		said <- b
	}()
	go func() {
		// git may exit before reading all of its input; its exit status
		// tells.
		for _, f := range wanted {
			if _, err := io.WriteString(stdin, f.SHA+"\n"); err != nil {
				break
			}
		}
		_ = stdin.Close()
	}()
	read := bufio.NewReaderSize(objects, readChunk)
	index, failed := readObjects(engine, read, wanted)
	if failed != nil {
		_ = cmd.Process.Kill()
	}
	_, _ = io.Copy(io.Discard, read)
	message := trimJS(jsval.DecodeUTF8(<-said))
	waitErr := cmd.Wait()
	switch {
	case failed != nil:
		return failed
	case waitErr != nil:
		if message == "" {
			message = exitText(waitErr)
		}
		return &SourceError{"git cat-file failed: " + message}
	case index != len(wanted):
		return &SourceError{"git cat-file ended early"}
	}
	return nil
}

// readObjects reads `git cat-file --batch`'s answer for wanted, each
// object's content in chunks through the engine; the error that stops it,
// and how many objects were read.
func readObjects(engine *Engine, read *bufio.Reader, wanted []StagedFile) (int, error) {
	buf := make([]byte, readChunk)
	index := 0
	for ; index < len(wanted); index++ {
		header, err := read.ReadBytes('\n')
		if err != nil {
			return index, nil // ended early
		}
		line := jsval.DecodeUTF8(header[:len(header)-1])
		file := wanted[index]
		m := objectRow.FindStringSubmatch(line)
		if m == nil || m[1] != file.SHA {
			return index, &SourceError{"unexpected output from git cat-file: " + quoted(line)}
		}
		remaining, _ := strconv.ParseInt(m[3], 10, 64)
		scan := engine.Begin(file.Path)
		over := false
		for remaining > 0 {
			n := int(min(remaining, int64(len(buf))))
			if _, err := io.ReadFull(read, buf[:n]); err != nil {
				return index, nil // ended early, inside an object
			}
			if !over && !scan.Push(buf[:n]) {
				over = true
			}
			remaining -= int64(n)
		}
		if over {
			scan.Fail("grew past the per-file bound while being read")
		} else {
			scan.End()
		}
		// The newline git writes after each object's content.
		_, _ = read.ReadByte()
	}
	// More than was asked for: what follows is another header.
	if rest, err := read.ReadBytes('\n'); err == nil {
		return index, &SourceError{"unexpected output from git cat-file: " + quoted(jsval.DecodeUTF8(rest[:len(rest)-1]))}
	}
	return index, nil
}

// ---- Paths ---------------------------------------------------------------------

// PathFile is a regular file to read: its absolute path, display path and
// size when listed.
type PathFile struct {
	Abs  string
	Path string
	Size int64
}

// PathListing is what a path scan reads.
type PathListing struct {
	Files      []PathFile
	NotScanned []NotScanned
}

// ListPaths is listPaths: the given files and directories walked, in a
// stable order, without following symbolic links. A name is read as
// Node.js's readdir reads it, as UTF-8 (each ill-formed sequence as
// U+FFFD), so a name that is not UTF-8 is reported as TypeScript reports
// it.
func ListPaths(args []string, cwd, projectRoot string) (*PathListing, error) {
	root, err := Realpath(projectRoot)
	if err != nil {
		return nil, err
	}
	listing := &PathListing{Files: []PathFile{}, NotScanned: []NotScanned{}}
	seen := map[string]bool{}
	var visit func(abs, display string)
	visit = func(abs, display string) {
		if seen[abs] {
			return
		}
		seen[abs] = true
		st, err := os.Lstat(abs)
		if err != nil {
			listing.NotScanned = append(listing.NotScanned, NotScanned{display, findfiles.ReasonOf(err)})
			return
		}
		switch mode := st.Mode(); {
		case mode&os.ModeSymlink != 0:
			listing.NotScanned = append(listing.NotScanned, NotScanned{display, "a symbolic link, not followed: scan its target directly"})
			return
		case mode.IsRegular():
			listing.Files = append(listing.Files, PathFile{abs, display, st.Size()})
			return
		case !mode.IsDir():
			listing.NotScanned = append(listing.NotScanned, NotScanned{display, "not a regular file"})
			return
		}
		names, err := readNames(abs)
		if err != nil {
			listing.NotScanned = append(listing.NotScanned, NotScanned{display, "directory " + findfiles.ReasonOf(err)})
			return
		}
		slices.Sort(names) // Buffer.compare of the names' UTF-8
		for _, name := range names {
			child := filepath.Join(abs, name)
			visit(child, RelativePath(root, child))
		}
	}
	for _, arg := range args {
		given := resolve(cwd, arg)
		abs, err := Realpath(given)
		if err != nil {
			listing.NotScanned = append(listing.NotScanned, NotScanned{RelativePath(root, given), findfiles.ReasonOf(err)})
			continue
		}
		display := RelativePath(root, abs)
		if display == "" {
			display = "."
		}
		visit(abs, display)
	}
	return listing, nil
}

// readNames is readdir's names, decoded as Node.js decodes them.
func readNames(dir string) ([]string, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(raw))
	for i, n := range raw {
		names[i] = jsval.DecodeUTF8([]byte(n))
	}
	return names, nil
}

// ScanPaths is scanPaths: each listed file streamed through the engine,
// one at a time, in chunks of 64 KiB.
func ScanPaths(engine *Engine, listing *PathListing) {
	buf := make([]byte, readChunk)
	for _, file := range listing.Files {
		if !engine.Admit(file.Path, file.Size, 0) {
			continue
		}
		scan := engine.Begin(file.Path)
		reason, over := readFile(file.Abs, buf, scan)
		switch {
		case reason != "":
			scan.Fail(reason)
		case over:
			scan.Fail("grew past the per-file bound while being read")
		default:
			scan.End()
		}
	}
}

// readFile pushes a file's content: why it could not be read to its end,
// or whether it went over the per-file bound.
func readFile(path string, buf []byte, scan *FileScan) (reason string, over bool) {
	f, err := os.Open(path)
	if err != nil {
		return findfiles.ReasonOf(err), false
	}
	defer f.Close()
	for {
		n, err := f.Read(buf)
		if n > 0 && !scan.Push(buf[:n]) {
			return "", true
		}
		if errors.Is(err, io.EOF) {
			return "", false
		}
		if err != nil {
			return findfiles.ReasonOf(err), false
		}
	}
}
