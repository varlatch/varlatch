// SPDX-License-Identifier: Apache-2.0

// Package findfiles is `varlatch scan --find-files [<dir>]` (ADR-0054
// Decision 8; apps/cli/src/findFiles.ts): list the files under a directory
// that look like copies of secrets by their name, say whether Git ignores
// each one, and point to `varlatch import`.
//
// Discovery uses file names and metadata (directory entries, lstat),
// without reading candidate contents, and never follows a symbolic link. It
// needs no project, no server, and no credential, and discloses nothing.
//
// Git is asked as little as possible: one `git check-ignore --no-index` per
// repository, which evaluates Git's own ignore rules (negation,
// directory-only patterns, `**`, escapes, nested .gitignore files,
// info/exclude, core.excludesFile) and reads no index and no objects.
// Before it runs, the repository is found and looked at here, by name, and
// anything unusual makes the state "unknown" instead: Git could otherwise be
// made to open a file that is a secret copy. File contents and raw Git
// diagnostics are never displayed.
//
// Names are bytes: a name that is not UTF-8 keeps its identity through the
// walk and Git, and is shown escaped.
package findfiles

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/termtext"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// ReportVersion is FIND_FILES_REPORT_VERSION.
const ReportVersion = 1

// skipDirs are never entered: version control and dependencies, as the
// agents hook skips them.
var skipDirs = map[string]bool{".git": true, ".hg": true, ".svn": true, "node_modules": true}

// Limits bound the walk.
type Limits struct {
	// MaxEntries is the directory entries read before the walk stops.
	MaxEntries int
	// MaxDepth is the directory levels below the starting directory that are entered.
	MaxDepth int
}

// DefaultLimits is FIND_LIMITS.
var DefaultLimits = Limits{MaxEntries: 200_000, MaxDepth: 20}

// gitTimeout is how long one Git command may take before its answer is
// given up.
const gitTimeout = 30 * time.Second

// envTemplates are the dotenv templates that hold no values (the hook's
// ENV_TEMPLATES).
var envTemplates = map[string]bool{".env.example": true, ".env.schema": true}

// CopyKindOf is copyKindOf: "dotenv" for `.env` and `.env.*` but the
// templates, "key" for `*.pem` and `*.key`, matched case-sensitively as
// bytes; "" for anything else.
func CopyKindOf(name string) string {
	if name == ".env" || strings.HasPrefix(name, ".env.") && !envTemplates[name] {
		return "dotenv"
	}
	if strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") {
		return "key"
	}
	return ""
}

// The Git states.
const (
	NotIgnored   = "not-ignored"
	Ignored      = "ignored"
	NoRepository = "no-repository"
	Unknown      = "unknown"
)

// File is one file found.
type File struct {
	// Path is relative to the starting directory, `/`-separated, as bytes.
	Path string
	Kind string
	// Symlink: a symbolic link is listed by its own name; its target is
	// never looked at.
	Symlink bool
	Git     string
	// GitError is why the Git state is unknown.
	GitError string
	abs      string
}

// NotSearched is a directory not searched, `/`-terminated, relative to the
// root.
type NotSearched struct {
	Path, Reason string
}

// Report is FindFilesReport.
type Report struct {
	Root           string
	Files          []File
	NotSearched    []NotSearched
	EntriesChecked int
	// Stopped: the walk stopped at MaxEntries; what follows was not looked at.
	Stopped bool
}

// Error is FindFilesError: the search could not start.
type Error struct{ Message string }

func (e *Error) Error() string { return e.Message }

// ---- Bytes ----------------------------------------------------------------------

const sep = string(filepath.Separator)

// utf8OrNull is TextDecoder("utf-8", {fatal: true}).decode: the text, a
// leading byte order mark dropped, or false when the bytes are not UTF-8.
func utf8OrNull(b string) (string, bool) {
	if !utf8.ValidString(b) {
		return "", false
	}
	return strings.TrimPrefix(b, "\uFEFF"), true
}

// child is dir + separator + name, for absolute paths.
func child(dir, name string) string {
	if dir != "" && strings.HasSuffix(dir, sep) {
		return dir + name
	}
	return dir + sep + name
}

// isBelow is whether abs lies below the directory dir.
func isBelow(abs, dir string) bool {
	base := dir
	if strings.HasSuffix(dir, sep) {
		base = dir[:len(dir)-1]
	}
	return len(abs) > len(base)+1 && abs[len(base)] == sep[0] && abs[:len(base)] == base
}

// parentOf is the directory above abs, "" (none) at the top.
func parentOf(abs string) string {
	at := strings.LastIndexByte(abs, sep[0])
	if at < 0 || len(abs) <= 1 {
		return ""
	}
	if at == 0 {
		return sep
	}
	return abs[:at]
}

func baseName(abs string) string { return abs[strings.LastIndexByte(abs, sep[0])+1:] }

// DisplayBytes is displayBytes: bytes as shown on a terminal. UTF-8 without
// controls is shown as is; anything else is shown quoted, with controls
// escaped (`\n`, `\u009b`) and each byte that is not UTF-8 as `\xfe`.
func DisplayBytes(b string) string {
	if text, ok := utf8OrNull(b); ok {
		return termtext.DisplayPath(text)
	}
	var out strings.Builder
	for i := 0; i < len(b); {
		c := b[i]
		n := 0
		switch {
		case c < 0x80:
			n = 1
		case c >= 0xc2 && c <= 0xdf:
			n = 2
		case c >= 0xe0 && c <= 0xef:
			n = 3
		case c >= 0xf0 && c <= 0xf4:
			n = 4
		}
		ch, ok := "", false
		if n > 0 && i+n <= len(b) {
			ch, ok = utf8OrNull(b[i : i+n])
		}
		if !ok {
			out.WriteString(`\x` + hex2(c))
			i++
			continue
		}
		out.WriteString(escapeChar(ch)) // a byte order mark decodes to nothing
		i += n
	}
	return `"` + out.String() + `"`
}

func hex2(c byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[c>>4], digits[c&15]})
}

// escapeChar is one character inside a quoted display: quotes,
// backslashes, and controls escaped.
func escapeChar(ch string) string {
	if ch == `"` || ch == `\` {
		return `\` + ch
	}
	shown := termtext.DisplayPath(ch)
	if shown == ch {
		return ch
	}
	return shown[1 : len(shown)-1]
}

// jsonPath is a path in JSON: key as UTF-8 (lossy when it is not), and
// key+"Base64" with the exact bytes when it is not.
func jsonPath(o jsjson.Object, b, key string) jsjson.Object {
	o = append(o, jsjson.Member{Key: key, Value: jsval.DecodeUTF8([]byte(b))})
	if !utf8.ValidString(b) {
		o = append(o, jsjson.Member{Key: key + "Base64", Value: base64.StdEncoding.EncodeToString([]byte(b))})
	}
	return o
}

// errNotDirectory is opendir's ENOTDIR for a path that is not a
// directory, the same on every platform.
var errNotDirectory = errors.New("not a directory")

// ErrnoName is libuv's name for a system error a file operation meets
// (EACCES, ENOENT, ...), or the error's text for one without.
func ErrnoName(err error) string { return errnoName(err) }

// ReasonOf is reasonOf: "does not exist", or "unreadable (<code>)".
func ReasonOf(err error) string { return reasonOf(err) }

// errnoName is libuv's name for a system error a file operation meets.
func errnoName(err error) string {
	if errors.Is(err, errNotDirectory) {
		return "ENOTDIR"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if name := errnoNames[errno]; name != "" {
			return name
		}
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "ENOENT"
	case errors.Is(err, fs.ErrPermission):
		return "EACCES"
	}
	return err.Error()
}

// reasonOf is reasonOf: "does not exist", or "unreadable (<code>)".
func reasonOf(err error) string {
	code := errnoName(err)
	if code == "ENOENT" {
		return "does not exist"
	}
	return "unreadable (" + code + ")"
}

// ---- The walk -------------------------------------------------------------------

type walk struct {
	root        string
	files       []File
	notSearched []NotSearched
	// repoDirs are directories that hold a `.git` entry: each may be the top
	// of its own repository.
	repoDirs       []string
	entriesChecked int
	stopped        bool
	limits         Limits
}

// walkForCopies walks dir (resolved from cwd) by name, without following
// links or opening files. Entries are read incrementally, in the order
// the directory gives them, and counted as they are read, so the entry
// bound also bounds memory; each directory's entries are then sorted
// (within the bound) for a stable order.
func walkForCopies(dir, cwd string, limits Limits) (*walk, error) {
	start := dir
	if !filepath.IsAbs(start) {
		start = filepath.Join(cwd, dir)
	}
	// Resolve the directory given (it may itself be a link); nothing below it is followed.
	root, err := filepath.EvalSymlinks(start)
	if err == nil {
		root, err = filepath.Abs(root)
	}
	if err != nil {
		return nil, &Error{"cannot search " + termtext.DisplayPath(dir) + ": " + reasonOf(err)}
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, &Error{"cannot search " + termtext.DisplayPath(dir) + ": " + reasonOf(err)}
	}
	if !info.IsDir() {
		return nil, &Error{"--find-files takes a directory; " + termtext.DisplayPath(dir) + " is not one"}
	}
	w := &walk{root: root, repoDirs: []string{root}, limits: limits}
	w.visit(root, "", false, 0)
	return w, nil
}

type entry struct {
	name string
	mode fs.FileMode
}

func (w *walk) visit(abs, rel string, nested bool, depth int) {
	shown := "./"
	if nested {
		shown = rel + "/"
	}
	f, err := os.Open(abs)
	if err == nil {
		var info os.FileInfo
		if info, err = f.Stat(); err == nil && !info.IsDir() {
			err = errNotDirectory
		}
		if err != nil {
			_ = f.Close()
		}
	}
	if err != nil {
		w.notSearched = append(w.notSearched, NotSearched{shown, "directory " + reasonOf(err)})
		return
	}
	var entries []entry
	for !w.stopped {
		batch, err := f.ReadDir(256)
		for _, e := range batch {
			if w.entriesChecked >= w.limits.MaxEntries {
				w.stopped = true
				break
			}
			w.entriesChecked++
			entries = append(entries, entry{e.Name(), e.Type()})
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				w.notSearched = append(w.notSearched, NotSearched{shown, "directory " + reasonOf(err) + " while being read"})
			}
			break
		}
	}
	_ = f.Close()
	slices.SortFunc(entries, func(a, b entry) int { return cmp.Compare(a.name, b.name) })
	if nested && slices.ContainsFunc(entries, func(e entry) bool { return e.name == ".git" }) {
		w.repoDirs = append(w.repoDirs, abs)
	}
	for _, e := range entries {
		path := e.name
		if nested {
			path = rel + "/" + e.name
		}
		if e.mode.IsDir() {
			if skipDirs[e.name] || w.stopped {
				continue
			}
			if depth >= w.limits.MaxDepth {
				w.notSearched = append(w.notSearched, NotSearched{path + "/", "below the depth bound of " + strconv.Itoa(w.limits.MaxDepth) + " directory levels"})
				continue
			}
			w.visit(child(abs, e.name), path, true, depth+1)
			continue
		}
		// Only regular files and links to anything; a link is never followed.
		symlink := e.mode&fs.ModeSymlink != 0
		if !symlink && !e.mode.IsRegular() {
			continue
		}
		if kind := CopyKindOf(e.name); kind != "" {
			w.files = append(w.files, File{abs: child(abs, e.name), Path: path, Kind: kind, Symlink: symlink, Git: Unknown})
		}
	}
}

// ---- Asking Git -----------------------------------------------------------------
//
// Checked with a FIFO in place of each file of a repository: this command
// opens the gitfile, `commondir`, `config`, `config.worktree`,
// `info/exclude`, `objects/info/alternates`, the excludes file, and the
// `.gitignore` files (never through a link).

// failure is GitFailure: why Git gave no answer, in fixed words (Git's own
// diagnostics could quote a file, so they are never shown).
type failure struct{ message string }

func (e *failure) Error() string { return e.message }

// gitEnv is the environment Git gets: none of the caller's GIT_*
// variables, no system and no global configuration.
func gitEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") {
			env = append(env, kv)
		}
	}
	return append(append(env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"), extra...)
}

// runGit runs git with a timeout: a Git that waits on something is given
// up, never waited for. Its stderr is discarded, never shown. A Git ended
// by a signal is status 1.
func runGit(cwd string, args []string, env []string, input []byte) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-c", "core.fsmonitor=false"}, args...)...)
	cmd.Dir = cwd
	cmd.Env = env
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	// Output collects Git's stdout (and keeps its stderr to itself, never shown).
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return 0, nil, &failure{"Git timed out (" + strconv.Itoa(int(gitTimeout/time.Second)) + " s)"}
	}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return 0, nil, &failure{"Git could not be started"}
		}
		code := exit.ExitCode()
		if code < 0 {
			code = 1
		}
		return code, out, nil
	}
	return 0, out, nil
}

// plainFile is "missing", "ok" for a regular file with no other name (not
// a link, not hard-linked), or why it is unusual.
func plainFile(path string) string {
	info, err := os.Lstat(path)
	if err != nil {
		if code := errnoName(err); code == "ENOENT" || code == "ENOTDIR" {
			return "missing"
		}
		return DisplayBytes(path) + ": " + reasonOf(err)
	}
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		return DisplayBytes(path) + symlinkSuffix
	case !info.Mode().IsRegular():
		return DisplayBytes(path) + " is not a regular file"
	case links(path, info) > 1:
		return DisplayBytes(path) + " has another name (a hard link)"
	}
	return "ok"
}

const symlinkSuffix = " is a symbolic link"

// namedFile is whether Git may read the file a configuration names:
// "missing", "ok", or why not. Each name on the way, through symbolic
// links, must not look like a secret copy, and the file must be a regular
// file with no other name.
func namedFile(path string) (string, error) {
	current := path
	for range 40 {
		if CopyKindOf(baseName(current)) != "" {
			return DisplayBytes(current) + " has the name of a secret copy", nil
		}
		verdict := plainFile(current)
		if !strings.HasSuffix(verdict, symlinkSuffix) {
			return verdict, nil
		}
		target, err := os.Readlink(current)
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(target, sep) {
			current = target
		} else {
			parent := parentOf(current)
			if parent == "" {
				parent = sep
			}
			current = child(parent, target)
		}
	}
	return DisplayBytes(path) + ": too many symbolic links", nil
}

func isDir(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir()
}

// pointer is a path stored in a small file Git keeps (`.git` file,
// `commondir`): a directory, or why it is unusual.
func pointer(file, prefix, base string) (dir, unusual string, err error) {
	if verdict := plainFile(file); verdict != "ok" {
		if verdict == "missing" {
			return "", DisplayBytes(file) + " is missing", nil
		}
		return "", verdict, nil
	}
	f, err := os.Open(file)
	if err != nil {
		return "", "", err
	}
	buf := make([]byte, 4097)
	n, err := io.ReadFull(f, buf)
	_ = f.Close()
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", "", err
	}
	raw := string(buf[:n])
	var m []string
	if len(raw) <= 4096 {
		if text, ok := utf8OrNull(raw); ok {
			m = regexp.MustCompile(`^` + regexp.QuoteMeta(prefix) + `([^\n\r]+)\r?\n?$`).FindStringSubmatch(text)
		}
	}
	if m == nil {
		return "", DisplayBytes(file) + " is not what Git writes there", nil
	}
	target := m[1]
	if !strings.HasPrefix(target, "/") {
		target = child(base, target)
	}
	if !isDir(target) {
		return "", DisplayBytes(file) + " does not point to a directory", nil
	}
	return target, "", nil
}

type repository struct {
	// top is the top of the working tree: the directory that holds `.git`.
	top, gitDir, commonDir string
}

// findRepository is the repository Git would find from start, found the
// way Git looks for it, without running Git: nil outside any repository;
// unusual when anything about it is (a linked `.git`, a bare repository, a
// pointer that is not a plain file pointing to a directory).
func findRepository(start string) (repo *repository, unusual string, err error) {
	for dir := start; dir != ""; dir = parentOf(dir) {
		dotGit := child(dir, ".git")
		info, statErr := os.Lstat(dotGit)
		if statErr != nil {
			if isDir(child(dir, "objects")) && isDir(child(dir, "refs")) {
				return nil, DisplayBytes(dir) + " looks like a bare repository", nil
			}
			continue
		}
		var gitDir string
		switch {
		case info.IsDir():
			gitDir = dotGit
		case info.Mode().IsRegular():
			target, unusual, err := pointer(dotGit, "gitdir: ", dir)
			if err != nil || unusual != "" {
				return nil, unusual, err
			}
			gitDir = target
		case info.Mode()&fs.ModeSymlink != 0:
			return nil, DisplayBytes(dotGit) + " is a symbolic link", nil
		default:
			return nil, DisplayBytes(dotGit) + " is not a directory or a file", nil
		}
		commonDir := gitDir
		commondir := child(gitDir, "commondir")
		if plainFile(commondir) != "missing" {
			target, unusual, err := pointer(commondir, "", gitDir)
			if err != nil || unusual != "" {
				return nil, unusual, err
			}
			commonDir = target
		}
		return &repository{top: dir, gitDir: gitDir, commonDir: commonDir}, "", nil
	}
	return nil, "", nil
}

// configFacts is what a configuration file says.
type configFacts struct {
	unusual      string
	includes     bool
	excludesFile *string // the last core.excludesFile, as written
}

// readConfig is what a configuration file says, read by `git config --file
// <f> --no-includes` with no repository and no other configuration, so
// that only that file is opened. Keys and values are compared as bytes.
func readConfig(file string) (configFacts, error) {
	var facts configFacts
	name, ok := utf8OrNull(file)
	if !ok {
		facts.unusual = DisplayBytes(file) + " is not a UTF-8 path"
		return facts, nil
	}
	tmp := os.TempDir()
	code, out, err := runGit(tmp, []string{"config", "--file", name, "--no-includes", "--list", "-z"}, gitEnv("GIT_DIR="+filepath.Join(tmp, "varlatch-find-files-no-repository")), nil)
	if err != nil {
		return facts, err
	}
	if code != 0 {
		facts.unusual = "Git could not read " + DisplayBytes(file) + " (exit status " + strconv.Itoa(code) + ")"
		return facts, nil
	}
	for _, e := range nulList(out) {
		key, value, _ := strings.Cut(e, "\n")
		key = latin1Lower(key)
		switch {
		case key == "include.path" || strings.HasPrefix(key, "includeif.") && strings.HasSuffix(key, ".path"):
			facts.includes = true
		case key == "core.worktree":
			if facts.unusual == "" {
				facts.unusual = DisplayBytes(file) + " sets core.worktree"
			}
		case key == "core.excludesfile":
			if text, ok := utf8OrNull(value); !ok {
				if facts.unusual == "" {
					facts.unusual = DisplayBytes(file) + " sets a core.excludesFile that is not UTF-8"
				}
			} else {
				facts.excludesFile = &text
			}
		}
	}
	return facts, nil
}

// latin1Lower is a key's toLowerCase(), read as latin1: ASCII letters, and
// the latin1 letters, which a key Git accepts never holds.
func latin1Lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' || c >= 0xc0 && c <= 0xde && c != 0xd7 {
			b[i] = c + 32
		}
	}
	return string(b)
}

// globalConfig is the global configuration's verdict and excludes file.
type globalConfig struct {
	unusual      string
	excludesFile *string
}

func getenv(e clientctx.Env, key string) (string, bool) { return e.LookupEnv(key) }

// readGlobalConfig is the global configuration, read here (Git itself
// never gets it): only core.excludesFile is used. Git reads the XDG file
// first and `~/.gitconfig` second, so a value in `~/.gitconfig` wins. An
// include could set the excludes file, and includes are not read, so any
// include makes every state unknown.
func readGlobalConfig(e clientctx.Env) (globalConfig, error) {
	var global globalConfig
	home, err := clientctx.HomeDir(e)
	if err != nil {
		return global, err
	}
	xdg, _ := getenv(e, "XDG_CONFIG_HOME")
	if xdg == "" {
		xdg = filepath.Join(home, ".config")
	}
	files := []string{filepath.Join(xdg, "git", "config"), filepath.Join(home, ".gitconfig")}
	if g, ok := getenv(e, "GIT_CONFIG_GLOBAL"); ok {
		files = []string{g}
	}
	for _, file := range files {
		if file == "/dev/null" {
			continue
		}
		verdict, err := namedFile(file)
		if err != nil {
			return global, err
		}
		if verdict == "missing" {
			continue
		}
		if verdict != "ok" {
			return globalConfig{unusual: verdict}, nil
		}
		facts, err := readConfig(file)
		if err != nil {
			return global, err
		}
		if facts.unusual != "" {
			return globalConfig{unusual: facts.unusual}, nil
		}
		if facts.includes {
			return globalConfig{unusual: DisplayBytes(file) + " includes other files, which are not read"}, nil
		}
		if facts.excludesFile != nil {
			global.excludesFile = facts.excludesFile
		}
	}
	return global, nil
}

// excludesFileOf is the excludes file Git would read, checked; or why it is
// unusual.
func excludesFileOf(e clientctx.Env, value *string) (path, unusual string, err error) {
	home, err := clientctx.HomeDir(e)
	if err != nil {
		return "", "", err
	}
	switch {
	case value == nil:
		xdg, _ := getenv(e, "XDG_CONFIG_HOME")
		if xdg == "" {
			xdg = filepath.Join(home, ".config")
		}
		path = filepath.Join(xdg, "git", "ignore")
	case strings.HasPrefix(*value, "~/"):
		path = filepath.Join(home, (*value)[2:])
	case strings.HasPrefix(*value, "/"):
		path = *value
	default:
		return "", "core.excludesFile " + termtext.DisplayPath(*value) + " is not an absolute path", nil
	}
	verdict, err := namedFile(path)
	if err != nil {
		return "", "", err
	}
	if verdict != "missing" && verdict != "ok" {
		return "", "core.excludesFile: " + verdict, nil
	}
	return path, "", nil
}

// repositoryCheck is why Git must not run for this repository, or the
// excludes file to give it. Unusual: a file Git opens that is a link or has
// another name, an alternate object store, an include or core.worktree in
// the repository's configuration, or an excludes file that could be a
// secret copy.
func repositoryCheck(e clientctx.Env, repo *repository, global globalConfig) (excludesFile, unusual string, err error) {
	if global.unusual != "" {
		return "", "the global Git configuration: " + global.unusual, nil
	}
	config := child(repo.commonDir, "config")
	worktreeConfig := child(repo.gitDir, "config.worktree")
	for _, file := range []string{child(repo.gitDir, "HEAD"), config} {
		if verdict := plainFile(file); verdict != "ok" {
			if verdict == "missing" {
				return "", DisplayBytes(file) + " is missing", nil
			}
			return "", verdict, nil
		}
	}
	for _, file := range []string{worktreeConfig, child(child(repo.commonDir, "info"), "exclude")} {
		if verdict := plainFile(file); verdict != "ok" && verdict != "missing" {
			return "", verdict, nil
		}
	}
	alternates := child(repo.commonDir, "objects/info/alternates")
	if _, err := os.Lstat(alternates); err == nil {
		return "", "the repository uses another object store (" + DisplayBytes(alternates) + ")", nil
	}
	excludes := global.excludesFile
	for _, file := range []string{config, worktreeConfig} {
		if plainFile(file) == "missing" {
			continue
		}
		facts, err := readConfig(file)
		if err != nil {
			return "", "", err
		}
		if facts.unusual != "" {
			return "", facts.unusual, nil
		}
		if facts.includes {
			return "", DisplayBytes(file) + " includes other files, which Git would read", nil
		}
		if facts.excludesFile != nil {
			excludes = facts.excludesFile
		}
	}
	return excludesFileOf(e, excludes)
}

func nulList(b []byte) []string {
	var out []string
	for _, part := range bytes.Split(b, []byte{0}) {
		if len(part) > 0 {
			out = append(out, string(part))
		}
	}
	return out
}

// gitignoreCheck is why Git must not read the `.gitignore` files that apply
// to these files (one in each directory from the top of the working tree
// down to each file's directory): one is a link, has another name, or is
// not a regular file. Git opens them without following a symbolic link,
// but a hard link or a FIFO would still be read.
func gitignoreCheck(top string, prefix int, files []*File) string {
	seen := map[string]bool{}
	for _, f := range files {
		rel := f.abs[prefix:]
		dir, at := top, 0
		for {
			if !seen[dir] {
				seen[dir] = true
				if verdict := plainFile(child(dir, ".gitignore")); verdict != "missing" && verdict != "ok" {
					return verdict
				}
			}
			slash := strings.IndexByte(rel[at:], sep[0])
			if slash < 0 {
				break
			}
			dir = child(top, rel[:at+slash])
			at += slash + 1
		}
	}
	return ""
}

// gitStates sets each file's Git state, with one `git check-ignore
// --no-index` per repository.
func gitStates(e clientctx.Env, w *walk) {
	unknown := func(files []*File, reason string) {
		for _, f := range files {
			f.Git, f.GitError = Unknown, reason
		}
	}
	// Each file belongs to the deepest directory above it that may be a repository's top.
	dirs := slices.Clone(w.repoDirs)
	slices.SortStableFunc(dirs, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
	type group struct {
		dir   string
		files []*File
	}
	var groups []*group
	byDir := map[string]*group{}
	for i := range w.files {
		file := &w.files[i]
		dir := w.root
		for _, d := range dirs {
			if isBelow(file.abs, d) {
				dir = d
				break
			}
		}
		if g := byDir[dir]; g != nil {
			g.files = append(g.files, file)
			continue
		}
		g := &group{dir: dir, files: []*File{file}}
		byDir[dir] = g
		groups = append(groups, g)
	}
	var global *globalConfig
	for _, g := range groups {
		if err := checkGroup(e, g.dir, g.files, &global); err != nil {
			reason := "the repository could not be checked (" + reasonOf(err) + ")"
			if f, ok := errors.AsType[*failure](err); ok {
				reason = f.message
			}
			unknown(g.files, reason)
		}
	}
}

// checkGroup asks Git about the files of one repository.
func checkGroup(e clientctx.Env, dir string, files []*File, global **globalConfig) error {
	unknown := func(reason string) {
		for _, f := range files {
			f.Git, f.GitError = Unknown, reason
		}
	}
	repo, unusual, err := findRepository(dir)
	if err != nil {
		return err
	}
	if unusual != "" {
		unknown(unusual)
		return nil
	}
	if repo == nil {
		for _, f := range files {
			f.Git = NoRepository
		}
		return nil
	}
	if *global == nil {
		g, err := readGlobalConfig(e)
		if err != nil {
			return err
		}
		*global = &g
	}
	excludesFile, unusual, err := repositoryCheck(e, repo, **global)
	if err != nil {
		return err
	}
	if unusual != "" {
		unknown(unusual)
		return nil
	}
	top, topOK := utf8OrNull(repo.top)
	parent := parentOf(repo.top)
	if parent == "" {
		parent = sep
	}
	ceiling, ceilingOK := utf8OrNull(parent)
	if !topOK || !ceilingOK {
		unknown("the repository's directory name is not UTF-8")
		return nil
	}
	prefix := len(repo.top)
	if !strings.HasSuffix(repo.top, sep) {
		prefix++
	}
	if verdict := gitignoreCheck(repo.top, prefix, files); verdict != "" {
		unknown(verdict)
		return nil
	}
	var input []byte
	for _, f := range files {
		input = append(append(input, f.abs[prefix:]...), 0)
	}
	// Git looks for the repository from its top and no higher; --no-index reads no index.
	code, out, err := runGit(top, []string{"-c", "core.excludesFile=" + excludesFile, "check-ignore", "--no-index", "-z", "--stdin"},
		gitEnv("GIT_CEILING_DIRECTORIES="+ceiling), input)
	if err != nil {
		return err
	}
	// Exit 0: some paths are ignored; 1: none is.
	if code != 0 && code != 1 {
		// Git's message is not shown: only that it refused or failed, and its exit status.
		unknown("Git refused or failed (exit status " + strconv.Itoa(code) + ")")
		return nil
	}
	ignored := map[string]bool{}
	for _, p := range nulList(out) {
		ignored[p] = true
	}
	for _, f := range files {
		if ignored[f.abs[prefix:]] {
			f.Git = Ignored
		} else {
			f.Git = NotIgnored
		}
	}
	return nil
}

// Find walks dir from cwd, then asks Git about what was found (findCopies).
func Find(e clientctx.Env, dir, cwd string, limits Limits) (*Report, error) {
	w, err := walkForCopies(dir, cwd, limits)
	if err != nil {
		return nil, err
	}
	if len(w.files) > 0 {
		gitStates(e, w)
	}
	return &Report{Root: w.root, Files: w.files, NotSearched: w.notSearched, EntriesChecked: w.entriesChecked, Stopped: w.stopped}, nil
}

// ExitCode is findFilesExitCode: 1 when a file was found; 2 when none was
// but the search was incomplete; 0 otherwise.
func (r *Report) ExitCode() int {
	if len(r.Files) > 0 {
		return 1
	}
	if r.Stopped || len(r.NotSearched) > 0 {
		return 2
	}
	return 0
}

var gitText = map[string]string{
	NotIgnored:   "not ignored by Git, so it can be committed",
	Ignored:      "ignored by Git",
	NoRepository: "not in a Git repository",
	Unknown:      "Git status unknown",
}

// Human is formatFindFilesHuman: the report's lines.
func (r *Report) Human(limits Limits) []string {
	var lines []string
	if len(r.Files) > 0 {
		lines = append(lines, "Files that look like copies of secrets, by name, under "+DisplayBytes(r.Root)+":")
		for _, f := range r.Files {
			git := gitText[f.Git]
			if f.Git == Unknown && f.GitError != "" {
				git = gitText[Unknown] + ": " + termtext.DisplayPath(f.GitError)
			}
			link := ""
			if f.Symlink {
				link = "a symbolic link, not followed; "
			}
			lines = append(lines, "  "+DisplayBytes(f.Path)+": "+link+git)
		}
	}
	if len(r.NotSearched) > 0 {
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, "Not searched ("+strconv.Itoa(len(r.NotSearched))+"), so not known to be clean:")
		for _, n := range r.NotSearched {
			lines = append(lines, "  "+DisplayBytes(n.Path)+": "+n.Reason)
		}
	}
	if r.Stopped {
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, "The search stopped after "+strconv.Itoa(limits.MaxEntries)+" entries; what follows was not searched. Search a smaller directory.")
	}
	if len(lines) > 0 {
		lines = append(lines, "")
	}
	count := func(state string) int {
		n := 0
		for _, f := range r.Files {
			if f.Git == state {
				n++
			}
		}
		return n
	}
	checked := strconv.Itoa(r.EntriesChecked) + " entries checked by name, without reading their contents."
	if len(r.Files) == 0 {
		return append(lines, "varlatch scan: no file looks like a copy of a secret; "+checked)
	}
	notes := ""
	if n := count(NotIgnored); n > 0 {
		notes = " (" + strconv.Itoa(n) + " not ignored by Git)"
	}
	lines = append(lines, "varlatch scan: "+strconv.Itoa(len(r.Files))+" file(s) look like copies of secrets"+notes+"; "+checked)
	if slices.ContainsFunc(r.Files, func(f File) bool { return f.Kind == "dotenv" }) {
		lines = append(lines, "Move a dotenv file into Varlatch and delete it: varlatch import <file> --delete-source")
	}
	if slices.ContainsFunc(r.Files, func(f File) bool { return f.Kind == "key" }) {
		lines = append(lines, "Store a key or certificate as one Secret, then delete the file: varlatch values set <ITEM> --from-file <file>")
	}
	if count(NotIgnored) > 0 {
		lines = append(lines, "A file Git does not ignore may already be committed (git log --all -- <file>): rotate the secrets of one that was.")
	}
	return append(lines, "See docs/reference/secret-scanning.md and docs/reference/import.md.")
}

// JSON is findFilesJson: paths as UTF-8, with pathBase64 (rootBase64)
// holding the exact bytes of a name that is not UTF-8.
func (r *Report) JSON() jsjson.Object {
	doc := jsjson.Object{{Key: "version", Value: float64(ReportVersion)}, {Key: "mode", Value: "find-files"}, {Key: "exitCode", Value: float64(r.ExitCode())}}
	doc = jsonPath(doc, r.Root, "root")
	files := []any{}
	for _, f := range r.Files {
		o := jsonPath(nil, f.Path, "path")
		o = append(o, jsjson.Member{Key: "kind", Value: f.Kind}, jsjson.Member{Key: "symlink", Value: f.Symlink}, jsjson.Member{Key: "git", Value: f.Git})
		if f.GitError != "" {
			o = append(o, jsjson.Member{Key: "gitError", Value: f.GitError})
		}
		files = append(files, o)
	}
	notSearched := []any{}
	for _, n := range r.NotSearched {
		notSearched = append(notSearched, append(jsonPath(nil, n.Path, "path"), jsjson.Member{Key: "reason", Value: n.Reason}))
	}
	return append(doc,
		jsjson.Member{Key: "files", Value: files},
		jsjson.Member{Key: "notSearched", Value: notSearched},
		jsjson.Member{Key: "entriesChecked", Value: float64(r.EntriesChecked)},
		jsjson.Member{Key: "stopped", Value: r.Stopped},
	)
}
