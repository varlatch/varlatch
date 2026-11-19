// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// File helpers for `varlatch agents install` (ADR-0043 Decisions 7 and 8),
// a port of apps/cli/src/agents/files.ts: exact additions that removing
// takes back byte for byte, and reads that never turn a file the CLI must
// not rewrite into text.

// state is what a read found: readText's string, null or undefined.
type state int

const (
	missing state = iota // null: nothing there
	isText               // a UTF-8 text file
	notText              // undefined: something other than a UTF-8 text file
)

// content is a file's text as readText reads it.
type content struct {
	text  string
	state state
}

// desired is the content a file should have; absent (nil) means no file.
type desired = *string

func ptr(s string) *string { return &s }

func eolOf(text string) string {
	if strings.Contains(text, "\r\n") {
		return "\r\n"
	}
	return "\n"
}

// appendOwned is files.ts's appendOwned: a new file is the addition alone;
// an existing file, even an empty one, keeps every byte and gains one line
// break and then the addition.
func appendOwned(current desired, owned string) string {
	if current == nil {
		return owned
	}
	return *current + eolOf(*current) + owned
}

// ownedEol is the line ending of an addition at [start, end): the one
// inside it, else the one that ends it.
func ownedEol(text string, start, end int) string {
	span := text[start:end]
	if strings.Contains(span, "\r\n") {
		return "\r\n"
	}
	if strings.Contains(span, "\n") {
		return "\n"
	}
	if strings.HasPrefix(text[end:], "\r\n") {
		return "\r\n"
	}
	return "\n"
}

// withoutOwned is the file without the addition at [start, end) and the
// line break that ends it; nil when nothing else was in the file.
func withoutOwned(text string, start, end int) desired {
	eol := ownedEol(text, start, end)
	before := text[:start]
	after := strings.TrimPrefix(text[end:], eol)
	if after != "" {
		return ptr(before + after)
	}
	if before == "" {
		return nil
	}
	return ptr(strings.TrimSuffix(before, eol))
}

// readBytes is a file's bytes; missing when nothing is there (or it cannot
// be looked at); notText when something other than a file is.
func readBytes(path string) ([]byte, state, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, missing, nil
	}
	if !info.Mode().IsRegular() {
		return nil, notText, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, missing, err
	}
	return data, isText, nil
}

// readText is a file's text; notText when the path is not a UTF-8 text
// file, which the CLI never edits. A byte order mark is kept.
func readText(path string) (content, error) {
	data, st, err := readBytes(path)
	if err != nil || st != isText {
		return content{state: st}, err
	}
	if !utf8.Valid(data) {
		return content{state: notText}, nil
	}
	return content{text: string(data), state: isText}, nil
}

// isSymlink is whether path itself is a symbolic link.
func isSymlink(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&fs.ModeSymlink != 0
}

// exists is existsSync: something is there, following links.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// resolve is path.resolve of one absolute or relative path.
func resolve(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return abs
}

// realpath is fs.realpathSync.
func realpath(path string) (string, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	return resolve(real), nil
}

// resolvedPath is where path leads: its resolved path, or for a link to
// nothing, the path its text names.
func resolvedPath(path string) string {
	if real, err := realpath(path); err == nil {
		return real
	}
	if isSymlink(path) {
		if target, err := os.Readlink(path); err == nil {
			if filepath.IsAbs(target) {
				return filepath.Clean(target)
			}
			return resolve(filepath.Join(filepath.Dir(path), target))
		}
	}
	return resolve(path)
}

// sameFile is whether two paths are one file: the same inode, or, when one
// does not exist yet, the same resolved path.
func sameFile(a, b string) bool {
	x, errA := os.Stat(a)
	y, errB := os.Stat(b)
	if errA == nil && errB == nil {
		return os.SameFile(x, y)
	}
	return resolvedPath(a) == resolvedPath(b)
}

// relative is path.relative: "" for the same path.
func relative(from, to string) string {
	rel, err := filepath.Rel(resolve(from), resolve(to))
	if err != nil {
		return resolve(to)
	}
	if rel == "." {
		return ""
	}
	return rel
}

// isInside is whether path lies inside the directory root; both resolved.
func isInside(root, path string) bool {
	rel := relative(root, path)
	return rel != "" && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)
}

// filesUnder is every entry under dir that is not a directory (a link to
// a directory included), in readdir's order, recursively.
// readDir is a directory's entries in the order readdirSync gives them:
// libuv sorts the names (strcmp) on Linux and macOS, and gives the file
// system's own order on Windows (NTFS keeps names in its case-insensitive
// order, so references/ comes before SKILL.md there). os.ReadDir always
// sorts by bytes; on Windows the entries are read as the system lists them
// instead, so every list built from a walk comes out in the TypeScript CLI's
// order on each platform.
func readDir(dir string) ([]os.DirEntry, error) {
	if runtime.GOOS != "windows" {
		return os.ReadDir(dir)
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.ReadDir(-1)
}

func filesUnder(dir string) ([]string, error) {
	if !exists(dir) {
		return nil, nil
	}
	entries, err := readDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			more, err := filesUnder(path)
			if err != nil {
				return nil, err
			}
			out = append(out, more...)
		} else {
			out = append(out, path)
		}
	}
	return out, nil
}

// parseJSON is JSON.parse over text the CLI read: a byte order mark is not
// JSON whitespace, so it makes the text unreadable.
func parseJSON(text string) (any, bool) {
	if strings.HasPrefix(text, "\uFEFF") {
		return nil, false
	}
	v, err := jsjson.Parse([]byte(text))
	return v, err == nil
}

// stringify2 is JSON.stringify(v, null, 2).
func stringify2(v any) string { return string(jsjson.StringifyIndent(v, 2)) }

// isCanonicalJSON is whether raw is what JSON.stringify(parsed, null, 2)
// writes, with or without a final line break.
func isCanonicalJSON(raw string, parsed any) bool {
	canonical := stringify2(parsed)
	return raw == canonical || raw == canonical+"\n"
}

// staging is files.ts's Staging: the edits one run plans, on top of each
// other; nothing touches the disk until the run applies them.
type staging struct {
	order  []string
	staged map[string]desired
}

func newStaging() *staging { return &staging{staged: map[string]desired{}} }

func (s *staging) read(path string) (content, error) {
	if d, ok := s.staged[path]; ok {
		if d == nil {
			return content{state: missing}, nil
		}
		return content{text: *d, state: isText}, nil
	}
	return readText(path)
}

func (s *staging) write(path string, d desired) {
	if _, ok := s.staged[path]; !ok {
		s.order = append(s.order, path)
	}
	s.staged[path] = d
}

func (s *staging) entries() []planned {
	out := make([]planned, 0, len(s.order))
	for _, path := range s.order {
		out = append(out, planned{path: path, desired: s.staged[path]})
	}
	return out
}

// planned is one file the command manages, with the content it should
// have (nil: absent).
type planned struct {
	path    string
	desired desired
}

// sameBytes is Buffer.equals.
func sameBytes(a []byte, b string) bool { return bytes.Equal(a, []byte(b)) }
