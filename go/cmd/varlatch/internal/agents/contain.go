// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Containment: install, check and remove never read, write or remove
// anything through a symbolic link below the scope's root (the project
// root, or the home directory). A directory on the way to a file the run
// would read, write, remove or prune that is a link refuses the whole
// run before anything is touched (78), and each write and removal checks
// again and goes through an os.Root opened at the scope's root, which
// cannot reach outside it. A link as the last component is left as it is
// (the human gets the edit), as before.

// linkBelow is the first component of rel, a path below root, that is a
// symbolic link (or a junction); "" when there is none (or the path stops existing).
func linkBelow(root, rel string) string {
	current := ""
	for _, part := range strings.Split(filepath.Clean(rel), string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(filepath.Join(root, current))
		if err != nil {
			return ""
		}
		// A Windows junction (or another reparse point) reads as irregular:
		// it leads elsewhere as a link does.
		if info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			return current
		}
	}
	return ""
}

func linkRefusal(rel string) error {
	return &Error{filepath.ToSlash(rel) + " is a symbolic link, so the CLI does not read, write or remove anything through it; " +
		"replace it with a directory, then run this again", false}
}

// checkBelow refuses a run when a directory on the way to rel is a link.
func checkBelow(root, rel string) error {
	if link := linkBelow(root, rel); link != "" {
		return linkRefusal(link)
	}
	return nil
}

// refuseBefore is the refusal of a run found before it touched anything:
// it names the link and says nothing changed. For --remove it also lists
// the skill files the run would have removed that are not behind a link,
// so the person can remove them by hand.
func refuseBefore(opts Options, link string) error {
	message := filepath.ToSlash(link) + " is a symbolic link, so the CLI does not read, write or remove anything through it; " +
		"nothing was changed. Replace it with a directory, then run this again"
	var files []string
	if opts.Mode == "remove" {
		for _, base := range skillBases {
			if linkBelow(opts.Root, base) != "" {
				continue
			}
			found, err := filesUnder(filepath.Join(opts.Root, base))
			if err != nil {
				continue
			}
			files = append(files, found...)
		}
	}
	if len(files) == 0 {
		return &Error{message, false}
	}
	return &Error{message + ", or remove these files by hand:\n  " + strings.Join(files, "\n  "), false}
}

// scopeDirs are the directories a run reads, writes, removes or prunes
// below its root.
func scopeDirs(opts Options) []string {
	dirs := slices.Clone(skillBases)
	remove := opts.Mode == "remove"
	if opts.Scope != "user" {
		dirs = append(dirs, ".claude", ".gemini")
	}
	if opts.Guardrails || remove {
		dirs = append(dirs, ".claude", ".codex")
	}
	if opts.MCP || remove {
		dirs = append(dirs, ".cursor", ".vscode", ".gemini", ".codex")
	}
	return dirs
}

// syncWrites: each replacement is synced before its rename. Only the
// vector tests, which write thousands of files, turn it off.
var syncWrites = true

// writer applies a run's changes through an os.Root at the scope's root.
type writer struct {
	path string
	root *os.Root
	// pairs: the run manages an AGENTS.md and the CLAUDE.md that is it (the
	// project scope), so such a pair is written and removed under both names.
	pairs bool
}

func (w *writer) open() error {
	if w.root != nil {
		return nil
	}
	// The TypeScript CLI creates a missing home directory with the files.
	if err := os.MkdirAll(w.path, 0o777); err != nil {
		return err
	}
	r, err := os.OpenRoot(w.path)
	if err != nil {
		return err
	}
	w.root = r
	return nil
}

func (w *writer) close() {
	if w.root != nil {
		w.root.Close()
	}
}

// aliasCandidates are the names install itself may give one file: an
// AGENTS.md and the CLAUDE.md that is that file.
var aliasCandidates = []string{"AGENTS.md", "CLAUDE.md", filepath.Join(".claude", "CLAUDE.md")}

// hardLinkRefusal refuses a file with a name the CLI does not manage: one
// it cannot see, or, outside a project's AGENTS.md/CLAUDE.md pair, any.
func hardLinkRefusal(rel string, nothingChanged bool) error {
	what := "the CLI stopped before changing it"
	if nothingChanged {
		what = "nothing was changed"
	}
	return &Error{filepath.ToSlash(rel) + " has another name (a hard link) the CLI does not manage, so " + what +
		"; replace it with a plain copy of itself, then run this again", false}
}

// aliases are the names of the regular file rel inside the root, rel
// first: every name the file has must be one of aliasCandidates found in
// the root, or there is a name the CLI cannot see (ok false). The count
// and the names are read one after the other, not as one snapshot: a name
// created after they are read is not seen. Such a name keeps the old
// content, because the file is replaced by renaming, never written in
// place, so nothing outside the root is ever changed.
//
// pairs: names are looked for only when the run manages such a pair (the
// project scope) and rel is one of aliasCandidates. Any other file with a
// second name (a skill file sharing its file with an AGENTS.md, say) has a
// name the CLI does not manage for it, so it is never expanded.
func aliases(root, rel string, pairs bool) (names []string, ok bool, err error) {
	at := func(name string) string { return filepath.Join(root, name) }
	f, err := os.Open(at(rel))
	if err != nil {
		return nil, false, err
	}
	n, err := linkCount(f)
	f.Close()
	if err != nil {
		return nil, false, err
	}
	names = []string{rel}
	if n <= 1 {
		return names, true, nil
	}
	if !pairs || !slices.Contains(aliasCandidates, rel) {
		return names, false, nil
	}
	info, err := os.Lstat(at(rel))
	if err != nil {
		return nil, false, err
	}
	for _, candidate := range aliasCandidates {
		if candidate == rel {
			continue
		}
		other, err := os.Lstat(at(candidate))
		if err == nil && other.Mode().IsRegular() && os.SameFile(info, other) {
			names = append(names, candidate)
		}
	}
	return names, uint64(len(names)) == n, nil
}

// checkHardLinks refuses, before anything changes, a file the run would
// change or remove that has a name the CLI does not manage.
func checkHardLinks(root, rel string, pairs bool) error {
	info, err := os.Lstat(filepath.Join(root, rel))
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	if _, ok, err := aliases(root, rel, pairs); err != nil || !ok {
		return hardLinkRefusal(rel, true)
	}
	return nil
}

// tempWritten, when set (only by tests), is called with each temporary
// file's name once its content is written and synced, before its mode is
// set.
var tempWritten func(root *os.Root, tmp string)

// temp writes data into a new temporary file next to rel, created 0600 so
// that nobody else can read it while it is written, synced, then given
// mode; its name, for a rename.
func (w *writer) temp(rel string, data []byte, mode os.FileMode) (string, error) {
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	tmp := filepath.Join(filepath.Dir(rel), "."+filepath.Base(rel)+".varlatch-"+hex.EncodeToString(suffix[:])+".tmp")
	f, err := w.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if err == nil && syncWrites {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil && tempWritten != nil {
		tempWritten(w.root, tmp)
	}
	if err == nil {
		err = w.root.Chmod(tmp, mode)
	}
	if err != nil {
		w.root.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// write replaces rel with data: a temporary file in the same directory,
// written while only its owner can read it, synced, given the replaced
// file's mode (or, for a new file, the default mode less the umask), then
// renamed over it. A file with several names is replaced only when every
// name is one install gives it (an AGENTS.md and the CLAUDE.md that is
// it): each name is renamed onto the new file, so they stay one file.
// One with a name the CLI does not manage is refused. A name created during
// the run may keep the old content (see aliases); nothing outside the
// root is ever changed. The names of a pair are renamed one at a time, not
// as one transaction: a crash between the renames leaves one name with the
// old content and the other with the new, each complete, never partly
// written. They are then two files, and running install again treats them
// so (CLAUDE.md gains the import of AGENTS.md).
func (w *writer) write(rel string, data []byte) error {
	if err := checkBelow(w.path, filepath.Dir(rel)); err != nil {
		return err
	}
	if err := w.open(); err != nil {
		return err
	}
	if dir := filepath.Dir(rel); dir != "." {
		if err := w.root.MkdirAll(dir, 0o777); err != nil {
			return err
		}
	}
	mode, names := newFileMode(), []string{rel}
	if info, err := w.root.Lstat(rel); err == nil && info.Mode().IsRegular() {
		mode = info.Mode().Perm()
		found, ok, err := aliases(w.path, rel, w.pairs)
		if err != nil || !ok {
			return hardLinkRefusal(rel, false)
		}
		names = found
	}
	tmp, err := w.temp(rel, data, mode)
	if err != nil {
		return err
	}
	if err := w.root.Rename(tmp, rel); err != nil {
		w.root.Remove(tmp)
		return err
	}
	for _, alias := range names[1:] {
		var suffix [6]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return err
		}
		link := filepath.Join(filepath.Dir(alias), "."+filepath.Base(alias)+".varlatch-"+hex.EncodeToString(suffix[:])+".tmp")
		if err := w.root.Link(rel, link); err != nil {
			return err
		}
		if err := w.root.Rename(link, alias); err != nil {
			w.root.Remove(link)
			return err
		}
	}
	return nil
}

// remove removes the file rel, if it is there. A project's AGENTS.md (or
// CLAUDE.md) whose every name is one install gives it goes under each of
// them, so no name keeps what was removed; it returns the other names
// removed. Any other file with a second name is refused (the run checked
// before changing anything; this checks again).
func (w *writer) remove(rel string) ([]string, error) {
	if err := checkBelow(w.path, filepath.Dir(rel)); err != nil {
		return nil, err
	}
	if err := w.open(); err != nil {
		return nil, err
	}
	names := []string{rel}
	if info, err := w.root.Lstat(rel); err == nil && info.Mode().IsRegular() {
		found, ok, err := aliases(w.path, rel, w.pairs)
		if err != nil || !ok {
			return nil, hardLinkRefusal(rel, false)
		}
		names = found
	}
	for _, name := range names {
		if err := checkBelow(w.path, filepath.Dir(name)); err != nil {
			return nil, err
		}
		if err := w.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	return names[1:], nil
}

// rmdir removes the empty directory rel, never a link.
func (w *writer) rmdir(rel string) error {
	if err := checkBelow(w.path, rel); err != nil {
		return err
	}
	if err := w.open(); err != nil {
		return err
	}
	info, err := w.root.Lstat(rel)
	if err != nil || !info.IsDir() {
		return err
	}
	return w.root.Remove(rel)
}
