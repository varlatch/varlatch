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
// symbolic link; "" when there is none (or the path stops existing).
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
		if info.Mode()&fs.ModeSymlink != 0 {
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

// write replaces rel with data: a temporary file in the same directory,
// synced, then renamed over it, with the replaced file's mode, or the
// default mode less the umask for a new one. A file with more than one
// name (a hard link, such as a CLAUDE.md that is AGENTS.md) is written in
// place, so that every name keeps seeing it.
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
	info, err := w.root.Lstat(rel)
	existing := err == nil && info.Mode().IsRegular()
	if existing && linkCount(info) > 1 {
		f, err := w.root.OpenFile(rel, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			return err
		}
		if syncWrites {
			if err := f.Sync(); err != nil {
				f.Close()
				return err
			}
		}
		return f.Close()
	}
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(rel), "."+filepath.Base(rel)+".varlatch-"+hex.EncodeToString(suffix[:])+".tmp")
	f, err := w.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil && syncWrites {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil && existing {
		err = w.root.Chmod(tmp, info.Mode().Perm())
	}
	if err == nil {
		err = w.root.Rename(tmp, rel)
	}
	if err != nil {
		w.root.Remove(tmp)
	}
	return err
}

// remove removes the file rel, if it is there.
func (w *writer) remove(rel string) error {
	if err := checkBelow(w.path, filepath.Dir(rel)); err != nil {
		return err
	}
	if err := w.open(); err != nil {
		return err
	}
	if err := w.root.Remove(rel); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
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
