// SPDX-License-Identifier: Apache-2.0

package upgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

// fsys is the file system an upgrade works on: each change is one call,
// named to the tests' seams, so that a kill after each of them, and a power
// cut that loses what was not synced, can be tried.
type fsys struct {
	// after is called after each change, with its name (op:base); an error
	// ends the work there.
	after func(point string) error
	// trace is told each change and each sync; nil for none.
	trace func(fsEvent)
	// fault fails a write to a path (a full disk), or, for a directory's
	// path that ends in a separator, its sync; nil for none.
	fault func(path string) error
}

// fsEvent is one change or sync: op is mkdir, create, link, rename, remove,
// remove-all, sync (a file's content) or sync-dir (a directory's entries).
type fsEvent struct{ op, path, to string }

func (f fsys) did(op, path, to string) error {
	if f.trace != nil {
		f.trace(fsEvent{op, path, to})
	}
	if f.after == nil || op == "sync" || op == "sync-dir" {
		return nil
	}
	name := path
	if to != "" {
		name = to
	}
	return f.after(op + ":" + filepath.Base(name))
}

// mkdir makes a directory that is not there.
func (f fsys) mkdir(path string, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil {
		return err
	}
	return f.did("mkdir", path, "")
}

func (f fsys) link(from, to string) error {
	if err := os.Link(from, to); err != nil {
		return err
	}
	return f.did("link", from, to)
}

func (f fsys) rename(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	return f.did("rename", from, to)
}

// remove removes a file; one that is not there is nothing.
func (f fsys) remove(path string) error {
	err := os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return f.did("remove", path, "")
}

func (f fsys) removeAll(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	return f.did("remove-all", path, "")
}

// copy copies from's content into a new file to, synced, with mode, and
// returns the content's SHA-256. A file that is there is an error.
func (f fsys) copy(from, to string, mode os.FileMode) (string, error) {
	in, err := os.Open(from)
	if err != nil {
		return "", err
	}
	defer in.Close()
	return f.create(to, mode, in)
}

// create writes r into a new file path, synced, with mode, and returns the
// content's SHA-256.
func (f fsys) create(path string, mode os.FileMode, r io.Reader) (sum string, err error) {
	if f.fault != nil {
		if err := f.fault(path); err != nil {
			return "", err
		}
	}
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(out, h), r)
	if err == nil {
		err = out.Chmod(mode)
	}
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if err := f.did("create", path, ""); err != nil {
		return "", err
	}
	return hexSum(h), f.did("sync", path, "")
}

// sync makes a file's content durable.
func (f fsys) sync(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	err = file.Sync()
	if cerr := file.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return f.did("sync", path, "")
}

// syncDir makes a directory's entries durable: an error is one, but for a
// file system that does not sync directories at all.
func (f fsys) syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if f.fault != nil {
		if err := f.fault(dir + string(filepath.Separator)); err != nil {
			return fmt.Errorf("syncing the directory %s: %w", dir, err)
		}
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	if err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return fmt.Errorf("syncing the directory %s: %w", dir, err)
	}
	return f.did("sync-dir", dir, "")
}

func hexSum(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }

// fileSum is a regular file's SHA-256.
func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hexSum(h), nil
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
