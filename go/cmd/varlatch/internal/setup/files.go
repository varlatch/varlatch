// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

// stagedName is a temporary name in path's own directory: a key is never
// written outside its target's directory.
func stagedName(path string) (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+hex.EncodeToString(b)+".tmp"), nil
}

// stagedFile is stagedName's name for one of the files setup writes in
// /etc/varlatch: what a run that ended mid-write can leave there.
var stagedFile = regexp.MustCompile(`^\.(root-kek|backup-key|setup\.json)\.[0-9a-f]{12}\.tmp$`)

// isStagedName says whether name is such a leftover.
func isStagedName(name string) bool { return stagedFile.MatchString(name) }

// writeStaged writes data to path (a new file, mode), synced.
func writeStaged(path string, data []byte, mode fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|noFollow, mode)
	if err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// createPrivate puts data at path (0600) only if nothing is there: written
// under a temporary name in the same directory, synced, then linked into
// place (a link never replaces a file), the directory synced.
func createPrivate(path string, data []byte) error {
	tmp, err := stagedName(path)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// replacePrivate puts data at path (0600), replacing what is there, the
// same way (a rename).
func replacePrivate(path string, data []byte) error {
	tmp, err := stagedName(path)
	if err != nil {
		return err
	}
	if err := writeStaged(tmp, data, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

// copyPrivate writes a key's copy to the operator's file: created 0600,
// never over another file; one that already holds this very key is left
// as it is (a rerun).
func copyPrivate(path string, key []byte) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("setup: %s: name a key's copy with an absolute path", path)
	}
	data := append(bytes.TrimSpace(key), '\n')
	defer clear(data)
	err := createPrivate(path, data)
	if !errors.Is(err, fs.ErrExist) {
		return err
	}
	got, rerr := os.ReadFile(path)
	defer clear(got)
	if rerr == nil && bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(key)) {
		return nil
	}
	return fmt.Errorf("setup: %s already exists and does not hold this key: name a new file; nothing was written there", path)
}

// syncDir makes a directory's entries durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		return err
	}
	return nil
}
