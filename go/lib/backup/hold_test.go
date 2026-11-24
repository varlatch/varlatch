// SPDX-License-Identifier: Apache-2.0

//go:build unix

package backup

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// What has the hold's name and is no hold holds: a link (dangling or not),
// a pipe (never waited for), a directory, a file that is not one, another
// user's file. RemoveHold removes each by its name, never what a link
// names, and says what it was.
func TestHoldIsNeverMistaken(t *testing.T) {
	outside := t.TempDir()
	valid := filepath.Join(outside, HoldFile)
	if err := WriteHold(outside, Hold{ArchiveID: "archive-1", RestoredAt: "t"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, what string
		make       func(path string) error
	}{
		{"a dangling link", "a symbolic link", func(p string) error { return os.Symlink(filepath.Join(outside, "missing"), p) }},
		{"a link to a hold", "a symbolic link", func(p string) error { return os.Symlink(valid, p) }},
		{"a pipe", "a named pipe", func(p string) error { return syscall.Mkfifo(p, 0o600) }},
		{"a directory", "a directory", func(p string) error { return os.Mkdir(p, 0o700) }},
		{"an empty file", "the hold's file", func(p string) error { return os.WriteFile(p, nil, 0o600) }},
		{"no archive", "the hold's file", func(p string) error { return os.WriteFile(p, []byte(`{"restoredAt":"t"}`), 0o600) }},
		{"a file this user cannot read", "the hold's file", func(p string) error {
			if os.Geteuid() == 0 {
				// Root reads any file: another user's is refused instead.
				if err := os.WriteFile(p, []byte(`{"archiveId":"a","restoredAt":"t"}`), 0o644); err != nil {
					return err
				}
				return os.Chown(p, 65534, 65534)
			}
			return os.WriteFile(p, []byte(`{"archiveId":"a","restoredAt":"t"}`), 0)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := c.make(filepath.Join(dir, HoldFile)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				h, err := ReadHold(dir)
				if h != nil {
					t.Errorf("taken for a hold: %+v", h)
				}
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, ErrHoldUnreadable) {
					t.Errorf("taken for no hold: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("ReadHold waits")
			}
			if what, err := RemoveHold(dir); err != nil || what != c.what {
				t.Errorf("removed %q, %v", what, err)
			}
			if h, err := ReadHold(dir); h != nil || err != nil {
				t.Errorf("after: %+v %v", h, err)
			}
			if _, err := os.Stat(valid); err != nil {
				t.Errorf("what the link names: %v", err)
			}
		})
	}
	if h, err := ReadHold(outside); err != nil || h.ArchiveID != "archive-1" {
		t.Errorf("a hold: %+v %v", h, err)
	}
	if what, err := RemoveHold(t.TempDir()); what != "" || err != nil {
		t.Errorf("nothing to remove: %q %v", what, err)
	}
	// A directory with something in it is the operator's to look at.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, HoldFile, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := RemoveHold(dir); err == nil {
		t.Error("removed a directory that is not empty")
	}
}
