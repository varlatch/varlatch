// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Hold is a restore's hold: the database is an archive's, so it may hold
// what was changed since (a cancelled deletion, a removed webhook, an old
// value a Sync Target would push). Until the host operator resumes the
// installation (`varlatchd admin restore resume`), varlatchd serves it, but
// its background work that delivers or destroys does not run. What a person
// or a client asks for is done.
//
// A completed restore leaves it (server/backups.Restore), durable before
// the restore's gate goes: the installation is never open without it.
type Hold struct {
	ArchiveID  string `json:"archiveId"`
	RestoredAt string `json:"restoredAt"`
}

// HoldFile is the hold's file in the data directory.
const HoldFile = "restore-hold.json"

// ErrHoldUnreadable keeps the installation held: a hold that cannot be
// read, or is not a file of root's or the data directory's owner, is never
// taken for none.
var ErrHoldUnreadable = &Error{"The restore hold is unreadable; the installation stays held"}

// maxHold is more than a hold's file holds.
const maxHold = 64 << 10

// ReadHold reads the hold, nil when there is none. Whatever else has its
// name (a link, dangling or not, a pipe, a directory, another user's file)
// is ErrHoldUnreadable: it is neither followed nor waited for.
func ReadHold(dir string) (*Hold, error) {
	path := filepath.Join(dir, HoldFile)
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, ErrHoldUnreadable
	}
	f, err := openHold(path)
	if err != nil {
		return nil, ErrHoldUnreadable
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !holdOwned(dir, info) {
		return nil, ErrHoldUnreadable
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxHold))
	var h Hold
	if err != nil || json.Unmarshal(raw, &h) != nil || h.ArchiveID == "" {
		return nil, ErrHoldUnreadable
	}
	return &h, nil
}

// WriteHold leaves h in dir, durably, in place of one that is there.
func WriteHold(dir string, h Hold) error {
	return DurableJSON(filepath.Join(dir, HoldFile), h, false)
}

// RemoveHold removes what has the hold's name in dir, durably, whatever it
// is (a directory only when it is empty), and says what it was: "" when
// there was nothing.
func RemoveHold(dir string) (string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	info, err := root.Lstat(HoldFile)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	what := "a file that is neither a regular file nor a link"
	switch m := info.Mode(); {
	case m.IsRegular():
		what = "the hold's file"
	case m&fs.ModeSymlink != 0:
		what = "a symbolic link"
	case m&fs.ModeNamedPipe != 0:
		what = "a named pipe"
	case m.IsDir():
		what = "a directory"
	}
	if err := root.Remove(HoldFile); err != nil {
		return "", err
	}
	return what, syncDir(dir)
}
