// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// Hold is a restore's hold: the database is an archive's, so it may hold
// what was changed since (a cancelled deletion, a removed webhook, an old
// value a Sync Target would push). Until the host operator resumes the
// installation (`varlatchd admin restore resume`), varlatchd serves it, but
// does nothing on its own that leaves the host or destroys.
//
// A completed restore leaves it (server/backups.Restore), durable before
// the restore's gate goes: the installation is never open without it.
type Hold struct {
	ArchiveID  string `json:"archiveId"`
	RestoredAt string `json:"restoredAt"`
}

// HoldFile is the hold's file in the data directory.
const HoldFile = "restore-hold.json"

// ErrHoldUnreadable keeps the installation held: a hold that cannot be read
// is never taken for none.
var ErrHoldUnreadable = &Error{"The restore hold is unreadable; the installation stays held"}

// ReadHold reads the hold, nil when there is none.
func ReadHold(dir string) (*Hold, error) {
	raw, err := os.ReadFile(filepath.Join(dir, HoldFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
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

// RemoveHold ends the hold, durably.
func RemoveHold(dir string) error {
	if err := os.Remove(filepath.Join(dir, HoldFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDir(dir)
}
