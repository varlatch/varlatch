// SPDX-License-Identifier: AGPL-3.0-or-later

package backups

import (
	"context"
	"os"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/preread"
	"github.com/varlatch/varlatch/go/server/ids"
)

// KeyAccess is what doctor's advisory check reports of the bucket key
// (ADR-0033 Decision 8: the server holds no standing read credentials):
// Reads is whether it may read archives, nil when that is not known, and
// Detail what was asked and answered.
type KeyAccess struct {
	Reads  *bool  `json:"reads,omitempty"`
	Detail string `json:"detail"`
}

// KeyAccess asks the destination, without reading any archive's content:
// a HEAD of the newest archive delivered there (metadata back: the key
// reads; refused: it does not), or, when none was delivered or it is gone,
// a HEAD of a name that was never written (no such object: the key reads
// and lists; refused says nothing, since a key that reads without listing
// is refused too).
func (s *Service) KeyAccess(ctx context.Context) KeyAccess {
	client, d, err := s.client()
	if err != nil {
		return KeyAccess{Detail: "the destination's key cannot be used: " + err.Error()}
	}
	yes, no := true, false
	st, err := backup.ReadStatus(s.dir, s.o.Now())
	if err == nil {
		for _, a := range st.Archives { // newest first
			if a.Delivery == nil || a.Delivery.Destination != s.o.Config.BackupDestination {
				continue
			}
			key, err := backup.ObjectKey(d, a.ArchiveID)
			if err != nil {
				break
			}
			access, err := client.ReadAccess(ctx, key)
			switch {
			case err != nil:
				return KeyAccess{Detail: "asking the destination failed" + backup.StorageErrorDetail(err)}
			case access == backup.Readable:
				return KeyAccess{Reads: &yes, Detail: "the key read the metadata of " + key}
			case access == backup.ReadRefused:
				return KeyAccess{Reads: &no, Detail: "the key may not read " + key}
			}
			break // not there: the name that was never written says more
		}
	}
	key := backup.BucketTestKey(d, ids.UUID()) + ".absent"
	access, err := client.ReadAccess(ctx, key)
	switch {
	case err != nil:
		return KeyAccess{Detail: "asking the destination failed" + backup.StorageErrorDetail(err)}
	case access == backup.NotThere:
		return KeyAccess{Reads: &yes, Detail: "the destination told the key that a name never written is not there, which it tells only a key that may read"}
	case access == backup.Readable:
		return KeyAccess{Reads: &yes, Detail: "the key read the metadata of " + key}
	}
	return KeyAccess{Detail: "no archive delivered there to ask about, and the destination refused to say whether a name never written is there"}
}

// credentialsWarning is what is wrong with the bucket key file's mode, ""
// when nothing is (backup.CredentialsModeProblem): said at each upload.
func credentialsWarning(path string) string {
	f, err := preread.Open(path)
	if err != nil {
		return "" // reading it says why
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return ""
	}
	return backup.CredentialsModeProblem(path, info, os.Getgid())
}
