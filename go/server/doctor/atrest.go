// SPDX-License-Identifier: AGPL-3.0-or-later

package doctor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/varlatch/varlatch/go/lib/backup"
)

// What lies on the host's disk besides the keys (docs/THREAT-MODEL.md, at
// rest): the tailnet's join key, and the bucket key backups upload with.

// pinFile is the tailnet pin's name in the data directory (tailnet.PinFile,
// pinned by a test: doctor does not import tsnet).
const pinFile = "tailnet-pin.json"

// tailnetJoined is whether the node in dataDir has joined a tailnet: its
// pin is taken (tailnet.Pin, not enrolling). A node with state of its own
// but no pin (one never pinned) counts as joined too: it never enrols
// again with the key.
func tailnetJoined(dataDir string) (joined bool, err error) {
	b, err := os.ReadFile(filepath.Join(dataDir, pinFile))
	if errors.Is(err, fs.ErrNotExist) {
		_, err := os.Stat(filepath.Join(dataDir, "tailnet", "tailscaled.state"))
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return err == nil, err
	}
	if err != nil {
		return false, err
	}
	var p struct {
		Suffix    string `json:"suffix"`
		Enrolling bool   `json:"enrolling"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return false, err
	}
	return !p.Enrolling && p.Suffix != "", nil
}

// tailnetAuthKey: the auth key enrols the node once; once it has joined,
// the copy on disk only lets whoever reads it join other nodes to the
// tailnet while the key is valid. Advisory: a migration, its rollback, or
// a name takeover on this host still needs it until it ends.
func tailnetAuthKey(in Inputs) Check {
	c := Check{ID: "tailnet.auth-key", Title: "Tailnet auth key on disk", Class: Advisory}
	path := in.Config.Tailnet.AuthKeyFile
	if path == "" {
		c.Status, c.Detail = Pass, "no auth key file is configured: the node keeps its identity in its tailnet/ state"
		return c
	}
	info, err := in.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		c.Status, c.Detail = Pass, path+" is not on disk: the node keeps its identity in its tailnet/ state"
		return c
	case credential(path) && errors.Is(err, fs.ErrPermission):
		c.Status, c.Detail, c.Remedy = Unknown, "the auth key is a systemd credential, visible to the unit (and root) only", "Run doctor as root: sudo varlatch doctor"
		return c
	case err != nil:
		return statFailure(c, "the auth key file", path, err)
	}
	if !info.Mode().IsRegular() {
		c.Status, c.Detail, c.Remedy = Fail, path+" is not a regular file", "Remove it, and set tailnet_auth_key_file to the key's file only while the node enrols"
		return c
	}
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		c.Status = Fail
		c.Detail = fmt.Sprintf("the auth key file %s is readable by others (mode %04o): anyone on this host can join a node to the tailnet with it", path, perm)
		c.Remedy = "chmod 0640 " + path + " (root and the service's group), or remove it once the node has joined"
		return c
	}
	joined, err := tailnetJoined(in.Config.DataDir)
	switch {
	case errors.Is(err, fs.ErrPermission):
		c.Status, c.Detail, c.Remedy = Unknown, "whether the node has joined cannot be read by this user", "Run doctor as root: sudo varlatch doctor"
	case err != nil:
		c.Status, c.Detail = Unknown, "whether the node has joined cannot be read: "+oneLine(err.Error())
	case !joined:
		c.Status, c.Detail = Pass, path+" stays until the node has joined its tailnet: it enrols with it"
	default:
		c.Status = Fail
		c.Detail = "the node has joined its tailnet, and its auth key is still on disk at " + path + ": while the key is valid, anyone with a copy of this disk can join a node to the tailnet with the node's tags"
		c.Remedy = "Once no migration, rollback or name takeover on this host still needs it: sudo rm " + path +
			" (varlatchd reads it only to enrol; tailnet_auth_key_file may stay, for a re-join), and revoke the key in the tailnet's admin console, or let it expire"
	}
	return c
}

// bucketKeyFile: the bucket key (writeCredentialsFile) is read by the
// service's user, so the service's group may read it and nobody else.
func bucketKeyFile(in Inputs) Check {
	c := Check{ID: "files.bucket-key", Title: "Bucket key file", Class: Mandatory}
	d, err := backup.ReadDestination(in.Config.BackupDestinationsFile, in.Config.BackupDestination)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			c.Status, c.Detail, c.Remedy = Unknown, "the destinations file "+in.Config.BackupDestinationsFile+" cannot be read by this user", "Run doctor as root: sudo varlatch doctor"
			return c
		}
		c.Status, c.Detail = Unknown, "the destination cannot be read: "+oneLine(err.Error())
		return c
	}
	path := d.WriteCredentialsFile
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(in.Config.BackupDestinationsFile), path)
	}
	info, err := in.Stat(path)
	if err != nil {
		c = statFailure(c, "the bucket key file", path, err)
		if c.Status == Fail {
			c.Remedy = "Write the bucket's key there (docs/operations/backup.md), or set writeCredentialsFile to where it is"
		}
		return c
	}
	// The service's group is the data directory's (systemd makes it the
	// unit's user's and group's; the image's is its user's).
	gid := -1
	if dir, err := in.Stat(in.Config.DataDir); err == nil {
		if g, ok := backup.FileGID(dir); ok {
			gid = g
		}
	}
	if why := backup.CredentialsModeProblem(path, info, gid); why != "" {
		c.Status, c.Detail = Fail, why
		c.Remedy = "chown root:<the service's group> " + path + " && chmod 0640 " + path + " (on a systemd host the group is varlatch; in the container image, mode 0400 owned by uid 65532)"
		return c
	}
	c.Status, c.Detail = Pass, fmt.Sprintf("%s (mode %04o)", path, info.Mode().Perm())
	return c
}

// bucketKeyRead: a bucket key that may read lets whoever has this host's
// disk, which holds the backup key too, download and open every archive
// the bucket keeps, older ones included (ADR-0033 Decision 8). Advisory:
// a key that may read is the operator's choice (docs/operations/backup.md).
func bucketKeyRead(in Inputs) Check {
	c := Check{ID: "backups.bucket-key-read", Title: "Bucket key may only write", Class: Advisory}
	switch {
	case in.Live == nil:
		c.Status, c.Detail, c.Remedy = Unknown, notRunning, startIt
	case in.Live.BucketKeyReads == nil:
		c.Status, c.Detail = Unknown, in.Live.BucketKeyDetail
	case *in.Live.BucketKeyReads:
		c.Status = Fail
		c.Detail = "the bucket key may read archives (" + in.Live.BucketKeyDetail + "): with a copy of this host's disk, which holds the backup key too, every archive the bucket keeps can be downloaded and opened, older ones included"
		c.Remedy = "Give the server a key that may only write, and check archives from another machine with a read key (docs/operations/backup.md, Scoping destination credentials)"
	default:
		c.Status, c.Detail = Pass, in.Live.BucketKeyDetail
	}
	return c
}
