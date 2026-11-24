// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"path/filepath"
	"slices"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/preread"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/tailnet"
)

// A host command run as root works in the data directory as its owner, the
// user varlatchd runs as: the directory is that user's, so what root wrote
// there by name could be led elsewhere by a link, and would be root's
// afterwards, where varlatchd could not open it. So `varlatchd admin`, once
// it has its configuration, opens what only root may read (keepForOwner),
// becomes the owner for good (becomeOwner), and then runs.
//
// Not so for the commands that do not work in the data directory, or work
// for root: kek (key files of the operator's), config check, doctor (which
// reads root's files and writes nothing), outbound check, tailnet reaches
// (a probe in a temporary directory), and migrate, which writes root's key
// files and reads its own files elsewhere: what it makes in the data
// directory is given to the owner when it ends (giveDataFiles).

// dataFiles are the data directory's files a varlatchd cannot start
// without reading or writing.
var dataFiles = []string{LockFile, config.DatabaseFile, config.DatabaseFile + "-wal", config.DatabaseFile + "-shm", backup.GateFile, JournalFile,
	tailnet.PinFile, tailnet.HoldFile, tailnet.ListenersFile, TakeoverFile, IssuanceFile}

// staysRoot are the commands that keep root's identity.
func staysRoot(sub string, rest []string) bool {
	return slices.Contains([]string{"kek", "config", "doctor", "outbound", "migrate", "conformance-probe", "conformance-fixture"}, sub) ||
		sub == "tailnet" && len(rest) > 0 && rest[0] == "reaches"
}

// keepForOwner keeps what a command reads outside the data directory open:
// the two keys, a backup's destination, a restore's archive and key, the
// tailnet's key and a name takeover's authority. One that cannot be opened
// is refused where it is used, as it would have been.
func keepForOwner(cfg *config.Config, sub string, rest []string, uid, gid int) {
	preread.Keep(cfg.RootKEKFile, nil)
	preread.Keep(cfg.BackupKeyFile, nil)
	switch sub {
	case "schema":
		if _, _, database, _ := schemaArguments(rest); database != "" {
			// An upgrade's varlatch copied it as root.
			giveFiles(uid, gid, database, database+"-wal", database+"-shm")
		}
	case "backup":
		if rest[0] == "restore" {
			args, _ := restoreArgs(rest[1:])
			preread.Keep(args["--in"], nil)
			preread.Keep(args["--backup-key-file"], nil)
			return
		}
		if cfg.BackupDestinationsFile == "" {
			return
		}
		preread.Keep(cfg.BackupDestinationsFile, nil)
		if d, err := backup.ReadDestination(cfg.BackupDestinationsFile, cfg.BackupDestination); err == nil {
			credentials := d.WriteCredentialsFile
			if !filepath.IsAbs(credentials) {
				credentials = filepath.Join(filepath.Dir(cfg.BackupDestinationsFile), credentials)
			}
			preread.Keep(credentials, nil)
		}
	case "tailnet":
		if cfg.Tailnet != nil {
			preread.Keep(cfg.Tailnet.AuthKeyFile, nil)
		}
		c, _ := nodeArgs(rest)
		preread.Keep(c.oauthFile, openSecretFile)
		preread.Keep(c.headscaleKeyFile, openSecretFile)
	}
}
