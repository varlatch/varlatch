// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"os"
	"path/filepath"
	"slices"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/preread"
	"github.com/varlatch/varlatch/go/server/config"
)

// A host command run as root works in the data directory as its owner, the
// user varlatchd runs as: the directory is that user's, so what root wrote
// there by name could be led elsewhere by a link, and would be root's
// afterwards, where varlatchd could not open it. So `varlatchd admin`, once
// it has its configuration, opens what only root may read (keepForOwner),
// becomes the owner for good (becomeOwner), and then runs.

// staysRoot are the commands that keep root's identity: those that do not
// work in the data directory or write nothing there (kek, with the
// operator's key files; config check; doctor, which reads root's files;
// outbound check; tailnet reaches, a probe in a temporary directory; schema
// upgrade of a database elsewhere), and migrate keys, which writes root's
// key files and nothing in the data directory (runMigrate).
func staysRoot(cfg *config.Config, sub string, rest []string) bool {
	switch sub {
	case "kek", "config", "doctor", "outbound", "conformance-probe", "conformance-fixture":
		return true
	case "migrate":
		return len(rest) > 0 && rest[0] == "keys"
	case "tailnet":
		return len(rest) > 0 && rest[0] == "reaches"
	case "schema":
		_, _, database, _ := schemaArguments(rest)
		return database != "" && !below(cfg.DataDir, database)
	}
	return false
}

// keepForOwner keeps what a command reads outside the data directory open:
// the two keys, a backup's destination, a restore's archive and key, a
// migration's bundle, the tailnet's key and a name takeover's authority. One
// that cannot be opened is refused where it is used, as it would have been.
func keepForOwner(cfg *config.Config, sub string, rest []string) {
	preread.Keep(cfg.RootKEKFile, nil)
	preread.Keep(cfg.BackupKeyFile, nil)
	if cfg.Tailnet != nil && slices.Contains([]string{"tailnet", "migrate"}, sub) {
		preread.Keep(cfg.Tailnet.AuthKeyFile, nil)
	}
	switch sub {
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
	case "migrate":
		a, _ := parseMigrate(rest)
		preread.Keep(a.in, nil)
	case "tailnet":
		c, _ := nodeArgs(rest)
		preread.Keep(c.oauthFile, checkedSecretFile)
		preread.Keep(c.headscaleKeyFile, checkedSecretFile)
	}
}

// rootOverOwner is whether root runs this over a data directory that is
// another user's.
func rootOverOwner(dataDir string) bool {
	if !adminAsRoot() {
		return false
	}
	st, err := os.Stat(dataDir)
	return err == nil && statOwner(st) > 0
}

// actsAsOwner is varlatchd's answer, in `admin config check`, that its host
// commands run as root work as the data directory's owner: setup refuses to
// restore with one that does not say so.
const actsAsOwner = true
