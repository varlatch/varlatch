// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// A restore onto a fresh host (slice 6.4c; ADR-0059's G13, through setup):
// `varlatch setup --restore <archive> --root-kek-file <file>
// --backup-key-file <file>`. The operator's keys are installed where setup
// would have made new ones (root, 0600), the archive is restored with
// `varlatchd admin backup restore` before the unit first starts, and the
// rest is setup's own steps: the restored administrators keep their
// passkeys, so no link is issued, no key is shown or copied, and the first
// backup proves the restored installation backs up and verifies again.

// restoreIntent records a restore in the journal, the first time, and
// refuses a restore onto a host whose setup is not one, or another archive
// than the one being restored.
func (r *run) restoreIntent() error {
	given := r.o.Restore
	switch {
	case r.j.Restore == nil && given == "":
		return nil
	case r.j.Restore == nil:
		if len(r.j.Done) > 0 {
			return &UsageError{"setup: this host's setup is not a restore (" + Journal + " has steps done): a restore goes onto a fresh host"}
		}
		if !filepath.IsAbs(given) || !filepath.IsAbs(r.o.RootKEKIn) || !filepath.IsAbs(r.o.BackupKeyIn) {
			return &UsageError{"setup: --restore, --root-kek-file and --backup-key-file each name a file with an absolute path"}
		}
		r.j.Restore = &RestoreRecord{Archive: given}
	case given != "" && given != r.j.Restore.Archive:
		return &UsageError{"setup: this host is restoring " + r.j.Restore.Archive + " (" + Journal + "): setup does not switch archives"}
	}
	return nil
}

// keyText is a key file's text: 64 hex digits, or 32 bytes in base64, as
// varlatchd reads them.
var keyText = regexp.MustCompile(`^[0-9A-Fa-f]{64}$`)

func isKey(b []byte) bool {
	if keyText.Match(b) {
		return true
	}
	raw, err := base64.StdEncoding.DecodeString(string(b))
	defer clear(raw)
	return err == nil && len(raw) == 32
}

// restoreKeys installs the operator's two keys in /etc/varlatch (root,
// 0600, linked into place, never over another key): the same file again is
// left as it is; a different one is refused.
func (r *run) restoreKeys() error {
	if err := os.MkdirAll(r.path(EtcDir), 0o750); err != nil {
		return err
	}
	var installed [][]byte
	defer func() {
		for _, k := range installed {
			clear(k)
		}
	}()
	for _, k := range []struct{ name, flag, in, path string }{
		{"Root KEK", "--root-kek-file", r.o.RootKEKIn, RootKEK},
		{"backup key", "--backup-key-file", r.o.BackupKeyIn, BackupKey},
	} {
		var given []byte
		if k.in != "" {
			raw, err := os.ReadFile(k.in)
			if err != nil {
				return fmt.Errorf("setup: cannot read the %s's file %s: %w", k.name, k.in, err)
			}
			given = bytes.TrimSpace(raw)
			if len(given) != len(raw) {
				given = append([]byte(nil), given...)
				clear(raw)
			}
			if !isKey(given) {
				clear(given)
				return &UsageError{fmt.Sprintf("setup: %s %s does not hold a key (64 hex digits, or 32 bytes in base64)", k.flag, k.in)}
			}
			installed = append(installed, given)
		}
		have, err := os.ReadFile(r.path(k.path))
		switch {
		case err == nil:
			same := given == nil || bytes.Equal(bytes.TrimSpace(have), given)
			clear(have)
			if !same {
				return fmt.Errorf("setup: %s already holds another %s: a restore installs your keys on a fresh host and never replaces one", k.path, k.name)
			}
			continue
		case !errors.Is(err, fs.ErrNotExist):
			return err
		case given == nil:
			return &UsageError{fmt.Sprintf("setup: give %s again: the %s is not installed yet", k.flag, k.name)}
		}
		data := append(append([]byte(nil), given...), '\n')
		err = createPrivate(r.path(k.path), data)
		clear(data)
		if err != nil {
			return fmt.Errorf("setup: writing %s: %w", k.path, err)
		}
		if err := r.o.Say("Installed your " + k.name + " in " + k.path + " (root, 0600)."); err != nil {
			return err
		}
	}
	if len(installed) == 2 && bytes.Equal(installed[0], installed[1]) {
		return &UsageError{"setup: --root-kek-file and --backup-key-file hold the same key: they are two different keys"}
	}
	return nil
}

var (
	restored     = regexp.MustCompile(`Restore completed for (\S+) from archive (\S+) \(created ([^)]*)\)`)
	restoredSets = regexp.MustCompile(`(?m)^  ([a-z_]+) = (.*)$`)
)

// restore: the archive restored into the data directory with the
// operator's keys, before the unit first starts (varlatchd checks the
// archive, its release and the Root KEK against the archive's canary; a
// restore that stopped resumes). The archive's installation must be reached
// at the address the answers give: its passkeys belong to it.
func (r *run) restore(ctx context.Context) error {
	if r.j.Restore == nil || r.j.Done["restore"] != "" {
		return nil
	}
	if err := r.o.Say("Restoring " + r.j.Restore.Archive + " with your keys."); err != nil {
		return err
	}
	out, err := r.h.Admin(ctx, "backup", "restore", "--in", r.j.Restore.Archive, "--backup-key-file", BackupKey)
	if err != nil {
		return err
	}
	m := restored.FindSubmatch(out)
	if m == nil {
		return errors.New("setup: varlatchd admin backup restore did not say what it restored")
	}
	r.j.Restore.InstallationID, r.j.Restore.ArchiveID = string(m[1]), string(m[2])
	created := string(m[3])
	settings := map[string]string{}
	for _, s := range restoredSets.FindAllSubmatch(out, -1) {
		settings[string(s[1])] = string(s[2])
	}
	if was := strings.TrimSuffix(settings["public_url"], "/"); was != "" && was != strings.TrimSuffix(r.j.Answers.PublicURL, "/") {
		_ = r.saveJournal()
		return &UsageError{fmt.Sprintf("setup: the archive's installation is reached at %s, not %s: its passkeys belong to that address. Remove %s and %s (this run's answers; the keys and the restored data stay), then run setup --restore again with --public-url %s; to change the address, restore first and move it with varlatch move",
			was, r.j.Answers.PublicURL, Journal, ConfigFile, was)}
	}
	uid, gid, _, err := r.h.LookupUser(User)
	if err != nil {
		return err
	}
	// The restore ran as root: what it wrote becomes the unit's.
	if err := filepath.WalkDir(r.path(DataDir), func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return r.h.Chown(p, uid, gid)
	}); err != nil {
		return err
	}
	return r.o.Say("Restored the installation " + r.j.Restore.InstallationID + " from the archive " + r.j.Restore.ArchiveID + " (made " + created + ").")
}
