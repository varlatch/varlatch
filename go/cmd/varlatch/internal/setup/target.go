// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// A migration's host target (internal docs/design/go-step7.md decision 20,
// slice 7.4e): `varlatch migrate` makes the Go installation it migrates
// into with setup's own steps, but for the keys, which are the source's
// (decision 9: the same Root KEK and BEK), installed later by `varlatchd
// admin migrate keys` where the unit loads them (/etc/varlatch, root's,
// 0600). Running `varlatch setup` first would make new keys instead.
//
// PrepareTarget checks first, and changes nothing until every check
// passes:
//   - answers: the given ones checked, setup's defaults for the rest;
//   - the unit: installed (install.sh --server), not running;
//   - user: an existing varlatch user judged as setup judges it (a system
//     account in no group but its own, unless --accept-existing-user);
//   - an /etc/varlatch or data directory there already: used as it is
//     (never chmodded or chowned) when it is as a target needs, refused
//     otherwise.
//
// Then it makes, in order:
//   - user: the varlatch system user, when there is none;
//   - /etc/varlatch (root:varlatch, 0750) and the data directory (varlatch,
//     0700), when they are not there;
//   - unit: the installed unit enabled, never started (migrate starts it at
//     the address transfer);
//   - config: varlatchd.conf, checked by varlatchd, put in place, last: the
//     configuration there is a target ready (migrate's Missing), so a run
//     killed before it makes the rest again.
//
// Before making anything it calls made with its name (one of the Made
// items), so the caller journals it first; what was already there is
// used, never named, and so never removed. UndoTarget removes exactly the
// items named, in the reverse order.

// The items PrepareTarget makes, and UndoTarget removes.
const (
	MadeUser        = "user"
	MadeEtcDir      = "etc-dir"
	MadeDataDir     = "data-dir"
	MadeConfig      = "config"
	MadeUnitEnabled = "unit-enabled"
	// The keys' files `varlatchd admin migrate keys` wrote into an
	// /etc/varlatch migrate made (the caller names them).
	MadeRootKEK   = "root-kek"
	MadeBackupKey = "backup-key"
)

// madeOrder is the order PrepareTarget makes the items in (the keys'
// files after it, by `admin migrate keys`); UndoTarget goes the other way.
var madeOrder = []string{MadeUser, MadeEtcDir, MadeDataDir, MadeUnitEnabled, MadeConfig, MadeRootKEK, MadeBackupKey}

// PrepareTarget makes a migration's host target. o.Given are the answers
// the source gave (its public URL, its ingress) and the operator's; o.Ask
// is not used (a missing answer is refused).
func PrepareTarget(ctx context.Context, o Options, made func(item string) error) (Answers, error) {
	if o.Say == nil {
		o.Say = func(string) error { return nil }
	}
	o.Ask = nil
	r := &run{o: o, h: o.Host, j: JournalDoc{FormatVersion: 1, Done: map[string]string{}}}
	if dd := r.path(DataDir); dd != DataDir {
		// A test root: the data directory is under it.
		r.configExtra = "data_dir = " + dd + "\n"
	}
	if _, err := os.Stat(r.path(ConfigFile)); err == nil {
		return Answers{}, fmt.Errorf("setup: %s exists: the target is there already", ConfigFile)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return Answers{}, err
	}
	if err := r.answers(); err != nil {
		return Answers{}, err
	}
	// The checks, before anything is changed.
	if _, err := os.Stat(r.path(UnitFile)); err != nil {
		return Answers{}, fmt.Errorf("setup: %s is not installed: install.sh --server installs it", UnitFile)
	}
	if out, err := r.h.Systemctl("is-active", Unit); err == nil && strings.TrimSpace(out) == "active" {
		return Answers{}, fmt.Errorf("setup: %s is running: a migration's target starts only at the address transfer", Unit)
	}
	uid, gid, found, err := r.h.LookupUser(User)
	if err != nil {
		return Answers{}, err
	}
	if found {
		if err := r.user(); err != nil { // judged only: it is there
			return Answers{}, err
		}
	}
	etcThere, err := r.targetDirThere(EtcDir, MadeEtcDir, func(o, g int, perm fs.FileMode) bool {
		// root's, written by no one else, and open to the varlatch user
		// (the unit reads its configuration there).
		return o == 0 && perm&0o022 == 0 && (perm&0o001 != 0 || found && g == gid && perm&0o010 != 0)
	}, "root's, not writable by anyone else, and open to the "+User+" user (root:"+User+" 0750)")
	if err != nil {
		return Answers{}, err
	}
	r.keepEtc = etcThere
	dataThere, err := r.targetDirThere(DataDir, MadeDataDir, func(o, _ int, perm fs.FileMode) bool {
		return found && o == uid && perm&0o077 == 0
	}, "the "+User+" user's alone (0700)")
	if err != nil {
		return Answers{}, err
	}
	// Then what is missing is made, each item named first.
	if !found {
		if err := made(MadeUser); err != nil {
			return Answers{}, err
		}
		if err := r.user(); err != nil {
			return Answers{}, err
		}
	}
	if !etcThere {
		if err := made(MadeEtcDir); err != nil {
			return Answers{}, err
		}
		if err := os.MkdirAll(r.path(EtcDir), 0o750); err != nil {
			return Answers{}, err
		}
	}
	if !dataThere {
		if err := made(MadeDataDir); err != nil {
			return Answers{}, err
		}
		if err := r.dataDir(); err != nil {
			return Answers{}, err
		}
	}
	if out, err := r.h.Systemctl("is-enabled", Unit); err != nil || strings.TrimSpace(out) != "enabled" {
		if err := made(MadeUnitEnabled); err != nil {
			return Answers{}, err
		}
		if out, err := r.h.Systemctl("daemon-reload"); err != nil {
			return Answers{}, fmt.Errorf("setup: systemctl daemon-reload: %v %s", err, oneLine(out))
		}
		if out, err := r.h.Systemctl("enable", Unit); err != nil {
			return Answers{}, fmt.Errorf("setup: systemctl enable %s: %v %s", Unit, err, oneLine(out))
		}
	}
	if err := made(MadeConfig); err != nil {
		return Answers{}, err
	}
	if err := r.config(); err != nil {
		return Answers{}, err
	}
	return r.j.Answers, nil
}

// targetDirThere is whether the directory p is there, as a target needs it
// (ok, on its owner, group and mode): one that is not is refused, as
// migrate changes nothing it did not make. The data directory holding a
// database is refused first (a restore's). One an earlier run of the
// migration made (item in Ours) is migrate's: made again (as not there).
func (r *run) targetDirThere(p, item string, ok func(uid, gid int, perm fs.FileMode) bool, needs string) (bool, error) {
	st, err := os.Stat(r.path(p))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if p == DataDir {
		if _, err := os.Stat(filepath.Join(r.path(DataDir), "varlatch.db")); err == nil {
			return false, fmt.Errorf("setup: %s already holds a database setup did not make: a restore is `varlatch setup --restore <archive>`; nothing was changed", DataDir)
		}
	}
	if slices.Contains(r.o.Ours, item) {
		return false, nil
	}
	uid, gid, err := r.h.Owner(r.path(p))
	if err != nil {
		return false, err
	}
	if !st.IsDir() || !ok(uid, gid, st.Mode().Perm()) {
		return false, fmt.Errorf("setup: %s is there, and not as a migration's target needs it: %s. migrate changes nothing it did not make: make it so, or remove it; nothing was changed", p, needs)
	}
	return true, nil
}

// ItemPresent is whether the file of one of the keys' items (MadeRootKEK,
// MadeBackupKey) is there.
func ItemPresent(h Host, item string) (bool, error) {
	p := map[string]string{MadeRootKEK: RootKEK, MadeBackupKey: BackupKey}[item]
	if p == "" {
		return false, fmt.Errorf("setup: %s is not a key's item", item)
	}
	_, err := os.Stat(h.Path(p))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}
	return false, err
}

// UndoTarget removes what PrepareTarget (and the keys' installation)
// made, the items named, in the reverse order; each removal is done again
// harmlessly. /etc/varlatch is removed only once empty (what else is there
// is not migrate's).
func UndoTarget(h Host, made []string, say func(string) error) error {
	if say == nil {
		say = func(string) error { return nil }
	}
	for i := len(madeOrder) - 1; i >= 0; i-- {
		item := madeOrder[i]
		if !slices.Contains(made, item) {
			continue
		}
		var err error
		switch item {
		case MadeUnitEnabled:
			if out, e := h.Systemctl("disable", Unit); e != nil {
				err = fmt.Errorf("systemctl disable %s: %v %s", Unit, e, oneLine(out))
			}
		case MadeBackupKey:
			err = removeFile(h.Path(BackupKey))
		case MadeRootKEK:
			err = removeFile(h.Path(RootKEK))
		case MadeConfig:
			err = removeFile(h.Path(ConfigFile))
			if err == nil {
				err = removeFile(h.Path(ConfigFile) + ".setup")
			}
		case MadeDataDir:
			err = os.RemoveAll(h.Path(DataDir))
		case MadeEtcDir:
			if e := os.Remove(h.Path(EtcDir)); e != nil && !errors.Is(e, fs.ErrNotExist) {
				err = say("Kept " + EtcDir + ": it holds files migrate did not make.")
			}
		case MadeUser:
			err = h.DeleteUser(User)
		}
		if err != nil {
			return fmt.Errorf("setup: removing the target's %s: %w", item, err)
		}
	}
	return nil
}

func removeFile(p string) error {
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
