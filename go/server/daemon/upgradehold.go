// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/upgradejournal"
	"github.com/varlatch/varlatch/go/server/maintenance"
)

// An upgrade that is not over, as serve reads it (internal docs/design/
// go-step6.md, decision 6): from its stop on until its checks passed, the
// database and the binaries may be neither release's to serve, whatever
// starts varlatchd (a reboot, an operator). It does not start then, but for
// the one start `varlatch upgrade` writes into its journal, and that one is
// held: the listeners answer 503 and nothing works in the background, so
// nothing a client or the server does can be lost by an undo. `admin status`,
// on the control socket, answers with the real readiness, which is what the
// upgrade checks. The hold ends when the journal says that the upgrade is
// over: the record that the checks passed was made durable before that one, so
// what is served from then on no power cut takes back. A journal at that
// record, read in a later boot, is as good.

// upgradeBootID is the kernel's boot id, "" where there is none (a variable
// for the tests).
var upgradeBootID = func() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// upgradeHoldEvery is how often a held varlatchd looks at the journal: the
// upgrade's checks have passed by then, and clients wait for it.
const upgradeHoldEvery = 100 * time.Millisecond

// upgradeStart is what the journal in configDir says to a varlatchd of
// version that is about to serve: held, or that it does not start.
func upgradeStart(configDir, version string) (held bool, err error) {
	j, err := readUpgrade(configDir)
	if err != nil || !j.Holds() || j.Settled(upgradeBootID()) {
		return false, err
	}
	if j.Allows(version, upgradeBootID()) || startedByFormatOne(j, version) {
		return true, nil
	}
	return false, upgradeNotOver(j)
}

// upgradeOver refuses what opens the database with varlatchd stopped while the
// journal in configDir holds: the database may be away (its first use makes a
// new one), or the one an undo discards.
func upgradeOver(configDir string) error {
	j, err := readUpgrade(configDir)
	if err != nil || !j.Holds() || j.Settled(upgradeBootID()) {
		return err
	}
	return upgradeNotOver(j)
}

func readUpgrade(configDir string) (*upgradejournal.Journal, error) {
	j, err := upgradejournal.Read(configDir)
	if err != nil {
		return nil, fmt.Errorf("the upgrade journal %s cannot be read (%w), so it is not known whether an upgrade is half done: run sudo varlatch upgrade, of the newest release that was installed on this host, which finishes or undoes it",
			filepath.Join(configDir, upgradejournal.File), err)
	}
	return j, nil
}

func upgradeNotOver(j *upgradejournal.Journal) error {
	if j.State == upgradejournal.Failed {
		return fmt.Errorf("the upgrade from %s to %s could not be undone (%s): run sudo varlatch upgrade, which goes on with it", j.From, j.To, j.Reason)
	}
	return fmt.Errorf("the upgrade from %s to %s is not over (its last step is %q): run sudo varlatch upgrade, which finishes or undoes it", j.From, j.To, j.Step)
}

// startedByFormatOne: a release before format 2 (0.50.0-rc.2, rc.3) upgrades
// this host with its own varlatch, whose journal names no start: it records
// the swap, then starts the new varlatchd. That start is this one; a later
// one, after a reboot too, is held all the same, and serves nothing until that
// varlatch, or a newer one, ends the upgrade. At any step before the swap is
// done there is no start of the new release. Its checks pass against a held
// one: they are `varlatchd admin status --json` alone, on the control socket
// (the version, the schema, serving, and the three of ready), never a
// listener (0.50.0-rc.2's and rc.3's upgrade.go, check). go/install/
// test-upgrade.sh upgrades from rc.2 with rc.2's own engine.
func startedByFormatOne(j *upgradejournal.Journal, version string) bool {
	return j.Format == upgradejournal.FormatOne && j.State == upgradejournal.InProgress && j.To == version &&
		(j.Step == upgradejournal.Swapped || j.Step == upgradejournal.Started || j.Step == upgradejournal.Checked)
}

// endUpgradeHold lifts admission's upgrade hold once the journal in configDir
// no longer holds. A journal that cannot be read, or is gone, says nothing:
// the hold stays.
func endUpgradeHold(ctx context.Context, configDir string, admission *maintenance.Admission, log *slog.Logger) {
	path := filepath.Join(configDir, upgradejournal.File)
	var seen os.FileInfo
	said := ""
	tick := time.NewTicker(upgradeHoldEvery)
	defer tick.Stop()
	for {
		// The journal is replaced whole (a rename): the same file, unchanged,
		// has been read.
		if info, err := os.Stat(path); err != nil || seen == nil || !os.SameFile(seen, info) || !info.ModTime().Equal(seen.ModTime()) || info.Size() != seen.Size() {
			j, rerr := upgradejournal.Read(configDir)
			switch {
			case rerr == nil && j != nil && !j.Holds():
				admission.EndUpgrade()
				log.Info("the upgrade passed its checks, or is over: varlatchd answers", "from", j.From, "to", j.To, "state", string(j.State), "step", string(j.Step))
				return
			case rerr == nil && j == nil:
				rerr = os.ErrNotExist
			}
			if rerr != nil && rerr.Error() != said {
				said = rerr.Error()
				log.Warn("the upgrade journal cannot be read: varlatchd keeps answering 503 MAINTENANCE; run sudo varlatch upgrade", "file", path, "error", rerr)
			}
			seen = info
			if rerr != nil {
				seen = nil
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
