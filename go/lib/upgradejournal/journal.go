// SPDX-License-Identifier: Apache-2.0

// Package upgradejournal is `varlatch upgrade`'s journal (ADR-0059
// Decision 8; internal docs/design/go-step6.md, decision 6, slice 6.6b):
// the one upgrade a host has under way or last made, step by step, so that
// a crash resumes or undoes it, and `varlatch doctor` (slice 6.5's
// release.pending-upgrade) can say that one is left pending.
//
// It is a file beside varlatchd.conf (/etc/varlatch/upgrade.json), root's,
// readable by anyone (0644): it holds releases, steps, times and paths,
// never a key or a credential. It is replaced whole and durably at each
// step, so a reader sees one step or the next, never a part.
//
// What a reader concludes:
//
//	no journal, or State done or undone   nothing is pending
//	State in-progress                      an upgrade was interrupted (or
//	                                       runs now): the next varlatch
//	                                       upgrade finishes it (Step checked)
//	                                       or undoes it (any earlier step)
//	State failed                           an undo did not complete: Reason
//	                                       says what is left, and the
//	                                       pre-upgrade snapshot (Snapshot) is
//	                                       the way back
package upgradejournal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/varlatch/varlatch/go/lib/release"
)

// File is the journal's name, in varlatchd.conf's directory.
const File = "upgrade.json"

// Format is the journal format this package reads and writes.
const Format = 1

// Step is an upgrade's step, named for what is true once it is done.
type Step string

const (
	// None: the upgrade has begun, nothing is done yet.
	None Step = ""
	// Verified: the release's binaries and manifest are downloaded,
	// verified against the release's signed SHA256SUMS, and staged; the
	// previous release's binaries are kept.
	Verified Step = "verified"
	// Snapshot: the pre-upgrade snapshot (an encrypted archive) is taken
	// and kept with the upgrade, 30 days.
	Snapshot Step = "snapshot"
	// Stopped: varlatchd is stopped.
	Stopped Step = "stopped"
	// Prepared: a copy of the database has the new release's schema.
	Prepared Step = "prepared"
	// Swapped: the new binaries and the upgraded copy are in place; the
	// original database is kept with the upgrade.
	Swapped Step = "swapped"
	// Started: the new varlatchd is started.
	Started Step = "started"
	// Checked: its health checks passed.
	Checked Step = "checked"
)

// Steps are the steps in order.
var Steps = []Step{Verified, Snapshot, Stopped, Prepared, Swapped, Started, Checked}

// State is where the upgrade stands.
type State string

const (
	InProgress State = "in-progress"
	// Done: the new release serves, after its checks.
	Done State = "done"
	// Undone: the previous release serves again, on the database as it
	// was.
	Undone State = "undone"
	// Failed: an undo that did not complete.
	Failed State = "failed"
)

// Journal is the file.
type Journal struct {
	Format int    `json:"format"`
	ID     string `json:"id"`
	// From and To are the releases; FromSchema and ToSchema their schema
	// versions; RollbackSafe whether the previous release may open the
	// upgraded database (the manifest's compatibleFrom at or below
	// FromSchema).
	From         string `json:"from"`
	To           string `json:"to"`
	FromSchema   int64  `json:"fromSchema"`
	ToSchema     int64  `json:"toSchema"`
	RollbackSafe bool   `json:"rollbackSafe"`
	State        State  `json:"state"`
	// Step is the last step completed.
	Step      Step   `json:"step"`
	StartedAt string `json:"startedAt"`
	UpdatedAt string `json:"updatedAt"`
	// BinDir holds varlatch and varlatchd; Releases each release's
	// binaries, the previous one's kept and the new one's staged
	// (<Releases>/<version>/); DataDir is varlatchd's; Work is the
	// upgrade's directory in it (<DataDir>/upgrades/<ID>), which holds the
	// snapshot, the database copy and the original database.
	BinDir   string `json:"binDir"`
	Releases string `json:"releases"`
	DataDir  string `json:"dataDir"`
	Work     string `json:"work"`
	// Snapshot is the pre-upgrade archive, "" before it is taken.
	Snapshot string `json:"snapshot"`
	// Reason says why the upgrade was undone, or what an undo left.
	Reason string `json:"reason,omitempty"`
}

// Pending is whether the journal holds an upgrade that is not over: one
// in progress (or interrupted), or an undo that failed.
func (j *Journal) Pending() bool { return j != nil && (j.State == InProgress || j.State == Failed) }

// Reached is whether step s is done.
func (j *Journal) Reached(s Step) bool {
	if s == None {
		return true
	}
	return slices.Index(Steps, j.Step) >= slices.Index(Steps, s) && slices.Contains(Steps, s)
}

// Read reads dir's journal: nil when there is none.
func Read(dir string) (*Journal, error) {
	raw, err := os.ReadFile(filepath.Join(dir, File))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var j Journal
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return nil, fmt.Errorf("upgrade journal: %s is not a journal: %w", filepath.Join(dir, File), err)
	}
	if err := j.check(); err != nil {
		return nil, err
	}
	return &j, nil
}

func (j *Journal) check() error {
	if j.Format != Format {
		return fmt.Errorf("upgrade journal: format %d, not %d: a newer varlatch wrote it", j.Format, Format)
	}
	if j.ID == "" || !release.ValidVersion(j.From) || !release.ValidVersion(j.To) {
		return errors.New("upgrade journal: no upgrade id, or a release that is no release version")
	}
	if !slices.Contains([]State{InProgress, Done, Undone, Failed}, j.State) || j.Step != None && !slices.Contains(Steps, j.Step) {
		return fmt.Errorf("upgrade journal: state %q, step %q", j.State, j.Step)
	}
	return nil
}

// Write replaces dir's journal with j, durably, readable by anyone.
func Write(dir string, j *Journal) error {
	j.Format = Format
	if err := j.check(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	return release.WriteDurably(filepath.Join(dir, File), append(b, '\n'), 0o644)
}
