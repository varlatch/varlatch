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
//	                                       or undoes it (any earlier step).
//	                                       From Stopping on (Holds) no
//	                                       varlatchd may start but the one
//	                                       Start allows, and that one is held:
//	                                       it opens once the journal is over
//	                                       (the record of Checked, durable,
//	                                       comes before that one), or after a
//	                                       reboot that read Checked back
//	                                       (Settled)
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

// Format is the journal format this package writes; it reads FormatOne too
// (0.50.0-rc.2 and rc.3), without what that had not: Undo, Start, Binaries,
// SnapshotSHA256 and SnapshotAt, and the steps Kept and Installed. A
// journal of any other format, or with a member not known here, is refused,
// never read in part.
const (
	Format    = 2
	FormatOne = 1
)

// FormatSince is the first release that reads Format: an upgrade undone to
// an earlier one leaves no journal its varlatch would refuse.
const FormatSince = "0.50.0-rc.4"

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
	// Stopping: varlatchd is about to be stopped, recorded before the stop:
	// from here on the service may be down, whatever the journal says next.
	Stopping Step = "stopping"
	// Stopped: varlatchd is stopped.
	Stopped Step = "stopped"
	// Prepared: a copy of the database has the new release's schema.
	Prepared Step = "prepared"
	// Kept: the original database's files are in their set
	// (<Work>/original), whole, under second names; the data directory is
	// as it was.
	Kept Step = "kept"
	// Installed: the new binaries are in place; the data directory is as it
	// was. From here on an undo puts the original back from its set.
	Installed Step = "installed"
	// Swapped: the upgraded copy is in the database's place.
	Swapped Step = "swapped"
	// Started: the new varlatchd is started.
	Started Step = "started"
	// Checked: its health checks passed. Its Start stays, until the upgrade
	// is over: it says in which boot the record was written.
	Checked Step = "checked"
)

// Steps are the steps in order.
var Steps = []Step{Verified, Snapshot, Stopping, Stopped, Prepared, Kept, Installed, Swapped, Started, Checked}

// UndoStep is how far an undo got, named for what is true once it is done;
// a run again goes on from there.
type UndoStep string

const (
	// UndoNone: no undo has begun, or nothing of it is done.
	UndoNone UndoStep = ""
	// FilesBack: the original database is back in its place (needed from
	// Installed on).
	// From here on it is what varlatchd may change: never put back again.
	FilesBack UndoStep = "files-back"
	// BinariesBack: the previous release's binaries are back.
	BinariesBack UndoStep = "binaries-back"
)

var undoSteps = []UndoStep{UndoNone, FilesBack, BinariesBack}

// Start is the one start of varlatchd allowed while the journal holds it
// (Holds): of this release, in this boot. It is written right before
// varlatchd is started and checked, and stays until the upgrade is over or
// undone.
type Start struct {
	Version string `json:"version"`
	// BootID is the kernel's boot id (/proc/sys/kernel/random/boot_id): a
	// start after a reboot is not the one meant.
	BootID string `json:"bootId"`
	At     string `json:"at"`
}

// Binaries are the SHA-256 (hex) of each release's two binaries.
type Binaries struct {
	From BinarySums `json:"from"`
	To   BinarySums `json:"to"`
}

// BinarySums are one release's.
type BinarySums struct {
	Varlatch  string `json:"varlatch"`
	Varlatchd string `json:"varlatchd"`
}

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
	// Step is the last step completed; Undo how far an undo got.
	Step Step     `json:"step"`
	Undo UndoStep `json:"undo,omitempty"`
	// Start is the start allowed now, nil for none.
	Start     *Start `json:"start,omitempty"`
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
	// Binaries are the two releases' binaries: From's as they were
	// installed, To's as its signed SHA256SUMS gives them. Nothing else is
	// put in place, or run from <Releases>.
	Binaries *Binaries `json:"binaries,omitempty"`
	// Snapshot is the pre-upgrade archive, "" before it is taken;
	// SnapshotSHA256 its SHA-256 and SnapshotAt when the archive was made
	// (RFC 3339).
	Snapshot       string `json:"snapshot"`
	SnapshotSHA256 string `json:"snapshotSha256,omitempty"`
	SnapshotAt     string `json:"snapshotAt,omitempty"`
	// Reason says why the upgrade was undone, or what an undo left.
	Reason string `json:"reason,omitempty"`
}

// Pending is whether the journal holds an upgrade that is not over: one
// in progress (or interrupted), or an undo that failed.
func (j *Journal) Pending() bool { return j != nil && (j.State == InProgress || j.State == Failed) }

// Holds is whether no varlatchd may start but the one Start allows, held:
// the upgrade is not over, and from the stop on (Stopping) the database, or
// the binaries, may be neither release's to serve. Checked is not enough:
// seen, its record may still be lost to a power cut, and what was served
// since with it, until the upgrader, having made it durable, writes that the
// upgrade is done. (In format 1, whose recovery never goes back once the new
// release may have served, Checked is.)
func (j *Journal) Holds() bool {
	return j.Pending() && j.Reached(Stopping) && (j.Format != FormatOne || !j.Reached(Checked))
}

// Settled is whether the record of Checked is durable for certain: it was
// read in another boot (bootID) than it was written in. The upgrade is then
// only ever finished, and its release may serve.
func (j *Journal) Settled(bootID string) bool {
	return j.Pending() && j.Reached(Checked) && bootID != "" && j.Start != nil && j.Start.BootID != "" && j.Start.BootID != bootID
}

// Allows is whether the journal, holding, allows a start of version in the
// boot bootID.
func (j *Journal) Allows(version, bootID string) bool {
	return j.Start != nil && j.Start.Version == version && j.Start.BootID == bootID && bootID != ""
}

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
	if j.Format != Format && j.Format != FormatOne {
		return fmt.Errorf("upgrade journal: format %d, not %d: a newer varlatch wrote it", j.Format, Format)
	}
	if j.Format == FormatOne && (j.Undo != UndoNone || j.Start != nil || j.Binaries != nil || j.SnapshotSHA256 != "" || j.SnapshotAt != "" || j.Step == Kept || j.Step == Installed) {
		return errors.New("upgrade journal: a member of a later format in one of format 1")
	}
	if !slices.Contains(undoSteps, j.Undo) {
		return fmt.Errorf("upgrade journal: undo %q", j.Undo)
	}
	if j.ID == "" || !release.ValidVersion(j.From) || !release.ValidVersion(j.To) {
		return errors.New("upgrade journal: no upgrade id, or a release that is no release version")
	}
	if !slices.Contains([]State{InProgress, Done, Undone, Failed}, j.State) || j.Step != None && !slices.Contains(Steps, j.Step) {
		return fmt.Errorf("upgrade journal: state %q, step %q", j.State, j.Step)
	}
	return nil
}

// Encode is the journal's file. A journal read in format 1 stays in it.
func (j *Journal) Encode() ([]byte, error) {
	if j.Format == 0 {
		j.Format = Format
	}
	if err := j.check(); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Write replaces dir's journal with j, durably, readable by anyone. An
// error that is release.ErrNotDurable left the new journal in place, not
// known to survive a power cut; any other left the one before.
func Write(dir string, j *Journal) error {
	b, err := j.Encode()
	if err != nil {
		return err
	}
	return release.WriteDurably(filepath.Join(dir, File), b, 0o644)
}
