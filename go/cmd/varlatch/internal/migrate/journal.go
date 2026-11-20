// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Phase is where a migration is (go-step7 decision 14). The journal
// records each before it is done, so an interruption is never guessed at.
type Phase string

// The phases, in order. Released is a migration undone (the barrier lifted,
// the old installation reopened, the target's database discarded).
const (
	Started   Phase = "started"   // the journal exists; nothing was done
	Preflight Phase = "preflight" // the source's fresh backup verified, the target's keys in place
	DryRun    Phase = "dry-run"   // a full copy from a snapshot checked; nothing switched
	Barrier   Phase = "barrier"   // the source behind its migration barrier, or being put there
	Copied    Phase = "copied"    // the final copy imported into the target
	Checked   Phase = "checked"   // the checks passed on the final copy
	Switched  Phase = "switched"  // the source marked migrated out: it refuses writes from here
	Open      Phase = "open"      // the target may serve
	Released  Phase = "released"  // undone before the switch
)

// Phases are the phases in order.
var Phases = []Phase{Started, Preflight, DryRun, Barrier, Copied, Checked, Switched, Open, Released}

// beforeBarrier are the phases where the source runs unchanged: an
// interruption there is redone from the preflight.
var beforeBarrier = []Phase{Started, Preflight, DryRun}

// held are the phases between the barrier and the switch: an
// interruption there is undone (the barrier lifted, the old installation
// reopened unchanged).
var held = []Phase{Barrier, Copied, Checked}

// JournalFile is the journal's name, in the source's directory and in the
// target's data directory.
const JournalFile = "migration.json"

// Journal is a migration's record. It holds ids, versions, digests of
// images, counts and moments; never a key, the run key, a value or a
// bundle.
type Journal struct {
	Format int    `json:"format"`
	ID     string `json:"id"`
	Phase  Phase  `json:"phase"`
	// Stopped is a run that ended where it meant to (a dry run), not one
	// that was interrupted.
	Stopped bool `json:"stopped"`
	// DryRunOnly is a run that stops after the dry run (--dry-run): a
	// resume does what it was asked, no more.
	DryRunOnly  bool             `json:"dryRunOnly"`
	Source      SourceInfo       `json:"source"`
	Target      TargetInfo       `json:"target"`
	MaxDowntime int64            `json:"maxDowntimeSeconds"`
	Drain       int64            `json:"drainSeconds"`
	Preflight   *PreflightRecord `json:"preflight,omitempty"`
	DryRun      *DryRunReport    `json:"dryRun,omitempty"`
	Barrier     *BarrierRecord   `json:"barrier,omitempty"`
	Copy        *CopyRecord      `json:"copy,omitempty"`
	Undone      *UndoneRecord    `json:"undone,omitempty"`
	// Transfer is the address transfer's record (slice 7.4b); until it
	// is built, what it says is that none was made.
	Transfer string `json:"transfer"`
	History  []Step `json:"history"`
}

// Step is one phase entered, and when.
type Step struct {
	Phase Phase  `json:"phase"`
	At    string `json:"at"`
}

// PreflightRecord is the preflight's: the fresh backup, uploaded,
// downloaded and verified, and the target's keys.
type PreflightRecord struct {
	ArchiveID   string `json:"archiveId"`
	Destination string `json:"destination"`
	VerifiedAt  string `json:"verifiedAt"`
	RootKEK     string `json:"rootKek"` // "written" or "unchanged": the target's key file
	BEK         string `json:"bek"`
}

// BarrierRecord is the barrier's: its gate and the frozen point.
type BarrierRecord struct {
	GateID        string `json:"gateId"`
	AuditPosition string `json:"auditPosition"`
	Snapshot      string `json:"snapshot,omitempty"`
	FrozenAt      string `json:"frozenAt"`
	DrainedMs     int64  `json:"drainedMs"`
}

// CopyRecord is the final copy's: the import and the checks.
type CopyRecord struct {
	InstallationID   string        `json:"installationId"`
	Tables           int64         `json:"tables"`
	Rows             int64         `json:"rows"`
	SessionsEnded    int64         `json:"sessionsEnded"`
	CredsRevoked     int64         `json:"credentialsRevoked"`
	MigratedPosition int64         `json:"migratedPosition"`
	Checks           *CheckSummary `json:"checks,omitempty"`
}

// UndoneRecord says why a migration was undone, and what undoing did.
type UndoneRecord struct {
	From     Phase  `json:"from"`
	Why      string `json:"why"`
	Released bool   `json:"barrierReleased"`
	At       string `json:"at"`
}

var idAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// newID is a migration id: mig_ and 26 base32 letters.
func newID() (string, error) {
	b := make([]byte, 26)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	var s strings.Builder
	s.WriteString("mig_")
	for _, x := range b {
		s.WriteByte(idAlphabet[x&31])
	}
	return s.String(), nil
}

// enter records phase p in j.
func (j *Journal) enter(p Phase, now time.Time) {
	j.Phase = p
	j.History = append(j.History, Step{Phase: p, At: now.UTC().Format(time.RFC3339Nano)})
}

// Encode is the journal as written: indented JSON and a newline.
func (j *Journal) Encode() ([]byte, error) {
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// readJournal reads dir's journal; nil when it has none.
func readJournal(dir string) (*Journal, error) {
	b, err := os.ReadFile(filepath.Join(dir, JournalFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var j Journal
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return nil, fmt.Errorf("%s is not a migration journal: %v", filepath.Join(dir, JournalFile), err)
	}
	if j.Format != 1 || !slices.Contains(Phases, j.Phase) {
		return nil, fmt.Errorf("%s is a journal of another format (%d) or phase (%q)", filepath.Join(dir, JournalFile), j.Format, j.Phase)
	}
	return &j, nil
}

// writeJournal writes j to dir durably: a temporary name, mode 0600,
// synced, renamed, the directory synced.
func writeJournal(dir string, j *Journal) error {
	b, err := j.Encode()
	if err != nil {
		return err
	}
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	path := filepath.Join(dir, JournalFile)
	tmp := filepath.Join(dir, "."+JournalFile+"."+hex.EncodeToString(suffix)+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
