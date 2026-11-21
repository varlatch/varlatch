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
	Transfer  Phase = "transfer"  // the address moving to the target, which serves isolated (decision 12)
	Switched  Phase = "switched"  // the source marked migrated out: it refuses writes from here
	Open      Phase = "open"      // the target may serve
	Released  Phase = "released"  // undone before the switch
)

// The reverse migration's phases (go-step7 decisions 16 and 17, slice
// 7.6a), after open. A reverse undone goes back to open; rolled back is it
// done: the last TypeScript release is the installation again.
const (
	Rollback         Phase = "rollback"          // Go behind its migration barrier, or being put there
	RollbackExported Phase = "rollback-exported" // the reverse bundle written, the transformed copy kept
	RollbackImported Phase = "rollback-imported" // the TypeScript release rebuilt on a fresh database from it
	RollbackChecked  Phase = "rollback-checked"  // the reverse checks passed
	RollbackTransfer Phase = "rollback-transfer" // the address moving back to the TypeScript release
	RolledBack       Phase = "rolled-back"       // the TypeScript release serves; Go never starts on its copy again
)

// Finished is a migration whose rollback window `varlatch migrate --finish`
// ended (decision 17), after open or rolled back: no reverse starts from
// it, and what the old side kept is removed (its data only with
// --delete-old-data).
const Finished Phase = "finished"

// Phases are the phases in order.
var Phases = []Phase{Started, Preflight, DryRun, Barrier, Copied, Checked, Transfer, Switched, Open, Released,
	Rollback, RollbackExported, RollbackImported, RollbackChecked, RollbackTransfer, RolledBack, Finished}

// reverseHeld are the reverse's phases before its address moves: an
// interruption there is undone (Go's barrier lifted, the TypeScript side
// as the forward migration left it).
var reverseHeld = []Phase{Rollback, RollbackExported, RollbackImported, RollbackChecked}

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
	// Stopped is a run that ended before the barrier, where it meant to (a
	// dry run) or on a failure there (stopBefore), not one that was
	// interrupted: the next run starts it again.
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
	// Undoing is an undo begun and not finished: --resume goes on with it.
	Undoing bool `json:"undoing,omitempty"`
	// Ingress is the source's ingress, which the transfer moves: public,
	// proxy or coolify (decision 12).
	Ingress Ingress `json:"ingress"`
	// Transfer is the address transfer's record.
	Transfer *TransferRecord `json:"transfer,omitempty"`
	// Rollback is the reverse migration's record (the last one begun).
	Rollback *RollbackRecord `json:"rollback,omitempty"`
	// Finish is --finish's record.
	Finish *FinishRecord `json:"finish,omitempty"`
	// Created is the target migrate made, when it made it (slice 7.4e).
	Created *CreatedRecord `json:"created,omitempty"`
	// WindowEnded is the rollback window ended early, on the Go side: an
	// upgrade to a release that ends it (decision 17, release.json's
	// endsRollbackWindow), recorded in Go's journal before the upgrade.
	WindowEnded *WindowEndedRecord `json:"windowEnded,omitempty"`
	History     []Step             `json:"history"`
}

// WindowEndedRecord is the release whose upgrade ended a migration's
// rollback window, and when it was recorded.
type WindowEndedRecord struct {
	Release string `json:"release"`
	At      string `json:"at"`
}

// RollbackRecord is a reverse migration's: Go's barrier, the reverse
// export, the TypeScript release's rebuild and import, the reverse checks,
// the address moved back, and the Go archives made since the switch.
type RollbackRecord struct {
	StartedAt string         `json:"startedAt"`
	Barrier   *BarrierRecord `json:"barrier,omitempty"`
	Export    *CopyRecord    `json:"export,omitempty"`
	// Rebuild is journalled before anything of it is made: the fresh
	// volumes, the Compose file naming them, and .env's COMPOSE_FILE
	// before, so an undo removes exactly those.
	Rebuild *RebuildRecord  `json:"rebuild,omitempty"`
	Import  *TSImportRecord `json:"import,omitempty"`
	Checks  *CheckSummary   `json:"checks,omitempty"`
	// GoStopped is Go's service stopped for the address (the public and
	// own-proxy shapes, at the transfer; Coolify's once the domain moved).
	GoStopped  bool   `json:"goStopped"`
	Asked      bool   `json:"asked"`
	VerifiedAt string `json:"verifiedAt,omitempty"`
	// Archives are the Go (format 3) archives made since the switch,
	// listed in the report and never deleted (decision 17).
	Archives []ArchiveInfo `json:"archives,omitempty"`
	Undoing  bool          `json:"undoing,omitempty"`
	Undone   *UndoneRecord `json:"undone,omitempty"`
	DoneAt   string        `json:"doneAt,omitempty"`
}

// RebuildRecord is the TypeScript side's fresh database: the Compose file
// renaming its Postgres and Convex volumes, the fresh volumes' names, and
// .env's COMPOSE_FILE before (null: unset).
type RebuildRecord struct {
	Override    string   `json:"override"`
	Volumes     []string `json:"volumes"`
	ComposeFile *string  `json:"composeFile"`
	Image       string   `json:"image"`
}

// TSImportRecord is the TypeScript release's `admin migration import`.
type TSImportRecord struct {
	InstallationID string `json:"installationId"`
	AuditPosition  string `json:"auditPosition"`
	Tables         int64  `json:"tables"`
	Rows           int64  `json:"rows"`
	SHA256         string `json:"sha256"`
	MigratedOut    string `json:"migratedOutGate"`
}

// ArchiveInfo is one Go archive.
type ArchiveInfo struct {
	ArchiveID string `json:"archiveId"`
	CreatedAt string `json:"createdAt"`
	Release   string `json:"release"`
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

// TransferRecord is the address transfer's: the origin it keeps, whether
// the operator was asked (the Coolify shape), and when the public URL
// answered with the migrated installation.
type TransferRecord struct {
	Origin string `json:"origin"`
	// Publish is, for an own proxy, the address the proxy targets (the
	// source's dashboard's), which the target must take over.
	Publish    string `json:"publish,omitempty"`
	Asked      bool   `json:"asked"`
	VerifiedAt string `json:"verifiedAt,omitempty"`
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
	// A journal of 7.4a's development builds held transfer as a string
	// (none was made): read as no transfer record.
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) == nil {
		if t, ok := raw["transfer"]; ok && len(t) > 0 && t[0] == '"' {
			delete(raw, "transfer")
			if nb, err := json.Marshal(raw); err == nil {
				b = nb
			}
		}
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
