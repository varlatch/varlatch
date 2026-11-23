// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// An installation's backup state on disk, in the TypeScript server's
// formats (packages/backup status.ts and maintenance.ts), so that step 7's
// migration and the CLI's admin backup read it as it is. Under the state
// directory (varlatchd's data directory):
//
//	backups/<archive id>.vltbak   an archive
//	backups/<archive id>.json     its status record (StatusRecord)
//	maintenance.json              the maintenance gate, when one is open (Gate)

// Verification is a check of an archive: it opened (integrity), this
// release can restore it (compatibility), and the Root KEK opens its
// canaries (keyMatch).
type Verification struct {
	Integrity     bool   `json:"integrity"`
	Compatibility bool   `json:"compatibility"`
	KeyMatch      bool   `json:"keyMatch"`
	TargetRelease string `json:"targetRelease"`
	CheckedAt     string `json:"checkedAt"`
}

func (v *Verification) passed() bool { return v != nil && v.Integrity && v.Compatibility && v.KeyMatch }

// Delivery is an archive's upload to a destination.
type Delivery struct {
	Destination        string        `json:"destination"`
	UploadedAt         string        `json:"uploadedAt"`
	RemoteVerification *Verification `json:"remoteVerification,omitempty"`
}

// CaptureStats is how the capture ran. Mode is "online" (the only mode the
// schema accepts): snapshotHeldMs is the snapshot's duration, dumpMs the
// sealing's, dumpBytes the snapshot's size.
type CaptureStats struct {
	Mode           string `json:"mode"`
	SnapshotHeldMs int64  `json:"snapshotHeldMs"`
	DumpMs         int64  `json:"dumpMs"`
	DumpBytes      int64  `json:"dumpBytes"`
}

// StatusRecord is an archive's status (statusSchema).
type StatusRecord struct {
	ArchiveID           string        `json:"archiveId"`
	InstallationID      string        `json:"installationId"`
	CreatedAt           string        `json:"createdAt"`
	Release             string        `json:"release"`
	RequiredKeyVersions []int         `json:"requiredKeyVersions"`
	Verification        *Verification `json:"verification,omitempty"`
	Delivery            *Delivery     `json:"delivery,omitempty"`
	Capture             *CaptureStats `json:"capture,omitempty"`
	// RetainUntil is when a TypeScript-format archive's retention ends, when
	// it is known (the migration records it: an Object Lock retain-until
	// date, or the operator's). Without it, the bucket's lifecycle rule
	// decides, which Varlatch does not read.
	RetainUntil string `json:"retainUntil,omitempty"`
}

var errStatus = errors.New("backup: an invalid status record")

// releaseVersion is a record's release: major.minor.patch, with any suffix.
var releaseVersion = regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.[0-9]+`)

// goLine is the first release of the Go line (ADR-0059 step 7, O1): the
// TypeScript line ends below it.
const goLine = 50

// line is the release line a record's release names: "typescript" below
// 0.50, "go" from 0.50, "" for one it cannot read.
func (s StatusRecord) line() string {
	m := releaseVersion.FindStringSubmatch(s.Release)
	if m == nil {
		return ""
	}
	// A number too large to read is no release at all: neither line, so
	// retention keeps the archive.
	major, err := strconv.Atoi(m[1])
	if err != nil {
		return ""
	}
	minor, err := strconv.Atoi(m[2])
	if err != nil {
		return ""
	}
	if major == 0 && minor < goLine {
		return "typescript"
	}
	return "go"
}

// TypeScript reports whether the record is a TypeScript-format archive's
// (format 1 or 2, made by a release below 0.50): restorable only through
// the converter (varlatch migrate --from-archive), never removed by Go's
// retention.
func (s StatusRecord) TypeScript() bool { return s.line() == "typescript" }

// Go reports whether the record names a Go release: the only archives Go's
// retention removes.
func (s StatusRecord) Go() bool { return s.line() == "go" }

func (v *Verification) valid() bool {
	return v == nil || (utf16Len(v.TargetRelease) <= 100 && datetimePattern.MatchString(v.CheckedAt))
}

func (s StatusRecord) validate() error {
	ok := uuidPattern.MatchString(s.ArchiveID) && utf16Len(s.InstallationID) <= 100 && datetimePattern.MatchString(s.CreatedAt) &&
		utf16Len(s.Release) <= 100 && s.RequiredKeyVersions != nil && len(s.RequiredKeyVersions) <= 100 && s.Verification.valid()
	for _, v := range s.RequiredKeyVersions {
		ok = ok && v > 0
	}
	if d := s.Delivery; d != nil {
		ok = ok && utf16Len(d.Destination) <= 100 && datetimePattern.MatchString(d.UploadedAt) && d.RemoteVerification.valid()
	}
	if c := s.Capture; c != nil {
		ok = ok && c.Mode == "online" && c.SnapshotHeldMs >= 0 && c.DumpMs >= 0 && c.DumpBytes >= 0
	}
	ok = ok && (s.RetainUntil == "" || datetimePattern.MatchString(s.RetainUntil))
	if !ok {
		return errStatus
	}
	return nil
}

// decodeExact decodes JSON with no member the type does not name.
func decodeExact(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("backup: trailing data")
	}
	return nil
}

// SaveStatus records an archive's status (saveStatus): merged member by
// member over the previous record, whose identity (installation, creation,
// release, key versions) must not change.
func SaveStatus(dir string, s StatusRecord) error {
	if err := s.validate(); err != nil {
		return err
	}
	backups := filepath.Join(dir, "backups")
	if err := os.MkdirAll(backups, 0o700); err != nil {
		return err
	}
	path := filepath.Join(backups, s.ArchiveID+".json")
	merged := s
	if raw, err := os.ReadFile(path); err == nil {
		var prev StatusRecord
		if err := decodeExact(raw, &prev); err != nil || prev.validate() != nil {
			return errStatus
		}
		if prev.InstallationID != s.InstallationID || prev.CreatedAt != s.CreatedAt || prev.Release != s.Release || !slices.Equal(prev.RequiredKeyVersions, s.RequiredKeyVersions) {
			return &Error{"Archive identity conflict"}
		}
		if merged.Verification == nil {
			merged.Verification = prev.Verification
		}
		if merged.Delivery == nil {
			merged.Delivery = prev.Delivery
		}
		if merged.Capture == nil {
			merged.Capture = prev.Capture
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return DurableJSON(path, merged, false)
}

// DurableJSON writes v to path through a temporary file, synced, renamed
// (or, exclusive, linked: never over an existing file) into place, and the
// directory synced (durableJson).
func DurableJSON(path string, v any, exclusive bool) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	temp := fmt.Sprintf("%s.%x.tmp", path, suffix)
	f, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer os.Remove(temp)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if exclusive {
		err = os.Link(temp, path)
	} else {
		err = os.Rename(temp, path)
	}
	if err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

var statusName = regexp.MustCompile(`^[a-f0-9-]{36}\.json$`)

// Status is the backup status an Installation Admin reads (backupStatus):
// the archives' records, newest first, and the warnings. TypeScript-format
// archives (go-step7 decision 18) are listed apart, newest first: they are
// restorable through the converter, with RetainUntil when their retention's
// end is known, and none of the warnings about Go's own archives counts
// them. With none, the member is left out: the status is then exactly the
// TypeScript server's.
type Status struct {
	Archives           []StatusRecord `json:"archives"`
	TypeScriptArchives []StatusRecord `json:"typescriptArchives,omitempty"`
	Warnings           []string       `json:"warnings"`
}

const (
	day                      = 24 * time.Hour
	remoteVerificationMaxAge = 30 * day
)

func at(iso string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, iso)
	return t
}

// Lifecycle is the live database's: its installation, and when the
// database was made (schema_version's created_at: a migration's import
// makes it then; a restore keeps the archive's). A data directory can
// hold the records of an earlier database (a migration rolled back, then
// a new one, keeps Go's backups/): they are listed, but say nothing of
// whether this one's backups are recent. The zero Lifecycle holds every
// record.
type Lifecycle struct {
	InstallationID string
	Since          time.Time
}

// lifecycleSlack is how much earlier than Since a record may be dated and
// still be the database's: records keep milliseconds, and an earlier
// database's last archive is older than a new import by far more (the
// new migration's preflight, dry run and copy come between).
const lifecycleSlack = time.Minute

// At is the lifecycle as judged at now. A clock that reads earlier than
// the database's making (moved back; within lifecycleSlack is the same
// moment) says nothing of what was made since: only the installation
// counts then.
func (l Lifecycle) At(now time.Time) Lifecycle {
	if !l.Since.IsZero() && now.Before(l.Since.Add(-lifecycleSlack)) {
		l.Since = time.Time{}
	}
	return l
}

// Holds is whether the record is of this lifecycle: the same
// installation, made since the database was (within lifecycleSlack).
func (l Lifecycle) Holds(r StatusRecord) bool {
	if l.InstallationID != "" && r.InstallationID != l.InstallationID {
		return false
	}
	return l.Since.IsZero() || !at(r.CreatedAt).Before(l.Since.Add(-lifecycleSlack))
}

// ReadStatus is ReadStatusFor with the zero Lifecycle: every record
// counts.
func ReadStatus(dir string, now time.Time) (Status, error) {
	return ReadStatusFor(dir, now, Lifecycle{})
}

// ReadStatusFor reads every status record under dir and judges them as
// backupStatus does: no archive within 48 hours, the newest one not
// verified or not delivered, the latest remote check failed or older than
// 30 days, and a required Root KEK version without a key check within 30
// days. The first three count only the records life holds; every record
// is listed, and the remote and key checks cover them all (an earlier
// database's archives stay restorable, and need their keys).
func ReadStatusFor(dir string, now time.Time, life Lifecycle) (Status, error) {
	life = life.At(now)
	entries, err := os.ReadDir(filepath.Join(dir, "backups"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Status{}, err
	}
	archives, typescript := []StatusRecord{}, []StatusRecord{}
	for _, e := range entries {
		if !statusName.MatchString(e.Name()) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, "backups", e.Name()))
		if err != nil {
			return Status{}, err
		}
		var s StatusRecord
		if err := decodeExact(raw, &s); err != nil || s.validate() != nil {
			return Status{}, errStatus
		}
		if s.TypeScript() {
			typescript = append(typescript, s)
			continue
		}
		archives = append(archives, s)
	}
	newestFirst := func(a, b StatusRecord) int { return strings.Compare(b.CreatedAt, a.CreatedAt) }
	slices.SortStableFunc(archives, newestFirst)
	slices.SortStableFunc(typescript, newestFirst)
	warnings := []string{}
	var newest *StatusRecord
	for i := range archives {
		if life.Holds(archives[i]) {
			newest = &archives[i]
			break
		}
	}
	if newest == nil || now.Sub(at(newest.CreatedAt)) > 48*time.Hour {
		warnings = append(warnings, "No archive created within the last 48 hours")
	}
	if newest != nil && !newest.Verification.passed() {
		warnings = append(warnings, fmt.Sprintf("Newest archive %s has not passed verification", newest.ArchiveID))
	}
	if newest != nil && newest.Delivery == nil {
		warnings = append(warnings, fmt.Sprintf("Newest archive %s has not been delivered to a destination", newest.ArchiveID))
	}
	var remote *StatusRecord
	delivered := false
	for i := range archives {
		a := &archives[i]
		if a.Delivery == nil {
			continue
		}
		delivered = true
		if v := a.Delivery.RemoteVerification; v != nil && (remote == nil || strings.Compare(v.CheckedAt, remote.Delivery.RemoteVerification.CheckedAt) > 0) {
			remote = a
		}
	}
	if remote != nil && !remote.Delivery.RemoteVerification.passed() {
		warnings = append(warnings, fmt.Sprintf("Remote copy of %s failed retrieval and verification", remote.ArchiveID))
	} else if delivered && !(remote != nil && now.Sub(at(remote.Delivery.RemoteVerification.CheckedAt)) < remoteVerificationMaxAge) {
		warnings = append(warnings, "No remote copy has passed retrieval and verification within the last 30 days")
	}
	// The Root KEK versions every archive needs, TypeScript-format ones
	// included: converting one still needs its key.
	var versions []int
	for _, a := range slices.Concat(archives, typescript) {
		for _, v := range a.RequiredKeyVersions {
			if !slices.Contains(versions, v) {
				versions = append(versions, v)
			}
		}
	}
	for _, v := range versions {
		checked := false
		for _, a := range slices.Concat(archives, typescript) {
			if slices.Contains(a.RequiredKeyVersions, v) && a.Verification != nil && a.Verification.KeyMatch && now.Sub(at(a.Verification.CheckedAt)) < 30*day {
				checked = true
			}
		}
		if !checked {
			warnings = append(warnings, fmt.Sprintf("Root KEK version %d required by recorded archives has no successful check within 30 days; retain it while those archives exist", v))
		}
	}
	return Status{Archives: archives, TypeScriptArchives: typescript, Warnings: warnings}, nil
}

// Gate is the maintenance gate (maintenance.ts Gate): while one is open,
// the server admits no work. A capture gate is a lease (ExpiresAt, in Unix
// milliseconds); a restore gate holds until the restore completes.
type Gate struct {
	ID        string  `json:"id"`
	Kind      string  `json:"kind"`  // "capture", "restore" or "migration"
	Phase     string  `json:"phase"` // "draining", "paused" or "reconciling"; for a migration "transfer", or its barrier's "draining" and "paused"
	ExpiresAt *int64  `json:"expiresAt"`
	ArchiveID *string `json:"archiveId"`
	// FrozenPosition is a drained migration barrier's frozen point, the
	// last audit position, in decimal (maintenance.ts's frozenPosition):
	// set once the barrier is paused, absent otherwise.
	FrozenPosition *string `json:"frozenPosition,omitempty"`
}

// ErrGateUnreadable keeps the installation isolated: a gate that cannot be
// read is never taken for no gate.
var ErrGateUnreadable = &Error{"Maintenance state is unreadable; isolation remains active"}

// GateFile is the gate's file in the state directory.
const GateFile = "maintenance.json"

// frozenPosition is a frozen point's text: a position, in decimal.
var frozenPosition = regexp.MustCompile(`^(0|[1-9][0-9]{0,18})$`)

// ReadGate reads the gate, nil when there is none (readGate).
func ReadGate(dir string) (*Gate, error) {
	raw, err := os.ReadFile(filepath.Join(dir, GateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	var g Gate
	if err != nil || json.Unmarshal(raw, &g) != nil || g.ID == "" {
		return nil, ErrGateUnreadable
	}
	// A migration's gate (go-step7 decisions 6 and 12), with no expiry,
	// holds the target isolated while its address is transferred (phase
	// transfer), or, the barrier of a reverse migration, holds the
	// installation while it drains (draining) and once frozen (paused, its
	// frozen point recorded).
	migration := g.Kind == "migration" && g.ExpiresAt == nil && g.ArchiveID == nil &&
		(g.Phase == "transfer" && g.FrozenPosition == nil || g.Phase == "draining" && g.FrozenPosition == nil ||
			g.Phase == "paused" && g.FrozenPosition != nil && frozenPosition.MatchString(*g.FrozenPosition))
	if g.Kind == "migration" && !migration {
		return nil, ErrGateUnreadable
	}
	if !migration && (g.FrozenPosition != nil || !slices.Contains([]string{"capture", "restore"}, g.Kind) || !slices.Contains([]string{"draining", "paused", "reconciling"}, g.Phase) ||
		(g.Kind == "capture" && (g.ExpiresAt == nil || *g.ExpiresAt <= 0))) {
		return nil, ErrGateUnreadable
	}
	return &g, nil
}

// Active is whether a gate admits no work at now: a restore gate and a
// migration's always, a capture gate until its lease expires.
func (g *Gate) Active(now time.Time) bool {
	return g != nil && (g.Kind != "capture" || *g.ExpiresAt > now.UnixMilli())
}
