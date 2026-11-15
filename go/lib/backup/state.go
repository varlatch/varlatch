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
}

var errStatus = errors.New("backup: an invalid status record")

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
// the archives' records, newest first, and the warnings.
type Status struct {
	Archives []StatusRecord `json:"archives"`
	Warnings []string       `json:"warnings"`
}

const (
	day                      = 24 * time.Hour
	remoteVerificationMaxAge = 30 * day
)

func at(iso string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, iso)
	return t
}

// ReadStatus reads every status record under dir and judges them as
// backupStatus does: no archive within 48 hours, the newest one not
// verified or not delivered, the latest remote check failed or older than
// 30 days, and a required Root KEK version without a key check within 30
// days.
func ReadStatus(dir string, now time.Time) (Status, error) {
	entries, err := os.ReadDir(filepath.Join(dir, "backups"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Status{}, err
	}
	archives := []StatusRecord{}
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
		archives = append(archives, s)
	}
	slices.SortStableFunc(archives, func(a, b StatusRecord) int { return strings.Compare(b.CreatedAt, a.CreatedAt) })
	warnings := []string{}
	var newest *StatusRecord
	if len(archives) > 0 {
		newest = &archives[0]
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
	var versions []int
	for _, a := range archives {
		for _, v := range a.RequiredKeyVersions {
			if !slices.Contains(versions, v) {
				versions = append(versions, v)
			}
		}
	}
	for _, v := range versions {
		checked := false
		for _, a := range archives {
			if slices.Contains(a.RequiredKeyVersions, v) && a.Verification != nil && a.Verification.KeyMatch && now.Sub(at(a.Verification.CheckedAt)) < 30*day {
				checked = true
			}
		}
		if !checked {
			warnings = append(warnings, fmt.Sprintf("Root KEK version %d required by recorded archives has no successful check within 30 days; retain it while those archives exist", v))
		}
	}
	return Status{Archives: archives, Warnings: warnings}, nil
}

// Gate is the maintenance gate (maintenance.ts Gate): while one is open,
// the server admits no work. A capture gate is a lease (ExpiresAt, in Unix
// milliseconds); a restore gate holds until the restore completes.
type Gate struct {
	ID        string  `json:"id"`
	Kind      string  `json:"kind"`  // "capture" or "restore"
	Phase     string  `json:"phase"` // "draining", "paused" or "reconciling"
	ExpiresAt *int64  `json:"expiresAt"`
	ArchiveID *string `json:"archiveId"`
}

// ErrGateUnreadable keeps the installation isolated: a gate that cannot be
// read is never taken for no gate.
var ErrGateUnreadable = &Error{"Maintenance state is unreadable; isolation remains active"}

// GateFile is the gate's file in the state directory.
const GateFile = "maintenance.json"

// ReadGate reads the gate, nil when there is none (readGate).
func ReadGate(dir string) (*Gate, error) {
	raw, err := os.ReadFile(filepath.Join(dir, GateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	var g Gate
	if err != nil || json.Unmarshal(raw, &g) != nil || g.ID == "" ||
		!slices.Contains([]string{"capture", "restore"}, g.Kind) || !slices.Contains([]string{"draining", "paused", "reconciling"}, g.Phase) ||
		(g.Kind == "capture" && (g.ExpiresAt == nil || *g.ExpiresAt <= 0)) {
		return nil, ErrGateUnreadable
	}
	return &g, nil
}

// Active is whether a gate admits no work at now: a restore gate always,
// a capture gate until its lease expires.
func (g *Gate) Active(now time.Time) bool {
	return g != nil && (g.Kind != "capture" || *g.ExpiresAt > now.UnixMilli())
}
