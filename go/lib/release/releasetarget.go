// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
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

// ReleaseTargetFile is the host's last verification of the release its
// check found newer (ADR-0065 Decision 3), in the data directory beside
// ReleaseCheckFile: `varlatch upgrade --check` downloads that release's
// SHA256SUMS, its signature, release.json and varlatchd-image.txt,
// verifies them as an upgrade would, and records what they declare through
// `varlatchd admin release-check record-target`. varlatchd only reads it,
// for the Release tab's pre-flight. Display state, not authority: an
// upgrade verifies the release again from scratch.
//
// It is a file of its own, not a member of the release check's record: a
// release before this one reads that record strictly, and would call it
// unreadable after an undo or a rollback to it.
const ReleaseTargetFile = "release-target.json"

// TargetFailures are the reasons a target could not be verified: GitHub
// unreachable or rate-limited, an asset missing (not-found), the
// signature or a checksum not as the release workflow's (not-verified), or
// a release.json or varlatchd-image.txt that is not the release's
// (invalid-release).
var TargetFailures = []string{"unreachable", "rate-limited", "not-found", "not-verified", "invalid-release"}

// imageReference is a varlatchd image's tag of one version with its index
// digest, as go/release/check-assets.sh accepts varlatchd-image.txt.
var imageReference = regexp.MustCompile(`^ghcr\.io/[a-z0-9]+(?:[._-][a-z0-9]+)*/varlatchd:([0-9A-Za-z.+-]+)@sha256:[0-9a-f]{64}$`)

// ValidImageReference reports whether ref is varlatchd-image.txt's
// reference for version: ghcr.io/<owner>/varlatchd:<version>@sha256:<digest>.
func ValidImageReference(version, ref string) bool {
	m := imageReference.FindStringSubmatch(ref)
	return m != nil && m[1] == version && len(ref) <= 300
}

// VerifiedTarget is what a verified release declares: its release.json's
// declaration (format 1's reads as ending nothing) and its image.
type VerifiedTarget struct {
	SchemaVersion      int64     `json:"schemaVersion"`
	CompatibleFrom     int64     `json:"compatibleFrom"`
	RollbackSafe       bool      `json:"rollbackSafe"`
	Previous           *Previous `json:"previous"`
	EndsRollbackWindow bool      `json:"endsRollbackWindow"`
	Image              string    `json:"image"`
}

// Declaration is the target's declaration, for DeclaredFor and SafeFor.
func (v VerifiedTarget) Declaration() Declaration {
	return Declaration{SchemaVersion: v.SchemaVersion, CompatibleFrom: v.CompatibleFrom, RollbackSafe: v.RollbackSafe, Previous: v.Previous, EndsRollbackWindow: v.EndsRollbackWindow}
}

// VerifiedTargetOf is what manifest m and image reference image (verified
// against the same signed SHA256SUMS) declare.
func VerifiedTargetOf(m Manifest, image string) VerifiedTarget {
	return VerifiedTarget{SchemaVersion: m.SchemaVersion, CompatibleFrom: m.CompatibleFrom, RollbackSafe: m.RollbackSafe, Previous: m.Previous, EndsRollbackWindow: m.EndsRollbackWindow(), Image: image}
}

// Target is the record: the release, when it was checked, and either what
// it declares (Verified) or why it could not be verified (Failed).
type Target struct {
	Version   string          `json:"version"`
	CheckedAt string          `json:"checkedAt"`
	Failed    *string         `json:"failed"`
	Verified  *VerifiedTarget `json:"verified"`
}

func (t Target) check() error {
	if len(t.Version) > 100 || !ValidVersion(t.Version) {
		return fmt.Errorf("release target: %q is not a release version", t.Version)
	}
	if t.CheckedAt != "" {
		if _, err := time.Parse(time.RFC3339, t.CheckedAt); err != nil {
			return errors.New("release target: checkedAt is not a date and time")
		}
	}
	switch {
	case (t.Failed == nil) == (t.Verified == nil):
		return errors.New("release target: a target is verified or failed, one of them")
	case t.Failed != nil && !slices.Contains(TargetFailures, *t.Failed):
		return fmt.Errorf("release target: %q is not a failure the record knows", *t.Failed)
	case t.Failed != nil:
		return nil
	}
	v := t.Verified
	if v.SchemaVersion < 1 || v.CompatibleFrom < 1 || v.CompatibleFrom > v.SchemaVersion {
		return fmt.Errorf("release target: compatibleFrom %d is not between 1 and schemaVersion %d", v.CompatibleFrom, v.SchemaVersion)
	}
	if p := v.Previous; p != nil && (!ValidVersion(p.Version) || p.Version == t.Version || p.SchemaVersion < 1) {
		return errors.New("release target: previous is not an earlier release")
	}
	if v.RollbackSafe && v.Previous == nil {
		return errors.New("release target: rollbackSafe without a previous release")
	}
	if !ValidImageReference(t.Version, v.Image) {
		return fmt.Errorf("release target: %q is not a varlatchd image of %s", v.Image, t.Version)
	}
	return nil
}

// ReadReleaseTarget reads the record: nil when none was ever recorded, an
// error when it is unreadable.
func ReadReleaseTarget(dir string) (*Target, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ReleaseTargetFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var t Target
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("release target: %s is not a release target: %w", ReleaseTargetFile, err)
	}
	if t.CheckedAt == "" {
		return nil, errors.New("release target: no checkedAt")
	}
	if err := t.check(); err != nil {
		return nil, err
	}
	return &t, nil
}

// RecordReleaseTarget records t, checked at now, durably, replacing the
// record before it whatever it was.
func RecordReleaseTarget(dir string, t Target, now time.Time) (*Target, error) {
	t.CheckedAt = ""
	if err := t.check(); err != nil {
		return nil, err
	}
	t.CheckedAt = now.UTC().Format("2006-01-02T15:04:05.000Z")
	b, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	if err := WriteDurably(filepath.Join(dir, ReleaseTargetFile), append(b, '\n'), 0o644); err != nil && !errors.Is(err, ErrNotDurable) {
		return nil, err
	}
	return &t, nil
}

// TargetFailure names why a target could not be verified, from the error
// the download and verification gave (unreachable is the error's own
// account, from the selfupdate package's Error).
func TargetFailure(err error, unreachable bool) string {
	text := err.Error()
	switch {
	case unreachable:
		return "unreachable"
	case strings.Contains(text, "rate limit"):
		return "rate-limited"
	case strings.Contains(text, "does NOT verify"), strings.Contains(text, "does not match SHA256SUMS"):
		return "not-verified"
	case strings.Contains(text, "no release"), strings.Contains(text, "has no signature"), strings.Contains(text, "does not list"):
		return "not-found"
	}
	return "invalid-release"
}
