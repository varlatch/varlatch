// SPDX-License-Identifier: Apache-2.0

package release

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testImage = "ghcr.io/varlatch/varlatchd:0.52.0@sha256:" + strings.Repeat("0123456789abcdef", 4)

func verifiedTarget() Target {
	return Target{Version: "0.52.0", Verified: &VerifiedTarget{SchemaVersion: 8, CompatibleFrom: 7, RollbackSafe: true, Previous: &Previous{Version: "0.51.0", SchemaVersion: 7}, Image: testImage}}
}

// The target record (ADR-0065 Decision 3): written whole, read back
// strictly, either verified or failed, and replaced by the next.
func TestReleaseTargetRecord(t *testing.T) {
	dir := t.TempDir()
	if got, err := ReadReleaseTarget(dir); got != nil || err != nil {
		t.Fatalf("no record: %+v, %v", got, err)
	}
	at := time.Date(2026, 11, 28, 8, 0, 0, 0, time.UTC)
	if _, err := RecordReleaseTarget(dir, verifiedTarget(), at); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, ReleaseTargetFile))
	want := `{"version":"0.52.0","checkedAt":"2026-11-28T08:00:00.000Z","failed":null,"verified":{"schemaVersion":8,"compatibleFrom":7,"rollbackSafe":true,"previous":{"version":"0.51.0","schemaVersion":7},"endsRollbackWindow":false,"image":"` + testImage + `"}}` + "\n"
	if string(raw) != want {
		t.Fatalf("the record:\n%s", raw)
	}
	back, err := ReadReleaseTarget(dir)
	if err != nil || back.Verified == nil || back.CheckedAt != "2026-11-28T08:00:00.000Z" || !back.Verified.Declaration().SafeFor("0.51.0", 7) {
		t.Fatalf("read back: %+v, %v", back, err)
	}

	failed := "not-verified"
	if _, err := RecordReleaseTarget(dir, Target{Version: "0.52.1", Failed: &failed}, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if back, err := ReadReleaseTarget(dir); err != nil || back.Verified != nil || back.Failed == nil || *back.Failed != "not-verified" || back.Version != "0.52.1" {
		t.Fatalf("a failure replaces the record: %+v, %v", back, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("a temporary file was left: %v", entries)
	}

	if err := os.WriteFile(filepath.Join(dir, ReleaseTargetFile), []byte(`{"version":"0.52.0","checkedAt":"2026-11-28T08:00:00.000Z","failed":null,"verified":null,"extra":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadReleaseTarget(dir); err == nil {
		t.Fatal("an unknown member was read")
	}
}

func TestReleaseTargetRefuses(t *testing.T) {
	bad := "timeout"
	for name, mutate := range map[string]func(*Target){
		"no version":              func(t *Target) { t.Version = "latest" },
		"both":                    func(t *Target) { f := "unreachable"; t.Failed = &f },
		"neither":                 func(t *Target) { t.Verified = nil },
		"unknown failure":         func(t *Target) { t.Verified, t.Failed = nil, &bad },
		"compatibleFrom too high": func(t *Target) { t.Verified.CompatibleFrom = 9 },
		"previous is itself":      func(t *Target) { t.Verified.Previous.Version = "0.52.0" },
		"safe without previous":   func(t *Target) { t.Verified.Previous = nil },
		"another version's image": func(t *Target) { t.Verified.Image = strings.Replace(testImage, ":0.52.0@", ":0.51.0@", 1) },
		"an image by tag only":    func(t *Target) { t.Verified.Image = "ghcr.io/varlatch/varlatchd:0.52.0" },
		"another registry":        func(t *Target) { t.Verified.Image = strings.Replace(testImage, "ghcr.io", "example.com", 1) },
	} {
		tg := verifiedTarget()
		mutate(&tg)
		if _, err := RecordReleaseTarget(t.TempDir(), tg, time.Now()); err == nil {
			t.Errorf("%s: recorded", name)
		}
	}
}

// One click only for a step of one release (ADR-0065 Decision 4), as
// `varlatch upgrade` judges it.
func TestDeclarationSafeFor(t *testing.T) {
	d := verifiedTarget().Verified.Declaration()
	switch {
	case !d.DeclaredFor("0.51.0") || !d.SafeFor("0.51.0", 7):
		t.Error("a step of one release is not rollback-safe")
	case d.DeclaredFor("0.50.2") || d.SafeFor("0.50.2", 7):
		t.Error("a jump that skips 0.51.0 is rollback-safe")
	case d.SafeFor("0.51.0", 6):
		t.Error("a schema below compatibleFrom is rollback-safe")
	}
	d.RollbackSafe = false
	if d.DeclaredFor("0.51.0") {
		t.Error("a release that does not declare it is rollback-safe")
	}
}

func TestTargetFailure(t *testing.T) {
	for want, err := range map[string]error{
		"rate-limited":    errors.New("GitHub's API rate limit is exhausted"),
		"not-verified":    errors.New("the signature on SHA256SUMS does NOT verify as the release workflow of varlatch/varlatch"),
		"not-found":       errors.New("SHA256SUMS of 0.52.0 does not list varlatchd-image.txt; nothing was recorded"),
		"invalid-release": errors.New("release: release.json: unknown key"),
	} {
		if got := TargetFailure(err, false); got != want {
			t.Errorf("%v: %s, want %s", err, got, want)
		}
	}
	if got := TargetFailure(errors.New("dial tcp"), true); got != "unreachable" {
		t.Errorf("unreachable: %s", got)
	}
}
