// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// A record's release line: TypeScript below 0.50 (go-step7 decision 18,
// the Go line starting at 0.50), Go from it, neither for a release that is
// not a version.
func TestReleaseLine(t *testing.T) {
	for _, c := range []struct {
		release string
		ts, go_ bool
	}{
		{"0.7.0", true, false},
		{"0.22.4", true, false},
		{"0.23.0", true, false},
		{"0.49.9", true, false},
		{"0.50.0", false, true},
		{"0.50.0-dev", false, true},
		{"0.50.0-rc.2", false, true},
		{"1.0.0", false, true},
		{"", false, false},
		{"dev", false, false},
		{"v0.22.4", false, false},
		// Too large to read: neither, so retention keeps it.
		{"0.99999999999999999999.0", false, false},
		{"99999999999999999999.0.0", false, false},
	} {
		r := StatusRecord{Release: c.release}
		if r.TypeScript() != c.ts || r.Go() != c.go_ {
			t.Errorf("%q: TypeScript %t, Go %t", c.release, r.TypeScript(), r.Go())
		}
	}
}

// TypeScript-format archives are listed apart, newest first, with their
// retention's end when known, and no warning about Go's own archives counts
// them; converting one still needs its Root KEK, so the key's warning does.
func TestStatusListsTypeScriptArchivesApart(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	iso := func(d time.Duration) string { return now.Add(d).Format("2006-01-02T15:04:05.000Z") }
	checked := &Verification{Integrity: true, Compatibility: true, KeyMatch: true, CheckedAt: iso(-time.Hour), TargetRelease: "0.23.0"}
	records := []StatusRecord{
		// The newest record is TypeScript's: it does not stand for a recent archive.
		{ArchiveID: "00000000-0000-4000-8000-000000000001", InstallationID: "inst_a", CreatedAt: iso(-time.Hour), Release: "0.23.0", RequiredKeyVersions: []int{1},
			Verification: checked, RetainUntil: iso(90 * 24 * time.Hour)},
		{ArchiveID: "00000000-0000-4000-8000-000000000002", InstallationID: "inst_a", CreatedAt: iso(-30 * 24 * time.Hour), Release: "0.22.4", RequiredKeyVersions: []int{1}},
		{ArchiveID: "00000000-0000-4000-8000-000000000003", InstallationID: "inst_a", CreatedAt: iso(-72 * time.Hour), Release: "0.50.0", RequiredKeyVersions: []int{1}},
	}
	for _, r := range records {
		if err := SaveStatus(dir, r); err != nil {
			t.Fatal(err)
		}
	}
	st, err := ReadStatus(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	ids := func(rs []StatusRecord) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.ArchiveID)
		}
		return out
	}
	if got := ids(st.Archives); !slices.Equal(got, []string{records[2].ArchiveID}) {
		t.Errorf("archives %v", got)
	}
	if got := ids(st.TypeScriptArchives); !slices.Equal(got, []string{records[0].ArchiveID, records[1].ArchiveID}) {
		t.Errorf("typescriptArchives %v", got)
	}
	if st.TypeScriptArchives[0].RetainUntil != records[0].RetainUntil || st.TypeScriptArchives[1].RetainUntil != "" {
		t.Errorf("retainUntil %+v", st.TypeScriptArchives)
	}
	for _, want := range []string{
		"No archive created within the last 48 hours",
		"Newest archive " + records[2].ArchiveID + " has not passed verification",
	} {
		if !slices.Contains(st.Warnings, want) {
			t.Errorf("warnings %q lack %q", st.Warnings, want)
		}
	}
	// The TypeScript archive's key check counts for the key both lines need.
	for _, w := range st.Warnings {
		if w == "Root KEK version 1 required by recorded archives has no successful check within 30 days; retain it while those archives exist" {
			t.Errorf("warnings %q", st.Warnings)
		}
	}
	// The member is there with TypeScript archives, and left out without
	// any: the status is then exactly the TypeScript server's.
	raw, _ := json.Marshal(st)
	if !strings.Contains(string(raw), `"typescriptArchives":[{"archiveId":"`+records[0].ArchiveID+`"`) {
		t.Errorf("%s", raw)
	}
	raw, _ = json.Marshal(Status{Archives: []StatusRecord{}, TypeScriptArchives: []StatusRecord{}, Warnings: []string{}})
	if string(raw) != `{"archives":[],"warnings":[]}` {
		t.Errorf("%s", raw)
	}

	// A record whose retainUntil is not a date is refused, as any invalid record is.
	bad := records[1]
	bad.ArchiveID = "00000000-0000-4000-8000-000000000004"
	bad.RetainUntil = "next year"
	if err := SaveStatus(dir, bad); !errors.Is(err, errStatus) {
		t.Errorf("SaveStatus: %v", err)
	}
	raw, _ = json.Marshal(bad)
	if err := os.WriteFile(filepath.Join(dir, "backups", bad.ArchiveID+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStatus(dir, now); !errors.Is(err, errStatus) {
		t.Errorf("ReadStatus: %v", err)
	}
}

// An earlier database's records (a migration rolled back, its old data
// deleted, then a new one: Go's backups/ kept) are listed, but do not make
// this database's backups recent nor stand for its newest archive; another
// installation's neither. The zero Lifecycle counts every record, as
// before.
func TestStatusCountsOnlyTheLiveDatabasesArchives(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	iso := func(d time.Duration) string { return now.Add(d).Format("2006-01-02T15:04:05.000Z") }
	checked := &Verification{Integrity: true, Compatibility: true, KeyMatch: true, CheckedAt: iso(-2 * time.Hour), TargetRelease: "0.50.0"}
	delivered := &Delivery{Destination: "b2", UploadedAt: iso(-2 * time.Hour), RemoteVerification: checked}
	// The earlier migration's final archive, two hours old: verified and
	// delivered, of the same installation.
	old := StatusRecord{ArchiveID: "00000000-0000-4000-8000-000000000001", InstallationID: "inst_a", CreatedAt: iso(-2 * time.Hour), Release: "0.50.0",
		RequiredKeyVersions: []int{1}, Verification: checked, Delivery: delivered}
	if err := SaveStatus(dir, old); err != nil {
		t.Fatal(err)
	}
	// The zero Lifecycle: as before, the old archive is recent.
	st, err := ReadStatus(dir, now)
	if err != nil || len(st.Warnings) != 0 || len(st.Archives) != 1 {
		t.Fatalf("every record: %+v %v", st, err)
	}
	// The new database, imported an hour ago: no archive of its own yet.
	life := Lifecycle{InstallationID: "inst_a", Since: now.Add(-time.Hour)}
	if life.Holds(old) {
		t.Fatal("the earlier database's archive is held")
	}
	st, err = ReadStatusFor(dir, now, life)
	if err != nil || len(st.Archives) != 1 || !slices.Contains(st.Warnings, "No archive created within the last 48 hours") {
		t.Fatalf("after the import: %+v %v", st, err)
	}
	// Its own first archive, not yet verified: it is the newest, the 48
	// hours are met.
	own := StatusRecord{ArchiveID: "00000000-0000-4000-8000-000000000002", InstallationID: "inst_a", CreatedAt: iso(-time.Minute), Release: "0.50.0", RequiredKeyVersions: []int{1}}
	if err := SaveStatus(dir, own); err != nil {
		t.Fatal(err)
	}
	st, err = ReadStatusFor(dir, now, life)
	if err != nil || slices.Contains(st.Warnings, "No archive created within the last 48 hours") ||
		!slices.Contains(st.Warnings, "Newest archive "+own.ArchiveID+" has not passed verification") || len(st.Archives) != 2 {
		t.Fatalf("its own archive: %+v %v", st, err)
	}
	// Within a minute of the making (records keep milliseconds) it is
	// held; a clock moved back before the making judges by installation
	// only.
	if !life.Holds(StatusRecord{InstallationID: "inst_a", CreatedAt: now.Add(-time.Hour - 30*time.Second).Format("2006-01-02T15:04:05.000Z")}) {
		t.Fatal("an archive made within the slack is not held")
	}
	if life.At(now.Add(-3*time.Hour)).Since != (time.Time{}) || !life.At(now.Add(-3*time.Hour)).Holds(old) || life.At(now).Since != life.Since || life.At(life.Since.Add(-time.Second)).Since != life.Since {
		t.Fatal("At with the clock moved back")
	}
	// Another installation's record is not this one's, whenever made.
	if (Lifecycle{InstallationID: "inst_b"}).Holds(own) || !(Lifecycle{}).Holds(own) || !(Lifecycle{InstallationID: "inst_a"}).Holds(old) {
		t.Fatal("Holds by installation")
	}
}
