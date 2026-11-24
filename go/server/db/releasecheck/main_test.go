// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/server/db"
)

var (
	declaration = filepath.Join("..", "..", "..", "release", "release.json")
	g6          = filepath.Join("..", "..", "..", "release", "testdata", "g6")
	schemaFile  = filepath.Join("..", "schema.sql")
)

func runIt(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

// checkedIn is the checked-in declaration (go/release/release.json): what
// this build declares, its previous release included. The tests about this
// build take their expectations from it, so a new previous release after a
// tag is release.json's change alone.
func checkedIn(t *testing.T) release.Declaration {
	t.Helper()
	b, err := os.ReadFile(declaration)
	if err != nil {
		t.Fatal(err)
	}
	d, err := release.ParseDeclaration(b)
	if err != nil {
		t.Fatal(err)
	}
	if d.Previous == nil || d.ReversibleTo == nil {
		t.Fatalf("the checked-in declaration names no previous release or no reversibleTo: %+v", d)
	}
	return d
}

// schemaWith is schema.sql with a G6 fixture appended, as a file.
func schemaWith(t *testing.T, fixture string) string {
	t.Helper()
	base, err := os.ReadFile(schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	extra, err := os.ReadFile(filepath.Join(g6, fixture))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "schema.sql")
	if err := os.WriteFile(path, append(base, extra...), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The checked-in declaration is this build's: G6 runs this first.
func TestTheDeclarationMatchesThisBuild(t *testing.T) {
	d := checkedIn(t)
	want := fmt.Sprintf("holds: schema %d, compatible from %d, rollback-safe %v, previous %s (schema %d), reversible to %s",
		db.SchemaVersion, db.CompatibleFrom, d.RollbackSafe, d.Previous.Version, d.Previous.SchemaVersion, *d.ReversibleTo)
	code, out, errs := runIt(t, "declaration", "--declaration", declaration)
	if code != exitOK || !strings.Contains(out, want) {
		t.Fatalf("%d %q %q, want %q", code, out, errs, want)
	}
	// A declaration of another schema version does not match it.
	code, _, errs = runIt(t, "declaration", "--declaration", filepath.Join(g6, "fixture.json"))
	if code != exitFailed || !strings.Contains(errs, "declares schemaVersion 5 and compatibleFrom 1; this varlatchd's schema is 4, compatible from 1") {
		t.Fatalf("%d %q", code, errs)
	}
}

func TestManifest(t *testing.T) {
	d := checkedIn(t)
	// A version that is not the previous release's: the next one's stand-in.
	next := "0.50.0"
	if d.Previous.Version == next {
		next = "0.50.1"
	}
	code, out, errs := runIt(t, "manifest", "--version", next, "--declaration", declaration)
	if code != exitOK {
		t.Fatalf("%d %q", code, errs)
	}
	m, err := release.ParseManifest([]byte(out))
	if err != nil || m.Version != next || m.SchemaVersion != db.SchemaVersion || m.CompatibleFrom != db.CompatibleFrom || m.RollbackSafe != d.RollbackSafe ||
		m.Previous == nil || *m.Previous != *d.Previous ||
		m.ManifestVersion != release.ManifestVersion || m.ReversibleTo == nil || *m.ReversibleTo != release.LastTypeScriptRelease || m.EndsRollbackWindow() {
		t.Fatalf("%+v, %v\n%s", m, err, out)
	}
	if code, _, errs := runIt(t, "manifest", "--version", "v0.50.0", "--declaration", declaration); code != exitFailed || !strings.Contains(errs, "is not a release version") {
		t.Fatalf("%d %q", code, errs)
	}
	// The previous release itself is not a manifest of this declaration.
	if code, _, errs := runIt(t, "manifest", "--version", d.Previous.Version, "--declaration", declaration); code != exitFailed || !strings.Contains(errs, "the previous release is this one") {
		t.Fatalf("the previous release's version: %d %q", code, errs)
	}
}

// TestADeclarationWithoutTheWindowFails: the release check refuses a
// declaration that says nothing of the rollback window, and states one that
// ends it (go-step7.md decision 17).
func TestADeclarationWithoutTheWindowFails(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	neither := write("neither.json", `{"schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null, "reversibleTo": null, "endsRollbackWindow": false}`)
	if code, _, errs := runIt(t, "declaration", "--declaration", neither); code != exitFailed || !strings.Contains(errs, "neither reversibleTo nor endsRollbackWindow") {
		t.Fatalf("%d %q", code, errs)
	}
	missing := write("missing.json", `{"schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null}`)
	if code, _, errs := runIt(t, "manifest", "--version", "0.50.0", "--declaration", missing); code != exitFailed || !strings.Contains(errs, `no "reversibleTo"`) {
		t.Fatalf("%d %q", code, errs)
	}
	ends := write("ends.json", fmt.Sprintf(`{"schemaVersion": %d, "compatibleFrom": %d, "rollbackSafe": false, "previous": null, "reversibleTo": null, "endsRollbackWindow": true}`, db.SchemaVersion, db.CompatibleFrom))
	if code, out, errs := runIt(t, "declaration", "--declaration", ends); code != exitOK || !strings.Contains(out, "ends the rollback window") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
}

// G6's positive fixture: the g6fixture build's change (additive.sql),
// declared rollback-safe against a previous schema of version 1.
func TestARollbackSafeAdditionPasses(t *testing.T) {
	code, out, errs := runIt(t, "schema", "--previous", schemaFile, "--current", schemaWith(t, "additive.sql"), "--declaration", filepath.Join(g6, "fixture.json"))
	if code != exitOK || !strings.Contains(out, "2 schema changes, rollback-safe true") || strings.Contains(out, "PROBLEM") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
}

// G6's negative fixtures: what fails the job.
func TestAnUndeclaredBreakFails(t *testing.T) {
	code, out, errs := runIt(t, "schema", "--previous", schemaFile, "--current", schemaWith(t, "breaking.sql"), "--declaration", filepath.Join(g6, "fixture.json"))
	if code != exitFailed || !strings.Contains(out, "PROBLEM: declared rollback-safe against 0.0.0-g6.base, but breaking: trigger g6_breaking_no_new_identities: a new trigger on the existing table identities") ||
		!strings.Contains(errs, "1 problems: the declaration does not hold") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	// The same change declared not rollback-safe is a note, not a failure.
	decl := filepath.Join(t.TempDir(), "release.json")
	if err := os.WriteFile(decl, []byte(`{"schemaVersion": 2, "compatibleFrom": 2, "rollbackSafe": false, "previous": {"version": "0.0.0-g6.base", "schemaVersion": 1}, "reversibleTo": "0.23.1", "endsRollbackWindow": false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := runIt(t, "schema", "--previous", schemaFile, "--current", schemaWith(t, "breaking.sql"), "--declaration", decl); code != exitOK || !strings.Contains(out, "note: breaking: trigger") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
}

func TestAChangedSchemaMustRaiseItsVersion(t *testing.T) {
	code, out, _ := runIt(t, "schema", "--previous", schemaFile, "--current", schemaWith(t, "additive.sql"), "--declaration", filepath.Join(g6, "unbumped.json"))
	if code != exitFailed || !strings.Contains(out, "PROBLEM: the schema changed since 0.0.0-g6.base, but its version is still 1") {
		t.Fatalf("%d %q", code, out)
	}
}

// The checked-in declaration holds against its previous release's schema.
// While the schema's version is still the previous release's (as right after
// a tag), that schema is this one's: no change, no problem. Once a change
// raises the version, the previous schema is the release tag's file, which
// CI's G6 step fetches; here it is read from the tag when this clone has
// it, and the case is skipped when it has not.
func TestTheDeclarationHoldsAgainstThePreviousRelease(t *testing.T) {
	d := checkedIn(t)
	previous := schemaFile
	if d.Previous.SchemaVersion != db.SchemaVersion {
		b, err := exec.Command("git", "show", "v"+d.Previous.Version+":go/server/db/schema.sql").Output()
		if err != nil {
			t.Skipf("the schema changed since %s, and this clone has not its tag (CI's G6 step checks against it): %v", d.Previous.Version, err)
		}
		previous = filepath.Join(t.TempDir(), "previous-schema.sql")
		if err := os.WriteFile(previous, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errs := runIt(t, "schema", "--previous", previous, "--declaration", declaration, "--json")
	var doc struct {
		Previous string            `json:"previous"`
		Changes  []json.RawMessage `json:"changes"`
		Problems []string          `json:"problems"`
	}
	want := fmt.Sprintf("%s (schema %d)", d.Previous.Version, d.Previous.SchemaVersion)
	if code != exitOK || json.Unmarshal([]byte(out), &doc) != nil || doc.Previous != want || len(doc.Problems) != 0 ||
		d.Previous.SchemaVersion == db.SchemaVersion && len(doc.Changes) != 0 {
		t.Fatalf("%d %q %q", code, out, errs)
	}
}

// The additive change between two real releases, with a declaration of its
// own: 0.50.0-rc.2's schema (version 2, the certificate issuances) against
// 0.50.0-rc.1's (version 1), both as their tags have them (testdata),
// declared rollback-safe. It does not depend on the checked-in declaration
// or on today's schema.
func TestAnAdditionBetweenTwoReleasesHolds(t *testing.T) {
	decl := filepath.Join(t.TempDir(), "release.json")
	if err := os.WriteFile(decl, []byte(`{"schemaVersion": 2, "compatibleFrom": 1, "rollbackSafe": true, "previous": {"version": "0.50.0-rc.1", "schemaVersion": 1}, "reversibleTo": "0.23.1", "endsRollbackWindow": false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runIt(t, "schema", "--previous", filepath.Join("testdata", "schema-0.50.0-rc.1.sql"), "--current", filepath.Join("testdata", "schema-0.50.0-rc.2.sql"), "--declaration", decl, "--json")
	var doc struct {
		Previous string            `json:"previous"`
		Changes  []json.RawMessage `json:"changes"`
		Problems []string          `json:"problems"`
	}
	if code != exitOK || json.Unmarshal([]byte(out), &doc) != nil || doc.Previous != "0.50.0-rc.1 (schema 1)" || len(doc.Changes) != 2 || len(doc.Problems) != 0 {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	// The same change unbumped (version still 1) is refused.
	unbumped := filepath.Join(t.TempDir(), "unbumped.json")
	if err := os.WriteFile(unbumped, []byte(`{"schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": true, "previous": {"version": "0.50.0-rc.1", "schemaVersion": 1}, "reversibleTo": "0.23.1", "endsRollbackWindow": false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runIt(t, "schema", "--previous", filepath.Join("testdata", "schema-0.50.0-rc.1.sql"), "--current", filepath.Join("testdata", "schema-0.50.0-rc.2.sql"), "--declaration", unbumped)
	if code != exitFailed || !strings.Contains(out, "PROBLEM: the schema changed since 0.50.0-rc.1, but its version is still 1") {
		t.Fatalf("unbumped: %d %q", code, out)
	}
}

func TestSchemaJSONAndNoPrevious(t *testing.T) {
	// A declaration without a previous release (as before the first Go
	// release): the schema is held against none.
	decl := filepath.Join(t.TempDir(), "release.json")
	if err := os.WriteFile(decl, []byte(fmt.Sprintf(`{"schemaVersion": %d, "compatibleFrom": %d, "rollbackSafe": false, "previous": null, "reversibleTo": %q, "endsRollbackWindow": false}`, db.SchemaVersion, db.CompatibleFrom, release.LastTypeScriptRelease)), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runIt(t, "schema", "--previous", schemaFile, "--declaration", decl, "--json")
	if code != exitOK {
		t.Fatalf("%d %q", code, errs)
	}
	var doc struct {
		Previous string            `json:"previous"`
		Changes  []json.RawMessage `json:"changes"`
		Problems []string          `json:"problems"`
		Notes    []string          `json:"notes"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Previous != "no previous release" || len(doc.Changes) != 0 || doc.Problems == nil || len(doc.Problems) != 0 ||
		len(doc.Notes) != 1 || doc.Notes[0] != "no previous Go release: the schema is not held against one" {
		t.Fatalf("%+v, %v\n%s", doc, err, out)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{
		nil, {"publish"}, {"manifest"}, {"schema"}, {"declaration", "--version", "1.0.0"},
		{"schema", "--previous", schemaFile, "--version", "1.0.0"}, {"declaration", "extra"}, {"declaration", "--nope"},
	} {
		if code, _, _ := runIt(t, args...); code != exitUsage {
			t.Errorf("%q: %d", args, code)
		}
	}
	if code, _, errs := runIt(t, "declaration", "--declaration", "missing.json"); code != exitFailed || !strings.Contains(errs, "missing.json") {
		t.Fatalf("%d %q", code, errs)
	}
}

// previous: release.json's previous release is the last Go release among
// the tags reachable from HEAD, by semantic version; the TypeScript
// server's tags (below 0.50.0) and lines that are no release tag do not
// count. G6's static step runs it on `git tag --merged HEAD -l 'v*'`.
func TestPreviousIsTheLastRelease(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	decl := func(previous string) string {
		prev := "null"
		if previous != "" {
			prev = fmt.Sprintf(`{"version": %q, "schemaVersion": 1}`, previous)
		}
		return write("release-"+previous+".json", fmt.Sprintf(`{"schemaVersion": 2, "compatibleFrom": 1, "rollbackSafe": %t, "previous": %s, "reversibleTo": %q, "endsRollbackWindow": false}`, previous != "", prev, release.LastTypeScriptRelease))
	}
	for _, c := range []struct {
		previous, tags string
		ok             bool
		newest         string
	}{
		{"0.50.0-rc.1", "v0.22.4\nv0.23.0\nv0.50.0-rc.1\nnot-a-tag\nv1\n", true, ""},
		{"0.50.0-rc.1", "v0.50.0-rc.1\nv0.50.0-rc.2\n", false, "v0.50.0-rc.2"},
		{"0.50.0-rc.9", "v0.50.0-rc.9\nv0.50.0-rc.10\n", false, "v0.50.0-rc.10"},
		{"0.50.0-rc.10", "v0.50.0-rc.9\nv0.50.0-rc.10\n", true, ""},
		{"0.50.0-rc.3", "v0.50.0-rc.3\nv0.50.0\n", false, "v0.50.0"},
		{"0.50.1", "v0.50.0\nv0.50.1\nv0.50.0-rc.12\n", true, ""},
		{"", "v0.22.4\nv0.23.0\n", true, ""},
		{"", "v0.23.0\nv0.50.0-rc.1\n", false, "v0.50.0-rc.1"},
	} {
		code, out, errs := runIt(t, "previous", "--tags", write("tags", c.tags), "--declaration", decl(c.previous))
		if c.ok != (code == exitOK) || !c.ok && !strings.Contains(errs, ": "+c.newest) {
			t.Errorf("previous %q, tags %q: %d %q %q", c.previous, c.tags, code, out, errs)
		}
	}
	if code, _, _ := runIt(t, "previous"); code != exitUsage {
		t.Errorf("previous without --tags: %d", code)
	}
}
