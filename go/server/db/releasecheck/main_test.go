// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"os"
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
	code, out, errs := runIt(t, "declaration", "--declaration", declaration)
	if code != exitOK || !strings.Contains(out, "holds: schema 1, compatible from 1, rollback-safe false, previous no previous release, reversible to 0.23.0") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	// A declaration of another schema version does not match it.
	code, _, errs = runIt(t, "declaration", "--declaration", filepath.Join(g6, "fixture.json"))
	if code != exitFailed || !strings.Contains(errs, "declares schemaVersion 2 and compatibleFrom 1; this varlatchd's schema is 1, compatible from 1") {
		t.Fatalf("%d %q", code, errs)
	}
}

func TestManifest(t *testing.T) {
	code, out, errs := runIt(t, "manifest", "--version", "0.50.0-rc.1", "--declaration", declaration)
	if code != exitOK {
		t.Fatalf("%d %q", code, errs)
	}
	m, err := release.ParseManifest([]byte(out))
	if err != nil || m.Version != "0.50.0-rc.1" || m.SchemaVersion != db.SchemaVersion || m.CompatibleFrom != db.CompatibleFrom || m.RollbackSafe || m.Previous != nil ||
		m.ManifestVersion != release.ManifestVersion || m.ReversibleTo == nil || *m.ReversibleTo != release.LastTypeScriptRelease || m.EndsRollbackWindow() {
		t.Fatalf("%+v, %v\n%s", m, err, out)
	}
	if code, _, errs := runIt(t, "manifest", "--version", "v0.50.0", "--declaration", declaration); code != exitFailed || !strings.Contains(errs, "is not a release version") {
		t.Fatalf("%d %q", code, errs)
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
	ends := write("ends.json", `{"schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null, "reversibleTo": null, "endsRollbackWindow": true}`)
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
	if err := os.WriteFile(decl, []byte(`{"schemaVersion": 2, "compatibleFrom": 2, "rollbackSafe": false, "previous": {"version": "0.0.0-g6.base", "schemaVersion": 1}, "reversibleTo": "0.23.0", "endsRollbackWindow": false}`), 0o600); err != nil {
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

func TestSchemaJSONAndNoPrevious(t *testing.T) {
	code, out, errs := runIt(t, "schema", "--previous", schemaFile, "--declaration", declaration, "--json")
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
