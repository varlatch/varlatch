// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	if code != exitOK || !strings.Contains(out, "holds: schema 2, compatible from 1, rollback-safe true, previous 0.50.0-rc.1 (schema 1)") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	// A declaration of another schema version does not match it.
	code, _, errs = runIt(t, "declaration", "--declaration", filepath.Join(g6, "fixture.json"))
	if code != exitFailed || !strings.Contains(errs, "declares schemaVersion 3 and compatibleFrom 1; this varlatchd's schema is 2, compatible from 1") {
		t.Fatalf("%d %q", code, errs)
	}
}

func TestManifest(t *testing.T) {
	code, out, errs := runIt(t, "manifest", "--version", "0.50.0-rc.2", "--declaration", declaration)
	if code != exitOK {
		t.Fatalf("%d %q", code, errs)
	}
	m, err := release.ParseManifest([]byte(out))
	if err != nil || m.Version != "0.50.0-rc.2" || m.SchemaVersion != db.SchemaVersion || m.CompatibleFrom != db.CompatibleFrom || !m.RollbackSafe ||
		m.Previous == nil || m.Previous.Version != "0.50.0-rc.1" || m.Previous.SchemaVersion != 1 {
		t.Fatalf("%+v, %v\n%s", m, err, out)
	}
	if code, _, errs := runIt(t, "manifest", "--version", "v0.50.0", "--declaration", declaration); code != exitFailed || !strings.Contains(errs, "is not a release version") {
		t.Fatalf("%d %q", code, errs)
	}
	// The previous release itself is not a manifest of this declaration.
	if code, _, errs := runIt(t, "manifest", "--version", "0.50.0-rc.1", "--declaration", declaration); code != exitFailed || !strings.Contains(errs, "the previous release is this one") {
		t.Fatalf("the previous release's version: %d %q", code, errs)
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
	if err := os.WriteFile(decl, []byte(`{"schemaVersion": 2, "compatibleFrom": 2, "rollbackSafe": false, "previous": {"version": "0.0.0-g6.base", "schemaVersion": 1}}`), 0o600); err != nil {
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

// The checked-in declaration holds against 0.50.0-rc.1's schema (what
// schema.sql held before version 2's section; CI's G6 job checks against
// the tag's own file): an addition, declared rollback-safe.
func TestTheDeclarationHoldsAgainstRC1(t *testing.T) {
	current, err := os.ReadFile(schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(current), "\n-- Certificate issuances for the public HTTPS name")
	if i < 0 {
		t.Fatal("schema.sql has no certificate_issuances section")
	}
	rc1 := filepath.Join(t.TempDir(), "rc1-schema.sql")
	if err := os.WriteFile(rc1, current[:i+1], 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runIt(t, "schema", "--previous", rc1, "--declaration", declaration, "--json")
	var doc struct {
		Previous string            `json:"previous"`
		Changes  []json.RawMessage `json:"changes"`
		Problems []string          `json:"problems"`
	}
	if code != exitOK || json.Unmarshal([]byte(out), &doc) != nil || doc.Previous != "0.50.0-rc.1 (schema 1)" || len(doc.Changes) != 2 || len(doc.Problems) != 0 {
		t.Fatalf("%d %q %q", code, out, errs)
	}
}

func TestSchemaJSONAndNoPrevious(t *testing.T) {
	// A declaration without a previous release (as before the first Go
	// release): the schema is held against none.
	decl := filepath.Join(t.TempDir(), "release.json")
	if err := os.WriteFile(decl, []byte(fmt.Sprintf(`{"schemaVersion": %d, "compatibleFrom": %d, "rollbackSafe": false, "previous": null}`, db.SchemaVersion, db.CompatibleFrom)), 0o600); err != nil {
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
		return write("release-"+previous+".json", fmt.Sprintf(`{"schemaVersion": 2, "compatibleFrom": 1, "rollbackSafe": %t, "previous": %s}`, previous != "", prev))
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
