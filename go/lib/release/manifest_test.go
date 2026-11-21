// SPDX-License-Identifier: Apache-2.0

package release

import (
	"strings"
	"testing"
)

// decl is a declaration that keeps the rollback window (reversibleTo the
// last TypeScript release), so the schema rules are what a case tests.
func decl(schema, compatible int64, safe bool, prev *Previous) Declaration {
	ts := LastTypeScriptRelease
	return Declaration{SchemaVersion: schema, CompatibleFrom: compatible, RollbackSafe: safe, Previous: prev, ReversibleTo: &ts}
}

func TestDeclarationRules(t *testing.T) {
	prev := func(v string, n int64) *Previous { return &Previous{Version: v, SchemaVersion: n} }
	for _, c := range []struct {
		name string
		d    Declaration
		want string // "" for valid
	}{
		{"the first release", decl(1, 1, false, nil), ""},
		{"rollback-safe, schema unchanged", decl(1, 1, true, prev("0.50.0-rc.1", 1)), ""},
		{"rollback-safe, schema added to", decl(2, 1, true, prev("0.50.0-rc.1", 1)), ""},
		{"not rollback-safe, raised", decl(2, 2, false, prev("0.50.0-rc.1", 1)), ""},

		{"no schema version", decl(0, 0, false, nil), "schemaVersion 0 is not 1 or more"},
		{"compatibleFrom above the schema", decl(1, 2, false, nil), "compatibleFrom 2 is not between 1 and schemaVersion 1"},
		{"compatibleFrom 0", decl(1, 0, false, nil), "compatibleFrom 0 is not between 1"},
		{"rollback-safe with nothing before", decl(1, 1, true, nil), "rollbackSafe without a previous release"},
		{"a previous version that is not one", decl(1, 1, true, prev("v0.50.0", 1)), `the previous release's version "v0.50.0" is not a release version`},
		{"a previous schema above this one", decl(1, 1, true, prev("0.50.0", 2)), "the previous release's schemaVersion 2 is not between 1 and 1"},
		{"rollback-safe, but the previous release is kept out", decl(2, 2, true, prev("0.50.0", 1)), "rollbackSafe, but compatibleFrom 2 keeps 0.50.0's varlatchd (schema 1) out"},
		{"not rollback-safe, but the previous release still opens it", decl(1, 1, false, prev("0.50.0", 1)), "not rollbackSafe, but compatibleFrom 1 lets 0.50.0's varlatchd (schema 1) open the database"},
	} {
		err := c.d.Check()
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// TestTheRollbackWindowIsDeclared: a release keeps the window (reversibleTo
// the last TypeScript release) or ends it (endsRollbackWindow), exactly one
// of them; one that declares neither fails (go-step7.md decision 17).
func TestTheRollbackWindowIsDeclared(t *testing.T) {
	other := "0.22.4"
	keeps := decl(1, 1, false, nil)
	ends := keeps
	ends.ReversibleTo, ends.EndsRollbackWindow = nil, true
	neither := keeps
	neither.ReversibleTo = nil
	both := keeps
	both.EndsRollbackWindow = true
	wrong := keeps
	wrong.ReversibleTo = &other
	for _, c := range []struct {
		name string
		d    Declaration
		want string
	}{
		{"keeps the window", keeps, ""},
		{"ends the window", ends, ""},
		{"declares neither", neither, "neither reversibleTo nor endsRollbackWindow"},
		{"declares both", both, "both set"},
		{"reversible to another release", wrong, `reversibleTo "0.22.4" is not the last TypeScript release, 0.23.0`},
	} {
		err := c.d.Check()
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestParseDeclaration(t *testing.T) {
	d, err := ParseDeclaration([]byte(`{"schemaVersion": 2, "compatibleFrom": 1, "rollbackSafe": true, "previous": {"version": "0.50.0-rc.1", "schemaVersion": 1}, "reversibleTo": "0.23.0", "endsRollbackWindow": false}`))
	if err != nil || d.SchemaVersion != 2 || !d.RollbackSafe || d.Previous == nil || d.Previous.Version != "0.50.0-rc.1" || d.ReversibleTo == nil || *d.ReversibleTo != "0.23.0" {
		t.Fatalf("%+v, %v", d, err)
	}
	const tail = `, "reversibleTo": "0.23.0", "endsRollbackWindow": false}`
	for _, c := range []struct{ name, json, want string }{
		{"a missing key", `{"schemaVersion": 1, "compatibleFrom": 1, "previous": null` + tail, `no "rollbackSafe"`},
		{"no reversibleTo", `{"schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null, "endsRollbackWindow": false}`, `no "reversibleTo"`},
		{"no endsRollbackWindow", `{"schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null, "reversibleTo": "0.23.0"}`, `no "endsRollbackWindow"`},
		{"neither declared", `{"schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null, "reversibleTo": null, "endsRollbackWindow": false}`, "neither reversibleTo nor endsRollbackWindow"},
		{"an unknown key", `{"schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null, "note": "x"` + tail, `an unknown key "note"`},
		{"an unknown key in previous", `{"schemaVersion": 2, "compatibleFrom": 1, "rollbackSafe": true, "previous": {"version": "0.50.0", "schemaVersion": 1, "x": 1}` + tail, `unknown field "x"`},
		{"a string for a number", `{"schemaVersion": "1", "compatibleFrom": 1, "rollbackSafe": false, "previous": null` + tail, "cannot unmarshal"},
		{"two values", `{"schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null` + tail + ` {}`, "more than one JSON value"},
		{"a broken rule", `{"schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": true, "previous": null` + tail, "rollbackSafe without a previous release"},
	} {
		if _, err := ParseDeclaration([]byte(c.json)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestManifestRoundTrip(t *testing.T) {
	m, err := NewManifest("0.50.0-rc.3", decl(2, 1, true, &Previous{"0.50.0-rc.2", 1}))
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "manifestVersion": 2,
  "version": "0.50.0-rc.3",
  "schemaVersion": 2,
  "compatibleFrom": 1,
  "rollbackSafe": true,
  "previous": {
    "version": "0.50.0-rc.2",
    "schemaVersion": 1
  },
  "reversibleTo": "0.23.0",
  "endsRollbackWindow": false
}
`
	if string(b) != want {
		t.Fatalf("%s", b)
	}
	back, err := ParseManifest(b)
	if err != nil || back.Version != m.Version || back.Declaration.Previous.Version != "0.50.0-rc.2" || back.SchemaVersion != 2 || back.EndsRollbackWindow() {
		t.Fatalf("%+v, %v", back, err)
	}
	first, err := NewManifest("0.50.0-rc.1", decl(1, 1, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := first.Bytes(); !strings.Contains(string(b), `"previous": null`) {
		t.Fatalf("%s", b)
	}
}

// TestAFormatOneManifestIsStillRead: rc.1's and rc.2's release.json, format
// 1, predate migrations: read, ending no window, and written back as they
// were.
func TestAFormatOneManifestIsStillRead(t *testing.T) {
	rc2 := `{
  "manifestVersion": 1,
  "version": "0.50.0-rc.2",
  "schemaVersion": 2,
  "compatibleFrom": 1,
  "rollbackSafe": true,
  "previous": {
    "version": "0.50.0-rc.1",
    "schemaVersion": 1
  }
}
`
	m, err := ParseManifest([]byte(rc2))
	if err != nil || m.ManifestVersion != 1 || m.EndsRollbackWindow() || m.ReversibleTo != nil {
		t.Fatalf("%+v, %v", m, err)
	}
	if b, err := m.Bytes(); err != nil || string(b) != rc2 {
		t.Errorf("written back: %s, %v", b, err)
	}
	// Format 1 with format 2's keys: refused.
	if _, err := ParseManifest([]byte(strings.Replace(rc2, `"previous": {`, `"reversibleTo": "0.23.0", "previous": {`, 1))); err == nil || !strings.Contains(err.Error(), `unknown key "reversibleTo"`) {
		t.Errorf("format 1 with reversibleTo: %v", err)
	}
}

func TestEndsRollbackWindow(t *testing.T) {
	ends := decl(1, 1, false, nil)
	ends.ReversibleTo, ends.EndsRollbackWindow = nil, true
	m, err := NewManifest("0.51.0", ends)
	if err != nil || !m.EndsRollbackWindow() {
		t.Fatalf("%+v, %v", m, err)
	}
	b, _ := m.Bytes()
	back, err := ParseManifest(b)
	if err != nil || !back.EndsRollbackWindow() || !strings.Contains(string(b), `"reversibleTo": null`) || !strings.Contains(string(b), `"endsRollbackWindow": true`) {
		t.Fatalf("%s: %+v, %v", b, back, err)
	}
	if !strings.Contains(RollbackWindowNotice, "varlatch migrate --rollback") || !strings.Contains(RollbackWindowNotice, LastTypeScriptRelease) {
		t.Errorf("the notice: %s", RollbackWindowNotice)
	}
}

func TestParseManifestRefuses(t *testing.T) {
	const tail = `, "reversibleTo": "0.23.0", "endsRollbackWindow": false}`
	for _, c := range []struct{ name, json, want string }{
		{"a later format", `{"manifestVersion": 3, "version": "0.50.0", "schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null` + tail, "not of manifest format 1 or 2"},
		{"no format", `{"version": "0.50.0", "schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null` + tail, "not of manifest format 1 or 2"},
		{"no version", `{"manifestVersion": 2, "schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null` + tail, `no "version"`},
		{"a bad version", `{"manifestVersion": 2, "version": "0.50", "schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null` + tail, `"0.50" is not a release version`},
		{"itself as previous", `{"manifestVersion": 2, "version": "0.50.1", "schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": true, "previous": {"version": "0.50.1", "schemaVersion": 1}` + tail, "the previous release is this one"},
		{"an unknown key", `{"manifestVersion": 2, "version": "0.50.0", "schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null, "images": {}` + tail, `unknown key "images"`},
		{"format 2 without the window", `{"manifestVersion": 2, "version": "0.50.0", "schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null}`, `no "reversibleTo"`},
		{"format 2 declaring neither", `{"manifestVersion": 2, "version": "0.50.0", "schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null, "reversibleTo": null, "endsRollbackWindow": false}`, "neither reversibleTo nor endsRollbackWindow"},
		{"a broken rule", `{"manifestVersion": 2, "version": "0.50.1", "schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": {"version": "0.50.0", "schemaVersion": 1}` + tail, "not rollbackSafe, but compatibleFrom 1"},
		{"not JSON", `release`, "invalid character"},
	} {
		if _, err := ParseManifest([]byte(c.json)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
