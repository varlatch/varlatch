// SPDX-License-Identifier: Apache-2.0

package release

import (
	"strings"
	"testing"
)

func TestDeclarationRules(t *testing.T) {
	prev := func(v string, n int64) *Previous { return &Previous{Version: v, SchemaVersion: n} }
	for _, c := range []struct {
		name string
		d    Declaration
		want string // "" for valid
	}{
		{"the first release", Declaration{1, 1, false, nil}, ""},
		{"rollback-safe, schema unchanged", Declaration{1, 1, true, prev("0.50.0-rc.1", 1)}, ""},
		{"rollback-safe, schema added to", Declaration{2, 1, true, prev("0.50.0-rc.1", 1)}, ""},
		{"not rollback-safe, raised", Declaration{2, 2, false, prev("0.50.0-rc.1", 1)}, ""},

		{"no schema version", Declaration{0, 0, false, nil}, "schemaVersion 0 is not 1 or more"},
		{"compatibleFrom above the schema", Declaration{1, 2, false, nil}, "compatibleFrom 2 is not between 1 and schemaVersion 1"},
		{"compatibleFrom 0", Declaration{1, 0, false, nil}, "compatibleFrom 0 is not between 1"},
		{"rollback-safe with nothing before", Declaration{1, 1, true, nil}, "rollbackSafe without a previous release"},
		{"a previous version that is not one", Declaration{1, 1, true, prev("v0.50.0", 1)}, `the previous release's version "v0.50.0" is not a release version`},
		{"a previous schema above this one", Declaration{1, 1, true, prev("0.50.0", 2)}, "the previous release's schemaVersion 2 is not between 1 and 1"},
		{"rollback-safe, but the previous release is kept out", Declaration{2, 2, true, prev("0.50.0", 1)}, "rollbackSafe, but compatibleFrom 2 keeps 0.50.0's varlatchd (schema 1) out"},
		{"not rollback-safe, but the previous release still opens it", Declaration{1, 1, false, prev("0.50.0", 1)}, "not rollbackSafe, but compatibleFrom 1 lets 0.50.0's varlatchd (schema 1) open the database"},
	} {
		err := c.d.Check()
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestParseDeclaration(t *testing.T) {
	d, err := ParseDeclaration([]byte(`{"schemaVersion": 2, "compatibleFrom": 1, "rollbackSafe": true, "previous": {"version": "0.50.0-rc.1", "schemaVersion": 1}}`))
	if err != nil || d.SchemaVersion != 2 || !d.RollbackSafe || d.Previous == nil || d.Previous.Version != "0.50.0-rc.1" {
		t.Fatalf("%+v, %v", d, err)
	}
	for _, c := range []struct{ name, json, want string }{
		{"a missing key", `{"schemaVersion": 1, "compatibleFrom": 1, "previous": null}`, `no "rollbackSafe"`},
		{"an unknown key", `{"schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null, "note": "x"}`, `an unknown key "note"`},
		{"an unknown key in previous", `{"schemaVersion": 2, "compatibleFrom": 1, "rollbackSafe": true, "previous": {"version": "0.50.0", "schemaVersion": 1, "x": 1}}`, `unknown field "x"`},
		{"a string for a number", `{"schemaVersion": "1", "compatibleFrom": 1, "rollbackSafe": false, "previous": null}`, "cannot unmarshal"},
		{"two values", `{"schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null} {}`, "more than one JSON value"},
		{"a broken rule", `{"schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": true, "previous": null}`, "rollbackSafe without a previous release"},
	} {
		if _, err := ParseDeclaration([]byte(c.json)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestManifestRoundTrip(t *testing.T) {
	m, err := NewManifest("0.50.0-rc.2", Declaration{2, 1, true, &Previous{"0.50.0-rc.1", 1}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := `{
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
	if string(b) != want {
		t.Fatalf("%s", b)
	}
	back, err := ParseManifest(b)
	if err != nil || back.Version != m.Version || back.Declaration.Previous.Version != "0.50.0-rc.1" || back.SchemaVersion != 2 {
		t.Fatalf("%+v, %v", back, err)
	}
	first, err := NewManifest("0.50.0-rc.1", Declaration{1, 1, false, nil})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := first.Bytes(); !strings.Contains(string(b), `"previous": null`) {
		t.Fatalf("%s", b)
	}
}

func TestParseManifestRefuses(t *testing.T) {
	for _, c := range []struct{ name, json, want string }{
		{"another format", `{"manifestVersion": 2, "version": "0.50.0", "schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null}`, "not of manifest format 1"},
		{"no format", `{"version": "0.50.0", "schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null}`, "not of manifest format 1"},
		{"no version", `{"manifestVersion": 1, "schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null}`, `no "version"`},
		{"a bad version", `{"manifestVersion": 1, "version": "0.50", "schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null}`, `"0.50" is not a release version`},
		{"itself as previous", `{"manifestVersion": 1, "version": "0.50.1", "schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": true, "previous": {"version": "0.50.1", "schemaVersion": 1}}`, "the previous release is this one"},
		{"an unknown key", `{"manifestVersion": 1, "version": "0.50.0", "schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": null, "images": {}}`, `unknown key "images"`},
		{"a broken rule", `{"manifestVersion": 1, "version": "0.50.1", "schemaVersion": 1, "compatibleFrom": 1, "rollbackSafe": false, "previous": {"version": "0.50.0", "schemaVersion": 1}}`, "not rollbackSafe, but compatibleFrom 1"},
		{"not JSON", `release`, "invalid character"},
	} {
		if _, err := ParseManifest([]byte(c.json)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
