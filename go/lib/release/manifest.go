// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ManifestAsset is the Go release's manifest, one of its assets and listed
// in its signed SHA256SUMS (ADR-0059 Decision 8; internal
// docs/design/go-step6.md decision 5).
const ManifestAsset = "release.json"

// ManifestVersion is the manifest format this package writes. Format 2
// adds what a release declares about the migration's rollback window
// (reversibleTo, endsRollbackWindow; internal docs/design/go-step7.md
// decision 17). Format 1 (0.50.0-rc.1 and rc.2, before any migration
// existed) is still read, as declaring nothing about the window. A
// manifest of a later format is refused: a newer CLI reads it.
const ManifestVersion = 2

// LastTypeScriptRelease is the TypeScript release a migration starts from,
// and the only one a reverse migration returns to (ADR-0059 Decision 9 and
// amendment 4; go-step7.md O1).
const LastTypeScriptRelease = "0.23.1"

// RollbackWindowNotice is what `varlatch upgrade` says before upgrading to a
// release that ends the migration's rollback window.
const RollbackWindowNotice = "This release ends the migration's rollback window: after it, `varlatch migrate --rollback` can no longer return this installation to the TypeScript release (" + LastTypeScriptRelease + "). Its data stays; only the way back goes."

// Declaration is what a release declares about its database schema,
// checked in as go/release/release.json and checked by G6: the schema
// version varlatchd records, the oldest version whose varlatchd may open a
// database of it, whether the release is rollback-safe, and the previous
// release that was checked against; and what it declares about a
// migration's rollback window (decision 17): the TypeScript release a
// reverse migration of its data returns to (ReversibleTo), or that it
// ends the window (EndsRollbackWindow), exactly one of them.
type Declaration struct {
	SchemaVersion      int64     `json:"schemaVersion"`
	CompatibleFrom     int64     `json:"compatibleFrom"`
	RollbackSafe       bool      `json:"rollbackSafe"`
	Previous           *Previous `json:"previous"`
	ReversibleTo       *string   `json:"reversibleTo"`
	EndsRollbackWindow bool      `json:"endsRollbackWindow"`
}

// DeclaredFor is whether the declaration says its release is rollback-safe
// for the installed release: rollbackSafe, checked against exactly that
// release (its previous). A release checked against another one (an upgrade
// that skips releases) declares nothing about this one.
func (d Declaration) DeclaredFor(installed string) bool {
	return d.RollbackSafe && d.Previous != nil && d.Previous.Version == installed
}

// SafeFor is whether going back to the installed release, of schema
// version schema, would keep the database: the declaration says so for it
// (DeclaredFor), and its compatibleFrom lets that schema version open the
// upgraded database. `varlatch upgrade` and the dashboard's pre-flight
// (ADR-0065 Decision 4) both judge by it.
func (d Declaration) SafeFor(installed string, schema int64) bool {
	return d.DeclaredFor(installed) && d.CompatibleFrom <= schema
}

// Previous is the release a declaration was checked against: the release
// before it on the Go line.
type Previous struct {
	Version       string `json:"version"`
	SchemaVersion int64  `json:"schemaVersion"`
}

// Manifest is a release's release.json: its declaration, with the format and
// the release's version.
type Manifest struct {
	ManifestVersion int    `json:"manifestVersion"`
	Version         string `json:"version"`
	Declaration
}

// manifestJSON fixes the key order of the asset.
type manifestJSON struct {
	ManifestVersion    int       `json:"manifestVersion"`
	Version            string    `json:"version"`
	SchemaVersion      int64     `json:"schemaVersion"`
	CompatibleFrom     int64     `json:"compatibleFrom"`
	RollbackSafe       bool      `json:"rollbackSafe"`
	Previous           *Previous `json:"previous"`
	ReversibleTo       *string   `json:"reversibleTo"`
	EndsRollbackWindow bool      `json:"endsRollbackWindow"`
}

// manifestV1JSON is format 1, read for releases before format 2.
type manifestV1JSON struct {
	ManifestVersion int       `json:"manifestVersion"`
	Version         string    `json:"version"`
	SchemaVersion   int64     `json:"schemaVersion"`
	CompatibleFrom  int64     `json:"compatibleFrom"`
	RollbackSafe    bool      `json:"rollbackSafe"`
	Previous        *Previous `json:"previous"`
}

var (
	declarationKeys = []string{"schemaVersion", "compatibleFrom", "rollbackSafe", "previous", "reversibleTo", "endsRollbackWindow"}
	manifestV1Keys  = []string{"manifestVersion", "version", "schemaVersion", "compatibleFrom", "rollbackSafe", "previous"}
	manifestKeys    = append([]string{"manifestVersion", "version"}, declarationKeys...)
)

// ParseDeclaration reads go/release/release.json: exactly the declaration's
// keys, each present, and the rules Check holds.
func ParseDeclaration(data []byte) (Declaration, error) {
	var raw map[string]json.RawMessage
	if err := strictDecode(data, &raw); err != nil {
		return Declaration{}, fmt.Errorf("release: the declaration: %w", err)
	}
	if err := keysExactly(raw, declarationKeys...); err != nil {
		return Declaration{}, fmt.Errorf("release: the declaration: %w", err)
	}
	var d Declaration
	if err := strictDecode(data, &d); err != nil {
		return Declaration{}, fmt.Errorf("release: the declaration: %w", err)
	}
	if err := d.Check(); err != nil {
		return Declaration{}, err
	}
	return d, nil
}

// ParseManifest reads a release's release.json, refusing any other format,
// a missing or unknown key, and a manifest that breaks Check's rules.
func ParseManifest(data []byte) (Manifest, error) {
	var raw map[string]json.RawMessage
	if err := strictDecode(data, &raw); err != nil {
		return Manifest{}, fmt.Errorf("release: %s: %w", ManifestAsset, err)
	}
	var format int
	if v, ok := raw["manifestVersion"]; !ok || json.Unmarshal(v, &format) != nil || (format != 1 && format != ManifestVersion) {
		return Manifest{}, fmt.Errorf("release: %s is not of manifest format 1 or %d", ManifestAsset, ManifestVersion)
	}
	var out Manifest
	if format == 1 {
		if err := keysExactly(raw, manifestV1Keys...); err != nil {
			return Manifest{}, fmt.Errorf("release: %s: %w", ManifestAsset, err)
		}
		var m manifestV1JSON
		if err := strictDecode(data, &m); err != nil {
			return Manifest{}, fmt.Errorf("release: %s: %w", ManifestAsset, err)
		}
		out = Manifest{ManifestVersion: 1, Version: m.Version, Declaration: Declaration{
			SchemaVersion: m.SchemaVersion, CompatibleFrom: m.CompatibleFrom, RollbackSafe: m.RollbackSafe, Previous: m.Previous,
		}}
	} else {
		if err := keysExactly(raw, manifestKeys...); err != nil {
			return Manifest{}, fmt.Errorf("release: %s: %w", ManifestAsset, err)
		}
		var m manifestJSON
		if err := strictDecode(data, &m); err != nil {
			return Manifest{}, fmt.Errorf("release: %s: %w", ManifestAsset, err)
		}
		out = Manifest{ManifestVersion: m.ManifestVersion, Version: m.Version, Declaration: Declaration{
			SchemaVersion: m.SchemaVersion, CompatibleFrom: m.CompatibleFrom, RollbackSafe: m.RollbackSafe, Previous: m.Previous,
			ReversibleTo: m.ReversibleTo, EndsRollbackWindow: m.EndsRollbackWindow,
		}}
	}
	if err := out.Check(); err != nil {
		return Manifest{}, err
	}
	return out, nil
}

// NewManifest is the manifest of release version with declaration d.
func NewManifest(version string, d Declaration) (Manifest, error) {
	m := Manifest{ManifestVersion: ManifestVersion, Version: version, Declaration: d}
	if err := m.Check(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func (m Manifest) asJSON() any {
	if m.ManifestVersion == 1 {
		return manifestV1JSON{m.ManifestVersion, m.Version, m.SchemaVersion, m.CompatibleFrom, m.RollbackSafe, m.Previous}
	}
	return manifestJSON{m.ManifestVersion, m.Version, m.SchemaVersion, m.CompatibleFrom, m.RollbackSafe, m.Previous, m.ReversibleTo, m.Declaration.EndsRollbackWindow}
}

// MarshalJSON writes the asset: its keys in a fixed order.
func (m Manifest) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.asJSON())
}

// Bytes is the asset as the release attaches it: indented, with a final
// newline.
func (m Manifest) Bytes() ([]byte, error) {
	b, err := json.MarshalIndent(m.asJSON(), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// EndsRollbackWindow reports whether upgrading to this release ends a
// migration's rollback window: its manifest says so. A format 1 manifest
// predates migrations and says nothing; it ends nothing.
func (m Manifest) EndsRollbackWindow() bool {
	return m.ManifestVersion >= 2 && m.Declaration.EndsRollbackWindow
}

// Check holds the manifest's rules: its format and version, then the
// declaration's (format 1: the schema's only, as it predates the window).
func (m Manifest) Check() error {
	if m.ManifestVersion != 1 && m.ManifestVersion != ManifestVersion {
		return fmt.Errorf("release: %s is not of manifest format 1 or %d", ManifestAsset, ManifestVersion)
	}
	if !versionPattern.MatchString(m.Version) {
		return fmt.Errorf("release: %s: %q is not a release version", ManifestAsset, m.Version)
	}
	if m.Previous != nil && m.Previous.Version == m.Version {
		return fmt.Errorf("release: %s: the previous release is this one (%s)", ManifestAsset, m.Version)
	}
	if m.ManifestVersion == 1 {
		if m.ReversibleTo != nil || m.Declaration.EndsRollbackWindow {
			return fmt.Errorf("release: %s: format 1 declares nothing about the rollback window", ManifestAsset)
		}
		return m.Declaration.checkSchema()
	}
	return m.Declaration.Check()
}

// Check holds the declaration's rules: the schema's (checkSchema), and the
// rollback window's: exactly one of reversibleTo, naming
// LastTypeScriptRelease, and endsRollbackWindow. A release that declares
// neither fails, so no release ends the window without saying so.
func (d Declaration) Check() error {
	if err := d.checkSchema(); err != nil {
		return err
	}
	switch {
	case d.ReversibleTo != nil && d.EndsRollbackWindow:
		return errors.New("release: the declaration: reversibleTo and endsRollbackWindow both set: a release either keeps the rollback window or ends it")
	case d.ReversibleTo == nil && !d.EndsRollbackWindow:
		return fmt.Errorf("release: the declaration: neither reversibleTo nor endsRollbackWindow: declare reversibleTo %q if a reverse migration of this release's data returns to it (G5 checks it), or endsRollbackWindow true", LastTypeScriptRelease)
	case d.ReversibleTo != nil && *d.ReversibleTo != LastTypeScriptRelease:
		return fmt.Errorf("release: the declaration: reversibleTo %q is not the last TypeScript release, %s", *d.ReversibleTo, LastTypeScriptRelease)
	}
	return nil
}

// checkSchema holds the schema's rules:
//
//   - a schema version of 1 or more, and compatibleFrom between 1 and it;
//   - no previous release (the first Go release): not rollback-safe, since
//     there is nothing to go back to;
//   - a previous release: a release version, its schema version between 1
//     and this one's; rollback-safe only if its varlatchd may open this
//     schema (compatibleFrom at or below its schema version), and, if not
//     rollback-safe, compatibleFrom above it, so the previous varlatchd
//     refuses the database instead of misreading it.
func (d Declaration) checkSchema() error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("release: the declaration: "+format, args...)
	}
	if d.SchemaVersion < 1 {
		return fail("schemaVersion %d is not 1 or more", d.SchemaVersion)
	}
	if d.CompatibleFrom < 1 || d.CompatibleFrom > d.SchemaVersion {
		return fail("compatibleFrom %d is not between 1 and schemaVersion %d", d.CompatibleFrom, d.SchemaVersion)
	}
	p := d.Previous
	if p == nil {
		if d.RollbackSafe {
			return fail("rollbackSafe without a previous release: the first Go release has nothing to go back to")
		}
		return nil
	}
	if !versionPattern.MatchString(p.Version) {
		return fail("the previous release's version %q is not a release version", p.Version)
	}
	if p.SchemaVersion < 1 || p.SchemaVersion > d.SchemaVersion {
		return fail("the previous release's schemaVersion %d is not between 1 and %d", p.SchemaVersion, d.SchemaVersion)
	}
	if d.RollbackSafe && d.CompatibleFrom > p.SchemaVersion {
		return fail("rollbackSafe, but compatibleFrom %d keeps %s's varlatchd (schema %d) out", d.CompatibleFrom, p.Version, p.SchemaVersion)
	}
	if !d.RollbackSafe && d.CompatibleFrom <= p.SchemaVersion {
		return fail("not rollbackSafe, but compatibleFrom %d lets %s's varlatchd (schema %d) open the database: raise the schema version and compatibleFrom", d.CompatibleFrom, p.Version, p.SchemaVersion)
	}
	return nil
}

func strictDecode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("more than one JSON value")
	}
	return nil
}

func keysExactly(raw map[string]json.RawMessage, want ...string) error {
	for _, k := range want {
		if _, ok := raw[k]; !ok {
			return fmt.Errorf("no %q", k)
		}
	}
	if len(raw) != len(want) {
		for k := range raw {
			found := false
			for _, w := range want {
				found = found || k == w
			}
			if !found {
				return fmt.Errorf("an unknown key %q", k)
			}
		}
	}
	return nil
}
