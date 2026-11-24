// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
)

// An archive's manifest: what it holds and what restoring it needs. Three
// formats exist:
//
//   - 1 and 2: the TypeScript server's (packages/backup manifest.ts; ADR-0033,
//     and ADR-0036's Secret Plane only), which step 7's converter reads;
//   - 3: the Go server's (ADR-0059 Decision 7): the database snapshot and
//     the installation's non-key configuration.
//
// ParseManifest checks a manifest as the TypeScript schema does (zod's
// strict objects, its integer and string rules) for formats 1 and 2, and
// with the same rules for format 3.

// Format is a manifest's formatVersion.
type Format int

const (
	FormatTSBothPlanes  Format = 1
	FormatTSSecretPlane Format = 2
	FormatGo            Format = 3
)

// FormatComponents are the components each format holds, in order: a
// fixed allowlist, so arbitrary files, configuration and keys cannot enter
// an archive.
var FormatComponents = map[Format][]string{
	FormatTSBothPlanes:  {"secret-plane.dump", "application-plane.dump", "convex-storage.tar"},
	FormatTSSecretPlane: {"secret-plane.dump"},
	FormatGo:            {ComponentDatabase, ComponentConfiguration},
}

const (
	// ComponentDatabase is a Go archive's database snapshot (SQLite).
	ComponentDatabase = "varlatch.db"
	// ComponentConfiguration is a Go archive's non-key configuration.
	ComponentConfiguration = "configuration.json"
	// MaxConfigurationBytes bounds it, when an archive is sealed and when
	// one is opened: it is settings, read whole, and far fewer than this.
	MaxConfigurationBytes = 16 << 20
)

// Manifest is an archive's manifest. Release is the release record as the
// format holds it (TSRelease for formats 1 and 2, GoRelease for 3).
type Manifest struct {
	FormatVersion       Format          `json:"formatVersion"`
	ArchiveID           string          `json:"archiveId"`
	InstallationID      string          `json:"installationId"`
	CreatedAt           string          `json:"createdAt"`
	Release             json.RawMessage `json:"release"`
	RequiredKeyVersions []int           `json:"requiredKeyVersions"`
	Canaries            []Canary        `json:"canaries"`
	Components          []Component     `json:"components"`
}

// Canary is the Root KEK canary of one key version, sealed under it.
type Canary struct {
	Version  int            `json:"version"`
	Envelope CanaryEnvelope `json:"envelope"`
}

// CanaryEnvelope is the canary's envelope (lib/envelope's form).
type CanaryEnvelope struct {
	FormatVersion int    `json:"formatVersion"`
	Algorithm     string `json:"algorithm"`
	Nonce         string `json:"nonce"`
	Ciphertext    string `json:"ciphertext"`
	AuthTag       string `json:"authTag"`
}

// Component is one component's size and SHA-256 (lowercase hex).
type Component struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// GoRelease is a Go archive's release record.
type GoRelease struct {
	// Version is the varlatchd release that made the archive.
	Version string `json:"version"`
	// APIMajor is its /v1 API major.
	APIMajor int `json:"apiMajor"`
	// DatabaseSchema is the database's schema version (server/db
	// SchemaVersion) when the snapshot was taken.
	DatabaseSchema int `json:"databaseSchema"`
}

// TSRelease is a TypeScript archive's release record (release.json).
type TSRelease struct {
	SchemaVersion           int             `json:"schemaVersion"`
	Version                 string          `json:"version"`
	APIMajor                int             `json:"apiMajor"`
	MigrationVersion        int             `json:"migrationVersion"`
	SupportedPostgresMajor  int             `json:"supportedPostgresMajor"`
	SupportedRestoreSources []RestoreSource `json:"supportedRestoreSources"`
}

// RestoreSource is a release a TypeScript release could restore from.
type RestoreSource struct {
	Version          string `json:"version"`
	MigrationVersion int    `json:"migrationVersion"`
}

// GoRelease returns a format-3 manifest's release record.
func (m Manifest) GoRelease() (GoRelease, error) {
	var r GoRelease
	if m.FormatVersion != FormatGo {
		return r, fmt.Errorf("backup: a format-%d archive has no Go release record", m.FormatVersion)
	}
	return r, json.Unmarshal(m.Release, &r)
}

var (
	// zod 4's z.uuid(): an RFC 9562 version 1-8 UUID, or the nil or max one.
	uuidPattern         = regexp.MustCompile(`^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$`)
	installationPattern = regexp.MustCompile(`^inst_[a-zA-Z0-9_-]+$`)
	sha256Pattern       = regexp.MustCompile(`^[a-f0-9]{64}$`)
	// zod 4's z.iso.datetime(): seconds required, any fraction, Z only.
	datetimePattern = regexp.MustCompile(`^(?:(?:\d\d[2468][048]|\d\d[13579][26]|\d\d0[48]|[02468][048]00|[13579][26]00)-02-29|\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\d|30)|(?:02)-(?:0[1-9]|1\d|2[0-8])))T(?:(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z))$`)
)

// ErrManifest is any manifest the schema refuses.
var ErrManifest = &Error{"Invalid archive manifest"}

// ParseManifest parses and checks a manifest: an object with exactly the
// schema's members, each of its type.
func ParseManifest(raw []byte) (Manifest, error) {
	var top map[string]json.RawMessage
	if err := decodeStrict(raw, &top); err != nil {
		return Manifest{}, ErrManifest
	}
	if !onlyKeys(top, "formatVersion", "archiveId", "installationId", "createdAt", "release", "requiredKeyVersions", "canaries", "components") {
		return Manifest{}, ErrManifest
	}
	var m Manifest
	var format float64
	ok := number(top["formatVersion"], &format) &&
		str(top["archiveId"], &m.ArchiveID) && uuidPattern.MatchString(m.ArchiveID) &&
		str(top["installationId"], &m.InstallationID) && installationPattern.MatchString(m.InstallationID) &&
		str(top["createdAt"], &m.CreatedAt) && datetimePattern.MatchString(m.CreatedAt)
	if !ok || (format != 1 && format != 2 && format != 3) {
		return Manifest{}, ErrManifest
	}
	m.FormatVersion = Format(format)
	m.Release = top["release"]
	if !validRelease(m.FormatVersion, m.Release) {
		return Manifest{}, ErrManifest
	}
	var versions []json.RawMessage
	if decodeStrict(top["requiredKeyVersions"], &versions) != nil || len(versions) == 0 {
		return Manifest{}, ErrManifest
	}
	for _, v := range versions {
		n, ok := positiveInt(v)
		if !ok {
			return Manifest{}, ErrManifest
		}
		m.RequiredKeyVersions = append(m.RequiredKeyVersions, n)
	}
	var canaries []json.RawMessage
	if decodeStrict(top["canaries"], &canaries) != nil || len(canaries) == 0 {
		return Manifest{}, ErrManifest
	}
	for _, c := range canaries {
		canary, ok := parseCanary(c)
		if !ok {
			return Manifest{}, ErrManifest
		}
		m.Canaries = append(m.Canaries, canary)
	}
	var components []json.RawMessage
	if decodeStrict(top["components"], &components) != nil || len(components) == 0 || len(components) > 3 {
		return Manifest{}, ErrManifest
	}
	for _, c := range components {
		component, ok := parseComponent(c, m.FormatVersion)
		if !ok {
			return Manifest{}, ErrManifest
		}
		if component.Name == ComponentConfiguration && component.Bytes > MaxConfigurationBytes {
			return Manifest{}, &Error{"The archive's configuration is larger than 16 MiB"}
		}
		m.Components = append(m.Components, component)
	}
	if !complete(m) {
		return Manifest{}, &Error{"Incomplete or duplicate archive components/key versions"}
	}
	return m, nil
}

// complete is the schema's refinement: each key version once, with exactly
// one canary each, and the format's components, in order.
func complete(m Manifest) bool {
	expected := FormatComponents[m.FormatVersion]
	seen := map[int]bool{}
	for _, v := range m.RequiredKeyVersions {
		if seen[v] {
			return false
		}
		seen[v] = true
	}
	canaries := map[int]bool{}
	for _, c := range m.Canaries {
		if canaries[c.Version] || !seen[c.Version] {
			return false
		}
		canaries[c.Version] = true
	}
	if len(m.Canaries) != len(m.RequiredKeyVersions) || len(m.Components) != len(expected) {
		return false
	}
	for i, c := range m.Components {
		if c.Name != expected[i] {
			return false
		}
	}
	return true
}

func validRelease(f Format, raw json.RawMessage) bool {
	var o map[string]json.RawMessage
	if decodeStrict(raw, &o) != nil {
		return false
	}
	if f == FormatGo {
		var r GoRelease
		if !onlyKeys(o, "version", "apiMajor", "databaseSchema") || !str(o["version"], &r.Version) || r.Version == "" {
			return false
		}
		_, a := positiveInt(o["apiMajor"])
		_, d := positiveInt(o["databaseSchema"])
		return a && d
	}
	// releaseSchema is not strict: other members are allowed and dropped.
	var version string
	var schema float64
	if !number(o["schemaVersion"], &schema) || schema != 1 {
		return false
	}
	if !str(o["version"], &version) || version == "" {
		return false
	}
	if _, ok := positiveInt(o["apiMajor"]); !ok {
		return false
	}
	if _, ok := nonNegativeInt(o["migrationVersion"]); !ok {
		return false
	}
	if _, ok := positiveInt(o["supportedPostgresMajor"]); !ok {
		return false
	}
	if src, ok := o["supportedRestoreSources"]; ok {
		var list []map[string]json.RawMessage
		if decodeStrict(src, &list) != nil {
			return false
		}
		for _, s := range list {
			var v string
			if s == nil || !str(s["version"], &v) {
				return false
			}
			if _, ok := nonNegativeInt(s["migrationVersion"]); !ok {
				return false
			}
		}
	}
	return true
}

func parseCanary(raw json.RawMessage) (Canary, bool) {
	var o map[string]json.RawMessage
	if decodeStrict(raw, &o) != nil || !onlyKeys(o, "version", "envelope") {
		return Canary{}, false
	}
	version, ok := positiveInt(o["version"])
	if !ok {
		return Canary{}, false
	}
	var e map[string]json.RawMessage
	if decodeStrict(o["envelope"], &e) != nil || !onlyKeys(e, "formatVersion", "algorithm", "nonce", "ciphertext", "authTag") {
		return Canary{}, false
	}
	c := Canary{Version: version}
	var fv float64
	if !number(e["formatVersion"], &fv) || fv != 1 || !str(e["algorithm"], &c.Envelope.Algorithm) || c.Envelope.Algorithm != "aes-256-gcm" ||
		!str(e["nonce"], &c.Envelope.Nonce) || utf16Len(c.Envelope.Nonce) > 32 ||
		!str(e["ciphertext"], &c.Envelope.Ciphertext) || utf16Len(c.Envelope.Ciphertext) > 256 ||
		!str(e["authTag"], &c.Envelope.AuthTag) || utf16Len(c.Envelope.AuthTag) > 32 {
		return Canary{}, false
	}
	c.Envelope.FormatVersion = 1
	return c, true
}

func parseComponent(raw json.RawMessage, f Format) (Component, bool) {
	var o map[string]json.RawMessage
	if decodeStrict(raw, &o) != nil || !onlyKeys(o, "name", "bytes", "sha256") {
		return Component{}, false
	}
	var c Component
	if !str(o["name"], &c.Name) || !str(o["sha256"], &c.SHA256) || !sha256Pattern.MatchString(c.SHA256) {
		return Component{}, false
	}
	// The name is one of the format family's: zod's enum over the TS names
	// for formats 1 and 2, the Go names for 3.
	names := FormatComponents[FormatTSBothPlanes]
	if f == FormatGo {
		names = FormatComponents[FormatGo]
	}
	if !slices.Contains(names, c.Name) {
		return Component{}, false
	}
	n, ok := nonNegativeInt(o["bytes"])
	if !ok {
		return Component{}, false
	}
	c.Bytes = int64(n)
	return c, true
}

// decodeStrict decodes JSON whose top value is exactly one value of v's
// kind (an object into a map, an array into a slice).
func decodeStrict(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return fmt.Errorf("backup: trailing data")
	}
	if b, ok := v.(*map[string]json.RawMessage); ok && *b == nil {
		return fmt.Errorf("backup: null")
	}
	return nil
}

func onlyKeys(o map[string]json.RawMessage, keys ...string) bool {
	if o == nil {
		return false
	}
	for k := range o {
		if !slices.Contains(keys, k) {
			return false
		}
	}
	for _, k := range keys {
		if _, ok := o[k]; !ok {
			return false
		}
	}
	return true
}

func str(raw json.RawMessage, out *string) bool {
	if len(raw) == 0 || raw[0] != '"' {
		return false
	}
	return json.Unmarshal(raw, out) == nil
}

func number(raw json.RawMessage, out *float64) bool {
	if len(raw) == 0 || (raw[0] != '-' && (raw[0] < '0' || raw[0] > '9')) {
		return false
	}
	return json.Unmarshal(raw, out) == nil && !math.IsInf(*out, 0)
}

// integer is zod's z.number().int(): a finite, safe integer.
func integer(raw json.RawMessage) (int, bool) {
	var n float64
	if !number(raw, &n) || n != math.Trunc(n) || math.Abs(n) > 1<<53-1 {
		return 0, false
	}
	return int(n), true
}

func positiveInt(raw json.RawMessage) (int, bool) {
	n, ok := integer(raw)
	return n, ok && n > 0
}

func nonNegativeInt(raw json.RawMessage) (int, bool) {
	n, ok := integer(raw)
	return n, ok && n >= 0
}

// utf16Len is a JavaScript string's length.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}
