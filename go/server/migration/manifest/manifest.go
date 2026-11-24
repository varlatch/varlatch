// SPDX-License-Identifier: AGPL-3.0-or-later

// Package manifest is the migration manifest (ADR-0059 Decision 9;
// docs/design/go-step7.md decisions 3 to 5): every table and column of the
// TypeScript server's PostgreSQL schema, where it goes in varlatchd's
// SQLite schema or why it is left out, the deterministic transformations,
// and what lives outside the database. v1.json is the manifest itself;
// manifest_test.go holds it to the PostgreSQL schema (db/testdata), to
// db/mapping.json and to schema.sql, so a new column on either side fails
// until the manifest accounts for it.
package manifest

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/varlatch/varlatch/go/server/migration/canonical"
)

// V1 is the manifest's text. The TypeScript server's copy
// (services/varlatchd/src/migration/manifest-v1.json, release/0.22) is the
// same but for the target's side, which only varlatchd reads: its
// target.schemaVersion and targetOnly tables follow schema.sql (since
// schema version 2, certificate_issuances), while the bundle header names
// the manifest version, 1 in both, and every source table and column is
// the same.
//
//go:embed v1.json
var V1 []byte

// Actions a table can take.
const (
	Copy      = "copy"      // rows copied, column by column
	Transform = "transform" // rows exported for a transformation, not copied
	LeftOut   = "leftOut"   // nothing exported; the reason says why
)

// Manifest is v1.json.
type Manifest struct {
	Comment  string `json:"comment"`
	Version  int    `json:"version"`
	Encoding string `json:"encoding"`
	Source   struct {
		Release    string   `json:"release"`
		Schema     string   `json:"schema"`
		Migrations []string `json:"migrations"`
	} `json:"source"`
	Target struct {
		SchemaVersion int `json:"schemaVersion"`
	} `json:"target"`
	ForeignKeys string  `json:"foreignKeys"`
	Tables      []Table `json:"tables"`
	TargetOnly  struct {
		Tables map[string]string `json:"tables"`
	} `json:"targetOnly"`
	Transformations []struct {
		ID   string `json:"id"`
		Text string `json:"text"`
	} `json:"transformations"`
	Outside []struct {
		Name   string `json:"name"`
		Reason string `json:"reason"`
	} `json:"outside"`
}

// Table is one PostgreSQL table.
type Table struct {
	Source          string   `json:"source"`
	Action          string   `json:"action"`
	Target          string   `json:"target,omitempty"`
	Transformation  string   `json:"transformation,omitempty"`
	Reason          string   `json:"reason,omitempty"`
	Precondition    string   `json:"precondition,omitempty"`
	Report          string   `json:"report,omitempty"`
	Note            string   `json:"note,omitempty"`
	OrderBy         []string `json:"orderBy,omitempty"`
	PhysicalOrder   bool     `json:"physicalOrder,omitempty"`
	ReplacesSeedRow bool     `json:"replacesSeedRow,omitempty"`
	Columns         []Column `json:"columns"`
}

// Column is one column, in the source's column order: the order of a row
// in the canonical encoding.
type Column struct {
	Source  string         `json:"source"`
	Type    canonical.Type `json:"type"`
	Target  string         `json:"target,omitempty"`
	LeftOut *string        `json:"leftOut,omitempty"`
}

// Load parses v1.json strictly and checks it is consistent with itself.
func Load() (*Manifest, error) { return Parse(V1) }

// Parse parses a manifest's text strictly (no unknown member) and checks
// it is consistent with itself.
func Parse(text []byte) (*Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if dec.More() {
		return nil, errors.New("manifest: text after the manifest")
	}
	if err := m.check(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Table returns the entry for a PostgreSQL table.
func (m *Manifest) Table(source string) (Table, bool) {
	for _, t := range m.Tables {
		if t.Source == source {
			return t, true
		}
	}
	return Table{}, false
}

// Types is the table's column types, in row order.
func (t Table) Types() []canonical.Type {
	ts := make([]canonical.Type, len(t.Columns))
	for i, c := range t.Columns {
		ts[i] = c.Type
	}
	return ts
}

// check is everything the manifest must say of itself, before it is
// compared with either schema.
func (m *Manifest) check() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf("manifest: "+format, args...)) }
	if m.Version != 1 || m.Encoding != "canonical-v1" {
		add("version %d, encoding %q: v1.json is version 1 in canonical-v1", m.Version, m.Encoding)
	}
	if m.ForeignKeys == "" {
		add("foreignKeys: how the import treats the schema's foreign keys is required")
	}
	if m.Source.Release == "" || m.Source.Schema == "" || len(m.Source.Migrations) == 0 || m.Target.SchemaVersion < 1 {
		add("the source release, schema, migrations and target schema version are required")
	}
	transformations := map[string]bool{}
	for _, tr := range m.Transformations {
		if tr.ID == "" || tr.Text == "" || transformations[tr.ID] {
			add("transformation %q: an id of its own and a text are required", tr.ID)
		}
		transformations[tr.ID] = true
	}
	for _, o := range m.Outside {
		if o.Name == "" || o.Reason == "" {
			add("outside %q: a name and a reason are required", o.Name)
		}
	}
	for name, why := range m.TargetOnly.Tables {
		if why == "" {
			add("target-only table %s: a reason is required", name)
		}
	}
	sources, targets := map[string]bool{}, map[string]string{}
	prev := ""
	for _, t := range m.Tables {
		if t.Source <= prev {
			add("table %s: tables are listed by name, each once", t.Source)
		}
		prev = t.Source
		sources[t.Source] = true
		switch t.Action {
		case Copy, Transform:
			if t.Target == "" {
				add("table %s: a %s needs its target table", t.Source, t.Action)
			} else if other, dup := targets[t.Target]; dup {
				add("table %s: target %s is also %s's", t.Source, t.Target, other)
			} else if _, dup := m.TargetOnly.Tables[t.Target]; dup {
				add("table %s: target %s is also listed as target-only", t.Source, t.Target)
			}
			targets[t.Target] = t.Source
			if t.Reason != "" || t.Precondition != "" || t.Report != "" {
				add("table %s: reason, precondition and report are for a table left out", t.Source)
			}
			if (t.Action == Transform) != (t.Transformation != "") {
				add("table %s: a transform names its transformation, a copy none", t.Source)
			} else if t.Transformation != "" && !transformations[t.Transformation] {
				add("table %s: no transformation %q", t.Source, t.Transformation)
			}
			if len(t.OrderBy) == 0 {
				add("table %s: orderBy is required", t.Source)
			}
		case LeftOut:
			if t.Reason == "" {
				add("table %s: a table left out needs its reason", t.Source)
			}
			if t.Target != "" || t.Transformation != "" || len(t.OrderBy) > 0 || t.PhysicalOrder || t.ReplacesSeedRow {
				add("table %s: a table left out has no target, transformation or order", t.Source)
			}
			if t.Precondition != "" && t.Precondition != "empty" {
				add("table %s: unknown precondition %q", t.Source, t.Precondition)
			}
			if t.Report != "" && t.Report != "rowCount" {
				add("table %s: unknown report %q", t.Source, t.Report)
			}
		default:
			add("table %s: unknown action %q", t.Source, t.Action)
		}
		if t.PhysicalOrder && t.Note == "" {
			add("table %s: physical order needs its note (an accepted difference)", t.Source)
		}
		if len(t.Columns) == 0 {
			add("table %s: no columns", t.Source)
		}
		cols, colTargets := map[string]bool{}, map[string]bool{}
		for _, c := range t.Columns {
			if c.Source == "" || cols[c.Source] {
				add("table %s: column %q: a name of its own is required", t.Source, c.Source)
			}
			cols[c.Source] = true
			if !canonical.Known(c.Type) {
				add("table %s: column %s: the encoding does not define type %q", t.Source, c.Source, c.Type)
			}
			switch t.Action {
			case Copy:
				if c.Target == "" || c.LeftOut != nil {
					add("table %s: column %s: a copied table's column has a target and nothing left out", t.Source, c.Source)
				}
			case Transform:
				if c.Target == "" {
					add("table %s: column %s: a transformed table's column names its counterpart", t.Source, c.Source)
				}
			case LeftOut:
				if c.Target != "" || c.LeftOut != nil {
					add("table %s: column %s: a table left out lists its columns only", t.Source, c.Source)
				}
			}
			if c.LeftOut != nil && *c.LeftOut == "" {
				add("table %s: column %s: leftOut, when present, gives the reason", t.Source, c.Source)
			}
			if c.Target != "" {
				if colTargets[c.Target] {
					add("table %s: target column %s twice", t.Source, c.Target)
				}
				colTargets[c.Target] = true
			}
		}
		for _, o := range t.OrderBy {
			if !cols[o] {
				add("table %s: orderBy column %s is not a column", t.Source, o)
			}
		}
	}
	return errors.Join(errs...)
}
