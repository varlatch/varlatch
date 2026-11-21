// SPDX-License-Identifier: AGPL-3.0-or-later

// Package check is the migration's checks (ADR-0059 Decision 9 phase 4;
// internal docs/design/go-step7.md slice 7.3b, decisions 7 and 8): after
// an import, the target database held against the forward bundle it was
// imported from. CHECKS.md says what each check reads and compares.
//
// The read side is its own: it queries SQLite directly, table and column
// names from the manifest, and never imports the import's package
// (server/migration/migrate; a test guards the import graph), so a fault
// of the import cannot hide itself behind the same code.
//
// Every check runs, whatever another found, so each fault shows at its
// own check. The report names checks, tables, classes, row positions,
// ids and counts; it never holds a value of a row, a plaintext, a digest
// or the run key.
package check

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/manifest"
)

// The checks, in the report's order.
const (
	Rows           = "rows"
	Classes        = "encryption-classes"
	Audit          = "audit"
	Authorization  = "authorization"
	Authentication = "authentication"
)

// Names are the checks, in the report's order.
var Names = []string{Rows, Classes, Audit, Authorization, Authentication}

// maxFailures bounds the failures a check lists; the rest are counted.
const maxFailures = 50

// Options are a check run's keys: the Root KEK opens the target's
// encrypted items, the run key (32 bytes, handed over on a pipe) keys their
// digests. Neither is kept or reported.
type Options struct {
	RootKEK []byte
	RunKey  []byte
	// Reverse is the reverse checks (go-step7 decision 16, slice 7.6a):
	// the target is the transformed copy a reverse bundle was written from,
	// and the bundle the TypeScript release's export of the database it
	// rebuilt from that reverse bundle. The rebuilt database holds the
	// copy's state exactly, so the target is held against the bundle with
	// no transformation between them: no event follows the frozen point,
	// and the bundle holds no session.
	Reverse bool
}

// Report is a check run's outcome.
type Report struct {
	Passed bool `json:"passed"`
	// Reverse is the reverse checks' report.
	Reverse bool         `json:"reverse,omitempty"`
	Bundle  BundleCounts `json:"bundle"`
	Checks  []Result     `json:"checks"`
}

// BundleCounts describe the bundle the target was held against.
type BundleCounts struct {
	Release       string `json:"release"`
	AuditPosition int64  `json:"auditPosition"`
	Tables        int    `json:"tables"`
	Rows          int64  `json:"rows"`
	Digests       int    `json:"digests"`
	Decisions     int    `json:"decisions"`
}

// Result is one check's.
type Result struct {
	Name     string    `json:"name"`
	Passed   bool      `json:"passed"`
	Checked  int64     `json:"checked"`
	Failures []Failure `json:"failures"`
	// More counts the failures past those listed.
	More int `json:"more"`
}

// Failure is one fault: the table or class it is in, and what it is.
type Failure struct {
	Table string `json:"table,omitempty"`
	Class string `json:"class,omitempty"`
	What  string `json:"what"`
}

// Result returns the named check's result.
func (r Report) Result(name string) Result {
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	return Result{}
}

// failures collects one check's.
type failures struct {
	res *Result
}

func (f failures) add(table, class, format string, args ...any) {
	f.res.Passed = false
	if len(f.res.Failures) >= maxFailures {
		f.res.More++
		return
	}
	f.res.Failures = append(f.res.Failures, Failure{Table: table, Class: class, What: fmt.Sprintf(format, args...)})
}

// Run holds the target database against the forward bundle in. db is the
// target, opened read-only; the bundle is read twice (it must be the one
// the target was imported from, whole: the first pass verifies it). An error is
// a run that could not finish; a fault the checks find is in the report.
func Run(ctx context.Context, db *sql.DB, in io.ReadSeeker, o Options) (Report, error) {
	if len(o.RunKey) != 32 {
		return Report{}, errors.New("check: the run key is 32 bytes")
	}
	m, err := manifest.Load()
	if err != nil {
		return Report{}, err
	}
	c := &checker{m: m, db: db, o: o, results: map[string]*Result{}}
	for _, n := range Names {
		c.results[n] = &Result{Name: n, Passed: true, Failures: []Failure{}}
	}
	// Pass 1, the whole bundle verified (its counts and SHA-256: one cut
	// short or damaged is refused before anything is held against it),
	// keeping what the checks need ahead of the rows: the sessions, the
	// browser credentials, the cursors, the audit log's ids.
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return Report{}, err
	}
	if err := c.firstPass(in); err != nil {
		return Report{}, fmt.Errorf("check: the bundle: %w", err)
	}
	if c.head.Direction != bundle.Forward {
		return Report{}, errors.New("check: the checks hold a target against a forward bundle; this one is a reverse bundle")
	}
	if err := c.audit(ctx); err != nil {
		return Report{}, err
	}
	// Pass 2: every row, then the digests and the decisions.
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return Report{}, err
	}
	r, err := bundle.NewReader(in, m)
	if err != nil {
		return Report{}, err
	}
	if err := c.tables(ctx, r); err != nil {
		return Report{}, err
	}
	if err := c.classes(ctx, r); err != nil {
		return Report{}, err
	}
	if err := c.authorization(ctx, r); err != nil {
		return Report{}, err
	}
	if err := r.End(); err != nil {
		return Report{}, err
	}
	rep := Report{Passed: true, Reverse: o.Reverse, Bundle: c.counts}
	rep.Bundle.Release, rep.Bundle.AuditPosition = c.head.Release, c.head.FrozenPoint.AuditPosition
	for _, n := range Names {
		res := c.results[n]
		rep.Checks = append(rep.Checks, *res)
		rep.Passed = rep.Passed && res.Passed
	}
	return rep, nil
}

// checker is one run's state.
type checker struct {
	m       *manifest.Manifest
	db      *sql.DB
	o       Options
	head    bundle.Header
	counts  BundleCounts
	results map[string]*Result
	// From the first pass.
	sessions map[string]bool
	browser  map[string]browserCredential
	cursors  map[string]map[string][]any // table -> row key -> cursor values
	// revoked is the target's revocations after the frozen point
	// (credential id -> revoked_at), as its credential.revoked events
	// name them: the audit check's to judge, the rows and authentication
	// checks' to expect.
	revoked map[string]int64
	// migratedAt is installation.migrated's occurred_at in the target (0
	// when it has none).
	migratedAt int64
	// sourceEvents are the source's audit events, by position.
	sourceEvents []sourceEvent
	// authnSeen counts the source rows the authentication check read, by
	// table.
	authnSeen map[string]int
}

// browserCredential is a source browser credential minted from a session,
// live in the source.
type browserCredential struct {
	session string
	expires *int64
}

func (c *checker) fail(check, table, class, format string, args ...any) {
	failures{c.results[check]}.add(table, class, format, args...)
}

func (c *checker) checked(check string, n int64) { c.results[check].Checked += n }

// targetTable is a manifest table's name in the target.
func targetTable(t manifest.Table) string {
	if t.Target != "" {
		return t.Target
	}
	return t.Source
}

// targetColumn is a manifest column's name in the target.
func targetColumn(col manifest.Column) string {
	if col.Target != "" {
		return col.Target
	}
	return col.Source
}

// ident quotes an SQLite identifier.
func ident(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// column is the position of a source column in t, -1 when it has none.
func column(t manifest.Table, source string) int {
	for i, col := range t.Columns {
		if col.Source == source {
			return i
		}
	}
	return -1
}

// Text is the report as the command prints it: one line per check, then
// its faults.
func (r Report) Text() string {
	var b strings.Builder
	verdict := "passed"
	if !r.Passed {
		verdict = "FAILED"
	}
	which := "The migration's checks"
	if r.Reverse {
		which = "The reverse checks"
	}
	fmt.Fprintf(&b, "%s %s, against the bundle of %s frozen at audit position %d (%d tables, %d rows, %d digests, %d decisions).\n",
		which, verdict, r.Bundle.Release, r.Bundle.AuditPosition, r.Bundle.Tables, r.Bundle.Rows, r.Bundle.Digests, r.Bundle.Decisions)
	for _, c := range r.Checks {
		if c.Passed {
			fmt.Fprintf(&b, "  %s: passed (%d checked)\n", c.Name, c.Checked)
			continue
		}
		fmt.Fprintf(&b, "  %s: FAILED (%d checked, %d faults)\n", c.Name, c.Checked, len(c.Failures)+c.More)
		for _, f := range c.Failures {
			where := f.Table
			if f.Class != "" {
				where = f.Class
			}
			if where != "" {
				where += ": "
			}
			fmt.Fprintf(&b, "    - %s%s\n", where, f.What)
		}
		if c.More > 0 {
			fmt.Fprintf(&b, "    - and %d more\n", c.More)
		}
	}
	return b.String()
}
