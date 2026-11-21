// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/migration/manifest"

	_ "modernc.org/sqlite"
)

// The target-only tables: an import writes schema_version's one row and
// nothing else, so rows anywhere else fail the forward checks. In the
// reverse checks the target is Go's copy after it served, and
// certificate_issuances (Go's issuance count, carried apart from the
// bundle) may hold rows; every other target-only table is still held to
// an import's rows.
func TestTargetOnlyTablesInTheReverseChecks(t *testing.T) {
	m, err := manifest.Load()
	if err != nil {
		t.Fatal(err)
	}
	m.Tables = nil // no bundle table: every table here is target-only
	m.TargetOnly.Tables = map[string]string{"schema_version": "", "certificate_issuances": "", "other_target_only": ""}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		"CREATE TABLE schema_version (version INTEGER)", "INSERT INTO schema_version VALUES (2)",
		"CREATE TABLE certificate_issuances (name TEXT)", "INSERT INTO certificate_issuances VALUES ('varlatch.example.test'), ('varlatch.example.test')",
		"CREATE TABLE other_target_only (x INTEGER)",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	run := func(reverse bool) []Failure {
		t.Helper()
		c := &checker{m: m, db: db, o: Options{Reverse: reverse}, results: map[string]*Result{Rows: {Name: Rows, Passed: true}}}
		if err := c.otherTables(context.Background()); err != nil {
			t.Fatal(err)
		}
		return c.results[Rows].Failures
	}
	tables := func(fs []Failure) string {
		var names []string
		for _, f := range fs {
			names = append(names, f.Table)
		}
		return strings.Join(names, ",")
	}
	if got := tables(run(false)); got != "certificate_issuances" {
		t.Errorf("forward, Go's issuance rows: failures in %q, want certificate_issuances", got)
	}
	if got := tables(run(true)); got != "" {
		t.Errorf("reverse, Go's issuance rows: failures in %q, want none", got)
	}
	if _, err := db.Exec("INSERT INTO other_target_only VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	if got := tables(run(true)); got != "other_target_only" {
		t.Errorf("reverse, a row in another target-only table: failures in %q, want other_target_only", got)
	}
}
