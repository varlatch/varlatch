// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/keyenv"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/db/schemadiff"
)

// releasedSchema1 is schema version 1 as 0.50.0-rc.1 released it, the
// schema server/db's releasecheck holds the upgrade steps against. Made
// absolute as the package loads: a test may change the directory.
var releasedSchema1, _ = filepath.Abs(filepath.Join("..", "db", "releasecheck", "testdata", "schema-0.50.0-rc.1.sql"))

// previousSchema makes the stopped installation's database the one the
// release before this schema left, its rows kept, and the version and
// compatible_from recorded as they were before the last upgrade step.
//
// The two schemas come from the released schema 1 (releasedSchema1), as
// releasecheck builds them: with every upgrade step but the last, and with
// every step. What differs between the two is the last step's own doing,
// and is undone: what it adds is dropped again; a table it makes again
// (schema 8 does so to widen approval_intents' operation CHECK) is made
// again as it was, its rows copied, and its indexes and triggers with it;
// an index or trigger it changes is made as it was. A step that removes a
// table, index or trigger is not rollback-safe, and is refused here. The
// result is held against the previous schema (schemadiff), so a step this
// cannot undo fails here rather than in the tests that use it.
func previousSchema(t *testing.T, in install) {
	t.Helper()
	ctx := context.Background()
	steps := db.Steps()
	if len(steps) == 0 {
		t.Fatal("this varlatchd has no upgrade step to undo")
	}
	last := steps[len(steps)-1]
	schema1, err := os.ReadFile(releasedSchema1)
	if err != nil {
		t.Fatal(err)
	}
	before := stepsSchema(t, string(schema1), steps[:len(steps)-1])
	after := stepsSchema(t, string(schema1), steps)

	var drop, rebuild, recreate []string
	for _, name := range sortedNames(before) {
		b := before[name]
		a, ok := after[name]
		switch {
		case !ok:
			t.Fatalf("schema %d's step removes %s %s, which a rollback-safe step does not: previousSchema cannot undo it", last.To, b.kind, name)
		case a.sql == b.sql:
		case b.kind == "table":
			rebuild = append(rebuild, name)
		default:
			recreate = append(recreate, name)
		}
	}
	for _, name := range sortedNames(after) {
		if _, ok := before[name]; !ok {
			drop = append(drop, name)
		}
	}
	if len(drop)+len(rebuild)+len(recreate) == 0 {
		t.Fatalf("schema %d's step changes nothing previousSchema can see\n%s", last.To, last.SQL)
	}
	// A table made again loses its indexes and triggers with the table set
	// aside: they are made again too.
	for _, name := range sortedNames(before) {
		if b := before[name]; b.kind != "table" && slices.Contains(rebuild, b.table) && !slices.Contains(recreate, name) {
			recreate = append(recreate, name)
		}
	}
	// Indexes before triggers, each in name order.
	slices.SortStableFunc(recreate, func(x, y string) int { return kindOrder(before[x].kind) - kindOrder(before[y].kind) })

	compatibleFrom := int64(1)
	if len(steps) > 1 {
		compatibleFrom = steps[len(steps)-2].CompatibleFrom
	}
	pool, err := sql.Open("sqlite", "file:"+filepath.Join(in.data, "varlatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	conn, err := pool.Conn(ctx) // the pragmas and the transaction on one connection
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := conn.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// Off, so a table set aside and dropped deletes no row by a cascade; the
	// legacy rename, so the references to a table set aside keep its name.
	exec("PRAGMA foreign_keys = OFF")
	exec("PRAGMA legacy_alter_table = ON")
	exec("BEGIN IMMEDIATE")
	// What the step added, triggers and indexes before their tables.
	for _, kind := range []string{"trigger", "index", "table"} {
		for _, name := range drop {
			if after[name].kind == kind {
				exec("DROP " + strings.ToUpper(kind) + " " + quoteName(name))
			}
		}
	}
	for _, name := range recreate {
		exec("DROP " + strings.ToUpper(before[name].kind) + " " + quoteName(name))
	}
	for _, name := range rebuild {
		aside := name + "_previous_schema"
		exec("ALTER TABLE " + quoteName(name) + " RENAME TO " + quoteName(aside))
		exec(before[name].sql)
		rows, err := conn.QueryContext(ctx, "SELECT name FROM pragma_table_info(?) WHERE name IN (SELECT name FROM pragma_table_info(?)) ORDER BY cid", name, aside)
		if err != nil {
			t.Fatal(err)
		}
		var columns []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			columns = append(columns, quoteName(c))
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		list := strings.Join(columns, ", ")
		exec("INSERT INTO " + quoteName(name) + " (" + list + ") SELECT " + list + " FROM " + quoteName(aside))
	}
	for _, name := range rebuild {
		exec("DROP TABLE " + quoteName(name+"_previous_schema"))
	}
	for _, name := range recreate {
		exec(before[name].sql)
	}
	exec("UPDATE schema_version SET version = ?, compatible_from = ?, updated_by_release = 'previous'", last.To-1, compatibleFrom)
	exec("COMMIT")
	var broken int
	if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM pragma_foreign_key_check").Scan(&broken); err != nil || broken != 0 {
		t.Fatalf("the previous schema's rows break %d references: %v", broken, err)
	}
	if changes := schemaChanges(t, definitions(before), definitions(schemaObjects(t, conn))); len(changes) != 0 {
		t.Fatalf("previousSchema did not make schema %d: %v", last.To-1, changes)
	}
}

// schemaObject is a table, index, view or trigger as sqlite_schema holds it.
type schemaObject struct{ kind, table, sql string }

// schemaObjects is every table, index, view and trigger a database holds
// with its statement, by name; SQLite's own and the indexes it makes for
// constraints are left out.
func schemaObjects(t *testing.T, conn interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) map[string]schemaObject {
	t.Helper()
	rows, err := conn.QueryContext(context.Background(), "SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	objects := map[string]schemaObject{}
	for rows.Next() {
		var name string
		var o schemaObject
		if err := rows.Scan(&o.kind, &name, &o.table, &o.sql); err != nil {
			t.Fatal(err)
		}
		objects[name] = o
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return objects
}

// stepsSchema is the schema the released schema 1 makes with steps applied
// in order, in a database of its own.
func stepsSchema(t *testing.T, schema1 string, steps []db.Step) map[string]schemaObject {
	t.Helper()
	conn, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "steps.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Exec(schema1); err != nil {
		t.Fatalf("the released schema 1: %v", err)
	}
	for _, st := range steps {
		if _, err := conn.Exec(st.SQL); err != nil {
			t.Fatalf("schema %d's step: %v", st.To, err)
		}
	}
	return schemaObjects(t, conn)
}

// definitions is objects' statements as one schema: tables, then indexes,
// views and triggers, each in name order.
func definitions(objects map[string]schemaObject) string {
	names := sortedNames(objects)
	slices.SortStableFunc(names, func(x, y string) int { return kindOrder(objects[x].kind) - kindOrder(objects[y].kind) })
	var b strings.Builder
	for _, name := range names {
		b.WriteString(objects[name].sql + ";\n")
	}
	return b.String()
}

// schemaChanges is what schemadiff finds from the schema older makes to the
// one newer makes: none when they are the same schema, written either way.
func schemaChanges(t *testing.T, older, newer string) []schemadiff.Change {
	t.Helper()
	changes, err := schemadiff.Diff(context.Background(), older, newer)
	if err != nil {
		t.Fatal(err)
	}
	return changes
}

func sortedNames(objects map[string]schemaObject) []string {
	names := make([]string, 0, len(objects))
	for name := range objects {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func kindOrder(kind string) int {
	return map[string]int{"table": 0, "index": 1, "view": 2, "trigger": 3}[kind]
}

func quoteName(name string) string { return `"` + strings.ReplaceAll(name, `"`, `""`) + `"` }

type recordedSchema struct {
	version, compatibleFrom int64
	updatedBy               string
	objects                 string // every table, index and trigger, by type and name
	definitions             string // their statements (definitions)
}

// String leaves the statements out of a failure's message.
func (r recordedSchema) String() string {
	return fmt.Sprintf("{version:%d compatibleFrom:%d updatedBy:%s objects:%s}", r.version, r.compatibleFrom, r.updatedBy, r.objects)
}

func readRecorded(t *testing.T, in install) recordedSchema {
	t.Helper()
	u := url.URL{Scheme: "file", Path: filepath.Join(in.data, "varlatch.db"), RawQuery: "mode=ro"}
	conn, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var r recordedSchema
	if err := conn.QueryRow("SELECT version, compatible_from, updated_by_release FROM schema_version").Scan(&r.version, &r.compatibleFrom, &r.updatedBy); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow("SELECT group_concat(type || ' ' || name, ', ') FROM (SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY type, name)").Scan(&r.objects); err != nil {
		t.Fatal(err)
	}
	r.definitions = definitions(schemaObjects(t, conn))
	return r
}

// serveRefused runs serve, which must stop before it serves: its exit code
// and what it logged.
func serveRefused(t *testing.T, in install) (int, string) {
	t.Helper()
	served := make(chan struct{}, 1)
	done := make(chan int, 1)
	stderr := &syncBuffer{}
	signals := make(chan os.Signal, 1)
	go func() {
		done <- Serve(Options{ConfigPath: in.conf, Stderr: stderr, Signals: signals, Ready: func(net.Addr) { served <- struct{}{} }})
	}()
	select {
	case code := <-done:
		return code, stderr.String()
	case <-served:
		signals <- os.Interrupt
		<-done
		t.Fatalf("serve served: %s", stderr.String())
	case <-time.After(30 * time.Second):
		t.Fatal("serve neither served nor stopped")
	}
	return 0, ""
}

// On the host target an older database stays refused: varlatch upgrade
// upgrades it, with its snapshot and journal.
func TestServeOnTheHostRefusesAnOlderSchema(t *testing.T) {
	t.Setenv(keyenv.ImageMarker, "")
	in := newInstall(t, "")
	start(t, in).stop(t)
	previousSchema(t, in)
	before := readRecorded(t, in)
	code, logged := serveRefused(t, in)
	if code != ExitFailure || !strings.Contains(logged, fmt.Sprintf("older than this varlatchd's %d; run varlatch upgrade", db.SchemaVersion)) {
		t.Fatalf("serve on the host, an older schema: %d %q", code, logged)
	}
	if after := readRecorded(t, in); after != before {
		t.Fatalf("serve on the host changed the schema: %+v (before %+v)", after, before)
	}
}

// In the image a rollback-safe upgrade runs at start: recorded as admin
// schema upgrade records it, logged, and served; the next start has
// nothing to do.
func TestServeInTheImageUpgradesARollbackSafeSchema(t *testing.T) {
	t.Setenv(keyenv.ImageMarker, "varlatchd")
	if !db.RollbackSafeFrom(db.SchemaVersion - 1) {
		t.Skipf("this release's last step is not rollback-safe: TestServeInTheImageRefusesAnUpgradeThatIsNotRollbackSafe and server/db cover it")
	}
	in := newInstall(t, "")
	start(t, in).stop(t)
	current := readRecorded(t, in)
	previousSchema(t, in)
	// Changed by what the last step does: a step that makes a table again
	// (schema 8) keeps every name, so the statements are compared.
	if got := readRecorded(t, in); got.version != db.SchemaVersion-1 || len(schemaChanges(t, got.definitions, current.definitions)) == 0 {
		t.Fatalf("the previous schema: %+v", got)
	}
	// admin schema status says what start will do.
	code, out, _ := runAdmin(t, "schema", "status", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, "this image's varlatchd applies it when it starts") {
		t.Fatalf("schema status in the image: %d %q", code, out)
	}

	r := start(t, in)
	logged := r.stderr.String()
	r.stop(t)
	if !strings.Contains(logged, "upgrading it before serving") || !strings.Contains(logged, "upgraded the database's schema") ||
		!strings.Contains(logged, fmt.Sprintf("from=%d to=%d compatibleFrom=%d", db.SchemaVersion-1, db.SchemaVersion, db.CompatibleFrom)) {
		t.Fatalf("the upgrade is not logged: %q", logged)
	}
	got := readRecorded(t, in)
	if changes := schemaChanges(t, current.definitions, got.definitions); len(changes) != 0 {
		t.Fatalf("after the upgrade at start, the schema is not a new database's: %v", changes)
	}
	want := recordedSchema{version: db.SchemaVersion, compatibleFrom: db.CompatibleFrom, updatedBy: buildinfo.Version, objects: current.objects, definitions: got.definitions}
	if got != want {
		t.Fatalf("after the upgrade at start: %+v, want %+v", got, want)
	}

	// The same schema: nothing to upgrade, nothing logged about it.
	r = start(t, in)
	logged = r.stderr.String()
	r.stop(t)
	if strings.Contains(logged, "upgrading it before serving") {
		t.Fatalf("a start on the current schema logged an upgrade: %q", logged)
	}
	// A newer schema this varlatchd may open (a rollback-safe newer release
	// wrote it): served as it is, the way back by digest.
	setSchema(t, in, db.SchemaVersion+1, db.SchemaVersion)
	r = start(t, in)
	logged = r.stderr.String()
	r.stop(t)
	if got := readRecorded(t, in); got.version != db.SchemaVersion+1 || got.compatibleFrom != db.SchemaVersion || strings.Contains(logged, "upgrading it before serving") {
		t.Fatalf("a newer compatible schema: %+v %q", got, logged)
	}
}

// In the image, an upgrade that is not rollback-safe is refused before
// anything is changed, with the one-off procedure in the message.
func TestServeInTheImageRefusesAnUpgradeThatIsNotRollbackSafe(t *testing.T) {
	t.Setenv(keyenv.ImageMarker, "varlatchd")
	in := newInstall(t, "")
	start(t, in).stop(t)
	previousSchema(t, in)
	before := readRecorded(t, in)
	// No released step is unsafe: the upgrade db.UpgradeIfRollbackSafe
	// refuses (server/db tests that it changes nothing then).
	upgradeIfRollbackSafe = func(context.Context, *storage.DB, string) (db.Upgraded, error) {
		return db.Upgraded{From: db.SchemaVersion - 1, To: db.SchemaVersion - 1, CompatibleFrom: 1},
			&db.NotRollbackSafeError{Database: db.SchemaVersion - 1, CompatibleFrom: db.SchemaVersion, Binary: db.SchemaVersion}
	}
	t.Cleanup(func() { upgradeIfRollbackSafe = db.UpgradeIfRollbackSafe })
	code, logged := serveRefused(t, in)
	if code != ExitFailure {
		t.Fatalf("exit %d: %q", code, logged)
	}
	for _, want := range []string{"is not rollback-safe", "nothing was changed", "varlatchd admin backup run", "admin schema upgrade", "previous image's digest"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("the refusal does not say %q: %q", want, logged)
		}
	}
	if strings.Contains(logged, "run varlatch upgrade") {
		t.Fatalf("the image's refusal names varlatch upgrade: %q", logged)
	}
	if after := readRecorded(t, in); after != before {
		t.Fatalf("the refusal changed the schema: %+v (before %+v)", after, before)
	}
}
