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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/keyenv"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db"
)

// previousSchema makes the stopped installation's database the one the
// release before this schema left: what the last upgrade step creates
// dropped again (a rollback-safe step only adds), and the version and
// compatible_from recorded as they were before it. A step that does more
// than add tables, indexes, triggers or columns needs its undoing here.
func previousSchema(t *testing.T, in install) {
	t.Helper()
	steps := db.Steps()
	if len(steps) == 0 {
		t.Fatal("this varlatchd has no upgrade step to undo")
	}
	last := steps[len(steps)-1]
	if regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|DROP|RENAME|REPLACE)\b`).MatchString(last.SQL) {
		t.Fatalf("previousSchema cannot undo schema %d's step, which does more than add: extend it\n%s", last.To, last.SQL)
	}
	var undo []string
	for _, m := range regexp.MustCompile(`(?i)\bCREATE\s+TRIGGER\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)`).FindAllStringSubmatch(last.SQL, -1) {
		undo = append(undo, "DROP TRIGGER "+m[1])
	}
	for _, m := range regexp.MustCompile(`(?i)\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)`).FindAllStringSubmatch(last.SQL, -1) {
		undo = append(undo, "DROP INDEX "+m[1])
	}
	for _, m := range regexp.MustCompile(`(?i)\bALTER\s+TABLE\s+(\w+)\s+ADD\s+(?:COLUMN\s+)?(\w+)`).FindAllStringSubmatch(last.SQL, -1) {
		undo = append(undo, "ALTER TABLE "+m[1]+" DROP COLUMN "+m[2])
	}
	for _, m := range regexp.MustCompile(`(?i)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)`).FindAllStringSubmatch(last.SQL, -1) {
		undo = append(undo, "DROP TABLE "+m[1])
	}
	if len(undo) == 0 {
		t.Fatalf("previousSchema found nothing to undo in schema %d's step: extend it\n%s", last.To, last.SQL)
	}
	compatibleFrom := int64(1)
	if len(steps) > 1 {
		compatibleFrom = steps[len(steps)-2].CompatibleFrom
	}
	s, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(in.data, "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Write(context.Background(), func(tx *storage.Tx) error {
		for _, q := range undo {
			if _, err := tx.ExecContext(context.Background(), q); err != nil {
				return fmt.Errorf("%s: %w", q, err)
			}
		}
		_, err := tx.ExecContext(context.Background(), "UPDATE schema_version SET version = ?, compatible_from = ?, updated_by_release = 'previous'", last.To-1, compatibleFrom)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

type recordedSchema struct {
	version, compatibleFrom int64
	updatedBy               string
	objects                 string // every table, index, trigger and column, by type and name
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
	// The columns too: a step may add one (schema 8's webhooks.url_envelope).
	if err := conn.QueryRow(`SELECT group_concat(entry, ', ') FROM (
		SELECT type || ' ' || name AS entry FROM sqlite_schema WHERE name NOT LIKE 'sqlite\_%' ESCAPE '\'
		UNION ALL SELECT 'column ' || m.name || '.' || c.name FROM sqlite_schema m, pragma_table_xinfo(m.name) c
		WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite\_%' ESCAPE '\'
		ORDER BY entry)`).Scan(&r.objects); err != nil {
		t.Fatal(err)
	}
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
	if got := readRecorded(t, in); got.version != db.SchemaVersion-1 || got.objects == current.objects {
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
	want := recordedSchema{version: db.SchemaVersion, compatibleFrom: db.CompatibleFrom, updatedBy: buildinfo.Version, objects: current.objects}
	if got := readRecorded(t, in); got != want {
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
