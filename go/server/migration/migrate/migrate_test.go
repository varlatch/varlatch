// SPDX-License-Identifier: AGPL-3.0-or-later

package migrate

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/manifest"
	"github.com/varlatch/varlatch/go/server/migration/migrationtest"
)

// The source is migrationtest's: the TypeScript server's rows of the
// v0.22.0 parity fixtures, under core's Root KEK, plus a person with a live
// browser session, a browser credential minted from it, an expired one and
// a CLI hand-off credential from the same session, a signing key, and the
// finished exposure backfill.
type source = migrationtest.Source

func loadSource(t *testing.T) source { return migrationtest.Load(t) }

// sourceBundle is the source's forward bundle, extra rows added by table.
func sourceBundle(t *testing.T, s source, extra map[string][][]any, sequences bool) []byte {
	t.Helper()
	return migrationtest.Bundle(t, s, migrationtest.Options{Extra: extra, Sequences: sequences})
}

// tablesOf reads a bundle into its rows by table.
func tablesOf(t *testing.T, b []byte) map[string][]string {
	t.Helper()
	m, _ := manifest.Load()
	r, err := bundle.NewReader(bytes.NewReader(b), m)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for range bundle.Tables(m) {
		tb, n, err := r.NextTable()
		if err != nil {
			t.Fatal(err)
		}
		out[tb.Source] = []string{}
		for range n {
			row, err := r.Row()
			if err != nil {
				t.Fatal(err)
			}
			out[tb.Source] = append(out[tb.Source], string(row))
		}
	}
	if err := r.SkipSections(); err != nil {
		t.Fatal(err)
	}
	if err := r.End(); err != nil {
		t.Fatal(err)
	}
	return out
}

func importInto(t *testing.T, dir string, b []byte, kek []byte) (Result, error) {
	t.Helper()
	return Import(context.Background(), bytes.NewReader(b), Options{DataDir: dir, RootKEK: kek, Release: "0.50.0-test"})
}

// The round trip: the TypeScript server's rows imported, then exported back
// (the reverse bundle) are the same rows, byte for byte, but for the
// documented transformations: the session ended (its browser credential
// revoked, the CLI credential kept), and the audit log a prefix of the
// reverse bundle's, which appends the revocation and installation.migrated
// (forward and reverse).
func TestRoundTrip(t *testing.T) {
	s := loadSource(t)
	src := sourceBundle(t, s, nil, false)
	// The tables the round trip carries rows of.
	var withData []string
	for table, rows := range tablesOf(t, src) {
		if len(rows) > 0 {
			withData = append(withData, table)
		}
	}
	slices.Sort(withData)
	t.Logf("%d tables with rows: %s", len(withData), strings.Join(withData, ", "))
	for _, want := range []string{"audit_events", "signing_keys", "audit_export_plans", "audit_exports", "webhooks", "platform_connections",
		"sync_cursor", "sync_targets", "passkey", "passkey_provenance", "session", "user", "credentials", "value_versions", "requirements", "exposure_backfill"} {
		if !slices.Contains(withData, want) {
			t.Errorf("%s has no rows in the round trip", want)
		}
	}
	if len(withData) < 45 {
		t.Errorf("only %d tables with rows", len(withData))
	}
	dir := t.TempDir()
	res, err := importInto(t, dir, src, s.RootKEK)
	if err != nil {
		t.Fatal(err)
	}
	if res.SessionsEnded != 1 || res.CredentialsRevoked != 1 || res.InstallationID == "" {
		t.Fatalf("import: %+v", res)
	}
	conn, err := sql.Open("sqlite", "file:"+filepath.Join(dir, config.DatabaseFile)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	var browserRevoked, cliRevoked, expiredRevoked sql.NullInt64
	_ = conn.QueryRow("SELECT revoked_at FROM credentials WHERE id = 'crd_migration_browser'").Scan(&browserRevoked)
	_ = conn.QueryRow("SELECT revoked_at FROM credentials WHERE id = 'crd_migration_cli'").Scan(&cliRevoked)
	_ = conn.QueryRow("SELECT revoked_at FROM credentials WHERE id = 'crd_migration_expired'").Scan(&expiredRevoked)
	var revokedEvents int
	_ = conn.QueryRow("SELECT count(*) FROM audit_events WHERE event_type = 'credential.revoked' AND credential_id LIKE 'crd_migration_%'").Scan(&revokedEvents)
	if expiredRevoked.Valid || revokedEvents != 1 {
		t.Fatalf("the expired browser credential: revoked %v; %d credential.revoked events, want 1", expiredRevoked, revokedEvents)
	}
	var sessions int
	_ = conn.QueryRow("SELECT count(*) FROM auth_sessions").Scan(&sessions)
	rows, err := conn.Query("SELECT event_type FROM audit_events ORDER BY event_order DESC LIMIT 2")
	if err != nil {
		t.Fatal(err)
	}
	var last []string
	for rows.Next() {
		var e string
		_ = rows.Scan(&e)
		last = append(last, e)
	}
	rows.Close()
	conn.Close()
	if !browserRevoked.Valid || cliRevoked.Valid || sessions != 0 || !slices.Equal(last, []string{MigratedEvent, "credential.revoked"}) {
		t.Fatalf("browser revoked %v, cli revoked %v, sessions %d, last events %q", browserRevoked, cliRevoked, sessions, last)
	}

	var rev bytes.Buffer
	out, err := ExportReverse(context.Background(), &rev, Options{DataDir: dir, Release: "0.50.0-test"})
	if err != nil {
		t.Fatal(err)
	}
	if out.SessionsEnded != 0 || out.InstallationID != res.InstallationID {
		t.Fatalf("export: %+v", out)
	}
	before, after := tablesOf(t, src), tablesOf(t, rev.Bytes())
	for table, want := range before {
		got := after[table]
		switch table {
		case "audit_events":
			if len(got) != len(want)+3 || !slices.Equal(got[:len(want)], want) {
				t.Errorf("audit_events: %d source events, %d after; the source is not a prefix", len(want), len(got))
			}
			for i, e := range []string{"credential.revoked", MigratedEvent, MigratedEvent} {
				if !strings.Contains(got[len(want)+i], `"`+e+`"`) {
					t.Errorf("appended event %d: %s", i, got[len(want)+i])
				}
			}
		case "session":
			if len(got) != 0 {
				t.Errorf("session: %d rows in the reverse bundle", len(got))
			}
		case "credentials":
			diff := 0
			for i := range want {
				if got[i] != want[i] {
					diff++
					if !strings.Contains(want[i], "crd_migration_browser") {
						t.Errorf("credentials: %s changed", want[i])
					}
				}
			}
			if diff != 1 || len(got) != len(want) {
				t.Errorf("credentials: %d changed of %d", diff, len(want))
			}
		default:
			if !slices.Equal(got, want) {
				t.Errorf("%s: the round trip changed it:\n source %q\n after  %q", table, want, got)
			}
		}
	}
	// The export changed nothing in the database.
	conn, _ = sql.Open("sqlite", "file:"+filepath.Join(dir, config.DatabaseFile)+"?mode=ro")
	defer conn.Close()
	var migrated int
	_ = conn.QueryRow("SELECT count(*) FROM audit_events WHERE event_type = ?", MigratedEvent).Scan(&migrated)
	if migrated != 1 {
		t.Errorf("the export wrote to the database: %d installation.migrated events", migrated)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".migrate-export-*")); len(left) != 0 {
		t.Errorf("the snapshot copy was left: %v", left)
	}
}

// What an import refuses, keeping nothing: a data directory in use, the
// wrong Root KEK, a bundle cut short or damaged, a broken foreign key, a
// row not in canonical form, a sequence, a reverse bundle.
func TestImportRefusals(t *testing.T) {
	s := loadSource(t)
	good := sourceBundle(t, s, nil, false)
	empty := func(t *testing.T) string { return t.TempDir() }
	nothingKept := func(t *testing.T, dir, name string) {
		t.Helper()
		if left, _ := filepath.Glob(filepath.Join(dir, "varlatch.db*")); len(left) != 0 {
			t.Errorf("%s: kept %v", name, left)
		}
	}
	wrongKEK := make([]byte, 32)
	_, _ = rand.Read(wrongKEK)
	m, _ := manifest.Load()
	var membership manifest.Table
	for _, tb := range m.Tables {
		if tb.Source == "org_memberships" {
			membership = tb
		}
	}
	orphan := make([]any, len(membership.Columns))
	for i, c := range membership.Columns {
		switch c.Source {
		case "organization_id":
			orphan[i] = "org_nowhere"
		case "identity_id":
			orphan[i] = "idn_nowhere"
		case "role":
			orphan[i] = "member"
		case "created_at":
			orphan[i] = int64(1)
		case "version":
			orphan[i] = int64(0)
		}
	}
	lines := bytes.SplitAfter(good, []byte("\n"))
	cut := bytes.Join(lines[:len(lines)/2], nil)
	var damaged, notCanonical []byte
	for i, l := range lines {
		if i > 0 && bytes.HasPrefix(lines[i-1], []byte(`{"table":"installation",`)) {
			d := slices.Clone(good)
			off := len(bytes.Join(lines[:i], nil))
			d[off+3] ^= 1
			damaged = d
			// The same row with a space after its first value, the
			// stream sealed again: refused for its form, not its digest.
			ls := slices.Clone(lines)
			ls[i] = bytes.Replace(l, []byte(`",`), []byte(`", `), 1)
			notCanonical = reseal(t, bytes.Join(ls, nil))
			break
		}
	}
	used := t.TempDir()
	if err := os.WriteFile(filepath.Join(used, "notes"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var rev bytes.Buffer
	{
		dir := t.TempDir()
		if _, err := importInto(t, dir, good, s.RootKEK); err != nil {
			t.Fatal(err)
		}
		if _, err := ExportReverse(context.Background(), &rev, Options{DataDir: dir, Release: "0.50.0-test"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name   string
		dir    string
		bundle []byte
		kek    []byte
		why    string
	}{
		{"a data directory in use", used, good, s.RootKEK, "not empty"},
		{"the wrong Root KEK", empty(t), good, wrongKEK, "does not open the installation's canary"},
		{"cut short", empty(t), cut, s.RootKEK, "cut short"},
		{"a damaged byte", empty(t), damaged, s.RootKEK, "damaged"},
		{"a row not in canonical form", empty(t), notCanonical, s.RootKEK, "table installation: row 1: canonical: the row is not in canonical form"},
		{"a broken foreign key", empty(t), sourceBundle(t, s, map[string][][]any{"org_memberships": {orphan}}, false), s.RootKEK, "foreign keys do not hold: org_memberships"},
		{"a sequence", empty(t), sourceBundle(t, s, nil, true), s.RootKEK, "sequences"},
		{"a reverse bundle", empty(t), rev.Bytes(), s.RootKEK, "a reverse bundle"},
		{"a session token carried", empty(t), withToken(t, s), s.RootKEK, "session.token holds a value"},
		{"a leftover that is not an import's", leftover(t, ".migrate-import-x.db"), good, s.RootKEK, "not empty (.migrate-import-x.db)"},
	} {
		_, err := importInto(t, c.dir, c.bundle, c.kek)
		if err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %v, want %q", c.name, err, c.why)
		}
		if c.dir != used {
			nothingKept(t, c.dir, c.name)
		}
		if left, _ := filepath.Glob(filepath.Join(c.dir, importPrefix+"*")); len(left) != 0 && c.name != "a leftover that is not an import's" {
			t.Errorf("%s: left %v", c.name, left)
		}
	}
}

// withToken is the source with its session's token carried.
func withToken(t *testing.T, s source) []byte {
	t.Helper()
	carried := source{RootKEK: s.RootKEK, AuditPosition: s.AuditPosition, Rows: map[string][]jsvalue.Object{}}
	for k, v := range s.Rows {
		carried.Rows[k] = v
	}
	row := slices.Clone(s.Rows["session"][0])
	for i, m := range row {
		if m.Key == "token" {
			row[i].Value = "a token the export never carries"
		}
	}
	carried.Rows["session"] = []jsvalue.Object{row}
	return sourceBundle(t, carried, nil, false)
}

// leftover is a data directory holding a file named name.
func leftover(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// An import that was killed leaves its database under the temporary name:
// the next import removes it (that exact pattern only) and builds the
// database, renamed into place; no temporary name is left.
func TestAnInterruptedImportsLeftovers(t *testing.T) {
	s := loadSource(t)
	dir := t.TempDir()
	// The -journal: killed while the database was being created, before
	// it was in WAL mode (the G5 gate's killed import found it).
	for _, name := range []string{importPrefix + "0123456789ab.db", importPrefix + "0123456789ab.db-wal", importPrefix + "0123456789ab.db-shm",
		importPrefix + "ba9876543210.db", importPrefix + "ba9876543210.db-journal"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("an import cut short"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := importInto(t, dir, sourceBundle(t, s, nil, false), s.RootKEK); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{config.DatabaseFile}) {
		t.Fatalf("the data directory after the import: %q", names)
	}
}

func reseal(t *testing.T, b []byte) []byte { return migrationtest.Reseal(t, b) }

// A reverse export that was killed leaves its snapshot copy under its
// temporary name: the next import removes it (that exact pattern, regular
// files only) and goes on; a look-alike, or a directory under the name, is
// refused and named.
func TestAnInterruptedExportsLeftovers(t *testing.T) {
	s := loadSource(t)
	dir := t.TempDir()
	for _, name := range []string{".migrate-export-0123456789ab.db", ".migrate-export-0123456789ab.db-wal", ".migrate-export-0123456789ab.db-shm",
		".migrate-export-ba9876543210.db", ".migrate-export-ba9876543210.db-journal"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("an export cut short"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := importInto(t, dir, sourceBundle(t, s, nil, false), s.RootKEK); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != config.DatabaseFile {
		t.Fatalf("the data directory after the import: %v", entries)
	}
	for _, name := range []string{".migrate-export-0123456789ab.db.bak", ".migrate-export-0123456789AB.db"} {
		if _, err := importInto(t, leftover(t, name), sourceBundle(t, s, nil, false), s.RootKEK); err == nil || !strings.Contains(err.Error(), "not empty ("+name+")") {
			t.Errorf("%s: %v", name, err)
		}
	}
	asDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(asDir, ".migrate-export-0123456789ab.db"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := importInto(t, asDir, sourceBundle(t, s, nil, false), s.RootKEK); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("a directory under the temporary name: %v", err)
	}
}

// The reverse export from a barrier's frozen copy (From): read as a file,
// never opened in place; a copy whose last audit position is not the
// frozen point it is given (another copy, or one written since) is
// refused, naming it, with nothing written and nothing kept; at the frozen
// point it exports, and keeps the transformed copy.
func TestTheFrozenCopy(t *testing.T) {
	s := loadSource(t)
	dir := t.TempDir()
	if _, err := importInto(t, dir, sourceBundle(t, s, nil, false), s.RootKEK); err != nil {
		t.Fatal(err)
	}
	frozen := filepath.Join(t.TempDir(), "frozen.db")
	b, err := os.ReadFile(filepath.Join(dir, config.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(frozen, b, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+frozen+"?mode=ro&immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	var last int64
	if err := db.QueryRow("SELECT max(event_order) FROM audit_events").Scan(&last); err != nil {
		t.Fatal(err)
	}
	db.Close()
	for _, at := range []int64{last - 1, last + 1} {
		keep := filepath.Join(t.TempDir(), "keep")
		var out bytes.Buffer
		_, err := ExportReverse(context.Background(), &out, Options{DataDir: dir, From: frozen, FrozenAt: at, Keep: keep, Release: "0.50.0-test"})
		if err == nil || !strings.Contains(err.Error(), "it is not the copy that barrier made") {
			t.Fatalf("a frozen point of %d for a copy at %d: %v", at, last, err)
		}
		if out.Len() != 0 {
			t.Errorf("a refused export wrote %d bytes", out.Len())
		}
		if _, err := os.Stat(filepath.Join(keep, config.DatabaseFile)); !os.IsNotExist(err) {
			t.Errorf("a refused export kept its copy: %v", err)
		}
	}
	after, _ := os.ReadFile(frozen)
	if !bytes.Equal(after, b) {
		t.Fatal("the frozen copy changed")
	}
	keep := filepath.Join(t.TempDir(), "keep")
	var out bytes.Buffer
	res, err := ExportReverse(context.Background(), &out, Options{DataDir: dir, From: frozen, FrozenAt: last, Keep: keep, Release: "0.50.0-test"})
	if err != nil || res.MigratedPosition <= last {
		t.Fatalf("at its frozen point: %+v %v", res, err)
	}
	if _, err := os.Stat(filepath.Join(keep, config.DatabaseFile)); err != nil {
		t.Errorf("the kept copy: %v", err)
	}
	for _, sfx := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(frozen + sfx); !os.IsNotExist(err) {
			t.Errorf("%s beside the frozen copy: the export opened it in place", sfx)
		}
	}
}

// Go's local backup store, backups/, kept in the data directory after a
// discarded copy (varlatch migrate --finish --delete-old-data after a
// rollback; rehearsal r16f): an import leaves it as it is, a directory
// only. CheckFresh, the check a preflight makes, gives the import's
// verdict without its removals.
func TestAnImportKeepsGoBackups(t *testing.T) {
	keep := []string{"backups"}
	t.Run("a backups directory: imported beside, untouched", func(t *testing.T) {
		s := loadSource(t)
		dir := t.TempDir()
		archive := filepath.Join(dir, "backups", "final.vltbak")
		if err := os.MkdirAll(filepath.Dir(archive), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(archive, []byte("the final archive"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := CheckFresh(dir, nil, keep); err != nil {
			t.Fatal(err)
		}
		if _, err := Import(context.Background(), bytes.NewReader(sourceBundle(t, s, nil, false)), Options{DataDir: dir, KeepDirs: keep, RootKEK: s.RootKEK, Release: "0.50.0-test"}); err != nil {
			t.Fatal(err)
		}
		if b, err := os.ReadFile(archive); err != nil || string(b) != "the final archive" {
			t.Fatalf("backups/ after the import: %q, %v", b, err)
		}
		if _, err := os.Stat(filepath.Join(dir, config.DatabaseFile)); err != nil {
			t.Fatal(err)
		}
	})
	for _, c := range []struct {
		what string
		make func(t *testing.T, dir string)
		want string
	}{
		{"a file named backups", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "backups"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "holds backups, which is not a directory"},
		{"a link named backups, to a directory", func(t *testing.T, dir string) {
			if err := os.Symlink(t.TempDir(), filepath.Join(dir, "backups")); err != nil {
				t.Fatal(err)
			}
		}, "holds backups, which is not a directory"},
		{"backups and another name", func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "backups"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "notes.txt"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "is not empty (notes.txt)"},
	} {
		t.Run(c.what, func(t *testing.T) {
			dir := t.TempDir()
			c.make(t, dir)
			for name, err := range map[string]error{"CheckFresh": CheckFresh(dir, nil, keep), "fresh": fresh(dir, nil, keep)} {
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Errorf("%s: %v, want %q", name, err, c.want)
				}
			}
		})
	}
	t.Run("an interrupted import's leftover: the check removes nothing", func(t *testing.T) {
		dir := t.TempDir()
		left := filepath.Join(dir, importPrefix+"0123456789ab.db")
		if err := os.WriteFile(left, []byte("cut short"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := CheckFresh(dir, nil, keep); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(left); err != nil {
			t.Fatalf("CheckFresh removed the leftover: %v", err)
		}
		if err := fresh(dir, nil, keep); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(left); !os.IsNotExist(err) {
			t.Fatalf("fresh kept the leftover: %v", err)
		}
	})
}
