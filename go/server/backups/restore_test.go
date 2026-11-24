// SPDX-License-Identifier: AGPL-3.0-or-later

package backups

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/maintenance"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/write"
)

// target is a fresh data directory with the source's settings.
func (f *fixture) target(t *testing.T) *config.Config {
	t.Helper()
	cfg := *f.cfg
	cfg.DataDir = t.TempDir()
	return &cfg
}

func (f *fixture) bekOf(t *testing.T) backup.BEK {
	t.Helper()
	bek, err := backup.KeyBEK(f.bek)
	if err != nil {
		t.Fatal(err)
	}
	return bek
}

// queryOne reads one value from a database file.
func queryOne(t *testing.T, path, q string, args ...any) string {
	t.Helper()
	conn, err := sql.Open("sqlite", fileURI(path)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var v sql.NullString
	if err := conn.QueryRow(q, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return v.String
}

// listing is a directory's names.
func listing(t *testing.T, dir string) string {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return strings.Join(names, " ")
}

// A restore onto a fresh data directory, from the archive and the two
// keys: the database is the snapshot, the installation and its canary are
// the archive's, installation.restored is the first new audit event, and
// nothing of the restore is left behind. Restoring again over the same
// installation works too.
func TestRestore(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.exec(t, "CREATE TABLE marker (v TEXT) STRICT")
	f.exec(t, "INSERT INTO marker VALUES ('restored')")
	res, err := f.service(nil).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg := f.target(t)
	got, err := Restore(ctx, cfg, res.Path, f.bekOf(t), f.rootKEK, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.ArchiveID != res.ArchiveID || got.InstallationID != f.inst || got.CreatedAt != res.CreatedAt || got.Settings["listen"] != "127.0.0.1:8686" {
		t.Errorf("%+v", got)
	}
	if l := listing(t, cfg.DataDir); l != "restore-hold.json varlatch.db" {
		t.Errorf("the data directory holds %q", l)
	}
	if h, err := backup.ReadHold(cfg.DataDir); err != nil || h == nil || h.ArchiveID != res.ArchiveID || h.RestoredAt == "" {
		t.Errorf("the hold: %+v %v", h, err)
	}
	db := cfg.DatabasePath()
	if v := queryOne(t, db, "SELECT v FROM marker"); v != "restored" {
		t.Errorf("marker %q", v)
	}
	if id := queryOne(t, db, "SELECT id FROM installation"); id != f.inst {
		t.Errorf("installation %q", id)
	}
	if a := queryOne(t, db, "SELECT json_extract(metadata, '$.archiveId') FROM audit_events WHERE event_type = 'installation.restored' ORDER BY event_order DESC LIMIT 1"); a != res.ArchiveID {
		t.Errorf("installation.restored names %q", a)
	}
	if last := queryOne(t, db, "SELECT event_type FROM audit_events ORDER BY event_order DESC LIMIT 1"); last != "installation.restored" {
		t.Errorf("the last event is %q", last)
	}
	if _, err := Restore(ctx, cfg, res.Path, f.bekOf(t), f.rootKEK, nil); err != nil {
		t.Errorf("restoring again over the same installation: %v", err)
	}
}

// A restore of an archive with a live audit export (ADR-0056 Decision 5):
// the export continues in a new stream at its restored cursor, its
// pending plan replaced by that stream's manifest, and
// audit_export.stream_started (reason restored) follows
// installation.restored.
func TestRestoreRestartsAuditExportStreams(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.exec(t, `INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'Alice')`)
	org, err := orgs.Create(ctx, &write.Writer{Store: f.store, Gates: write.NewGates()}, f.rootKEK, "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	const id, stream = "aex_aaaaaaaaaaaaaaaaaaaaaaaaaa", "aes_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	now := time.Now().UnixMicro()
	f.exec(t, `INSERT INTO audit_exports (id, organization_id, endpoint, region, bucket, prefix, path_style, credential_envelope, stream_id, stream_started_at,
		cursor_order, state, created_by) VALUES (?, ?, 'https://s3.example.test', 'us-east-1', 'bucket', 'p/', 1, '{}', ?, ?, 3, 'active', 'idn_a')`, id, org.ID, stream, now)
	f.exec(t, `INSERT INTO audit_export_plans (id, export_id, export_version, stream_id, generation, kind, object_name, body, sha256, md5, content_type, format_version, planned_at)
		VALUES ('aep_aaaaaaaaaaaaaaaaaaaaaaaaaa', ?, 1, ?, 0, 'manifest', 'p/x/stream.json', X'7B7D', ?, ?, 'application/json', 1, ?)`,
		id, stream, strings.Repeat("a", 64), strings.Repeat("b", 32), now)
	res, err := f.service(nil).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg := f.target(t)
	if _, err := Restore(ctx, cfg, res.Path, f.bekOf(t), f.rootKEK, nil); err != nil {
		t.Fatal(err)
	}
	db := cfg.DatabasePath()
	current := queryOne(t, db, "SELECT stream_id FROM audit_exports WHERE id = ?", id)
	manifest := queryOne(t, db, "SELECT CAST(body AS TEXT) FROM audit_export_plans WHERE export_id = ?", id)
	var m map[string]any
	if err := json.Unmarshal([]byte(manifest), &m); err != nil || current == stream || m["reason"] != "restored" || m["previousStreamId"] != stream ||
		m["startOrder"] != "3" || m["streamId"] != current || queryOne(t, db, "SELECT generation FROM audit_exports WHERE id = ?", id) != "1" {
		t.Errorf("stream %s, manifest %s: %v", current, manifest, err)
	}
	if got := queryOne(t, db, "SELECT group_concat(event_type, ' ') FROM (SELECT event_type FROM audit_events ORDER BY event_order DESC LIMIT 2)"); got != "audit_export.stream_started installation.restored" {
		t.Errorf("the last events: %q", got)
	}
}

// What a restore refuses before it changes anything.
func TestRestoreRefusals(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	res, err := f.service(nil).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	untouched := func(cfg *config.Config, what string) {
		t.Helper()
		if l := listing(t, cfg.DataDir); l != "" {
			t.Errorf("%s left %q", what, l)
		}
	}
	cfg := f.target(t)
	if _, err := Restore(ctx, cfg, res.Path, f.bekOf(t), envelope.GenerateKey(), nil); err == nil || !strings.Contains(err.Error(), "Root KEK does not open") {
		t.Errorf("another Root KEK: %v", err)
	}
	untouched(cfg, "another Root KEK")
	other, _ := backup.KeyBEK(envelope.GenerateKey())
	if _, err := Restore(ctx, cfg, res.Path, other, f.rootKEK, nil); err == nil {
		t.Error("another BEK opened the archive")
	}
	untouched(cfg, "another BEK")
	same, _ := backup.KeyBEK(f.rootKEK)
	if _, err := Restore(ctx, cfg, res.Path, same, f.rootKEK, nil); err == nil {
		t.Error("a BEK that is the Root KEK")
	}
	raw, _ := os.ReadFile(res.Path)
	raw[len(raw)/2] ^= 1
	bad := filepath.Join(t.TempDir(), "bad.vltbak")
	os.WriteFile(bad, raw, 0o600)
	if _, err := Restore(ctx, cfg, bad, f.bekOf(t), f.rootKEK, nil); err == nil {
		t.Error("a changed archive was restored")
	}
	untouched(cfg, "a changed archive")
	// Another installation's data directory.
	g := newFixture(t)
	if _, err := Restore(ctx, g.cfg, res.Path, f.bekOf(t), f.rootKEK, nil); err == nil || !strings.Contains(err.Error(), "another installation") || !strings.Contains(err.Error(), "move varlatch.db") {
		t.Errorf("over another installation: %v", err)
	}
	if _, err := os.Stat(filepath.Join(g.dir, backup.GateFile)); !os.IsNotExist(err) {
		t.Errorf("a refused restore opened a gate: %v", err)
	}
	// While a lease is open.
	a := maintenance.Open(cfg.DataDir, nil)
	lease, _ := a.Begin(60e9)
	if _, err := Restore(ctx, cfg, res.Path, f.bekOf(t), f.rootKEK, nil); err == nil || !strings.Contains(err.Error(), "another maintenance operation") {
		t.Errorf("during a lease: %v", err)
	}
	a.End(lease.ID)
}

// A restore that fails after the database was replaced leaves its gate:
// a varlatchd that starts stays isolated. Running it again with the same
// archive resumes and completes it.
func TestFailedRestoreStaysIsolatedAndResumes(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	res, err := f.service(nil).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The same archive, its database without the installation: it opens
	// and passes the checks before the swap, and fails after it.
	bek := f.bekOf(t)
	o, err := backup.Open(res.Path, bek, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := o.Path(backup.ComponentDatabase)
	conn, err := sql.Open("sqlite", fileURI(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec("DELETE FROM installation"); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	m := o.Manifest
	for i, c := range m.Components {
		d, err := backup.Describe(c.Name, o.Path(c.Name))
		if err != nil {
			t.Fatal(err)
		}
		m.Components[i] = d
	}
	manifest, _ := json.Marshal(m)
	damaged := filepath.Join(t.TempDir(), "damaged.vltbak")
	if err := backup.Seal(damaged, manifest, []string{snapshot, o.Path(backup.ComponentConfiguration)}, bek, backup.SealOptions{}); err != nil {
		t.Fatal(err)
	}
	o.Close()

	cfg := f.target(t)
	if _, err := Restore(ctx, cfg, damaged, bek, f.rootKEK, nil); err == nil || !strings.Contains(err.Error(), "no installation") {
		t.Fatalf("the damaged restore: %v", err)
	}
	g, err := backup.ReadGate(cfg.DataDir)
	if err != nil || g == nil || g.Kind != "restore" || *g.ArchiveID != res.ArchiveID || g.ExpiresAt != nil {
		t.Fatalf("gate %+v %v", g, err)
	}
	if !maintenance.Open(cfg.DataDir, nil).Isolated() {
		t.Error("a varlatchd starting now would not be isolated")
	}
	// Another archive is refused, with how to clear the gate.
	f.add(time.Hour)
	other, err := f.service(nil).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(ctx, cfg, other.Path, bek, f.rootKEK, nil); err == nil || !strings.Contains(err.Error(), "a restore of archive "+res.ArchiveID+" has not completed") || !strings.Contains(err.Error(), "remove maintenance.json") {
		t.Errorf("another archive after a failed restore: %v", err)
	}
	if _, err := Restore(ctx, cfg, res.Path, bek, f.rootKEK, nil); err != nil {
		t.Fatalf("the retry: %v", err)
	}
	if l := listing(t, cfg.DataDir); l != "restore-hold.json varlatch.db" {
		t.Errorf("after the retry the data directory holds %q", l)
	}
	if id := queryOne(t, cfg.DatabasePath(), "SELECT id FROM installation"); id != f.inst {
		t.Errorf("installation %q", id)
	}
}

// A database a later, rollback-safe release wrote, with this release back
// on it: its archives pass their check and restore. One whose
// compatible_from keeps this release out, and an older schema, do not.
func TestNewerSchema(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name                    string
		version, compatibleFrom int64
		ok                      bool
	}{
		{"newer, this release opens it", db.SchemaVersion + 1, db.SchemaVersion, true},
		{"newer, opens from long before", db.SchemaVersion + 5, 1, true},
		{"newer, this release does not", db.SchemaVersion + 1, db.SchemaVersion + 1, false},
		{"older", db.SchemaVersion - 1, 1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.exec(t, "UPDATE schema_version SET version = ?, compatible_from = ?", c.version, c.compatibleFrom)
			res, err := f.service(nil).Run(ctx)
			if !c.ok {
				if err == nil || !strings.Contains(err.Error(), "compatibility false") {
					t.Fatalf("%+v, %v", res, err)
				}
				return
			}
			if err != nil || !res.Verification.Compatibility {
				t.Fatalf("%+v, %v", res, err)
			}
			cfg := f.target(t)
			if _, err := Restore(ctx, cfg, res.Path, f.bekOf(t), f.rootKEK, nil); err != nil {
				t.Fatal(err)
			}
			if v := queryOne(t, cfg.DatabasePath(), "SELECT version FROM schema_version"); v != fmt.Sprint(c.version) {
				t.Errorf("the restored schema is %s", v)
			}
		})
	}
}

// resealed is an archive of f's with its database changed and its manifest
// naming schema, sealed again with f's keys.
func (f *fixture) resealed(t *testing.T, schema int, change ...string) string {
	t.Helper()
	ctx := context.Background()
	s := f.service(nil)
	res, err := s.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	o, err := backup.Open(res.Path, f.bekOf(t), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	snapshot, configuration := o.Path(backup.ComponentDatabase), o.Path(backup.ComponentConfiguration)
	meta, err := readMetadata(ctx, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := sql.Open("sqlite", fileURI(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range change {
		if _, err := conn.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	conn.Close()
	meta.schemaVersion = schema
	manifest, err := s.manifest(ctx, ids.UUID(), res.CreatedAt, meta, snapshot, configuration)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "resealed.vltbak")
	if err := backup.Seal(path, manifest, []string{snapshot, configuration}, f.bekOf(t), backup.SealOptions{}); err != nil {
		t.Fatal(err)
	}
	return path
}

// An archive whose database is not of the schema its manifest names, or of
// one startup would refuse, is refused before the gate opens and the
// database is replaced.
func TestRestoreChecksTheArchivesSchema(t *testing.T) {
	ctx := context.Background()
	newer := fmt.Sprint(db.SchemaVersion + 1)
	current := fmt.Sprint(db.SchemaVersion)
	for _, c := range []struct {
		name   string
		schema int
		change []string
		ok     bool
	}{
		{"as made", db.SchemaVersion, nil, true},
		{"the manifest's is this release's, the database's too new", db.SchemaVersion, []string{"UPDATE schema_version SET version = " + newer + ", compatible_from = " + newer}, false},
		{"the manifest's is this release's, the database's newer", db.SchemaVersion, []string{"UPDATE schema_version SET version = " + newer + ", compatible_from = 1"}, false},
		{"the manifest's is newer, the database's this release's", db.SchemaVersion + 1, nil, false},
		{"both newer, this release opens it", db.SchemaVersion + 1, []string{"UPDATE schema_version SET version = " + newer + ", compatible_from = " + current}, true},
		{"both newer, this release does not", db.SchemaVersion + 1, []string{"UPDATE schema_version SET version = " + newer + ", compatible_from = " + newer}, false},
		{"no row", db.SchemaVersion, []string{"DELETE FROM schema_version"}, false},
		{"a view in its place", db.SchemaVersion, []string{"DROP TABLE schema_version", "CREATE VIEW schema_version AS SELECT 1 AS singleton, " + current + " AS version, 1 AS compatible_from"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			archive := f.resealed(t, c.schema, c.change...)
			// Over a database that is there: the same installation's.
			cfg := f.target(t)
			if _, err := Restore(ctx, cfg, f.resealed(t, db.SchemaVersion), f.bekOf(t), f.rootKEK, nil); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(cfg.DatabasePath())
			if err != nil {
				t.Fatal(err)
			}
			_, err = Restore(ctx, cfg, archive, f.bekOf(t), f.rootKEK, nil)
			if c.ok {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "cannot restore an archive") {
				t.Fatalf("%v", err)
			}
			if after, err := os.ReadFile(cfg.DatabasePath()); err != nil || !bytes.Equal(before, after) {
				t.Errorf("the database was changed (%v)", err)
			}
			if l := listing(t, cfg.DataDir); l != backup.HoldFile+" varlatch.db" {
				t.Errorf("the data directory holds %q", l)
			}
		})
	}
}
