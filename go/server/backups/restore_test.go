// SPDX-License-Identifier: AGPL-3.0-or-later

package backups

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/maintenance"
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
	if l := listing(t, cfg.DataDir); l != "varlatch.db" {
		t.Errorf("the data directory holds %q", l)
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
	if l := listing(t, cfg.DataDir); l != "varlatch.db" {
		t.Errorf("after the retry the data directory holds %q", l)
	}
	if id := queryOne(t, cfg.DatabasePath(), "SELECT id FROM installation"); id != f.inst {
		t.Errorf("installation %q", id)
	}
}
