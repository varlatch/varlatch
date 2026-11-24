// SPDX-License-Identifier: AGPL-3.0-or-later

package backups

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auditexport"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Restore puts an archive's installation into a data directory, offline
// (varlatchd stopped, its lock held by the caller), from the archive and
// the two separately held keys: the Backup Encryption Key opens the
// archive, the Root KEK must open its canaries. It is the TypeScript
// restore's sequence for one SQLite file:
//
//  1. the archive opens (integrity), this release restores it, and the
//     Root KEK opens its canaries;
//  2. in the copy unpacked from the archive: it opens with this release,
//     its installation is the archive's and its canary opens with the Root
//     KEK, and the installation.restored audit event is the first new one,
//     with every live audit export's new stream after it (ADR-0056
//     Decision 5);
//  3. a database already in the directory must be the same installation.
//     A failure up to here changed nothing in the directory;
//  4. a restore gate (maintenance.json, kind restore) is opened, or a
//     restore of the same archive that stopped is resumed. While it is
//     open a varlatchd that starts answers 503 MAINTENANCE;
//  5. that copy replaces the database: copied beside it and synced, the
//     old WAL removed, renamed into place, the directory synced;
//  6. the installation is held (backup.Hold): what an archive brings back
//     does nothing on its own until the host operator resumes it;
//  7. the gate is removed.
//
// A restore that fails or is killed from 4 on leaves the gate open; running
// it again with the same archive completes it.
func Restore(ctx context.Context, cfg *config.Config, archive string, bek backup.BEK, rootKEK []byte, now func() time.Time) (RestoreResult, error) {
	if now == nil {
		now = time.Now
	}
	// What a check that was killed left.
	if err := os.RemoveAll(filepath.Join(cfg.DataDir, checkScratch)); err != nil {
		return RestoreResult{}, err
	}
	// Before SQLite is used at all: its temporary files, where nothing else
	// is writable, in the data directory, never in the scratch one.
	if _, err := storage.PrepareTemp(cfg.DataDir); err != nil {
		return RestoreResult{}, err
	}
	scratch := filepath.Join(cfg.DataDir, ".restore-work")
	defer os.RemoveAll(scratch)
	opened, err := openArchive(ctx, archive, bek, rootKEK, scratch)
	if err != nil {
		return RestoreResult{}, err
	}
	defer opened.Close()
	settings, err := restores(ctx, opened, rootKEK)
	if err != nil {
		return RestoreResult{}, err
	}
	// The restore's own writes, on the copy unpacked from the archive: one
	// that refuses them leaves this data directory as it was.
	if err := reconcile(audit.WithClock(ctx, now), opened, rootKEK, now()); err != nil {
		return RestoreResult{}, err
	}
	m := opened.Manifest
	snapshot := opened.Path(backup.ComponentDatabase)

	dbPath := cfg.DatabasePath()
	// A restore of this archive that stopped left the database it put in
	// place: resuming it replaces that one whatever it holds.
	if !resuming(cfg.DataDir, m.ArchiveID) {
		if err := sameInstallation(ctx, dbPath, m); err != nil {
			return RestoreResult{}, err
		}
	}
	if _, err := openRestoreGate(cfg.DataDir, m.ArchiveID, now); err != nil {
		return RestoreResult{}, err
	}

	// The snapshot replaces the database. The old WAL goes first: SQLite
	// would apply it to the restored file.
	staged := dbPath + ".restore"
	// A stopped restore's; the copy is a file of its own, never one that is
	// there.
	if err := os.Remove(staged); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return RestoreResult{}, err
	}
	if err := copyFile(snapshot, staged); err != nil {
		return RestoreResult{}, err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(dbPath + suffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return RestoreResult{}, err
		}
	}
	if err := os.Rename(staged, dbPath); err != nil {
		return RestoreResult{}, err
	}
	if err := backup.SyncDir(cfg.DataDir); err != nil {
		return RestoreResult{}, err
	}

	if err := backup.WriteHold(cfg.DataDir, backup.Hold{ArchiveID: m.ArchiveID, RestoredAt: iso(now())}); err != nil {
		return RestoreResult{}, fmt.Errorf("the restored installation could not be held: %w", err)
	}
	if err := os.Remove(filepath.Join(cfg.DataDir, backup.GateFile)); err != nil {
		return RestoreResult{}, err
	}
	if err := backup.SyncDir(cfg.DataDir); err != nil {
		return RestoreResult{}, err
	}
	return RestoreResult{ArchiveID: m.ArchiveID, InstallationID: m.InstallationID, CreatedAt: m.CreatedAt, Settings: settings.Settings}, nil
}

// checkScratch is where CheckRestore opens the archive, in the data
// directory: not Restore's own.
const checkScratch = ".restore-check"

// Checked is what CheckRestore found in an archive.
type Checked struct {
	ArchiveID    string `json:"archiveId"`
	Installation string `json:"installation"`
	CreatedAt    string `json:"createdAt"`
	// History is its last audit position: what a restore keeps, and nothing
	// after it.
	History int64 `json:"history"`
	// Sessions are the browser sessions in it that have not expired, which a
	// restore makes valid again.
	Sessions int64 `json:"sessions"`
	// Restores is whether this release restores it.
	Restores bool `json:"restores"`
}

// CheckRestore is whether Restore would take the archive with these keys:
// its first two steps, which write nothing but a scratch directory it
// removes. A varlatchd may run. With opens, an archive of a release this one
// does not restore is not refused.
func CheckRestore(ctx context.Context, cfg *config.Config, archive string, bek backup.BEK, rootKEK []byte, opens bool) (Checked, error) {
	if _, err := storage.PrepareTemp(cfg.DataDir); err != nil {
		return Checked{}, err
	}
	scratch := filepath.Join(cfg.DataDir, checkScratch)
	defer os.RemoveAll(scratch)
	opened, err := openArchive(ctx, archive, bek, rootKEK, scratch)
	if err != nil {
		return Checked{}, err
	}
	defer opened.Close()
	m := opened.Manifest
	c := Checked{ArchiveID: m.ArchiveID, Installation: m.InstallationID, CreatedAt: m.CreatedAt}
	if _, err := restores(ctx, opened, rootKEK); err == nil {
		c.Restores = true
	} else if !opens {
		return Checked{}, err
	}
	if err := sameInstallation(ctx, cfg.DatabasePath(), m); err != nil {
		return Checked{}, err
	}
	conn, err := sql.Open("sqlite", fileURI(opened.Path(backup.ComponentDatabase))+"?mode=ro&immutable=1")
	if err != nil {
		return Checked{}, err
	}
	defer conn.Close()
	if err := conn.QueryRowContext(ctx, "SELECT coalesce(max(event_order), 0) FROM audit_events").Scan(&c.History); err != nil {
		return Checked{}, fmt.Errorf("the archive's audit events cannot be read: %w", err)
	}
	if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM auth_sessions WHERE expires_at > ?", time.Now().UnixMicro()).Scan(&c.Sessions); err != nil {
		return Checked{}, fmt.Errorf("the archive's sessions cannot be read: %w", err)
	}
	if c.Restores {
		// Last: it writes to the copy read above.
		_ = conn.Close()
		if err := reconcile(ctx, opened, rootKEK, time.Now()); err != nil && !opens {
			return Checked{}, err
		} else if err != nil {
			c.Restores = false
		}
	}
	return c, nil
}

// restores is whether this release restores an opened archive, why not, and
// its settings.
func restores(ctx context.Context, opened *backup.Opened, rootKEK []byte) (Configuration, error) {
	m := opened.Manifest
	if !Compatible(ctx, m, opened.Path(backup.ComponentDatabase)) {
		r, _ := m.GoRelease()
		return Configuration{}, fmt.Errorf("this release (%s, database schema %d) cannot restore an archive of %s with database schema %d", buildinfo.Version, db.SchemaVersion, r.Version, r.DatabaseSchema)
	}
	return contents(ctx, opened, rootKEK)
}

// contents is what a restore needs of an opened archive's components, as a
// backup's own check, a restore's and Restore itself ask it: the settings
// can be read, and the database holds the manifest's installation, whose
// canary the Root KEK opens. reconcile asks the rest, by writing.
func contents(ctx context.Context, opened *backup.Opened, rootKEK []byte) (Configuration, error) {
	var c Configuration
	// At most backup.MaxConfigurationBytes (the manifest's check).
	raw, err := os.ReadFile(opened.Path(backup.ComponentConfiguration))
	if err != nil || json.Unmarshal(raw, &c) != nil || c.FormatVersion < 1 || c.Settings == nil {
		return Configuration{}, errors.New("the archive's configuration.json cannot be read")
	}
	conn, err := sql.Open("sqlite", fileURI(opened.Path(backup.ComponentDatabase))+"?mode=ro&immutable=1")
	if err != nil {
		return Configuration{}, err
	}
	defer conn.Close()
	var id, stored string
	if err := conn.QueryRowContext(ctx, "SELECT id, kek_canary FROM installation").Scan(&id, &stored); err != nil {
		return Configuration{}, fmt.Errorf("the archive's database has no installation: %w", err)
	}
	var canary envelope.Envelope
	if id != opened.Manifest.InstallationID || json.Unmarshal([]byte(stored), &canary) != nil || !envelope.VerifyCanary(rootKEK, canary, id) {
		return Configuration{}, errors.New("the archive's database is not its installation's, or its canary did not verify")
	}
	return c, nil
}

// openArchive opens a Go archive into scratch, made anew, when the Root KEK
// opens its canaries.
func openArchive(ctx context.Context, archive string, bek backup.BEK, rootKEK []byte, scratch string) (_ *backup.Opened, err error) {
	if err := backup.DistinctKeys(bek, rootKEK); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(scratch); err != nil {
		return nil, err
	}
	if err := os.Mkdir(scratch, 0o700); err != nil {
		return nil, err
	}
	opened, err := backup.Open(archive, bek, scratch)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			opened.Close()
		}
	}()
	m := opened.Manifest
	if m.FormatVersion != backup.FormatGo {
		return nil, fmt.Errorf("this is the TypeScript server's archive (format %d): the migration to varlatchd (ADR-0059 step 7) converts it; a restore takes a varlatchd archive", m.FormatVersion)
	}
	candidates := map[int][]byte{}
	for _, v := range m.RequiredKeyVersions {
		candidates[v] = rootKEK
	}
	if !backup.CheckKeys(m, candidates) {
		return nil, errors.New("the Root KEK does not open the archive's canary: a restore needs the installation's own Root KEK")
	}
	return opened, nil
}

// RestoreResult is what a restore put in place.
type RestoreResult struct {
	ArchiveID, InstallationID, CreatedAt string
	// Settings are the archive's non-key settings, for the operator to
	// compare with this host's varlatchd.conf.
	Settings map[string]string
}

// resuming is whether a restore of this archive left its gate.
func resuming(dir, archiveID string) bool {
	g, err := backup.ReadGate(dir)
	return err == nil && g != nil && g.Kind == "restore" && g.ArchiveID != nil && *g.ArchiveID == archiveID
}

// openRestoreGate opens the restore's gate, or resumes the gate a restore
// of the same archive left.
func openRestoreGate(dir, archiveID string, now func() time.Time) (backup.Gate, error) {
	path := filepath.Join(dir, backup.GateFile)
	g, err := backup.ReadGate(dir)
	if err != nil {
		return backup.Gate{}, err
	}
	if g != nil {
		switch {
		case g.Kind == "restore" && g.ArchiveID != nil && *g.ArchiveID == archiveID:
			g.Phase = "paused"
			return *g, backup.DurableJSON(path, g, false)
		case g.Kind == "restore":
			other := "another archive"
			if g.ArchiveID != nil {
				other = "archive " + *g.ArchiveID
			}
			return backup.Gate{}, fmt.Errorf("a restore of %s has not completed: run the restore again with that archive to complete it, or, to restore a different archive instead, remove %s from the data directory (varlatchd stopped; maintenance end does not end a restore)", other, backup.GateFile)
		case g.Active(now()):
			return backup.Gate{}, errors.New("another maintenance operation owns this installation (maintenance.json); end it before a restore")
		}
		// A lease that expired.
		if err := os.Remove(path); err != nil {
			return backup.Gate{}, err
		}
	}
	id := archiveID
	gate := backup.Gate{ID: ids.UUID(), Kind: "restore", Phase: "paused", ArchiveID: &id}
	return gate, backup.DurableJSON(path, gate, true)
}

// reconcile opens an archive's unpacked database with this release, as the
// server opens it, checks it is the archive's installation under this Root
// KEK, and records installation.restored, every live audit export's stream
// restarted at its restored cursor in the same job (recordRestore). It ends
// with the database whole in its one file. A restore puts that file in
// place; a check asked for (restore --check, the remote copy's) makes the
// same writes, to know that a restore can, and throws the copy away.
func reconcile(ctx context.Context, opened *backup.Opened, rootKEK []byte, now time.Time) error {
	path, m := opened.Path(backup.ComponentDatabase), opened.Manifest
	store, err := storage.Open(ctx, storage.Options{Path: path, ReadConns: 1})
	if err != nil {
		return fmt.Errorf("the archive's database does not open: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = store.Close()
		}
	}()
	if _, err := db.Init(ctx, store, buildinfo.Version); err != nil {
		return fmt.Errorf("the archive's database: %w", err)
	}
	sum := sha256.Sum256(opened.ManifestJSON)
	if err := store.Write(ctx, func(tx *storage.Tx) error {
		row, err := query.New(tx).GetInstallation(ctx)
		if err != nil {
			return fmt.Errorf("the archive's database has no installation: %w", err)
		}
		var canary envelope.Envelope
		if row.ID != m.InstallationID || json.Unmarshal([]byte(row.KekCanary), &canary) != nil || !envelope.VerifyCanary(rootKEK, canary, row.ID) {
			return errors.New("the archive's installation, or its canary, did not verify")
		}
		return auditexport.RecordRestore(ctx, tx, audit.Event{
			Type: "installation.restored", Decision: audit.Info,
			Metadata: jsvalue.Object{{Key: "archiveId", Value: m.ArchiveID}, {Key: "manifestIdentity", Value: hex.EncodeToString(sum[:])}, {Key: "installationId", Value: row.ID}},
		}, now)
	}); err != nil {
		return err
	}
	closed = true
	if err := store.Close(); err != nil {
		return err
	}
	if st, err := os.Stat(path + "-wal"); err == nil && st.Size() > 0 {
		return errors.New("the archive's database did not take its write-ahead log in when it was closed")
	}
	return nil
}

// sameInstallation is whether the database at path, if there is one, is the
// archive's installation.
func sameInstallation(ctx context.Context, path string, m backup.Manifest) error {
	existing, err := installationOf(ctx, path)
	if err != nil {
		return err
	}
	if existing != "" && existing != m.InstallationID {
		return fmt.Errorf("refusing to replace the installation %s with %s, another installation; to restore into this data directory anyway, move varlatch.db (with varlatch.db-wal and varlatch.db-shm) out of it first", existing, m.InstallationID)
	}
	return nil
}

// installationOf is the installation in the database at path, "" when
// there is no database or no installation in it.
func installationOf(ctx context.Context, path string) (string, error) {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	conn, err := sql.Open("sqlite", fileURI(path)+"?mode=ro")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	var tables int
	if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'installation'").Scan(&tables); err != nil {
		return "", fmt.Errorf("the data directory's database cannot be read (%v); move %s aside to restore into this directory", err, path)
	}
	if tables == 0 {
		return "", nil
	}
	var id string
	switch err := conn.QueryRowContext(ctx, "SELECT id FROM installation").Scan(&id); {
	case errors.Is(err, sql.ErrNoRows):
		return "", nil
	case err != nil:
		return "", err
	}
	return id, nil
}

func copyFile(from, to string) (err error) {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(to)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
