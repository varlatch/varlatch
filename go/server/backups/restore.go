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
//  1. the archive opens (integrity), this release restores it, the Root
//     KEK opens its canaries, and it holds no audit export stream (those
//     restart on a restore, which arrives with the audit export port);
//  2. a database already in the directory must be the same installation;
//  3. a restore gate (maintenance.json, kind restore) is opened, or a
//     restore of the same archive that stopped is resumed. While it is
//     open a varlatchd that starts answers 503 MAINTENANCE;
//  4. the snapshot replaces the database: copied beside it and synced, the
//     old WAL removed, renamed into place, the directory synced;
//  5. the restored database opens with this release, its installation is
//     the archive's and its canary opens with the Root KEK, and the
//     installation.restored audit event is the first new one;
//  6. the gate is removed.
//
// A restore that fails or is killed leaves the gate open; running it
// again with the same archive completes it.
func Restore(ctx context.Context, cfg *config.Config, archive string, bek backup.BEK, rootKEK []byte, now func() time.Time) (RestoreResult, error) {
	if now == nil {
		now = time.Now
	}
	if err := backup.DistinctKeys(bek, rootKEK); err != nil {
		return RestoreResult{}, err
	}
	scratch := filepath.Join(cfg.DataDir, ".restore-work")
	if err := os.RemoveAll(scratch); err != nil {
		return RestoreResult{}, err
	}
	if err := os.Mkdir(scratch, 0o700); err != nil {
		return RestoreResult{}, err
	}
	defer os.RemoveAll(scratch)
	opened, err := backup.Open(archive, bek, scratch)
	if err != nil {
		return RestoreResult{}, err
	}
	defer opened.Close()
	m := opened.Manifest
	if m.FormatVersion != backup.FormatGo {
		return RestoreResult{}, fmt.Errorf("this is the TypeScript server's archive (format %d): the migration to varlatchd (ADR-0059 step 7) converts it; a restore takes a varlatchd archive", m.FormatVersion)
	}
	if !Compatible(m) {
		r, _ := m.GoRelease()
		return RestoreResult{}, fmt.Errorf("this release (%s, database schema %d) cannot restore an archive of %s with database schema %d", buildinfo.Version, db.SchemaVersion, r.Version, r.DatabaseSchema)
	}
	candidates := map[int][]byte{}
	for _, v := range m.RequiredKeyVersions {
		candidates[v] = rootKEK
	}
	if !backup.CheckKeys(m, candidates) {
		return RestoreResult{}, errors.New("the Root KEK does not open the archive's canary: a restore needs the installation's own Root KEK")
	}
	snapshot := opened.Path(backup.ComponentDatabase)
	if n, err := activeAuditExports(ctx, snapshot); err != nil {
		return RestoreResult{}, err
	} else if n > 0 {
		return RestoreResult{}, fmt.Errorf("the archive has %d active audit export(s), whose streams a restore restarts; varlatchd restores them once the audit export is ported (ADR-0059 step 4)", n)
	}
	var settings Configuration
	if raw, err := os.ReadFile(opened.Path(backup.ComponentConfiguration)); err != nil || json.Unmarshal(raw, &settings) != nil {
		return RestoreResult{}, errors.New("the archive's configuration.json cannot be read")
	}

	dbPath := cfg.DatabasePath()
	// A restore of this archive that stopped left the database it put in
	// place: resuming it replaces that one whatever it holds.
	if !resuming(cfg.DataDir, m.ArchiveID) {
		if existing, err := installationOf(ctx, dbPath); err != nil {
			return RestoreResult{}, err
		} else if existing != "" && existing != m.InstallationID {
			return RestoreResult{}, fmt.Errorf("refusing to replace the installation %s with %s, another installation", existing, m.InstallationID)
		}
	}
	if _, err := openRestoreGate(cfg.DataDir, m.ArchiveID, now); err != nil {
		return RestoreResult{}, err
	}

	// The snapshot replaces the database. The old WAL goes first: SQLite
	// would apply it to the restored file.
	staged := dbPath + ".restore"
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

	if err := reconcile(audit.WithClock(ctx, now), cfg, m, opened.ManifestJSON, rootKEK); err != nil {
		return RestoreResult{}, err
	}
	if err := os.Remove(filepath.Join(cfg.DataDir, backup.GateFile)); err != nil {
		return RestoreResult{}, err
	}
	if err := backup.SyncDir(cfg.DataDir); err != nil {
		return RestoreResult{}, err
	}
	return RestoreResult{ArchiveID: m.ArchiveID, InstallationID: m.InstallationID, CreatedAt: m.CreatedAt, Settings: settings.Settings}, nil
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

// reconcile opens the restored database with this release, checks it is
// the archive's installation under this Root KEK, and records
// installation.restored.
func reconcile(ctx context.Context, cfg *config.Config, m backup.Manifest, manifest []byte, rootKEK []byte) error {
	store, err := storage.Open(ctx, storage.Options{Path: cfg.DatabasePath()})
	if err != nil {
		return fmt.Errorf("the restored database does not open: %w", err)
	}
	defer store.Close()
	if _, err := db.Init(ctx, store, buildinfo.Version); err != nil {
		return fmt.Errorf("the restored database: %w", err)
	}
	sum := sha256.Sum256(manifest)
	return store.Write(ctx, func(tx *storage.Tx) error {
		row, err := query.New(tx).GetInstallation(ctx)
		if err != nil {
			return fmt.Errorf("the restored database has no installation: %w", err)
		}
		var canary envelope.Envelope
		if row.ID != m.InstallationID || json.Unmarshal([]byte(row.KekCanary), &canary) != nil || !envelope.VerifyCanary(rootKEK, canary, row.ID) {
			return errors.New("the restored installation, or its canary, did not verify")
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Type: "installation.restored", Decision: audit.Info,
			Metadata: jsvalue.Object{{Key: "archiveId", Value: m.ArchiveID}, {Key: "manifestIdentity", Value: hex.EncodeToString(sum[:])}, {Key: "installationId", Value: row.ID}},
		})
		return err
	})
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

// activeAuditExports counts the snapshot's audit exports whose stream a
// restore would restart.
func activeAuditExports(ctx context.Context, snapshot string) (int, error) {
	conn, err := sql.Open("sqlite", fileURI(snapshot)+"?mode=ro&immutable=1")
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	var n int
	err = conn.QueryRowContext(ctx, "SELECT count(*) FROM audit_exports WHERE state IN ('active', 'draining')").Scan(&n)
	return n, err
}

func copyFile(from, to string) (err error) {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
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
