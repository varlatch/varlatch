// SPDX-License-Identifier: AGPL-3.0-or-later

package migrate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/canonical"
	"github.com/varlatch/varlatch/go/server/migration/manifest"
)

// ExportReverse writes the reverse bundle of the database in o.DataDir to
// out (decision 2's reverse): a snapshot copy is made in the data
// directory, the transformations are applied to the copy (every Go browser
// session ends, installation.migrated is appended), the copy is read in the
// manifest's tables and columns, and removed. The database itself is never
// changed. The caller holds the data directory (no varlatchd runs).
func ExportReverse(ctx context.Context, out io.Writer, o Options) (Result, error) {
	res := Result{Direction: bundle.Reverse, PerTable: map[string]int{}}
	m, err := manifest.Load()
	if err != nil {
		return res, err
	}
	path := filepath.Join(o.DataDir, config.DatabaseFile)
	if _, err := os.Stat(path); err != nil {
		return res, fmt.Errorf("migrate: no database to export: %w", err)
	}
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return res, err
	}
	snap := filepath.Join(o.DataDir, ".migrate-export-"+hex.EncodeToString(suffix)+".db")
	defer func() {
		for _, s := range []string{"", "-wal", "-shm"} {
			_ = os.Remove(snap + s)
		}
	}()
	live, err := storage.Open(ctx, storage.Options{Path: path})
	if err != nil {
		return res, err
	}
	_, err = live.Snapshot(ctx, snap, storage.SnapshotOptions{})
	if cerr := live.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return res, fmt.Errorf("migrate: the snapshot copy: %w", err)
	}
	store, err := storage.Open(ctx, storage.Options{Path: snap})
	if err != nil {
		return res, err
	}
	defer store.Close()

	// The transformations, on the copy: every session ends (the trigger
	// revokes its browser credentials), then installation.migrated.
	actx := audit.WithClock(ctx, o.now())
	var last int64
	err = store.Write(actx, func(tx *storage.Tx) error {
		if err := tx.QueryRowContext(actx, "SELECT count(*) FROM auth_sessions").Scan(&res.SessionsEnded); err != nil {
			return err
		}
		revoked, err := revokedBy(actx, tx, func() error {
			_, err := tx.ExecContext(actx, "DELETE FROM auth_sessions")
			return err
		})
		if err != nil {
			return err
		}
		res.CredentialsRevoked = revoked
		if err := tx.QueryRowContext(actx, "SELECT coalesce(max(event_order), 0) FROM audit_events").Scan(&last); err != nil {
			return err
		}
		h := bundle.Header{Direction: bundle.Reverse, Release: o.Release, FrozenPoint: bundle.FrozenPoint{AuditPosition: last}}
		recorded, err := audit.Record(actx, tx, audit.Event{Type: MigratedEvent, Decision: audit.Info, Metadata: migratedMetadata(m, h, res)})
		if err != nil {
			return err
		}
		res.MigratedPosition = recorded[0].Position
		return nil
	})
	if err != nil {
		return res, fmt.Errorf("migrate: the transformations on the copy: %w", err)
	}
	w, err := bundle.NewWriter(out, m, bundle.Header{Manifest: m.Version, Encoding: m.Encoding, Direction: bundle.Reverse, Release: o.Release,
		FrozenPoint: bundle.FrozenPoint{AuditPosition: res.MigratedPosition}})
	if err != nil {
		return res, err
	}
	reader := store.Reader()
	if err := reader.QueryRowContext(ctx, "SELECT id FROM installation").Scan(&res.InstallationID); err != nil {
		return res, fmt.Errorf("migrate: the database holds no installation: %w", err)
	}
	for _, t := range bundle.Tables(m) {
		n, err := exportTable(ctx, store, w, t)
		if err != nil {
			return res, fmt.Errorf("migrate: table %s: %w", t.Source, err)
		}
		res.Tables++
		res.Rows += int64(n)
		res.PerTable[t.Source] = n
	}
	// The check sections stay empty until the reverse checks fill them
	// (slice 7.6).
	if err := w.Digests(0); err != nil {
		return res, err
	}
	if err := w.Decisions(0, o.now()().UnixMicro()); err != nil {
		return res, err
	}
	return res, w.Close()
}

// exportTable writes one table: its rows in the manifest's order, in the
// source's columns. The session table is written empty: every session ended
// on the copy.
func exportTable(ctx context.Context, store *storage.DB, w *bundle.Writer, t manifest.Table) (int, error) {
	table := ident(targetTable(t))
	var n int
	if err := store.Reader().QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		return 0, err
	}
	if t.Action == manifest.Transform {
		if t.Transformation != sessionTransformation || n != 0 {
			return 0, fmt.Errorf("a %s table this export does not write (%d rows)", t.Transformation, n)
		}
		return 0, w.Table(t.Source, 0)
	}
	if err := w.Table(t.Source, n); err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	cols := targetColumns(t)
	if len(cols.names) != len(t.Columns) {
		return 0, errors.New("a copied table with a left-out column, which this export does not write")
	}
	quoted := make([]string, len(cols.names))
	for i, c := range cols.names {
		quoted[i] = ident(c)
	}
	order, err := orderBy(t)
	if err != nil {
		return 0, err
	}
	rows, err := store.Reader().QueryContext(ctx, "SELECT "+strings.Join(quoted, ", ")+" FROM "+table+" ORDER BY "+order)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	types := t.Types()
	values := make([]any, len(types))
	ptrs := make([]any, len(types))
	for i := range values {
		ptrs[i] = &values[i]
	}
	written := 0
	var row []byte
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return 0, err
		}
		if row, err = canonical.AppendRow(row[:0], types, values); err != nil {
			return 0, fmt.Errorf("row %d: %w", written+1, err)
		}
		if err := w.Row(row); err != nil {
			return 0, err
		}
		written++
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if written != n {
		return 0, fmt.Errorf("%d rows counted, %d read", n, written)
	}
	return n, nil
}

// orderBy is the manifest's order in the target: its orderBy columns, or
// the rowid where the manifest keeps the source's physical order.
func orderBy(t manifest.Table) (string, error) {
	if t.PhysicalOrder {
		return "rowid", nil
	}
	if len(t.OrderBy) == 0 {
		return "", errors.New("the manifest gives no order")
	}
	target := map[string]string{}
	for _, c := range t.Columns {
		name := c.Target
		if name == "" {
			name = c.Source
		}
		target[c.Source] = name
	}
	parts := make([]string, len(t.OrderBy))
	for i, s := range t.OrderBy {
		name, ok := target[s]
		if !ok {
			return "", fmt.Errorf("orderBy names %s, not a column", s)
		}
		parts[i] = ident(name)
	}
	return strings.Join(parts, ", "), nil
}
