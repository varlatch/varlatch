// SPDX-License-Identifier: AGPL-3.0-or-later

package migrate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
// out (decision 2's reverse): a snapshot copy is made, the transformations
// are applied to the copy (every Go browser session ends,
// installation.migrated is appended), the copy is read in the manifest's
// tables and columns, and removed, or kept in o.Keep for the reverse
// checks. The database itself is never changed. Either the caller holds
// the data directory (no varlatchd runs), or o.From is the migration
// barrier's frozen copy (go-step7 decision 6, the reverse), which is read
// as a file and copied, never opened in place, so a varlatchd behind that
// barrier may run.
func ExportReverse(ctx context.Context, out io.Writer, o Options) (Result, error) {
	res := Result{Direction: bundle.Reverse, PerTable: map[string]int{}}
	m, err := manifest.Load()
	if err != nil {
		return res, err
	}
	path := filepath.Join(o.DataDir, config.DatabaseFile)
	if o.From != "" {
		path = o.From
	}
	if _, err := os.Stat(path); err != nil {
		return res, fmt.Errorf("migrate: no database to export: %w", err)
	}
	var snap string
	if o.Keep != "" {
		if err := emptyDir(o.Keep); err != nil {
			return res, fmt.Errorf("migrate: --keep %s: %w", o.Keep, err)
		}
		snap = filepath.Join(o.Keep, config.DatabaseFile)
	} else {
		work := o.Work
		if work == "" {
			work = o.DataDir
		}
		suffix := make([]byte, 6)
		if _, err := rand.Read(suffix); err != nil {
			return res, err
		}
		snap = filepath.Join(work, ".migrate-export-"+hex.EncodeToString(suffix)+".db")
	}
	kept := false
	defer func() {
		if kept {
			return
		}
		for _, s := range []string{"", "-wal", "-shm", "-journal"} {
			_ = os.Remove(snap + s)
		}
	}()
	if o.From != "" {
		if err := copyFile(o.From, snap); err != nil {
			return res, fmt.Errorf("migrate: the frozen copy: %w", err)
		}
	} else {
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
		if o.From != "" {
			// The copy as the barrier froze it, before the transformations
			// append their events.
			var frozen int64
			if err := tx.QueryRowContext(actx, "SELECT coalesce(max(event_order), 0) FROM audit_events").Scan(&frozen); err != nil {
				return err
			}
			if frozen != o.FrozenAt {
				return fmt.Errorf("the frozen copy's last audit position is %d, not its barrier's frozen point %d: it is not the copy that barrier made", frozen, o.FrozenAt)
			}
		}
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
	if err := w.Close(); err != nil {
		return res, err
	}
	if o.Keep != "" {
		// The copy as the checks read it: one file, its write-ahead log
		// folded in.
		if err := store.Close(); err != nil {
			return res, err
		}
		kept = true
	}
	return res, nil
}

// emptyDir makes dir, or finds it an empty directory.
func emptyDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return errors.New("not an absolute path")
	}
	if err := os.Mkdir(dir, 0o700); err == nil || !errors.Is(err, fs.ErrExist) {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return errors.New("not empty: the transformed copy is kept in a new or empty directory")
	}
	return nil
}

// copyFile copies a database file that nothing writes (a frozen copy) to
// a new file, mode 0600, synced.
func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", from)
	}
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
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
