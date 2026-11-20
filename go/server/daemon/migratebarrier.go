// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/storage"
)

// The reverse migration's barrier on Go (internal docs/design/go-step7.md
// decision 6's Go half, decision 16; slice 7.6a): the same kind of gate as
// the TypeScript release's, `migration`, in the data directory's
// maintenance.json, with no expiry, so a restart under it stays behind it.
//
//	varlatchd admin migrate barrier --id <migration> [--drain-seconds <n>]
//	varlatchd admin migrate release --id <migration>
//
// Both go through the running varlatchd's control socket (its admission
// holds the gate), or run offline on the data directory.
//
// barrier opens the gate (phase draining): from then nothing new is
// admitted, no request but GET /v1/meta, no background pass (sync delivery,
// webhooks, audit export, the security report, organization deletion, the
// GitHub App sweep, scheduled backups), no host command that writes. It
// waits, at most the drain, for what was admitted to end, then makes the
// frozen copy: a snapshot of the database (the backup API, consistent),
// written beside it as FrozenCopyName(id), whose last audit position is the
// frozen point. The gate then says paused, with that position. The reverse
// export reads that copy, never the database varlatchd holds, so varlatchd
// keeps running, isolated, until the reverse moves the address. A barrier
// of the same migration already open is continued (an interrupted drain)
// or answered as it stands (paused with its copy); another gate is refused.
// It prints one JSON object, the TypeScript barrier's shape: the gate, the
// drain's duration, the frozen point.
//
// release lifts the barrier (the reverse undone): the gate removed, the
// frozen copy removed. varlatchd serves again at once.
//
// The data directory's journal must name the migration and say open: a
// reverse migration starts from an installation that migrated to Go.

// FrozenCopyName is the barrier's frozen copy's name in the data directory.
func FrozenCopyName(id string) string { return ".migration-frozen-" + id + ".db" }

// barrierTimeout bounds a barrier's command on the socket: its drain and
// the copy.
func barrierTimeout(args []string) time.Duration {
	a, _ := parseMigrate(args[1:])
	d := a.drain
	if d == 0 {
		d = defaultDrain
	}
	return d + 30*time.Minute
}

// barrierRecord is what barrier prints.
type barrierRecord struct {
	Gate struct {
		ID    string `json:"id"`
		Kind  string `json:"kind"`
		Phase string `json:"phase"`
	} `json:"gate"`
	Drained struct {
		Ms int64 `json:"ms"`
	} `json:"drained"`
	Frozen struct {
		AuditPosition string `json:"auditPosition"`
		At            string `json:"at"`
		Copy          string `json:"copy"`
	} `json:"frozen"`
}

// migrationOpen checks the data directory's journal: the migration id, open.
func migrationOpen(dir, id, what string) error {
	h, ok, err := readJournal(dir)
	switch {
	case err != nil:
		return fmt.Errorf("the data directory's journal: %v", err)
	case !ok:
		return fmt.Errorf("the data directory holds no migration: %s is a reverse migration's, of an installation that migrated to Go", what)
	case h.ID != id:
		return fmt.Errorf("the data directory's journal is the migration %s, not %s", h.ID, id)
	case h.Phase != "open":
		return fmt.Errorf("the migration %s is in phase %s: its reverse starts from an open migration", h.ID, h.Phase)
	}
	return nil
}

func runMigrateBarrier(ctx context.Context, env *hostEnv, rest []string, stdout, stderr io.Writer) int {
	fail := func(status int, format string, args ...any) int {
		fmt.Fprintf(stderr, "varlatchd admin migrate barrier: "+format+"\n", args...)
		return status
	}
	a, msg := parseMigrate(rest)
	if msg != "" || a.sub != "barrier" {
		fmt.Fprintln(stderr, migrateUsage)
		return 64
	}
	dir := env.cfg.DataDir
	if err := migrationOpen(dir, a.id, "the barrier"); err != nil {
		return fail(ExitFailure, "%v; no barrier was opened", err)
	}
	drain := a.drain
	if drain == 0 {
		drain = defaultDrain
	}
	g, err := env.admission.BeginBarrier(a.id)
	if err != nil {
		return fail(ExitFailure, "%v", err)
	}
	path := filepath.Join(dir, FrozenCopyName(a.id))
	rec := barrierRecord{}
	rec.Gate.ID, rec.Gate.Kind = a.id, "migration"
	if g.Phase == "paused" {
		// Frozen already: its copy stands (or is made again, the barrier
		// having held since: nothing changed).
		if pos, at, err := frozenOf(path); err == nil && g.FrozenPosition != nil && strconv.FormatInt(pos, 10) == *g.FrozenPosition {
			rec.Gate.Phase = "paused"
			rec.Frozen.AuditPosition, rec.Frozen.At, rec.Frozen.Copy = *g.FrozenPosition, at, FrozenCopyName(a.id)
			return barrierJSON(stdout, rec)
		}
	}
	start := time.Now()
	for n := env.admission.Busy(); n > 0; n = env.admission.Busy() {
		if time.Since(start) > drain {
			return fail(ExitFailure, "%d requests or background passes still ran after %s; the barrier stays, isolating varlatchd: varlatchd admin migrate barrier again waits for them, varlatchd admin migrate release --id %s lifts it", n, drain, a.id)
		}
		select {
		case <-ctx.Done():
			return fail(ExitFailure, "stopped while draining; the barrier stays")
		case <-time.After(20 * time.Millisecond):
		}
	}
	rec.Drained.Ms = time.Since(start).Milliseconds()
	pos, err := freezeCopy(ctx, env.store, dir, path)
	if err != nil {
		return fail(ExitFailure, "the frozen copy: %v; the barrier stays, isolating varlatchd (varlatchd admin migrate barrier again makes the copy)", err)
	}
	if _, err := env.admission.PauseBarrier(a.id, pos); err != nil {
		return fail(ExitFailure, "the frozen copy is made, but the gate could not say paused: %v; the barrier stays", err)
	}
	_, at, err := frozenOf(path)
	if err != nil {
		return fail(ExitFailure, "%v", err)
	}
	rec.Gate.Phase = "paused"
	rec.Frozen.AuditPosition, rec.Frozen.At, rec.Frozen.Copy = strconv.FormatInt(pos, 10), at, FrozenCopyName(a.id)
	return barrierJSON(stdout, rec)
}

func barrierJSON(stdout io.Writer, v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return ExitFailure
	}
	fmt.Fprintln(stdout, string(b))
	return ExitOK
}

// freezeCopy writes the frozen copy: a snapshot of store under a temporary
// name, given to the data directory's owner, mode 0600, synced, renamed
// into place, the directory synced. It returns the copy's last audit
// position.
func freezeCopy(ctx context.Context, store *storage.DB, dir, path string) (int64, error) {
	tmp := path + ".partial"
	clean := func(p string) {
		for _, s := range []string{"", "-wal", "-shm", "-journal"} {
			_ = os.Remove(p + s)
		}
	}
	clean(tmp)
	if _, err := store.Snapshot(ctx, tmp, storage.SnapshotOptions{}); err != nil {
		clean(tmp)
		return 0, err
	}
	pos, err := lastPosition(tmp)
	if err == nil {
		err = os.Chmod(tmp, 0o600)
	}
	if err == nil {
		if st, serr := os.Stat(dir); serr == nil {
			if owner := statOwner(st); owner >= 0 && owner != os.Getuid() {
				err = os.Chown(tmp, owner, -1)
			}
		}
	}
	if err == nil {
		err = syncFile(tmp)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err == nil {
		err = syncFile(dir)
	}
	if err != nil {
		clean(tmp)
		return 0, err
	}
	return pos, nil
}

// lastPosition reads a frozen copy's last audit position. The copy is
// opened immutable: nothing writes it, and no -wal or -shm file is made
// beside it.
func lastPosition(path string) (int64, error) {
	db, err := sql.Open("sqlite", "file:"+uriPath(path)+"?mode=ro&immutable=1")
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var pos int64
	if err := db.QueryRow("SELECT coalesce(max(event_order), 0) FROM audit_events").Scan(&pos); err != nil {
		return 0, fmt.Errorf("the frozen copy %s: %v", path, err)
	}
	return pos, nil
}

// uriPath escapes what an SQLite file URI reads specially.
func uriPath(path string) string {
	r := strings.NewReplacer("%", "%25", "?", "%3F", "#", "%23")
	return r.Replace(path)
}

// frozenOf is a frozen copy's last audit position and when it was made.
func frozenOf(path string) (int64, string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, "", err
	}
	pos, err := lastPosition(path)
	return pos, st.ModTime().UTC().Format(time.RFC3339Nano), err
}

// frozenCopy is a paused barrier's copy, for the reverse export.
type frozenCopy struct {
	path     string
	position int64
}

// barrierCopy is the data directory's paused migration barrier's frozen
// copy: nil when no migration barrier stands (the export then needs a
// stopped varlatchd); an error for a barrier still draining, one whose
// copy is missing, or one of another migration than the journal's.
func barrierCopy(dir string) (*frozenCopy, error) {
	g, err := backup.ReadGate(dir)
	switch {
	case err != nil:
		return nil, fmt.Errorf("the data directory's maintenance gate: %w", err)
	case g == nil || g.Kind != "migration" || g.Phase == "transfer":
		return nil, nil
	case g.Phase == "draining":
		return nil, fmt.Errorf("the migration %s's barrier is still draining: varlatchd admin migrate barrier --id %s finishes it", g.ID, g.ID)
	}
	if err := migrationOpen(dir, g.ID, "the reverse export"); err != nil {
		return nil, err
	}
	pos, err := strconv.ParseInt(*g.FrozenPosition, 10, 64)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, FrozenCopyName(g.ID))
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("the migration %s's barrier holds no frozen copy (%v): varlatchd admin migrate barrier --id %s makes it again", g.ID, err, g.ID)
	}
	return &frozenCopy{path: path, position: pos}, nil
}

func runMigrateRelease(env *hostEnv, rest []string, stdout, stderr io.Writer) int {
	fail := func(status int, format string, args ...any) int {
		fmt.Fprintf(stderr, "varlatchd admin migrate release: "+format+"\n", args...)
		return status
	}
	a, msg := parseMigrate(rest)
	if msg != "" || a.sub != "release" {
		fmt.Fprintln(stderr, migrateUsage)
		return 64
	}
	dir := env.cfg.DataDir
	h, ok, err := readJournal(dir)
	switch {
	case err != nil:
		return fail(ExitFailure, "the data directory's journal: %v", err)
	case !ok || h.ID != a.id:
		return fail(ExitFailure, "the data directory's journal is not the migration %s's; nothing was released", a.id)
	}
	if err := env.admission.ReleaseBarrier(a.id); err != nil {
		return fail(ExitFailure, "%v; nothing was released", err)
	}
	path := filepath.Join(dir, FrozenCopyName(a.id))
	for _, p := range []string{path, path + ".partial", path + ".partial-wal", path + ".partial-shm", path + ".partial-journal"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fail(ExitFailure, "the barrier is lifted, but its frozen copy %s could not be removed: %v", p, err)
		}
	}
	fmt.Fprintln(stdout, `{"released":true}`)
	return ExitOK
}
