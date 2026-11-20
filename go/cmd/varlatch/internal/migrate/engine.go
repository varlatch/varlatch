// SPDX-License-Identifier: Apache-2.0

// Package migrate is `varlatch migrate`'s engine (ADR-0059 Decision 9;
// internal docs/design/go-step7.md decisions 2, 14, 19 and 20, slice
// 7.4a): the phases from the last TypeScript release to varlatchd, each
// journalled before it is done, in the source's directory and in the
// target's data directory, so an interruption is continued or undone,
// never guessed at:
//
//  1. preflight: the source is the last TypeScript release (by version
//     and image digest), behind no gate; a fresh backup made, uploaded,
//     downloaded and verified; the target's key files given the source's
//     keys (decision 9);
//  2. the dry run: a full copy from a snapshot of the running source,
//     imported into a scratch directory and checked, timed; the projected
//     downtime held against the budget (decision 19, O7);
//  3. the barrier on the source, its frozen point recorded;
//  4. the final copy: exported at the frozen point, imported into the
//     target, checked (varlatchd's checks, slice 7.3b); any failure lifts
//     the barrier, and the old installation reopens unchanged;
//  5. the switch: the source marked migrated out (it refuses writes from
//     here); the address transfer (slice 7.4b) comes here;
//  6. open: the target's journal says open, and varlatchd may start.
//
// The run key is made per run, handed to each side on a pipe (the export's
// and the checks' stdin), and cleared; it is never in an argument, the
// environment, the journal, a log or the report.
//
// The sides are processes (Source, Target): this package opens no
// database, and imports nothing of the server (G12).
package migrate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// Options are a migration's settings.
type Options struct {
	// MaxDowntime is the downtime budget (O7: 10 minutes by default); the
	// barrier is refused when the dry run projects more.
	MaxDowntime time.Duration
	// Drain is how long the barrier waits for in-flight work.
	Drain time.Duration
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Say reports progress, one line at a time (nil: silent).
	Say func(string)
	// Work is a directory of this host's for the dry run's scratch
	// database (removed after it).
	Work string
}

// DefaultMaxDowntime is O7's budget.
const DefaultMaxDowntime = 10 * time.Minute

// DefaultDrain bounds the barrier's wait for in-flight work.
const DefaultDrain = 60 * time.Second

// Engine runs a migration between a Source and a Target.
type Engine struct {
	Source  Source
	Target  Target
	Options Options
	// BEK is the source's Backup Encryption Key file's text, given to the
	// target's key file (nil: none is copied). The caller clears it.
	BEK []byte
}

// DryRunReport is the dry run's: each part of the projected downtime
// (decision 19), the total against the budget, and the checks.
type DryRunReport struct {
	At               string        `json:"at"`
	ExportMs         int64         `json:"exportMs"`
	ImportMs         int64         `json:"importMs"`
	CheckMs          int64         `json:"checkMs"`
	DrainMs          int64         `json:"drainMs"`
	TransferMs       int64         `json:"transferMs"`
	TransferMeasured bool          `json:"transferMeasured"`
	ProjectedMs      int64         `json:"projectedMs"`
	MaxDowntimeMs    int64         `json:"maxDowntimeMs"`
	Fits             bool          `json:"fits"`
	Copy             CopyRecord    `json:"copy"`
	Checks           *CheckSummary `json:"checks,omitempty"`
}

// ErrOverBudget is a dry run whose projection exceeds the budget.
var ErrOverBudget = errors.New("the projected downtime exceeds --max-downtime")

func (e *Engine) now() time.Time {
	if e.Options.Now != nil {
		return e.Options.Now()
	}
	return time.Now()
}

func (e *Engine) say(format string, args ...any) {
	if e.Options.Say != nil {
		e.Options.Say(fmt.Sprintf(format, args...))
	}
}

// save writes the journal in both places: the source's directory first,
// then the target's data directory (varlatchd reads its own there).
func (e *Engine) save(ctx context.Context, j *Journal) error {
	if err := writeJournal(e.Source.Dir(), j); err != nil {
		return fmt.Errorf("the journal in %s: %w", e.Source.Dir(), err)
	}
	if err := e.Target.WriteJournal(ctx, j); err != nil {
		return fmt.Errorf("the journal in the target's data directory: %w", err)
	}
	return nil
}

func (e *Engine) enter(ctx context.Context, j *Journal, p Phase) error {
	j.enter(p, e.now())
	return e.save(ctx, j)
}

// Status is the source directory's journal (nil when none).
func Status(dir string) (*Journal, error) { return readJournal(dir) }

// Run is `varlatch migrate`: a new migration (or, after an undone or
// stopped one, the next), to the open target; with dryRunOnly, it stops
// after the dry run. A migration that was interrupted is refused: that is
// Resume's.
func (e *Engine) Run(ctx context.Context, dryRunOnly bool) (*Journal, error) {
	unlock, err := lockDir(e.Source.Dir())
	if err != nil {
		return nil, err
	}
	defer unlock()
	j, err := readJournal(e.Source.Dir())
	if err != nil {
		return nil, err
	}
	switch {
	case j == nil, j.Phase == Released, j.Stopped && slices.Contains(beforeBarrier, j.Phase):
	case j.Phase == Open:
		return j, fmt.Errorf("the migration %s is open: this installation was migrated (varlatch migrate --status)", j.ID)
	default:
		return j, fmt.Errorf("the migration %s was interrupted in phase %s: varlatch migrate --resume continues or undoes it (varlatch migrate --status)", j.ID, j.Phase)
	}
	reuse := j != nil && j.Phase != Released
	return e.start(ctx, j, reuse, dryRunOnly)
}

// start runs from the preflight: on j's id when reuse (a stopped dry run
// or one interrupted before the barrier), else on a new one.
func (e *Engine) start(ctx context.Context, prev *Journal, reuse, dryRunOnly bool) (*Journal, error) {
	src, err := e.Source.Discover(ctx)
	if err != nil {
		return prev, err
	}
	if src.Release != LastTypeScriptRelease {
		return prev, fmt.Errorf("the source runs %s; a migration starts from the last TypeScript release, %s, only: upgrade it first", orNone(src.Release), LastTypeScriptRelease)
	}
	if src.Digest == "" {
		return prev, errors.New("the source's image is not pinned by a digest: a migration starts from the last TypeScript release's published image only")
	}
	tgt, st, err := e.Target.Describe(ctx)
	if err != nil {
		return prev, err
	}
	head := st.Journal
	if head == nil && st.Database {
		return prev, fmt.Errorf("the target's data directory %s holds a database and no migration journal: a migration imports into an empty one only", tgt.DataDir)
	}
	j := &Journal{Format: 1, DryRunOnly: dryRunOnly, Source: src, Target: tgt, MaxDowntime: int64(e.maxDowntime() / time.Second),
		Drain: int64(e.drain() / time.Second), Transfer: "none: the address transfer is slice 7.4b's", History: []Step{}}
	if reuse {
		j.ID = prev.ID
		j.History = prev.History
	} else if j.ID, err = newID(); err != nil {
		return prev, err
	}
	if head != nil && head.ID != j.ID && head.Phase != Released {
		return prev, fmt.Errorf("the target's data directory holds the migration %s, in phase %s: it is not this one", head.ID, head.Phase)
	}
	if head != nil && head.ID == j.ID && !slices.Contains(beforeBarrier, head.Phase) && head.Phase != Released {
		return prev, fmt.Errorf("the target's journal says the migration %s is in phase %s, the source's %s: varlatch migrate --resume", j.ID, head.Phase, prev.Phase)
	}
	if err := e.enter(ctx, j, Started); err != nil {
		return j, err
	}
	// What a migration interrupted before the barrier built is discarded
	// (decision 14); a new migration's target holds no database.
	if err := e.discard(ctx, j); err != nil {
		return j, err
	}
	if err := e.preflight(ctx, j); err != nil {
		return j, err
	}
	report, err := e.dryRun(ctx, j)
	if err != nil {
		return j, err
	}
	if dryRunOnly || !report.Fits {
		j.Stopped = true
		if err := e.save(ctx, j); err != nil {
			return j, err
		}
		if !report.Fits {
			return j, fmt.Errorf("%w: %s projected, %s allowed; nothing was switched", ErrOverBudget, ms(report.ProjectedMs), ms(report.MaxDowntimeMs))
		}
		return j, nil
	}
	return e.cutover(ctx, j)
}

func orNone(s string) string {
	if s == "" {
		return "a release it does not name"
	}
	return s
}

func ms(n int64) string { return (time.Duration(n) * time.Millisecond).Round(time.Second).String() }

func (e *Engine) maxDowntime() time.Duration {
	if e.Options.MaxDowntime > 0 {
		return e.Options.MaxDowntime
	}
	return DefaultMaxDowntime
}

func (e *Engine) drain() time.Duration {
	if e.Options.Drain > 0 {
		return e.Options.Drain
	}
	return DefaultDrain
}

// preflight: no gate on the source, a fresh backup made, uploaded,
// downloaded and verified, and the target's key files given the source's
// keys.
func (e *Engine) preflight(ctx context.Context, j *Journal) error {
	g, err := e.Source.Gate(ctx)
	if err != nil {
		return err
	}
	if g != nil {
		return fmt.Errorf("the source is behind a %s gate (%s): a migration starts from an installation that serves; nothing was done", g.Kind, g.ID)
	}
	e.say("Preflight: a fresh backup of the source, uploaded, then downloaded and verified.")
	archive, err := e.Source.Backup(ctx)
	if err != nil {
		return fmt.Errorf("preflight: the backup: %w; nothing was done", err)
	}
	if err := e.Source.VerifyBackup(ctx, archive); err != nil {
		return fmt.Errorf("preflight: the backup %s did not verify: %w; nothing was done", archive, err)
	}
	kek, err := e.Source.RootKEK()
	if err != nil {
		return fmt.Errorf("preflight: the source's Root KEK: %w", err)
	}
	defer clear(kek)
	kekState, bekState, err := e.Target.Keys(ctx, kek, e.BEK)
	if err != nil {
		return fmt.Errorf("preflight: the target's keys: %w", err)
	}
	j.Preflight = &PreflightRecord{ArchiveID: archive, VerifiedAt: e.now().UTC().Format(time.RFC3339Nano), RootKEK: kekState, BEK: bekState}
	return e.enter(ctx, j, Preflight)
}

// newRunKey is a run key: 32 random bytes.
func newRunKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// dryRun: the copy from a snapshot of the running source, into a scratch
// directory, checked and timed; nothing of it is kept but the report.
func (e *Engine) dryRun(ctx context.Context, j *Journal) (*DryRunReport, error) {
	e.say("Dry run: a full copy from a snapshot of the running source, imported and checked.")
	runKey, err := newRunKey()
	if err != nil {
		return nil, err
	}
	defer clear(runKey)
	scratch, err := os.MkdirTemp(e.work(), ".dry-run-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(scratch)
	start := e.now()
	bundle, err := e.Source.Export(ctx, runKey, true)
	if err != nil {
		return nil, fmt.Errorf("the dry run's export: %w; nothing was switched", err)
	}
	defer os.Remove(bundle)
	exported := e.now()
	cp, err := e.Target.Import(ctx, bundle, filepath.Join(scratch, "data"))
	if err != nil {
		return nil, fmt.Errorf("the dry run's import: %w; nothing was switched", err)
	}
	imported := e.now()
	checks, err := e.Target.Check(ctx, bundle, filepath.Join(scratch, "data"), runKey)
	if err != nil {
		return nil, fmt.Errorf("the dry run's checks: %w; nothing was switched", err)
	}
	checked := e.now()
	r := &DryRunReport{At: checked.UTC().Format(time.RFC3339Nano), ExportMs: exported.Sub(start).Milliseconds(),
		ImportMs: imported.Sub(exported).Milliseconds(), CheckMs: checked.Sub(imported).Milliseconds(),
		DrainMs: e.drain().Milliseconds(), MaxDowntimeMs: e.maxDowntime().Milliseconds(), Copy: cp, Checks: &checks}
	r.ProjectedMs = r.DrainMs + r.ExportMs + r.ImportMs + r.CheckMs + r.TransferMs
	r.Fits = r.ProjectedMs <= r.MaxDowntimeMs
	j.DryRun = r
	if !checks.Passed {
		j.Stopped = true
		if err := e.save(ctx, j); err != nil {
			return r, err
		}
		return r, fmt.Errorf("the dry run's checks failed: %v; nothing was switched", checks.Faults)
	}
	return r, e.enter(ctx, j, DryRun)
}

func (e *Engine) work() string {
	if e.Options.Work != "" {
		return e.Options.Work
	}
	return e.Source.Dir()
}

// cutover: the barrier, the final copy and its checks, the switch, open.
// A failure before the switch undoes: the barrier lifted, the target's
// database discarded.
func (e *Engine) cutover(ctx context.Context, j *Journal) (*Journal, error) {
	// Journalled before the barrier is asked for: killed while it drains,
	// the resume finds a barrier to lift.
	j.Barrier = &BarrierRecord{}
	if err := e.enter(ctx, j, Barrier); err != nil {
		return j, err
	}
	e.say("Barrier: the source stops taking requests and drains (at most %s).", e.drain())
	b, err := e.Source.Barrier(ctx, e.drain())
	if err != nil {
		return j, e.undo(ctx, j, fmt.Errorf("the barrier: %w", err))
	}
	j.Barrier = &b
	if err := e.save(ctx, j); err != nil {
		return j, e.undo(ctx, j, err)
	}
	if err := e.finalCopy(ctx, j); err != nil {
		return j, e.undo(ctx, j, err)
	}
	return j, e.switchAndOpen(ctx, j)
}

// finalCopy: the export at the frozen point, the import into the target's
// data directory, the checks.
func (e *Engine) finalCopy(ctx context.Context, j *Journal) error {
	e.say("Final copy: the export at the frozen point, imported into the target and checked.")
	runKey, err := newRunKey()
	if err != nil {
		return err
	}
	defer clear(runKey)
	bundle, err := e.Source.Export(ctx, runKey, false)
	if err != nil {
		return fmt.Errorf("the export: %w", err)
	}
	defer os.Remove(bundle)
	cp, err := e.Target.Import(ctx, bundle, "")
	if err != nil {
		return fmt.Errorf("the import: %w", err)
	}
	j.Copy = &cp
	if err := e.enter(ctx, j, Copied); err != nil {
		return err
	}
	checks, err := e.Target.Check(ctx, bundle, "", runKey)
	if err != nil {
		return fmt.Errorf("the checks: %w", err)
	}
	j.Copy.Checks = &checks
	if !checks.Passed {
		return fmt.Errorf("the checks failed: %v", checks.Faults)
	}
	return e.enter(ctx, j, Checked)
}

// switchAndOpen: the source marked migrated out (journalled first: from
// here the migration goes forward only), then the target opened.
func (e *Engine) switchAndOpen(ctx context.Context, j *Journal) error {
	if err := e.enter(ctx, j, Switched); err != nil {
		return err
	}
	if err := e.migratedOut(ctx, j); err != nil {
		return err
	}
	e.say("Switched: the source refuses writes from now on.")
	// The address transfer (slice 7.4b) goes here.
	if err := e.enter(ctx, j, Open); err != nil {
		return err
	}
	e.say("Open: start varlatchd on the target; it serves the migrated installation.")
	return nil
}

// migratedOut marks the source migrated out, unless it already is.
func (e *Engine) migratedOut(ctx context.Context, j *Journal) error {
	g, err := e.Source.Gate(ctx)
	if err != nil {
		return err
	}
	if g != nil && g.Kind == "migrated-out" {
		return nil
	}
	if g == nil || g.Kind != "migration" || (j.Barrier.GateID != "" && g.ID != j.Barrier.GateID) {
		return fmt.Errorf("the source's gate is %v, not this migration's barrier %s: it is not marked migrated out; varlatch migrate --status", g, j.Barrier.GateID)
	}
	return e.Source.MarkMigratedOut(ctx, g.ID)
}

// undo lifts the barrier (the gate the source holds now, if it is a
// migration barrier), discards the target's database, and journals the
// migration released; cause is returned, with what undoing could not do.
func (e *Engine) undo(ctx context.Context, j *Journal, cause error) error {
	from := j.Phase
	e.say("Undoing: %v.", cause)
	var problems []error
	released := false
	g, err := e.Source.Gate(ctx)
	switch {
	case err != nil:
		problems = append(problems, fmt.Errorf("reading the source's gate: %w", err))
	case g != nil && g.Kind == "migration":
		if err := e.Source.Release(ctx, g.ID); err != nil {
			problems = append(problems, fmt.Errorf("lifting the barrier %s: %w", g.ID, err))
		} else {
			released = true
		}
	case g != nil:
		problems = append(problems, fmt.Errorf("the source is behind a %s gate (%s), not a migration barrier: left as it is", g.Kind, g.ID))
	}
	if err := e.discard(ctx, j); err != nil {
		problems = append(problems, fmt.Errorf("discarding the target's database: %w", err))
	}
	if len(problems) > 0 {
		// Not released: the journal stays where it was, for --resume.
		return fmt.Errorf("%w; undoing did not finish (%v): varlatch migrate --resume tries again", cause, errors.Join(problems...))
	}
	j.Undone = &UndoneRecord{From: from, Why: cause.Error(), Released: released, At: e.now().UTC().Format(time.RFC3339Nano)}
	if err := e.enter(ctx, j, Released); err != nil {
		return fmt.Errorf("%w; the barrier was lifted, but the journal could not say so: %v", cause, err)
	}
	return fmt.Errorf("%w; the barrier was lifted and the old installation reopened unchanged", cause)
}

// discard removes the database this migration built in the target's data
// directory, when there is one; one of another migration, or of none, is
// never removed.
func (e *Engine) discard(ctx context.Context, j *Journal) error {
	_, st, err := e.Target.Describe(ctx)
	if err != nil {
		return err
	}
	switch {
	case !st.Database:
		return nil
	case st.Journal == nil || st.Journal.ID != j.ID:
		return fmt.Errorf("the target's database is not this migration's (its journal names %v): it is left as it is", st.Journal)
	}
	return e.Target.Discard(ctx, j.ID)
}

// Resume is `varlatch migrate --resume`: an interrupted migration
// continued or undone, by its journal's phase (decision 14's stated
// states):
//   - before the barrier: redone from the preflight (the source ran
//     unchanged; what the target holds is discarded);
//   - between the barrier and the switch: undone (the barrier lifted, the
//     old installation reopened unchanged, the target's database
//     discarded);
//   - switched: continued to open (the source refuses writes);
//   - open or released: nothing to do.
func (e *Engine) Resume(ctx context.Context) (*Journal, error) {
	unlock, err := lockDir(e.Source.Dir())
	if err != nil {
		return nil, err
	}
	defer unlock()
	j, err := readJournal(e.Source.Dir())
	if err != nil {
		return nil, err
	}
	if j == nil {
		return nil, fmt.Errorf("%s holds no migration journal: there is nothing to resume", e.Source.Dir())
	}
	switch {
	case slices.Contains(beforeBarrier, j.Phase):
		e.say("The migration %s stopped before the barrier: it starts again from the preflight.", j.ID)
		return e.start(ctx, j, true, j.DryRunOnly)
	case slices.Contains(held, j.Phase):
		e.say("The migration %s was interrupted in phase %s: it is undone.", j.ID, j.Phase)
		return j, e.undo(ctx, j, fmt.Errorf("interrupted in phase %s", j.Phase))
	case j.Phase == Switched:
		e.say("The migration %s was switched: it goes on to open.", j.ID)
		if err := e.migratedOut(ctx, j); err != nil {
			return j, err
		}
		if err := e.enter(ctx, j, Open); err != nil {
			return j, err
		}
		e.say("Open: start varlatchd on the target; it serves the migrated installation.")
		return j, nil
	}
	return j, nil
}

// RunKeyText is a run key as the sides read it: 64 lowercase hex digits
// and a newline. The caller clears it.
func RunKeyText(k []byte) []byte {
	out := make([]byte, hex.EncodedLen(len(k))+1)
	hex.Encode(out, k)
	out[len(out)-1] = '\n'
	return out
}
