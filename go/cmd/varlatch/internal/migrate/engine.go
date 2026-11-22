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
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
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
	// Ingress is the source's ingress shape (decision 12); required.
	Ingress Ingress
	// TransferTimeout bounds the wait for the public URL to answer from
	// the target (3 minutes by default: an ACME issuance, a domain move).
	TransferTimeout time.Duration
	// ProbeEvery is the wait between two probes (2 s by default).
	ProbeEvery time.Duration
	// Stage, when set (an image target, whose varlatchd runs as the
	// image's user), is the user a bundle and the dry run's scratch
	// database are given to: each in a directory of its own in StageBase
	// (this source's), which that user owns.
	Stage     *Owner
	StageBase string
	// StageKeep is this run's own directory in StageBase (an image's
	// derived configuration), which the leftovers' cleanup spares.
	StageKeep string
}

// DefaultTransferTimeout bounds the transfer's wait for the public URL.
const DefaultTransferTimeout = 3 * time.Minute

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
	// Prober asks the public URL which installation serves it.
	Prober Prober
	// pin replaces the published image's (the tests' fakes only).
	pin *imagePin
	// sleep waits between probes (time.Sleep; the tests' clock).
	sleep func(time.Duration)
}

// DryRunReport is the dry run's: each part of the projected downtime
// (decision 19), the total against the budget, and the checks.
type DryRunReport struct {
	At       string `json:"at"`
	ExportMs int64  `json:"exportMs"`
	ImportMs int64  `json:"importMs"`
	CheckMs  int64  `json:"checkMs"`
	DrainMs  int64  `json:"drainMs"`
	// TransferMs is the address transfer's share, estimated for the
	// ingress shape (decision 19: an ACME issuance or a domain move about
	// a minute, an own proxy's port a few seconds), and the target's
	// restart at open; it is included in ProjectedMs. The dry run cannot
	// measure it: nothing is transferred before the barrier.
	TransferMs       int64         `json:"transferMs"`
	TransferMeasured bool          `json:"transferMeasured"`
	Ingress          Ingress       `json:"ingress"`
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
	if err := e.save(ctx, j); err != nil {
		return err
	}
	crashPoint("entered " + string(p))
	return nil
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
	case j.Phase == RolledBack:
		return j, fmt.Errorf("the migration %s was rolled back: the TypeScript release serves again, and the target holds Go's copy; varlatch migrate --finish --delete-old-data removes it before a new migration", j.ID)
	case j.Phase == Finished && j.Finish != nil && j.Finish.After == RolledBack && j.Finish.DeleteOldData && j.Finish.DoneAt != "":
		// Rolled back, Go's copy discarded: a new migration may start.
	case j.Phase == Finished && j.Finish != nil && j.Finish.After == RolledBack:
		return j, fmt.Errorf("the migration %s was rolled back and finished, but Go's copy is kept: varlatch migrate --finish --delete-old-data removes it before a new migration", j.ID)
	case j.Phase == Finished:
		return j, fmt.Errorf("the migration %s is finished: this installation was migrated, and its rollback window is closed (varlatch migrate --status)", j.ID)
	default:
		return j, fmt.Errorf("the migration %s was interrupted in phase %s: varlatch migrate --resume continues or undoes it (varlatch migrate --status)", j.ID, j.Phase)
	}
	reuse := j != nil && j.Phase != Released && j.Phase != Finished
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
	if err := e.pinned(src); err != nil {
		return prev, err
	}
	tgt, st, err := e.Target.Describe(ctx)
	if err != nil {
		return prev, err
	}
	head := st.Journal
	if head == nil && st.Database {
		return prev, fmt.Errorf("the target's data directory %s holds a database and no migration journal: a migration imports into an empty one only", tgt.DataDir)
	}
	ing, err := e.Source.Ingress(ctx)
	if err != nil {
		return prev, err
	}
	origin, err := e.sameAddress(ing, tgt)
	if err != nil {
		return prev, err
	}
	j := &Journal{Format: 1, DryRunOnly: dryRunOnly, Source: src, Target: tgt, MaxDowntime: int64(e.maxDowntime() / time.Second),
		Drain: int64(e.drain() / time.Second), Ingress: e.Options.Ingress, Transfer: &TransferRecord{Origin: origin}, History: []Step{}}
	if e.Options.Ingress == Proxy {
		j.Transfer.Publish = ing.WebAddress
	}
	if reuse {
		// The same migration goes on only to the same target.
		if prev.Target.Config != tgt.Config || prev.Target.DataDir != tgt.DataDir {
			return prev, fmt.Errorf("the migration %s's target is %s (data directory %s), not %s (data directory %s): it goes on to its own target only",
				prev.ID, prev.Target.Config, prev.Target.DataDir, tgt.Config, tgt.DataDir)
		}
		j.ID = prev.ID
		j.History = prev.History
	} else if j.ID, err = newID(); err != nil {
		return prev, err
	}
	// Another migration's journal: one undone (released), or reversed with
	// its database discarded (rolled back, then finished with its old
	// data deleted), gives way to a new one.
	if head != nil && head.ID != j.ID && head.Phase != Released && !(head.Phase == RolledBack && !st.Database) {
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
		return j, e.stopBefore(ctx, j, err)
	}
	if err := e.preflight(ctx, j); err != nil {
		return j, e.stopBefore(ctx, j, err)
	}
	report, err := e.dryRun(ctx, j)
	if err != nil {
		return j, e.stopBefore(ctx, j, err)
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

// stopBefore records a migration that failed before the barrier (its
// discard, preflight or dry run: nothing was frozen or switched) as
// stopped, as a dry run that ends is: the next run starts it again, on the
// same id, instead of finding it interrupted (--resume or --abort only).
// A run killed there is still interrupted; --resume says what to do.
func (e *Engine) stopBefore(ctx context.Context, j *Journal, cause error) error {
	j.Stopped = true
	if err := e.save(ctx, j); err != nil {
		return fmt.Errorf("%w; recording it as stopped: %v", cause, err)
	}
	return fmt.Errorf("%w (recorded as stopped: varlatch migrate starts it again once that is fixed)", cause)
}

// pinned refuses a source that is not the last TypeScript release's
// published image: its registry digest, of its own repository, must be the
// pinned one. While no digest is pinned (0.23.0 not published yet), every
// source is refused.
func (e *Engine) pinned(src SourceInfo) error {
	pin := imagePin{Repository: LastTypeScriptRepository, Digest: LastTypeScriptDigest}
	if testPin != nil {
		pin = *testPin
	}
	if e.pin != nil {
		pin = *e.pin
	}
	switch {
	case pin.Digest == "":
		return fmt.Errorf("%s is not yet published; this varlatch cannot migrate yet (it pins the release's image by its digest)", LastTypeScriptRelease)
	case src.Digest == "":
		return errors.New("the source's image is not pinned by a registry digest: a migration starts from the last TypeScript release's published image only")
	case src.DigestRepository != pin.Repository || src.Digest != pin.Digest:
		// Repository and digest apart, never joined by "@": the CLI's
		// fail-safe reads what comes before an "@" as possible credentials.
		return fmt.Errorf("the source's image is repository %s, digest %s, not the published %s image: repository %s, digest %s",
			src.DigestRepository, src.Digest, LastTypeScriptRelease, pin.Repository, pin.Digest)
	}
	return nil
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
	// What a run killed before it could clean up left on this host: the
	// dry run's scratch directories and the bundles (the lock is held).
	if err := e.Source.CleanLeftovers(); err != nil {
		return fmt.Errorf("preflight: removing what an interrupted run left: %w", err)
	}
	if err := cleanScratch(e.work()); err != nil {
		return fmt.Errorf("preflight: removing what an interrupted run left: %w", err)
	}
	if e.Options.Stage != nil && e.Options.StageBase != "" {
		for _, re := range []*regexp.Regexp{leftoverStage, leftoverConf} {
			if err := removeMatchingExcept(e.Options.StageBase, re, true, e.Options.StageKeep); err != nil {
				return fmt.Errorf("preflight: removing what an interrupted run left: %w", err)
			}
		}
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

// leftoverScratch is a dry run's scratch directory (os.MkdirTemp's
// ".dry-run-" and its digits); leftoverJournal a journal's temporary name.
var (
	leftoverScratch = regexp.MustCompile(`^\.dry-run-[0-9]+$`)
	leftoverJournal = regexp.MustCompile(`^\.migration\.json\.[0-9a-f]{12}\.tmp$`)
	leftoverStage   = regexp.MustCompile(`^\.varlatch-migrate-stage-[0-9]+$`)
)

// cleanScratch removes what a killed run left in its work directory: the
// dry run's scratch directories (directories only) and the journal's
// temporary names (regular files only), by their exact names.
func cleanScratch(dir string) error {
	if err := removeMatching(dir, leftoverScratch, true); err != nil {
		return err
	}
	return removeMatching(dir, leftoverJournal, false)
}

// removeMatching removes dir's entries whose names match: directories
// (whole) when dirs, else regular files; nothing else, no symbolic link.
func removeMatching(dir string, names *regexp.Regexp, dirs bool) error {
	return removeMatchingExcept(dir, names, dirs, "")
}

// removeMatchingExcept is removeMatching sparing the path keep.
func removeMatchingExcept(dir string, names *regexp.Regexp, dirs bool, keep string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !names.MatchString(e.Name()) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if keep != "" && filepath.Clean(p) == filepath.Clean(keep) {
			continue
		}
		switch {
		case dirs && e.Type().IsDir():
			err = os.RemoveAll(p)
		case !dirs && e.Type().IsRegular():
			err = os.Remove(p)
		default:
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
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
	scratch, err := e.scratchDir()
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(scratch)
	start := e.now()
	exported, err := e.Source.Export(ctx, runKey, true)
	if err != nil {
		return nil, fmt.Errorf("the dry run's export: %w; nothing was switched", err)
	}
	defer os.Remove(exported)
	bundle, err := e.stage(exported, scratch)
	if err != nil {
		return nil, err
	}
	exportedAt := e.now()
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
	r := &DryRunReport{At: checked.UTC().Format(time.RFC3339Nano), ExportMs: exportedAt.Sub(start).Milliseconds(),
		ImportMs: imported.Sub(exportedAt).Milliseconds(), CheckMs: checked.Sub(imported).Milliseconds(),
		DrainMs: e.drain().Milliseconds(), MaxDowntimeMs: e.maxDowntime().Milliseconds(), Copy: cp, Checks: &checks,
		TransferMs: transferEstimate(j.Ingress).Milliseconds(), Ingress: j.Ingress}
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

// scratchDir is a new directory for the dry run's database or a staged
// bundle: in the work directory, or, with Stage, under the system's
// temporary directory and given to that user.
func (e *Engine) scratchDir() (string, error) {
	if e.Options.Stage == nil {
		return os.MkdirTemp(e.work(), ".dry-run-")
	}
	dir, err := os.MkdirTemp(e.Options.StageBase, ".varlatch-migrate-stage-")
	if err != nil {
		return "", err
	}
	if err := chownAll(*e.Options.Stage, dir); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// stage is the bundle as the target's varlatchd reads it: as it is, or,
// with Stage, a copy in dir given to that user (the export's file is the
// source container's user's).
func (e *Engine) stage(bundle, dir string) (string, error) {
	if e.Options.Stage == nil {
		return bundle, nil
	}
	in, err := os.Open(bundle)
	if err != nil {
		return "", err
	}
	defer in.Close()
	p := filepath.Join(dir, "bundle.jsonl")
	out, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = chownAll(*e.Options.Stage, p)
	}
	if err != nil {
		_ = os.Remove(p)
		return "", fmt.Errorf("staging the bundle for the target's user: %w", err)
	}
	return p, nil
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
	crashPoint("barrier held")
	if err := e.finalCopy(ctx, j); err != nil {
		return j, e.undo(ctx, j, err)
	}
	if err := e.transfer(ctx, j); err != nil {
		return j, err
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
	exported, err := e.Source.Export(ctx, runKey, false)
	if err != nil {
		return fmt.Errorf("the export: %w", err)
	}
	defer os.Remove(exported)
	bundle := exported
	if e.Options.Stage != nil {
		dir, err := e.scratchDir()
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		if bundle, err = e.stage(exported, dir); err != nil {
			return err
		}
	}
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

// switchAndOpen: once the public URL answers from the target, the source
// marked migrated out (journalled first: from here the migration goes
// forward only), then the target opened: stopped, its journal open (which
// removes the transfer's gate), started again.
func (e *Engine) switchAndOpen(ctx context.Context, j *Journal) error {
	if err := e.enter(ctx, j, Switched); err != nil {
		return err
	}
	if err := e.migratedOut(ctx, j); err != nil {
		return err
	}
	e.say("Switched: the source refuses writes from now on.")
	return e.open(ctx, j)
}

// open restarts the target out of the transfer's isolation: stopped, its
// journal open (varlatchd removes the gate first), started. Interrupted
// anywhere, --resume finishes it (finishOpen).
func (e *Engine) open(ctx context.Context, j *Journal) error {
	_, st, err := e.Target.Describe(ctx)
	if err != nil {
		return err
	}
	if st.Running {
		// The live open: the source's journal open, then the running
		// target ends its gate and writes its own journal open.
		j.enter(Open, e.now())
		if err := writeJournal(e.Source.Dir(), j); err != nil {
			return fmt.Errorf("the journal in %s: %w", e.Source.Dir(), err)
		}
		crashPoint("open source")
		if err := e.Target.OpenLive(ctx, j.ID); err != nil {
			return fmt.Errorf("opening the target: %w; varlatch migrate --resume finishes it", err)
		}
	} else {
		if err := e.enter(ctx, j, Open); err != nil {
			return fmt.Errorf("opening the target: %w; varlatch migrate --resume finishes it", err)
		}
		if err := e.Target.Start(ctx); err != nil {
			return e.waitForHuman(err, "The migration is open; start the target, then varlatch migrate --resume checks it serves.")
		}
	}
	at := "its address"
	if j.Transfer != nil {
		at = j.Transfer.Origin
	}
	e.say("Open: the target serves the migrated installation at %s.", at)
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
		// Switched, yet the barrier is gone: it was lifted (or replaced)
		// by hand. The old installation may have taken writes since the
		// frozen point, which the target does not hold. Not automated.
		now := "no gate"
		if g != nil {
			now = fmt.Sprintf("a %s gate (%s)", g.Kind, g.ID)
		}
		return fmt.Errorf("the migration %s is switched, but the source holds %s, not its barrier %s: the barrier was lifted outside varlatch migrate. "+
			"A person must decide: marking the source migrated out now loses every write it took since the frozen point (audit position %s), "+
			"which the target does not have; varlatch migrate does neither on its own", j.ID, now, j.Barrier.GateID, j.Barrier.AuditPosition)
	}
	return e.Source.MarkMigratedOut(ctx, g.ID)
}

// undo lifts the barrier (the gate the source holds now, if it is a
// migration barrier), discards the target's database, and journals the
// migration released; cause is returned, with what undoing could not do.
func (e *Engine) undo(ctx context.Context, j *Journal, cause error) error {
	from := j.Phase
	e.say("Undoing: %v.", cause)
	// Marked first: an undo held up (a step for the operator, a side that
	// failed) is resumed as an undo, never as what it undid.
	if !j.Undoing {
		j.Undoing = true
		if err := e.save(ctx, j); err != nil {
			return fmt.Errorf("%w; undoing could not start: %v", cause, err)
		}
	}
	// In the transfer: the target stops first, then the barrier is lifted,
	// then the source's ingress starts (returnAddress says why in that
	// order). With the ingress stopped, nothing reaches the source between
	// the two.
	var problems []error
	stopped := true
	if from == Transfer {
		stop := e.stopTargetForUndo(ctx)
		stopped = len(stop) == 0
		problems = append(problems, stop...)
	}
	// open: the source is behind no gate now. Otherwise closed says why its
	// ingress is not started.
	released, open, closed := false, false, ""
	g, err := e.Source.Gate(ctx)
	switch {
	case err != nil:
		problems = append(problems, fmt.Errorf("reading the source's gate: %w", err))
		closed = "could not confirm the source's gate is lifted, so its %s is not started again"
	case g != nil && g.Kind == "migration":
		if err := e.Source.Release(ctx, g.ID); err != nil {
			problems = append(problems, fmt.Errorf("lifting the barrier %s: %w", g.ID, err))
			closed = "the source's %s is not started again while its barrier stands"
		} else {
			released, open = true, true
		}
	case g != nil:
		problems = append(problems, fmt.Errorf("the source is behind a %s gate (%s), not a migration barrier: left as it is", g.Kind, g.ID))
		closed = "the source's %s is not started again while its gate stands"
	default:
		open = true
	}
	if from == Transfer {
		switch {
		case j.Ingress == Coolify:
			// Coolify's domain goes back by hand, whatever the gate or the
			// target: there is nothing of this host's to start or wait for.
			problems = append(problems, e.returnAddress(ctx, j)...)
		case !stopped:
			// The target may still hold the address (an image's service
			// the operator stops, a unit that would not stop): the source's
			// ingress would collide with it or race it, and a wait would
			// probe the target. Left for --resume once it is stopped.
			problems = append(problems, fmt.Errorf("the source's %s is not started again while the target may still serve the address", ingressPart(j.Ingress)))
		case !open:
			problems = append(problems, fmt.Errorf(closed, ingressPart(j.Ingress)))
		default:
			back := e.returnAddress(ctx, j)
			problems = append(problems, back...)
			// The old installation is reopened only once it answers at its
			// address: its ingress started is not yet its dashboard
			// listening (7.8b rehearsal, run r12). A journal that records
			// no address (one from before the transfer record) has none to
			// check.
			switch {
			case len(back) > 0:
			case j.Transfer == nil || j.Transfer.Origin == "":
				e.say("The source's %s was started again; the journal records no address to check it at.", ingressPart(j.Ingress))
			default:
				want := ""
				if j.Copy != nil {
					want = j.Copy.InstallationID
				}
				if err := e.waitForTypeScript(ctx, j, want); err != nil {
					problems = append(problems, fmt.Errorf("the source's %s was started again, but %w", ingressPart(j.Ingress), err))
					if !j.UndoUnanswered {
						j.UndoUnanswered = true
						if err := e.save(ctx, j); err != nil {
							problems = append(problems, fmt.Errorf("recording that the source did not answer: %w", err))
						}
					}
				}
			}
		}
	}
	// A target that may still run keeps its database: discarding it would
	// only say to stop the target first, again.
	if stopped {
		if err := e.discard(ctx, j); err != nil {
			problems = append(problems, fmt.Errorf("discarding the target's database: %w", err))
		}
	}
	if len(problems) > 0 {
		// Not released: the journal stays where it was, for --resume.
		return fmt.Errorf("%w; undoing did not finish (%v): varlatch migrate --resume tries again", cause, errors.Join(problems...))
	}
	j.Undone = &UndoneRecord{From: from, Why: cause.Error(), Released: released, At: e.now().UTC().Format(time.RFC3339Nano)}
	j.Undoing, j.UndoUnanswered = false, false
	if err := e.enter(ctx, j, Released); err != nil {
		did := "the barrier lifted, the target's database discarded"
		if from == Transfer {
			did = "the target stopped, the barrier lifted, the address returned, the target's database discarded"
		}
		return fmt.Errorf("%w; it was undone (%s), but a journal could not say released: %v; varlatch migrate --resume finishes it", cause, did, err)
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
//   - transfer: the public URL checked again, then switched and opened (or,
//     in the public and proxy shapes, the address given back and undone);
//   - switched: continued to open (the source refuses writes);
//   - open or released: finished on the target if it was not (its journal
//     open and its service started, or its journal released), else
//     nothing.
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
	if slices.Contains(reverseHeld, j.Phase) || j.Phase == RollbackTransfer || j.Phase == RolledBack {
		return j, e.resumeReverse(ctx, j)
	}
	if j.Phase == Finished {
		if j.Finish == nil {
			return j, nil
		}
		// Go's journal first: the same migration, and finished there too
		// (written now when a run was killed between the two journals).
		if err := e.finishAgrees(ctx, j); err != nil {
			return j, err
		}
		if j.Finish.DoneAt == "" {
			e.say("The migration %s's --finish was interrupted: it goes on.", j.ID)
			return j, e.finishRemove(ctx, j)
		}
		return j, nil
	}
	switch {
	case j.Undoing && j.Phase != Released:
		e.say("The migration %s was being undone: undoing goes on.", j.ID)
		return j, e.undo(ctx, j, errors.New("undoing resumed"))
	case slices.Contains(beforeBarrier, j.Phase):
		e.say("The migration %s stopped before the barrier: it starts again from the preflight.", j.ID)
		return e.start(ctx, j, true, j.DryRunOnly)
	case slices.Contains(held, j.Phase):
		e.say("The migration %s was interrupted in phase %s: it is undone.", j.ID, j.Phase)
		return j, e.undo(ctx, j, fmt.Errorf("interrupted in phase %s", j.Phase))
	case j.Phase == Transfer:
		e.say("The migration %s is transferring its address: the public URL is checked again.", j.ID)
		if err := e.transfer(ctx, j); err != nil {
			return j, err
		}
		return j, e.switchAndOpen(ctx, j)
	case j.Phase == Switched:
		e.say("The migration %s was switched: it goes on to open.", j.ID)
		if err := e.migratedOut(ctx, j); err != nil {
			return j, err
		}
		return j, e.open(ctx, j)
	case j.Phase == Open:
		return j, e.finishOpen(ctx, j)
	case j.Phase == Released:
		return j, e.finishReleased(ctx, j)
	}
	return j, nil
}

// finishOpen finishes an open the source's journal records: the target's
// journal open (which removes its gate) and its service running. Done
// already, it changes nothing.
func (e *Engine) finishOpen(ctx context.Context, j *Journal) error {
	_, st, err := e.Target.Describe(ctx)
	if err != nil {
		return err
	}
	if st.Barrier != "" && j.Rollback != nil && j.Rollback.Undone != nil {
		// A reverse undone, interrupted before Go's barrier was lifted:
		// lifted now, through the running varlatchd or, stopped, on its
		// data directory (varlatchd's release works offline too).
		if rt, ok := e.Target.(ReverseTarget); ok {
			e.say("The reverse of the migration %s was undone, but Go's barrier stands: it is lifted.", j.ID)
			if err := rt.ReleaseBarrier(ctx, j.ID); err != nil {
				return err
			}
			_, st, err = e.Target.Describe(ctx)
			if err != nil {
				return err
			}
		}
	}
	if st.Barrier == "" && j.Rollback != nil && j.Rollback.Undone != nil && !j.Rollback.Undone.Released {
		// Lifted (now, or by a run killed before it journalled it).
		// The source's journal only, as undoReverse writes it.
		j.Rollback.Undone.Released = true
		if err := writeJournal(e.Source.Dir(), j); err != nil {
			return err
		}
	}
	if st.Journal != nil && st.Journal.ID == j.ID && st.Journal.Phase == Open && !st.Gate && st.Running {
		return nil
	}
	e.say("The migration %s is open, but the target does not serve it yet: it is opened.", j.ID)
	if st.Running {
		return e.Target.OpenLive(ctx, j.ID)
	}
	if err := e.Target.WriteJournal(ctx, j); err != nil {
		return err
	}
	if err := e.Target.Start(ctx); err != nil {
		return e.waitForHuman(err, "Then varlatch migrate --resume checks it serves.")
	}
	return nil
}

// waitForHuman is err, or, when it is a step for the operator (an image's
// service to start or stop), its instruction said with what follows, and
// ErrAwaitingOperator.
func (e *Engine) waitForHuman(err error, then string) error {
	var human *HumanStep
	if !errors.As(err, &human) {
		return err
	}
	e.say("%s %s", human.Instruction, then)
	return ErrAwaitingOperator
}

// finishReleased finishes an undo the source's journal records: the
// target's journal released (which removes the transfer's gate).
func (e *Engine) finishReleased(ctx context.Context, j *Journal) error {
	_, st, err := e.Target.Describe(ctx)
	if err != nil {
		return err
	}
	if st.Journal == nil || st.Journal.ID != j.ID || (st.Journal.Phase == Released && !st.Gate) {
		return nil
	}
	if st.Running {
		if err := e.Target.Stop(ctx); err != nil {
			return e.waitForHuman(err, "Then run varlatch migrate --resume (or --abort) again.")
		}
	}
	return e.Target.WriteJournal(ctx, j)
}

// Abort is `varlatch migrate --abort`: a migration not yet switched
// undone on purpose, from any phase before the switch (the address
// returned first, during the transfer). A switched one is not: it goes
// forward only.
func (e *Engine) Abort(ctx context.Context) (*Journal, error) {
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
	case j == nil:
		return nil, fmt.Errorf("%s holds no migration journal: there is nothing to abort", e.Source.Dir())
	case j.Phase == Released:
		return j, nil
	case slices.Contains(reverseHeld, j.Phase) || j.Phase == RollbackTransfer:
		if j.Rollback == nil {
			return j, fmt.Errorf("the migration %s is in phase %s, but its journal records no reverse", j.ID, j.Phase)
		}
		err := e.undoReverse(ctx, j, errors.New("aborted by the operator"))
		if j.Phase == Open && j.Rollback.Undone != nil {
			return j, nil
		}
		return j, err
	case j.Phase == RolledBack:
		return j, fmt.Errorf("the migration %s was rolled back: the TypeScript release serves; going to Go again is a new migration (after varlatch migrate --finish)", j.ID)
	case j.Phase == Finished:
		return j, fmt.Errorf("the migration %s is finished: its rollback window is closed, and nothing of it is undone", j.ID)
	case j.Phase == Switched || j.Phase == Open:
		return j, fmt.Errorf("the migration %s is %s: past its switch it goes forward only (varlatch migrate --resume)", j.ID, j.Phase)
	}
	err = e.undo(ctx, j, errors.New("aborted by the operator"))
	if j.Phase == Released {
		return j, nil
	}
	return j, err
}

// RunKeyText is a run key as the sides read it: 64 lowercase hex digits
// and a newline. The caller clears it.
func RunKeyText(k []byte) []byte {
	out := make([]byte, hex.EncodedLen(len(k))+1)
	hex.Encode(out, k)
	out[len(out)-1] = '\n'
	return out
}
