// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"
)

// `varlatch migrate --rollback` (go-step7 decisions 16 and 17, slice
// 7.6a): the reverse migration, from the open Go installation back to the
// last TypeScript release, each phase journalled in both places before it
// is done, as the forward migration's:
//
//  1. rollback: Go's migration barrier, through its control socket: Go
//     keeps running, isolated, its frozen copy made;
//  2. rollback-exported: the reverse bundle from the frozen copy, the
//     transformed copy kept for the checks;
//  3. rollback-imported: the TypeScript release rebuilt on a fresh
//     database (ReverseSource: a new Postgres and Convex volume, its
//     `admin migration import`, which lifts the migrated-out marker, Convex
//     reset);
//  4. rollback-checked: the reverse checks, the release's own export of
//     the rebuilt database held against the kept copy (CHECKS.md, "The
//     reverse checks");
//  5. rollback-transfer: the address moved back (Go stops serving it, the
//     TypeScript release starts; in Coolify the operator moves the domain);
//     once the public URL answers from the TypeScript release,
//  6. rolled-back: Go's journal says so, and its varlatchd never starts on
//     that data directory again; the report lists the Go archives made
//     since the switch, which the TypeScript release cannot read.
//
// Until the address moves (phases 1 to 4) an interruption, a failed check
// or --abort undoes the reverse: the TypeScript side as the forward
// migration left it (its fresh volumes removed, its marker made again),
// Go's journal open again and its barrier lifted. Go runs throughout. In
// the transfer, --resume checks the public URL again, and --abort gives
// the address back to Go first. Rolled back goes forward only.

// RollbackWindow is decision 17's: a reverse migration within 30 days of
// the switch.
const RollbackWindow = 30 * 24 * time.Hour

// reverseSides are the sides' reverse halves.
func (e *Engine) reverseSides() (ReverseSource, ReverseTarget, error) {
	rs, ok := e.Source.(ReverseSource)
	if !ok {
		return nil, nil, errors.New("this source cannot be rebuilt by a reverse migration")
	}
	rt, ok := e.Target.(ReverseTarget)
	if !ok {
		return nil, nil, errors.New("this target cannot be reversed")
	}
	return rs, rt, nil
}

// switchedAt is when the migration switched (its history's step).
func switchedAt(j *Journal) (time.Time, bool) {
	for _, s := range j.History {
		if s.Phase == Switched {
			t, err := time.Parse(time.RFC3339Nano, s.At)
			return t, err == nil
		}
	}
	return time.Time{}, false
}

// Rollback is `varlatch migrate --rollback`: an open migration reversed,
// within the window.
func (e *Engine) Rollback(ctx context.Context) (*Journal, error) {
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
		return nil, fmt.Errorf("%s holds no migration journal: there is nothing to roll back", e.Source.Dir())
	case j.Phase == RolledBack:
		return j, nil
	case slices.Contains(reverseHeld, j.Phase) || j.Phase == RollbackTransfer:
		return j, fmt.Errorf("the reverse of the migration %s was interrupted in phase %s: varlatch migrate --resume continues or undoes it (varlatch migrate --status)", j.ID, j.Phase)
	case j.Phase == Finished:
		return j, fmt.Errorf("the migration %s is finished: varlatch migrate --finish ended its rollback window, so no reverse starts from it", j.ID)
	case j.Phase != Open:
		return j, fmt.Errorf("the migration %s is in phase %s: --rollback reverses an open migration only", j.ID, j.Phase)
	}
	if _, _, err := e.reverseSides(); err != nil {
		return j, err
	}
	at, ok := switchedAt(j)
	if !ok {
		return j, fmt.Errorf("the migration %s's journal records no switch", j.ID)
	}
	if e.now().Sub(at) > RollbackWindow {
		return j, fmt.Errorf("the migration %s switched at %s, more than %d days ago: the rollback window is over (go-step7 decision 17)", j.ID, at.Format(time.RFC3339), int(RollbackWindow.Hours()/24))
	}
	_, st, err := e.Target.Describe(ctx)
	if err != nil {
		return j, err
	}
	if st.Journal == nil || st.Journal.ID != j.ID || st.Journal.Phase != Open {
		return j, fmt.Errorf("the target's journal says %v, not the migration %s open: nothing was done", st.Journal, j.ID)
	}
	if w := st.Journal.WindowEnded; w != nil {
		return j, fmt.Errorf("the migration %s's rollback window ended when varlatchd %s was installed (%s, varlatch upgrade): that release's data does not go back to the TypeScript release; nothing was done", j.ID, w.Release, w.At)
	}
	if !st.Running {
		return j, errors.New("the Go installation does not run: a reverse migration starts from the installation that serves (start it; it stays running until the address moves)")
	}
	// What a killed run left on this host (the bundles in the
	// installation's backups directory, the export's directories), under
	// the lock.
	if err := e.Source.CleanLeftovers(); err != nil {
		return j, fmt.Errorf("removing what an interrupted run left: %w", err)
	}
	e.cleanReverseScratch()
	j.Rollback = &RollbackRecord{StartedAt: e.now().UTC().Format(time.RFC3339Nano)}
	if err := e.enter(ctx, j, Rollback); err != nil {
		return j, err
	}
	return j, e.reverse(ctx, j)
}

// reverse runs phases 1 to 4, then the transfer.
func (e *Engine) reverse(ctx context.Context, j *Journal) error {
	rs, rt, err := e.reverseSides()
	if err != nil {
		return err
	}
	e.say("Barrier: Go stops taking requests and drains (at most %s); it keeps running, isolated.", e.drain())
	b, err := rt.Barrier(ctx, j.ID, e.drain())
	if err != nil {
		return e.undoReverse(ctx, j, fmt.Errorf("Go's barrier: %w", err))
	}
	j.Rollback.Barrier = &b
	if err := e.save(ctx, j); err != nil {
		return e.undoReverse(ctx, j, err)
	}
	crashPoint("rollback barrier held")

	dir, err := e.scratchDir()
	if err != nil {
		return e.undoReverse(ctx, j, err)
	}
	defer os.RemoveAll(dir)
	out, keep := filepath.Join(dir, "reverse.jsonl"), filepath.Join(dir, "keep")
	e.say("Reverse export: Go's frozen copy, transformed, written as the reverse bundle.")
	cp, err := rt.ExportReverse(ctx, out, keep)
	if err != nil {
		return e.undoReverse(ctx, j, fmt.Errorf("the reverse export: %w", err))
	}
	j.Rollback.Export = &cp
	if err := e.enter(ctx, j, RollbackExported); err != nil {
		return e.undoReverse(ctx, j, err)
	}

	plan, err := rs.RebuildPlan(ctx, j)
	if err != nil {
		return e.undoReverse(ctx, j, err)
	}
	// Journalled before anything of it is made.
	j.Rollback.Rebuild = &plan
	if err := e.save(ctx, j); err != nil {
		return e.undoReverse(ctx, j, err)
	}
	e.say("The TypeScript release on a fresh database: new volumes %v (the old ones kept as they are).", plan.Volumes)
	if err := rs.Rebuild(ctx, plan); err != nil {
		return e.undoReverse(ctx, j, fmt.Errorf("the fresh database: %w", err))
	}
	crashPoint("rollback rebuilt")
	imp, err := rs.ImportReverse(ctx, out)
	if err != nil {
		return e.undoReverse(ctx, j, fmt.Errorf("the import: %w", err))
	}
	j.Rollback.Import = &imp
	if imp.InstallationID != cp.InstallationID {
		return e.undoReverse(ctx, j, fmt.Errorf("the import rebuilt the installation %s, not %s", imp.InstallationID, cp.InstallationID))
	}
	if err := rs.ResetConvex(ctx); err != nil {
		return e.undoReverse(ctx, j, fmt.Errorf("the Convex reset: %w", err))
	}
	if err := e.enter(ctx, j, RollbackImported); err != nil {
		return e.undoReverse(ctx, j, err)
	}

	e.say("Reverse checks: the TypeScript release's export of the rebuilt database, held against Go's transformed copy.")
	runKey, err := newRunKey()
	if err != nil {
		return e.undoReverse(ctx, j, err)
	}
	defer clear(runKey)
	exported, err := rs.ExportForCheck(ctx, runKey)
	if err != nil {
		return e.undoReverse(ctx, j, fmt.Errorf("the TypeScript release's export: %w", err))
	}
	defer os.Remove(exported)
	staged, err := e.stage(exported, dir)
	if err != nil {
		return e.undoReverse(ctx, j, err)
	}
	checks, err := rt.CheckReverse(ctx, staged, keep, runKey)
	if err != nil {
		return e.undoReverse(ctx, j, fmt.Errorf("the reverse checks: %w", err))
	}
	j.Rollback.Checks = &checks
	if !checks.Passed {
		return e.undoReverse(ctx, j, fmt.Errorf("the reverse checks failed: %v", checks.Faults))
	}
	if err := e.enter(ctx, j, RollbackChecked); err != nil {
		return e.undoReverse(ctx, j, err)
	}
	return e.reverseTransfer(ctx, j)
}

// reverseTransfer moves the address back: Go stops serving it (public and
// own-proxy ingress: its listener frees the address; an image's service is
// the operator's to stop), the TypeScript release starts and its ingress
// with it; in the Coolify shape the operator moves the domain back first,
// Go stopping once it answers from the TypeScript release. A public URL
// that does not answer gives the address back to Go (undone), but in
// Coolify's shape, which waits for the operator.
func (e *Engine) reverseTransfer(ctx context.Context, j *Journal) error {
	rs, _, err := e.reverseSides()
	if err != nil {
		return err
	}
	if j.Phase != RollbackTransfer {
		if err := e.enter(ctx, j, RollbackTransfer); err != nil {
			return e.undoReverse(ctx, j, err)
		}
	}
	kind := j.Ingress
	stopGo := func(then string) (bool, error) {
		if j.Rollback.GoStopped {
			return true, nil
		}
		if err := e.Target.Stop(ctx); err != nil {
			var human *HumanStep
			if errors.As(err, &human) {
				j.Rollback.Asked = true
				if serr := e.save(ctx, j); serr != nil {
					return false, serr
				}
				e.say("Address back, by hand: %s %s", human.Instruction, then)
				return false, ErrAwaitingOperator
			}
			return false, e.undoReverse(ctx, j, fmt.Errorf("stopping Go: %w", err))
		}
		j.Rollback.GoStopped = true
		return true, e.save(ctx, j)
	}
	if kind != Coolify {
		e.say("Address back: Go stops serving %s; the TypeScript release starts on it.", originOf(j))
		if ok, err := stopGo("Then varlatch migrate --resume starts the TypeScript release on the address; or --abort undoes the reverse."); !ok || err != nil {
			return err
		}
		crashPoint("rollback go stopped")
	}
	if err := rs.StartServing(ctx, kind); err != nil {
		return e.undoReverse(ctx, j, fmt.Errorf("starting the TypeScript release: %w", err))
	}
	crashPoint("rollback transfer started")
	if kind == Coolify && !j.Rollback.Asked {
		j.Rollback.Asked = true
		if err := e.save(ctx, j); err != nil {
			return err
		}
		e.say("Address back, by hand: in Coolify, move the domain of %s from the Go application back to the TypeScript one (its domain setting), "+
			"and redeploy the proxy if Coolify asks. Then varlatch migrate --resume checks it answers from the TypeScript release; "+
			"or varlatch migrate --abort undoes the reverse (move the domain back to Go first).", originOf(j))
		return ErrAwaitingOperator
	}
	if err := e.waitForSource(ctx, j); err != nil {
		if kind == Coolify {
			return fmt.Errorf("%w; once the domain is moved, varlatch migrate --resume checks again; varlatch migrate --abort undoes (move the domain back to Go first)", err)
		}
		return e.undoReverse(ctx, j, err)
	}
	j.Rollback.VerifiedAt = e.now().UTC().Format(time.RFC3339Nano)
	if err := e.save(ctx, j); err != nil {
		return err
	}
	if kind == Coolify {
		if ok, err := stopGo("Then varlatch migrate --resume finishes the reverse."); !ok || err != nil {
			return err
		}
	}
	return e.rolledBack(ctx, j)
}

func originOf(j *Journal) string {
	if j.Transfer != nil && j.Transfer.Origin != "" {
		return j.Transfer.Origin
	}
	return "the installation's address"
}

// waitForSource probes the public URL until it answers with the
// installation's id and the TypeScript release's version.
func (e *Engine) waitForSource(ctx context.Context, j *Journal) error {
	timeout := e.Options.TransferTimeout
	if timeout <= 0 {
		timeout = DefaultTransferTimeout
	}
	every := e.Options.ProbeEvery
	if every <= 0 {
		every = 2 * time.Second
	}
	sleep := e.sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	want := ""
	if j.Rollback.Export != nil {
		want = j.Rollback.Export.InstallationID
	}
	deadline := e.now().Add(timeout)
	var last error
	for {
		id, version, err := e.Prober.Probe(ctx, originOf(j))
		switch {
		case err != nil:
			last = err
		case id != want:
			last = fmt.Errorf("it answers as the installation %s, not %s", orNone(id), want)
		case version != j.Source.Release:
			last = fmt.Errorf("it answers with release %s, not the TypeScript release %s", orNone(version), j.Source.Release)
		default:
			e.say("The public URL %s answers from the TypeScript release (installation %s, release %s).", originOf(j), id, version)
			return nil
		}
		if !e.now().Before(deadline) {
			return fmt.Errorf("the public URL %s did not answer from the TypeScript release within %s: %v", originOf(j), timeout, last)
		}
		sleep(every)
	}
}

// rolledBack finishes the reverse: Go's archives since the switch listed
// (never deleted), both journals rolled back (Go's written with Go
// stopped: its varlatchd never starts there again).
func (e *Engine) rolledBack(ctx context.Context, j *Journal) error {
	_, rt, err := e.reverseSides()
	if err != nil {
		return err
	}
	if at, ok := switchedAt(j); ok {
		archives, err := rt.Archives(ctx)
		if err != nil {
			e.say("Go's archives could not be listed (%v): list them with varlatchd admin backup status before varlatch migrate --finish.", err)
		}
		j.Rollback.Archives = nil
		for _, a := range archives {
			if t, err := time.Parse(time.RFC3339Nano, a.CreatedAt); err == nil && !t.Before(at) {
				j.Rollback.Archives = append(j.Rollback.Archives, a)
			}
		}
	}
	j.Rollback.DoneAt = e.now().UTC().Format(time.RFC3339Nano)
	if err := e.enter(ctx, j, RolledBack); err != nil {
		return fmt.Errorf("the TypeScript release serves, but a journal could not say rolled back: %w; varlatch migrate --resume finishes it", err)
	}
	_ = e.Source.CleanLeftovers()
	e.cleanReverseScratch()
	e.say("Rolled back: the TypeScript release serves %s again, on a fresh database rebuilt from Go's. The volumes it ran on before the migration are kept until varlatch migrate --finish --delete-old-data.", originOf(j))
	e.say("Go's copy stays in %s, stopped, behind the reverse's barrier (its paused gate, and its frozen copy %s): varlatch migrate --finish --delete-old-data archives it, lifts the barrier (removing the frozen copy) and discards it; a plain --finish keeps it.",
		j.Target.DataDir, ".migration-frozen-"+j.ID+".db")
	if n := len(j.Rollback.Archives); n > 0 {
		e.say("%d Go archives were made since the switch; the TypeScript release cannot read them, so they restore through a Go varlatchd (setup --restore) or a later forward migration's installation only. migrate deletes none of them; their uploaded copies stay at Go's backup destination, and the local files follow Go's backup_keep (a later backup run, --finish --delete-old-data's final archive included, may remove the oldest):", n)
		for _, a := range j.Rollback.Archives {
			e.say("  %s (release %s, %s)", a.ArchiveID, a.Release, a.CreatedAt)
		}
	}
	return nil
}

// undoReverse undoes a reverse not yet rolled back: the address given back
// to Go (when the transfer began), the TypeScript side as the forward
// migration left it, Go's journal open again (beside it) and then its
// barrier lifted, the source's journal open. Go runs throughout but in
// the transfer, where it is started again (the operator's step for an
// image's service).
func (e *Engine) undoReverse(ctx context.Context, j *Journal, cause error) error {
	rs, rt, err := e.reverseSides()
	if err != nil {
		return errors.Join(cause, err)
	}
	from := j.Phase
	e.say("Undoing the reverse: %v.", cause)
	if !j.Rollback.Undoing {
		j.Rollback.Undoing = true
		if err := e.save(ctx, j); err != nil {
			return fmt.Errorf("%w; undoing could not start: %v", cause, err)
		}
	}
	var problems []error
	if from == RollbackTransfer {
		if err := rs.StopServing(ctx, j.Ingress); err != nil {
			problems = append(problems, fmt.Errorf("stopping the TypeScript release: %w", err))
		}
		if j.Ingress == Coolify {
			e.say("The address goes back by hand: in Coolify, move the domain of %s back to the Go application.", originOf(j))
		}
		if err := e.Target.Start(ctx); err != nil {
			var human *HumanStep
			if errors.As(err, &human) {
				e.say("To undo, by hand: %s Then run varlatch migrate --abort (or --resume) again.", human.Instruction)
			}
			problems = append(problems, fmt.Errorf("starting Go again: %w", err))
		} else {
			j.Rollback.GoStopped = false
		}
	}
	if j.Rollback.Rebuild != nil {
		if err := rs.UndoRebuild(ctx, *j.Rollback.Rebuild); err != nil {
			problems = append(problems, fmt.Errorf("putting the TypeScript installation back: %w", err))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w; undoing did not finish (%v): varlatch migrate --resume tries again", cause, errors.Join(problems...))
	}
	_ = e.Source.CleanLeftovers()
	e.cleanReverseScratch()
	// Released is journalled once the barrier is lifted, never before.
	j.Rollback.Undone = &UndoneRecord{From: from, Why: cause.Error(), At: e.now().UTC().Format(time.RFC3339Nano)}
	j.Rollback.Undoing = false
	// Go's journal open first (beside the running varlatchd), then its
	// barrier lifted: an interruption between leaves Go open behind its
	// barrier, which --resume lifts (finishOpen).
	if err := e.enter(ctx, j, Open); err != nil {
		return fmt.Errorf("%w; the TypeScript side is back as it was, but a journal could not say open: %v; varlatch migrate --resume finishes it", cause, err)
	}
	crashPoint("rollback undone open")
	if err := rt.ReleaseBarrier(ctx, j.ID); err != nil {
		return fmt.Errorf("%w; the reverse was undone, but Go's barrier could not be lifted: %v; varlatch migrate --resume lifts it", cause, err)
	}
	crashPoint("rollback undone released")
	// The source's journal only: it is where the record is read, and Go's
	// says open already (rewriting it open beside its running varlatchd
	// is refused, rightly: open changes the gate).
	j.Rollback.Undone.Released = true
	if err := writeJournal(e.Source.Dir(), j); err != nil {
		return fmt.Errorf("%w; the reverse was undone and Go's barrier lifted, but the journal could not record it: %v; varlatch migrate --resume records it", cause, err)
	}
	return fmt.Errorf("%w; the reverse was undone: Go serves again, the TypeScript installation is as the migration left it", cause)
}

// cleanReverseScratch removes the reverse's staged files a killed run
// left: the export's directory (the dry run's names) in this host's work
// directory, or its stage directories.
func (e *Engine) cleanReverseScratch() {
	_ = cleanScratch(e.work())
	if e.Options.Stage != nil && e.Options.StageBase != "" {
		for _, re := range []*regexp.Regexp{leftoverStage} {
			_ = removeMatchingExcept(e.Options.StageBase, re, true, e.Options.StageKeep)
		}
	}
}

// resumeReverse is --resume of a reverse: undone before its transfer,
// continued in it, finished once rolled back.
func (e *Engine) resumeReverse(ctx context.Context, j *Journal) error {
	switch {
	case j.Rollback == nil:
		return fmt.Errorf("the migration %s is in phase %s, but its journal records no reverse", j.ID, j.Phase)
	case j.Rollback.Undoing:
		e.say("The reverse of the migration %s was being undone: undoing goes on.", j.ID)
		return e.undoReverse(ctx, j, errors.New("undoing resumed"))
	case slices.Contains(reverseHeld, j.Phase):
		e.say("The reverse of the migration %s was interrupted in phase %s: it is undone, and Go serves again.", j.ID, j.Phase)
		e.cleanReverseScratch()
		return e.undoReverse(ctx, j, fmt.Errorf("interrupted in phase %s", j.Phase))
	case j.Phase == RollbackTransfer:
		e.say("The reverse of the migration %s is moving its address back: the public URL is checked again.", j.ID)
		return e.reverseTransfer(ctx, j)
	case j.Phase == RolledBack:
		return e.finishRolledBack(ctx, j)
	}
	return nil
}

// finishRolledBack finishes a reverse the source's journal records: Go
// stopped and its journal rolled back. Done already, it changes nothing.
func (e *Engine) finishRolledBack(ctx context.Context, j *Journal) error {
	_, st, err := e.Target.Describe(ctx)
	if err != nil {
		return err
	}
	if st.Journal != nil && st.Journal.ID == j.ID && st.Journal.Phase == RolledBack && !st.Running {
		_ = e.Source.CleanLeftovers()
		e.cleanReverseScratch()
		return nil
	}
	if st.Running {
		if err := e.Target.Stop(ctx); err != nil {
			return e.waitForHuman(err, "Then run varlatch migrate --resume again.")
		}
	}
	if err := e.Target.WriteJournal(ctx, j); err != nil {
		return err
	}
	_ = e.Source.CleanLeftovers()
	e.cleanReverseScratch()
	return nil
}
