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

	"github.com/varlatch/varlatch/go/lib/tailhandoff"
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
//     TypeScript release starts; in Coolify the operator routed the name
//     back before phase 1, routeBack, and Go stops once it answers); once
//     the public URL answers from the TypeScript release,
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

// sidecarOwned is whether the forward migration's tailnet handoff moved
// the name (done), stopping the source's sidecar at the switch: the
// sidecar is then migrate's own to start for the reverse and to stop
// again on its undo. Without a handoff, a stopped sidecar is the
// operator's to start (ReverseReady says how).
func sidecarOwned(j *Journal) bool {
	return j != nil && j.Tailnet != nil && j.Tailnet.Handoff != nil && j.Tailnet.Handoff.Phase == tailhandoff.Done
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
	if j.Rollback != nil && j.Rollback.Unrestored != "" {
		return j, fmt.Errorf("the last reverse of the migration %s was undone, but the TypeScript installation is not put back (%s): varlatch migrate --resume first; nothing was done", j.ID, j.Rollback.Unrestored)
	}
	if err := e.keepProject(ctx, j, true); err != nil {
		return j, err
	}
	rs, _, err := e.reverseSides()
	if err != nil {
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
	// Refused here, before Go's barrier and anything journalled, rather
	// than at the rebuilt database's export after the rebuild. A sidecar
	// the forward handoff stopped is migrate's own: the reverse starts it
	// (reverse), and its undo stops it again.
	if !sidecarOwned(j) {
		if err := rs.ReverseReady(ctx); err != nil {
			return j, err
		}
	}
	// What a killed run left on this host (the bundles in the
	// installation's backups directory, the export's directories), under
	// the lock.
	if err := e.Source.CleanLeftovers(); err != nil {
		return j, fmt.Errorf("removing what an interrupted run left: %w", err)
	}
	e.cleanReverseScratch()
	if j.Ingress == Coolify {
		// Its containers start again before Go's barrier (checkRoute), on the
		// database they left: behind the migration's gate only.
		if err := rs.CheckGate(ctx, sourceGate(j)); err != nil {
			return j, gateLost(j, err)
		}
	}
	// What the rebuild would stand on, told before Go's barrier (it is read
	// again after it).
	if _, err := rs.RebuildPlan(ctx, j); err != nil {
		return j, fmt.Errorf("%w; nothing was done", err)
	}
	// Its images may be gone by now (a prune, over a window of weeks).
	if err := rs.EnsureImages(ctx, j); err != nil {
		return j, fmt.Errorf("%w; nothing was done", err)
	}
	if j.Ingress == Coolify {
		if err := e.askRoute(ctx, j); err != nil {
			return j, err
		}
	}
	// Journalled before anything starts: a kill from here is undone.
	j.Rollback = &RollbackRecord{StartedAt: e.now().UTC().Format(time.RFC3339Nano)}
	if err := e.enter(ctx, j, Rollback); err != nil {
		return j, err
	}
	if j.Ingress == Coolify {
		if err := e.checkRoute(ctx, j, rs); err != nil {
			return j, e.undoReverse(ctx, j, err)
		}
		crashPoint("rollback route checked")
	}
	return j, e.reverse(ctx, j)
}

// routedSource is a source whose address the operator routes back
// (Coolify's proxy).
type routedSource interface {
	// RouteFile is the proxy's file that routes origin to the source's
	// dashboard, whatever the containers' labels say: where it goes, and
	// its text. An answer through it bears routeHeader with id.
	RouteFile(ctx context.Context, origin, id string) (path, text string, err error)
}

// askRoute and checkRoute are the Coolify shape's way back, held to work
// before Go's barrier. Coolify's domain setting changes no container until
// one is made again, and the TypeScript application's must not be: so the
// operator puts a route of their own in the proxy, above the containers'
// labels, to the TypeScript dashboard. Without it, askRoute says it and
// stops (exit 75), the migration still open. With it, checkRoute starts
// what answers behind the dashboard, and the name must reach the
// TypeScript installation, migrated out as the forward migration left it.
func (e *Engine) askRoute(ctx context.Context, j *Journal) error {
	path, text, gp, err := e.route(ctx, j)
	if err != nil {
		return fmt.Errorf("%w; nothing was done", err)
	}
	ask := func(why string) error {
		e.say("Address back, by hand, before the reverse begins (%s): do not Deploy, Restart or Stop the TypeScript application in Coolify (it would make its containers again, from its own Compose file, on the volumes from before the migration). "+
			"Put this in the proxy, as %s on the host (or in Coolify: the server's Proxy, Dynamic Configurations). It routes the name to the TypeScript dashboard, above the containers' own routers, at once; the address does not answer from Go from then on:\n%s"+
			"Then run varlatch migrate --rollback again: it starts the dashboard, and checks the name reaches the TypeScript installation, before Go's barrier. To leave it: remove the file, and Go serves the address as before.", why, path, text)
		return ErrAwaitingOperator
	}
	// With its dashboard stopped, whatever answers is not the TypeScript
	// installation, and the proxy's own error through the route bears its
	// header too.
	if err := e.Source.StopIngress(ctx, Coolify); err != nil {
		return fmt.Errorf("stopping the source's dashboard: %w; nothing was done", err)
	}
	sleep := e.sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	// An address that does not answer at all is asked again; one that
	// answers without the route's header has no route, whoever answers.
	deadline := e.now().Add(askRouteWait)
	for {
		a, err := gp.ProbeGate(ctx, originOf(j))
		switch {
		case err == nil && a.Route == j.ID:
			return nil
		case err == nil && a.Route != "":
			return ask("the address answers by another migration's route, " + a.Route)
		case err == nil:
			return ask(fmt.Sprintf("the address answers by no route of this migration: %s", a))
		case !e.now().Before(deadline):
			return fmt.Errorf("%s does not answer (%v), so whether the name is routed back is not known; nothing was done", originOf(j), err)
		}
		sleep(time.Second)
	}
}

// gateLost is a way back refused, before anything of it: the TypeScript
// installation is not behind the migration's gate.
func gateLost(j *Journal, err error) error {
	return fmt.Errorf("%w; nothing was done, and nothing was started. Go serves on. Do not start the TypeScript installation: without the migration's gate %s it takes requests, on the database it left. "+
		"If that volume was replaced or restored, put back the very one the migration left", err, sourceGate(j).ID)
}

// askRouteWait is how long askRoute waits for any answer.
const askRouteWait = 10 * time.Second

func (e *Engine) route(ctx context.Context, j *Journal) (path, text string, gp GateProber, err error) {
	rs, ok := e.Source.(routedSource)
	gp, ok2 := e.Prober.(GateProber)
	if !ok || !ok2 {
		return "", "", nil, errors.New("the address's way back to this source cannot be checked")
	}
	path, text, err = rs.RouteFile(ctx, originOf(j), j.ID)
	return path, text, gp, err
}

func (e *Engine) checkRoute(ctx context.Context, j *Journal, rs ReverseSource) error {
	path, text, gp, err := e.route(ctx, j)
	if err != nil {
		return err
	}
	e.say("The address is routed away from Go: the TypeScript dashboard starts, behind its migrated-out gate.")
	owned := sidecarOwned(j)
	if owned {
		e.say("Tailnet: the TypeScript release's sidecar starts with it (its old node, under its temporary name; the name stays with Go's node until the transfer).")
	}
	gate := sourceGate(j)
	if err := rs.ServeGated(ctx, GatedStart{Gate: gate, Owned: owned, Starting: func(svc string) error {
		if slices.Contains(j.Rollback.Started, svc) {
			return nil
		}
		j.Rollback.Started = append(j.Rollback.Started, svc)
		return e.save(ctx, j)
	}}); err != nil {
		return fmt.Errorf("starting the TypeScript installation behind its gate: %w", err)
	}
	crashPoint("rollback gated started")
	// Again, now that its containers run: nothing reaches them before this.
	if err := rs.CheckGate(ctx, gate); err != nil {
		return fmt.Errorf("the TypeScript dashboard was not started: %w", err)
	}
	// Made again, not only started: it resolves varlatchd once.
	if err := e.Source.StartIngress(ctx, Coolify, true); err != nil {
		return fmt.Errorf("starting the TypeScript dashboard: %w", err)
	}
	if err := e.waitForGate(ctx, gp, j); err != nil {
		return fmt.Errorf("%w; check %s names the dashboard's container (its text is below), then varlatch migrate --rollback again; or remove it, and Go serves the address as before:\n%s", err, path, text)
	}
	return nil
}

// waitForGate waits, at most the transfer's timeout, until the address
// answers from the TypeScript installation's migrated-out gate.
func (e *Engine) waitForGate(ctx context.Context, gp GateProber, j *Journal) error {
	timeout := e.Options.TransferTimeout
	if timeout <= 0 {
		timeout = DefaultTransferTimeout
	}
	sleep := e.sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	deadline := e.now().Add(timeout)
	for {
		a, err := gp.ProbeGate(ctx, originOf(j))
		switch {
		case err == nil && a.Route == j.ID && a.migratedOut():
			e.say("The name reaches the TypeScript installation, migrated out, by the operator's route: the way back works.")
			return nil
		case err == nil && a.Route != j.ID:
			err = fmt.Errorf("it answers by another route: %s", a)
		case err == nil:
			err = fmt.Errorf("the route answers: %s", a)
		}
		if !e.now().Before(deadline) {
			return fmt.Errorf("%s did not reach the TypeScript installation through its dashboard within %s: %v", originOf(j), timeout, err)
		}
		sleep(2 * time.Second)
	}
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
	if sidecarOwned(j) {
		// Its one-off commands run in the sidecar's network.
		e.say("Tailnet: the TypeScript release's sidecar starts again (its old node, under its temporary name; the name stays with Go's node until the transfer).")
		if err := rs.StartNetworkOwner(ctx); err != nil {
			return e.undoReverse(ctx, j, fmt.Errorf("starting the TypeScript release's tailnet sidecar: %w", err))
		}
	}
	made, err := rs.MakeVolumes(ctx, plan)
	if err != nil {
		return e.undoReverse(ctx, j, fmt.Errorf("the fresh volumes: %w", err))
	}
	crashPoint("rollback volumes made")
	plan.Made = made
	j.Rollback.Rebuild = &plan
	if err := e.save(ctx, j); err != nil {
		return e.undoReverse(ctx, j, err)
	}
	if err := rs.Rebuild(ctx, plan); err != nil {
		return e.undoReverse(ctx, j, fmt.Errorf("the fresh database: %w", err))
	}
	crashPoint("rollback rebuilt")
	// Never an import into the retained volume: refused before it, and
	// undone.
	if err := rs.CheckRebuilt(ctx, plan, false); err != nil {
		return e.undoReverse(ctx, j, fmt.Errorf("the fresh database: %w; nothing was imported", err))
	}
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
	if err := rs.CheckRebuilt(ctx, plan, true); err != nil {
		return e.undoReverse(ctx, j, fmt.Errorf("the fresh database: %w", err))
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
	// Before anything starts, stops or moves: the installation runs on the
	// fresh volumes. Before the transfer, one that does not is undone;
	// within it, nothing is done (what was written to the TypeScript
	// release since is on the fresh volumes, which an undo removes).
	if err := e.checkRebuilt(ctx, j); err != nil {
		if j.Phase != RollbackTransfer {
			return e.undoReverse(ctx, j, err)
		}
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
	if err := e.waitForSource(ctx, j); err != nil {
		if kind == Coolify {
			return fmt.Errorf("%w; the route put in the proxy before the reverse must still be there, to the TypeScript dashboard; then varlatch migrate --resume checks again (Go was not stopped), or varlatch migrate --abort undoes the reverse", err)
		}
		return e.undoReverse(ctx, j, err)
	}
	j.Rollback.VerifiedAt = e.now().UTC().Format(time.RFC3339Nano)
	if err := e.save(ctx, j); err != nil {
		return err
	}
	// What answers: an installation on the retained volumes has the same id
	// and release, so the probe alone does not tell. Before Go stops
	// (Coolify's shape), before the name moves, and before it is recorded.
	if err := e.checkRebuilt(ctx, j); err != nil {
		return err
	}
	if kind == Coolify {
		if ok, err := stopGo("Then varlatch migrate --resume finishes the reverse."); !ok || err != nil {
			return err
		}
	}
	// The tailnet name after the address (decision 12's order).
	if err := e.rollbackTailnet(ctx, j); err != nil {
		return err
	}
	if err := e.checkRebuilt(ctx, j); err != nil {
		return err
	}
	return e.rolledBack(ctx, j)
}

// checkRebuilt refuses an installation that is not on the fresh volumes
// the reverse rebuilt it on, saying how it is again.
func (e *Engine) checkRebuilt(ctx context.Context, j *Journal) error {
	rs, _, err := e.reverseSides()
	if err != nil {
		return err
	}
	if j.Rollback == nil || j.Rollback.Rebuild == nil {
		return fmt.Errorf("the migration %s's journal records no rebuild: what the TypeScript installation runs on is not known; nothing was done", j.ID)
	}
	if err := rs.CheckRebuilt(ctx, *j.Rollback.Rebuild, true); err != nil {
		if j.Phase == RollbackTransfer || j.Phase == RolledBack {
			what := "Go was not stopped"
			if j.Rollback.GoStopped {
				what = "nothing more was done (Go is stopped already)"
			}
			then := "then varlatch migrate --resume."
			if j.Phase == RollbackTransfer {
				then += " (varlatch migrate --abort undoes the reverse instead: it gives the address back to Go and removes the fresh volumes, with what was written to the TypeScript release since the address moved.)"
			}
			return fmt.Errorf("the TypeScript installation is not on the fresh volumes the reverse rebuilt it on: %w; %s; %s", err, what, then)
		}
		return fmt.Errorf("the fresh database: %w", err)
	}
	return nil
}

// tailnetReturn is the reverse's tailnet handoff (nil for none).
func tailnetReturn(j *Journal) *tailhandoff.State {
	if j.Tailnet == nil {
		return nil
	}
	return j.Tailnet.Rollback
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
	want := ""
	if j.Rollback.Export != nil {
		want = j.Rollback.Export.InstallationID
	}
	return e.waitForTypeScript(ctx, j, want)
}

// waitForTypeScript probes the public URL until it answers from the
// TypeScript release: its version, and the installation id want when one
// is known. It waits up to the transfer's timeout.
func (e *Engine) waitForTypeScript(ctx context.Context, j *Journal, want string) error {
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
	deadline := e.now().Add(timeout)
	var last error
	for {
		id, version, err := e.Prober.Probe(ctx, originOf(j))
		switch {
		case err != nil:
			last = err
		case id == "":
			// The TypeScript server omits it while its database does not
			// answer: not yet the installation serving.
			last = errors.New("it answers without an installation id")
		case want != "" && id != want:
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
	if j.Ingress == Coolify {
		e.say("By hand: 1. in Coolify, move the domain of %s back to the TypeScript application (its domain setting; Save only). 2. Remove the route put in the proxy before the reverse, and check that the address still answers: the dashboard's container routes it itself, and Go's is stopped.", originOf(j))
		e.say("Do not Deploy, Restart or Redeploy the TypeScript application in Coolify now: Coolify starts it from its own Compose file, which names the volumes it ran on before the migration, without what was written since. " +
			"Its containers may be restarted (docker restart), not made again. (Coolify's Restart of a Compose application deploys it.)")
	}
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
	// Once the name's return has opened, the TypeScript release holds the
	// name: the reverse goes forward only. Refused before anything is
	// marked, so --resume still finishes it.
	if rb := tailnetReturn(j); rb != nil && (rb.Phase == tailhandoff.Done || rb.IncomingOpened) {
		return fmt.Errorf("%w; the tailnet name is the TypeScript release's again: the reverse cannot be undone now; varlatch migrate --resume finishes it", cause)
	}
	e.say("Undoing the reverse: %v.", cause)
	if !j.Rollback.Undoing {
		j.Rollback.Undoing = true
		if err := e.save(ctx, j); err != nil {
			return fmt.Errorf("%w; undoing could not start: %v", cause, err)
		}
	}
	// Before anything of the TypeScript side is started, stopped or put back:
	// its gate, which the import lifted, stands again. From here whatever
	// starts its server (Docker, a deploy) starts it behind the gate.
	if err := e.holdSource(ctx, j, rs, func() error { return e.save(ctx, j) }); err != nil {
		// Its server stopped is the safer side, but in the transfer, where
		// the address may be its own.
		held := "nothing of it was started"
		if from != RollbackTransfer {
			if serr := rs.StopServers(ctx); serr == nil {
				held += ", and its server is stopped"
			}
			if j.Ingress == Coolify {
				_ = rs.StopFront(ctx, Coolify)
			}
		}
		return notHeld(cause, j, held, err)
	}
	crashPoint("rollback undo gate held")
	// Each step's failure counts by what it left, once everything is done.
	var problems []error
	front := from == RollbackTransfer || j.Ingress == Coolify
	if from == RollbackTransfer {
		// The tailnet name back to Go's node first, then the address.
		if err := e.unwindRollbackTailnet(ctx, j); err != nil {
			return fmt.Errorf("%w; undoing did not finish (%v): varlatch migrate --resume tries again", cause, err)
		}
		// Asked again below, when it could not.
		_ = rs.StopServing(ctx, j.Ingress)
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
	if j.Ingress == Coolify {
		// checkRoute started it: while it runs, its router names the domain
		// beside Go's.
		_ = rs.StopFront(ctx, Coolify)
		e.say("The address goes back by hand: remove the route put in the proxy before the reverse, then check that %s/v1/meta answers from Go (its container routes it itself; migrate does not check it here).", originOf(j))
	}
	unrestored := ""
	if j.Rollback.Rebuild != nil {
		if err := e.restoreSource(ctx, j, rs); err != nil {
			unrestored = fmt.Errorf("putting the TypeScript installation back: %w", err).Error()
		}
	} else if len(j.Rollback.Started) > 0 {
		// What the route's check started, and nothing else: the forward
		// migration left it stopped.
		if err := rs.StopStarted(ctx, j.Rollback.Started); err != nil {
			problems = append(problems, fmt.Errorf("stopping what the route's check started: %w", err))
		}
	}
	crashPoint("rollback undo restored")
	// The TypeScript side as the forward migration left it: the reverse
	// started its tailnet sidecar for its one-off commands and, on Coolify,
	// for the route's check; the name is Go's node's, so the old node is
	// stopped again (not logged out), its state kept for the window.
	if ts, ok := e.Source.(TailnetSource); ok && sidecarOwned(j) {
		if err := stopSidecar(ctx, ts); err != nil {
			problems = append(problems, fmt.Errorf("stopping the TypeScript release's tailnet sidecar: %w", err))
		}
	}
	// What serves its address, stopped by now, whatever an earlier step said.
	if front {
		if err := rs.StopFront(ctx, j.Ingress); err != nil {
			problems = append(problems, fmt.Errorf("stopping what serves the TypeScript release's address: %w", err))
		}
	}
	if unrestored != "" {
		// Not needed to be safe (the gate is held), and so not a condition.
		_ = rs.StopServers(ctx)
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w; undoing did not finish (%v): varlatch migrate --resume tries again", cause, errors.Join(problems...))
	}
	// Go takes requests again only while the TypeScript side cannot.
	if err := rs.CheckHeld(ctx, sourceGate(j)); err != nil {
		return notHeld(cause, j, "what could be put back is", err)
	}
	if unrestored != "" {
		// Journalled, then said, before Go opens.
		j.Rollback.Unrestored = unrestored
		if err := e.save(ctx, j); err != nil {
			return fmt.Errorf("%w; undoing could not go on: %v; varlatch migrate --resume tries again", cause, err)
		}
		e.say("The TypeScript installation is not put back (%s). It is behind its gate, and its server is stopped: do not start it, and start no containers of it (docker compose up, or Coolify's Deploy); varlatch migrate --resume puts it back. Go is opened again now: its outage does not wait for that.", unrestored)
	}
	_ = e.Source.CleanLeftovers()
	e.cleanReverseScratch()
	// Released is journalled once the barrier is lifted, never before.
	j.Rollback.Undone = &UndoneRecord{From: from, Why: cause.Error(), At: e.now().UTC().Format(time.RFC3339Nano)}
	j.Rollback.Undoing, j.Rollback.Unrestored = false, unrestored
	// Go's journal open first (beside the running varlatchd), then its
	// barrier lifted: an interruption between leaves Go open behind its
	// barrier, which --resume lifts (finishOpen).
	if err := e.enter(ctx, j, Open); err != nil {
		return fmt.Errorf("%w; the reverse was undone but for Go's barrier, which stands: a journal could not say open: %v; varlatch migrate --resume finishes it", cause, err)
	}
	crashPoint("rollback undone open")
	if err := rs.CheckHeld(ctx, sourceGate(j)); err != nil {
		return notHeld(cause, j, "Go's journal says open, its barrier stands", err)
	}
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
	if unrestored != "" {
		at := "Go serves again"
		if j.Ingress == Coolify {
			at = "Go runs and takes requests again, and the address reaches it once the route is out of the proxy"
		}
		return fmt.Errorf("%w; the reverse was undone: %s. The TypeScript installation is not put back (%s): it is behind its gate, and its server is stopped. Do not start it, and start no containers of it (docker compose up, or Coolify's Deploy): varlatch migrate --resume puts it back, and no other --rollback or --finish begins before", cause, at, unrestored)
	}
	if j.Ingress == Coolify {
		return undoneError{fmt.Errorf("%w; the reverse was undone: Go runs and takes requests again, and the address reaches it once the route is out of the proxy; the TypeScript installation is as the migration left it", cause)}
	}
	return undoneError{fmt.Errorf("%w; the reverse was undone: Go serves again, the TypeScript installation is as the migration left it", cause)}
}

// notHeld is an undo that stops: the TypeScript installation is not held
// behind its gate, so Go's barrier is not lifted.
func notHeld(cause error, j *Journal, done string, err error) error {
	barrier := "Go goes on as it was (it has no barrier)"
	if j.Rollback.Barrier != nil {
		barrier = "Go stays behind its barrier: the outage goes on, and no data is lost"
	}
	return fmt.Errorf("%w; undoing stopped: the TypeScript installation is not held behind its gate (%w); %s. %s. Do not start the TypeScript installation by any means (docker, or Coolify's Deploy, Restart or Start). "+
		"By hand: have its state volume and its varlatchd container as the migration left them (docker volume inspect, docker inspect; the message says what is not), then varlatch migrate --resume, or --abort, tries again", cause, err, done, barrier)
}

// holdSource is HoldGate, journalled.
func (e *Engine) holdSource(ctx context.Context, j *Journal, rs ReverseSource, save func() error) error {
	position := ""
	if j.Barrier != nil {
		position = j.Barrier.AuditPosition
	}
	was := sourceGate(j)
	g, err := rs.HoldGate(ctx, was, position)
	if err != nil {
		return err
	}
	if g.ID == was.ID && (g.State == nil || was.State != nil && *g.State == *was.State) {
		return nil
	}
	j.SourceGate, j.Source.State = g.ID, g.State
	return save()
}

// checkHeld is CheckHeld once Go's journal says open: an earlier build's
// journal, which records no volume, is given it first (the source's journal
// only, beside a Go that may run).
func (e *Engine) checkHeld(ctx context.Context, j *Journal, rs ReverseSource) error {
	if j.Source.State == nil {
		if err := e.holdSource(ctx, j, rs, func() error { return writeJournal(e.Source.Dir(), j) }); err != nil {
			return err
		}
	}
	return rs.CheckHeld(ctx, sourceGate(j))
}

// undoneError is an undo that is done, its cause with it.
type undoneError struct{ error }

func (e undoneError) Unwrap() error { return e.error }

// restoreSource puts the rebuilt source back, as the forward migration left
// it: its server started again, but where a sidecar that the forward handoff
// stopped has its network.
func (e *Engine) restoreSource(ctx context.Context, j *Journal, rs ReverseSource) error {
	return rs.UndoRebuild(ctx, *j.Rollback.Rebuild, sourceGate(j), !sidecarOwned(j))
}

// finishRestore puts back a source that an undone reverse could not
// (Unrestored), Go open since. It writes the source's journal only, as
// undoReverse does beside a running Go.
func (e *Engine) finishRestore(ctx context.Context, j *Journal) error {
	if j.Rollback == nil || j.Rollback.Unrestored == "" {
		return nil
	}
	if err := e.keepProject(ctx, j, true); err != nil {
		return err
	}
	rs, _, err := e.reverseSides()
	if err != nil {
		return err
	}
	e.say("The TypeScript installation, which an undone reverse left (%s), is put back.", j.Rollback.Unrestored)
	if err := e.checkHeld(ctx, j, rs); err != nil {
		return fmt.Errorf("the TypeScript installation is not held behind its gate: %w; nothing of it was started. Go serves: do not start the TypeScript installation", err)
	}
	if err := e.restoreSource(ctx, j, rs); err != nil {
		return fmt.Errorf("the TypeScript installation is still not put back: %w; Go serves; varlatch migrate --resume tries again", errors.Join(err, rs.StopServers(ctx)))
	}
	j.Rollback.Unrestored = ""
	return writeJournal(e.Source.Dir(), j)
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
	// Go is not stopped, nor written rolled back, for an installation that
	// is not on its fresh volumes (any more).
	if err := e.checkRebuilt(ctx, j); err != nil {
		return err
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
