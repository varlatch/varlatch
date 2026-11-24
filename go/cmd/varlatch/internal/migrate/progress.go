// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailhandoff"
)

// Progress lines (Options.Progress): what an undo, a rollback or a wait is
// doing, one line as a step starts and one as it ends, and one every
// progressEvery while it lasts, so that a run that takes minutes is told
// from one that hangs. A nil Progress says none and starts nothing.
//
// They are a help, never a condition: neither Progress nor Say may wait for
// its reader (Lines).

// progressEvery is how often a step that goes on is said again.
const progressEvery = 15 * time.Second

// progress is the steps a run is in, the innermost last, and the lock its
// lines are said under: a step's ticks come from a goroutine of their own.
type progress struct {
	mu    sync.Mutex
	steps []*stepRun
}

type stepRun struct {
	what  string
	since time.Time
}

func (e *Engine) progressLine(format string, args ...any) {
	e.Options.Progress(fmt.Sprintf(format, args...))
}

// step runs f as the step what (a phrase that follows a colon, holding no
// secret): said as it starts, every progressEvery while it lasts, and as it
// ends. Of steps within each other only the innermost is said to go on.
func (e *Engine) step(what string, f func() error) (err error) {
	if e.Options.Progress == nil {
		return f()
	}
	s := &stepRun{what: what, since: e.now()}
	e.prog.mu.Lock()
	e.prog.steps = append(e.prog.steps, s)
	e.progressLine("Step: %s.", what)
	e.prog.mu.Unlock()

	ticks, stop := e.progressTicks()
	end, ended := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(ended)
		for {
			select {
			case <-end:
				return
			case <-ticks:
				e.stepGoesOn(s)
			}
		}
	}()
	returned := false
	defer func() {
		stop()
		close(end)
		<-ended
		e.prog.mu.Lock()
		defer e.prog.mu.Unlock()
		e.prog.steps = e.prog.steps[:len(e.prog.steps)-1]
		took := elapsed(e.now().Sub(s.since))
		var human *HumanStep
		switch {
		case !returned: // a panic says itself
		case err == nil:
			e.progressLine("Done in %s: %s.", took, what)
		case errors.As(err, &human), errors.Is(err, ErrAwaitingOperator):
			e.progressLine("Left to you after %s: %s.", took, what)
		default:
			// Why is in what the command says as it ends.
			e.progressLine("Failed after %s: %s.", took, what)
		}
	}()
	err = f()
	returned = true
	return err
}

func (e *Engine) stepGoesOn(s *stepRun) {
	e.prog.mu.Lock()
	defer e.prog.mu.Unlock()
	if n := len(e.prog.steps); n > 0 && e.prog.steps[n-1] == s {
		e.progressLine("Still going after %s: %s.", elapsed(e.now().Sub(s.since)), s.what)
	}
}

// elapsed is d in whole seconds.
func elapsed(d time.Duration) string { return d.Round(time.Second).String() }

// progressTicks is a tick every progressEvery (the tests' own, ticks).
func (e *Engine) progressTicks() (<-chan time.Time, func()) {
	if e.ticks != nil {
		return e.ticks(progressEvery)
	}
	t := time.NewTicker(progressEvery)
	return t.C, t.Stop
}

// awaiting is the wait for the public URL to answer from who, as a step.
func (e *Engine) awaiting(j *Journal, who string) string {
	timeout := e.Options.TransferTimeout
	if timeout <= 0 {
		timeout = DefaultTransferTimeout
	}
	return fmt.Sprintf("waiting for %s to answer from %s (about %s at most)", originOf(j), who, timeout)
}

// stepChecked is step for checks, which end without an error when they do
// not pass: not a step that is done.
func (e *Engine) stepChecked(what string, f func() (CheckSummary, error)) (sum CheckSummary, err error) {
	_ = e.step(what, func() error {
		if sum, err = f(); err == nil && !sum.Passed {
			return errors.New("the checks did not pass")
		}
		return err
	})
	return sum, err
}

// nameMoved is whether unwindTailnet has anything to give back: a handoff
// that is only prepared, or undone, moved nothing.
func nameMoved(j *Journal) bool {
	return j.Tailnet != nil && j.Tailnet.Handoff != nil && j.Tailnet.Handoff.Phase != tailhandoff.Prepared && j.Tailnet.Handoff.Phase != tailhandoff.Undone
}

// stepIf is step when there is something to do, f alone otherwise.
func (e *Engine) stepIf(something bool, what string, f func() error) error {
	if !something {
		return f()
	}
	return e.step(what, f)
}

// stepAll is step for an f that answers with every problem it met.
func (e *Engine) stepAll(what string, f func() []error) (problems []error) {
	_ = e.step(what, func() error {
		problems = f()
		return errors.Join(problems...)
	})
	return problems
}

// stepOf is step for an f that answers with a value too.
func stepOf[T any](e *Engine, what string, f func() (T, error)) (v T, err error) {
	err = e.step(what, func() error {
		v, err = f()
		return err
	})
	return v, err
}

// moveName is one of a handoff's acts (Switch, Resume) as a step: the
// control plane's renames, the nodes' stops and starts, the certificate,
// each bounded within the handoff.
func (e *Engine) moveName(ctx context.Context, act func(context.Context, string) (*tailhandoff.State, error), op string) (*tailhandoff.State, error) {
	return stepOf(e, "the tailnet name moves between the two nodes", func() (*tailhandoff.State, error) { return act(ctx, op) })
}

// steppedSource and steppedTarget are the reverse's two sides with each act
// that can take a while a step (reverseSides). What they embed does
// everything else.
type steppedSource struct {
	ReverseSource
	e *Engine
}

type steppedTarget struct {
	ReverseTarget
	e *Engine
}

func (s steppedSource) MakeVolumes(ctx context.Context, plan RebuildRecord) ([]VolumeRecord, error) {
	return stepOf(s.e, "making the fresh volumes", func() ([]VolumeRecord, error) { return s.ReverseSource.MakeVolumes(ctx, plan) })
}

func (s steppedSource) Rebuild(ctx context.Context, plan RebuildRecord) error {
	return s.e.step("starting Postgres on its fresh volume", func() error { return s.ReverseSource.Rebuild(ctx, plan) })
}

func (s steppedSource) ImportReverse(ctx context.Context, bundle string) (TSImportRecord, error) {
	return stepOf(s.e, "importing the reverse bundle", func() (TSImportRecord, error) { return s.ReverseSource.ImportReverse(ctx, bundle) })
}

func (s steppedSource) ResetConvex(ctx context.Context) error {
	return s.e.step("starting Convex on its fresh volume and deploying its functions", func() error { return s.ReverseSource.ResetConvex(ctx) })
}

func (s steppedSource) ExportForCheck(ctx context.Context, runKey []byte) (string, error) {
	return stepOf(s.e, "exporting the rebuilt database for the checks", func() (string, error) { return s.ReverseSource.ExportForCheck(ctx, runKey) })
}

func (s steppedSource) StartServing(ctx context.Context, kind Ingress) error {
	return s.e.step("starting the TypeScript release", func() error { return s.ReverseSource.StartServing(ctx, kind) })
}

func (s steppedSource) StopServing(ctx context.Context, kind Ingress) error {
	return s.e.step("stopping the TypeScript release", func() error { return s.ReverseSource.StopServing(ctx, kind) })
}

func (s steppedSource) UndoRebuild(ctx context.Context, plan RebuildRecord, gate GateRef, start bool) error {
	return s.e.step("putting the TypeScript installation back on its own volumes", func() error { return s.ReverseSource.UndoRebuild(ctx, plan, gate, start) })
}

func (s steppedSource) HoldGate(ctx context.Context, g GateRef, position string) (GateRef, error) {
	return stepOf(s.e, "having the TypeScript installation's gate stand", func() (GateRef, error) { return s.ReverseSource.HoldGate(ctx, g, position) })
}

func (s steppedSource) CheckHeld(ctx context.Context, g GateRef) error {
	return s.e.step("checking that the TypeScript installation is held behind its gate", func() error { return s.ReverseSource.CheckHeld(ctx, g) })
}

func (s steppedSource) StopFront(ctx context.Context, kind Ingress) error {
	return s.e.step("stopping what serves the TypeScript release's address", func() error { return s.ReverseSource.StopFront(ctx, kind) })
}

func (s steppedSource) CheckGate(ctx context.Context, g GateRef) error {
	return s.e.step("reading the TypeScript installation's gate", func() error { return s.ReverseSource.CheckGate(ctx, g) })
}

func (s steppedSource) ServeGated(ctx context.Context, start GatedStart) error {
	return s.e.step("starting the TypeScript installation behind its migrated-out gate", func() error { return s.ReverseSource.ServeGated(ctx, start) })
}

func (s steppedSource) StopStarted(ctx context.Context, services []string) error {
	return s.e.step("stopping what the route's check started", func() error { return s.ReverseSource.StopStarted(ctx, services) })
}

func (s steppedSource) EnsureImages(ctx context.Context, j *Journal) error {
	return s.e.step("having the images the rollback starts on this host", func() error { return s.ReverseSource.EnsureImages(ctx, j) })
}

func (s steppedSource) StartNetworkOwner(ctx context.Context) error {
	return s.e.step("starting the TypeScript release's tailnet sidecar", func() error { return s.ReverseSource.StartNetworkOwner(ctx) })
}

func (s steppedSource) StopServers(ctx context.Context) error {
	return s.e.step("stopping the TypeScript installation's server", func() error { return s.ReverseSource.StopServers(ctx) })
}

func (t steppedTarget) Barrier(ctx context.Context, id string, drain time.Duration) (BarrierRecord, error) {
	return stepOf(t.e, "Go's barrier", func() (BarrierRecord, error) { return t.ReverseTarget.Barrier(ctx, id, drain) })
}

func (t steppedTarget) ReleaseBarrier(ctx context.Context, id string) error {
	return t.e.step("lifting Go's barrier", func() error { return t.ReverseTarget.ReleaseBarrier(ctx, id) })
}

func (t steppedTarget) ExportReverse(ctx context.Context, out, keep string) (CopyRecord, error) {
	return stepOf(t.e, "writing the reverse bundle", func() (CopyRecord, error) { return t.ReverseTarget.ExportReverse(ctx, out, keep) })
}

func (t steppedTarget) CheckReverse(ctx context.Context, bundle, keep string, runKey []byte) (CheckSummary, error) {
	return t.e.stepChecked("the reverse checks", func() (CheckSummary, error) { return t.ReverseTarget.CheckReverse(ctx, bundle, keep, runKey) })
}
