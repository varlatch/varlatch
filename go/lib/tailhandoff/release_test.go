// SPDX-License-Identifier: Apache-2.0

package tailhandoff_test

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailhandoff"
)

// waits records the names the engine waited for (Engine.Waiting).
type waits struct {
	mu    sync.Mutex
	names []string
}

func (w *waits) add(name string) { w.mu.Lock(); w.names = append(w.names, name); w.mu.Unlock() }
func (w *waits) list() []string  { w.mu.Lock(); defer w.mu.Unlock(); return slices.Clone(w.names) }

// Tailscale keeps a name a rename freed for a moment (2026-11-26): the
// incoming node's rename to it, back to back with the serving node's, reads
// back suffixed (-1). The handoff renames again until it reads back, and
// the rollback's reverse handoff does the same.
func TestTheHandoffWaitsForTheNameToBeReleased(t *testing.T) {
	r := newRig(t)
	w := &waits{}
	r.engine.Waiting = w.add
	r.f.SetReleaseRenames(2)
	if _, err := r.engine.Prepare(ctx, r.forward(t)); err != nil {
		t.Fatal(err)
	}
	s, err := r.engine.Switch(ctx, op)
	if err != nil || s.Phase != tailhandoff.Done {
		t.Fatalf("%+v, %v", s, err)
	}
	if n := r.names(); n["1"] != "vault-vl-"+op+"-o" || n["2"] != "vault" {
		t.Fatalf("names %v", n)
	}
	if got := w.list(); !slices.Equal(got, []string{"vault"}) || r.f.Deduped != 2 {
		t.Fatalf("waited for %v, deduped %d", got, r.f.Deduped)
	}

	const rop = "rrrrrrrr25"
	rev := tailhandoff.NewReverse(rop, "vault", "2", "1", "vault-vl-"+op+"-o", true)
	r.c.set(tailhandoff.Incoming, "vault", time.Now().Add(40*24*time.Hour))
	r.ep.servingOpen, r.ep.incomingOpen = true, false
	if _, err := r.engine.Prepare(ctx, rev); err != nil {
		t.Fatal(err)
	}
	s, err = r.engine.Switch(ctx, rop)
	if err != nil || s.Phase != tailhandoff.Done {
		t.Fatalf("reverse: %+v, %v", s, err)
	}
	if n := r.names(); n["1"] != "vault" || n["2"] != "vault-vl-"+rop+"-n" {
		t.Fatalf("names after reverse %v", n)
	}
	if got := w.list(); !slices.Equal(got, []string{"vault", "vault"}) {
		t.Fatalf("waited for %v", got)
	}
}

// The undo gives the serving node its name back through the same wait: the
// name the incoming node let go of a moment ago reads back suffixed first.
func TestTheUndoWaitsForTheNameToBeReleased(t *testing.T) {
	r := newRig(t)
	w := &waits{}
	r.engine.Waiting = w.add
	r.f.SetReleaseRenames(1)
	if _, err := r.engine.Prepare(ctx, r.forward(t)); err != nil {
		t.Fatal(err)
	}
	r.ep.openErr = errors.New("port in use")
	s, err := r.engine.Switch(ctx, op)
	assertUndone(t, r, s, err)
	if !strings.Contains(err.Error(), "port in use") {
		t.Errorf("%v", err)
	}
	// The forward's rename to the name, the incoming node's back to its
	// own (it let go of it too), and the serving node's back to the name.
	if got := w.list(); !slices.Equal(got, []string{"vault", "vault-vl-" + op + "-n", "vault"}) || r.f.Deduped != 3 {
		t.Errorf("waited for %v, deduped %d", got, r.f.Deduped)
	}
}

// A name the control plane does not release within the budget fails as
// before the wait: the undo cannot give it back either, both installations
// stay closed, and Resume finishes the undo once the name is released.
func TestANameNotReleasedInTheBudgetFailsCleanly(t *testing.T) {
	r := newRig(t)
	r.f.SetReleaseRenames(1 << 30)
	if _, err := r.engine.Prepare(ctx, r.forward(t)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	s, err := r.engine.Switch(ctx, op)
	var he *tailhandoff.HandoffError
	if !errors.As(err, &he) || he.Phase != tailhandoff.UndoPending || s.Phase != tailhandoff.UndoPending {
		t.Fatalf("%+v, %v", s, err)
	}
	if !strings.Contains(err.Error(), `"vault-1", not "vault"`) {
		t.Errorf("the failure does not say the read-back: %v", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("the budget's failure took %s", took)
	}
	if serving, incoming := r.ep.state(); serving || incoming {
		t.Fatalf("an installation opened: serving %v, incoming %v", serving, incoming)
	}
	r.f.SetReleaseRenames(0)
	r.f.ReleaseAll()
	s, err = r.engine.Resume(ctx, op)
	assertUndone(t, r, s, err)
}
