// SPDX-License-Identifier: AGPL-3.0-or-later

package write

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
)

// A set of gates is taken in the order whatever order it is asked in, a
// repeated gate once in its strongest mode, and released in reverse.
func TestGatesOrder(t *testing.T) {
	gs := NewGates()
	var mu sync.Mutex
	var events []string
	gs.Observe(func(event string, g Gate) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event+" "+g.String())
	})
	ctx, release, err := gs.Acquire(context.Background(),
		Resource("github-app-registration", "ghr_1"), Person("idn_b", Shared), Organization("org_a", Shared),
		Person("idn_a", Shared), Person("idn_b", Exclusive), Singleton("approval-creation", "idn_a"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"1:approval-creation:idn_a(exclusive)", "2:organization:org_a(shared)", "3:person:idn_a(shared)",
		"3:person:idn_b(exclusive)", "4:github-app-registration:ghr_1(exclusive)",
	}
	var got []string
	for _, g := range Held(ctx) {
		got = append(got, g.String())
	}
	if !slices.Equal(got, want) {
		t.Errorf("held %v", got)
	}
	release()
	release() // once
	if len(events) != 10 || events[0] != "acquired "+want[0] || events[9] != "released "+want[0] || events[5] != "released "+want[4] {
		t.Errorf("events %v", events)
	}
	if len(gs.held) != 0 {
		t.Errorf("%d gates kept", len(gs.held))
	}
}

// A gate that comes before one already held is refused, and so is any
// gate taken inside a write job (the gate tracer).
func TestGatesTracer(t *testing.T) {
	gs := NewGates()
	ctx, release, err := gs.Acquire(context.Background(), Person("idn_b", Shared))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	var oe *OrderError
	for _, g := range []Gate{Organization("org_a", Shared), Person("idn_a", Shared), Person("idn_b", Shared)} {
		if _, _, err := gs.Acquire(ctx, g); !errors.As(err, &oe) || oe.InJob {
			t.Errorf("%s after idn_b: %v", g, err)
		}
	}
	// Later in the order is fine.
	_, rel2, err := gs.Acquire(ctx, Person("idn_c", Shared), Resource("audit-export", "aex_1"))
	if err != nil {
		t.Fatal(err)
	}
	rel2()

	w := newWriter(t)
	err = w.Store.Write(context.Background(), func(tx *storage.Tx) error {
		_, rel, err := gs.Acquire(context.Background(), Organization("org_a", Shared))
		if err == nil {
			rel()
		}
		return err
	})
	if !errors.As(err, &oe) || !oe.InJob {
		t.Errorf("inside a job: %v", err)
	}
}

// Shared holders run together; an exclusive taker waits for them, and while
// it waits, new shared takers wait behind it (no starvation). A waiter
// gives up with its context.
func TestGatesExclusion(t *testing.T) {
	gs := NewGates()
	bg := context.Background()
	_, r1, _ := gs.Acquire(bg, Organization("org_a", Shared))
	_, r2, _ := gs.Acquire(bg, Organization("org_a", Shared))
	got := make(chan string, 4)
	go func() {
		_, r, err := gs.Acquire(bg, Organization("org_a", Exclusive))
		if err == nil {
			got <- "exclusive"
			time.Sleep(20 * time.Millisecond)
			r()
		}
	}()
	waitFor(t, func() bool {
		gs.mu.Lock()
		defer gs.mu.Unlock()
		return gs.held[slot{LevelOrganization, "organization", "org_a"}].writersWaiting == 1
	})
	go func() {
		_, r, err := gs.Acquire(bg, Organization("org_a", Shared))
		if err == nil {
			got <- "shared"
			r()
		}
	}()
	// Another Organization's gate is independent.
	_, r3, err := gs.Acquire(bg, Organization("org_b", Exclusive))
	if err != nil {
		t.Fatal(err)
	}
	r3()
	select {
	case g := <-got:
		t.Fatalf("%s ran while shared holders remain", g)
	case <-time.After(50 * time.Millisecond):
	}
	r1()
	r2()
	if a, b := <-got, <-got; a != "exclusive" || b != "shared" {
		t.Errorf("order %s, %s", a, b)
	}
	// Cancelled while waiting: nothing is held, and the gate is free.
	_, r4, _ := gs.Acquire(bg, Person("idn_a", Exclusive))
	ctx, cancel := context.WithTimeout(bg, 20*time.Millisecond)
	defer cancel()
	if _, _, err := gs.Acquire(ctx, Person("idn_a", Shared)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("cancelled: %v", err)
	}
	r4()
	_, r5, err := gs.Acquire(bg, Person("idn_a", Exclusive))
	if err != nil {
		t.Fatal(err)
	}
	r5()
	if len(gs.held) != 0 {
		t.Errorf("%d gates kept", len(gs.held))
	}
}

// A set that cannot be taken whole holds nothing.
func TestGatesPartialRelease(t *testing.T) {
	gs := NewGates()
	bg := context.Background()
	_, hold, _ := gs.Acquire(bg, Person("idn_b", Exclusive))
	ctx, cancel := context.WithTimeout(bg, 20*time.Millisecond)
	defer cancel()
	if _, _, err := gs.Acquire(ctx, Organization("org_a", Exclusive), Person("idn_a", Exclusive), Person("idn_b", Shared)); err == nil {
		t.Fatal("acquired")
	}
	// org_a and idn_a were released.
	_, r, err := gs.Acquire(bg, Organization("org_a", Exclusive), Person("idn_a", Exclusive))
	if err != nil {
		t.Fatal(err)
	}
	r()
	hold()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("condition not reached")
}

// A plain write job takes its gates before it is queued: it waits for an
// exclusive holder (an effect consuming its requester's approval), and the
// writer is not held up meanwhile.
func TestJobWaitsForItsGates(t *testing.T) {
	w := newWriter(t)
	bg := context.Background()
	_, release, err := w.Gates.Acquire(bg, Person("idn_a", Exclusive))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- w.Job(bg, []Gate{Organization("org_a", Shared), Person("idn_a", Shared)}, func(ctx context.Context, tx *storage.Tx) error {
			if len(Held(ctx)) != 2 {
				t.Error("the job's context does not record its gates")
			}
			_, err := tx.ExecContext(ctx, `UPDATE organizations SET name = 'by the job' WHERE id = 'org_a'`)
			return err
		})
	}()
	// Another write goes through meanwhile.
	exec(t, w.Store, `UPDATE organizations SET name = 'meanwhile' WHERE id = 'org_a'`)
	select {
	case err := <-done:
		t.Fatalf("the job did not wait: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	release()
	if err := <-done; err != nil || count(t, w.Store, `SELECT count(*) FROM organizations WHERE name = 'by the job'`) != 1 {
		t.Fatal(err)
	}
}
