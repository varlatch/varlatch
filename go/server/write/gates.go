// SPDX-License-Identifier: AGPL-3.0-or-later

// Package write is varlatchd's write path without row locks (ADR-0059
// step 4, feature-parity decision 4). The TypeScript server orders every
// row lock by one documented order (domain/liveness.ts, ADR-0054
// amendment E) and holds some of them across outbound calls. varlatchd has
// a single writer instead (ADR-0059 Decision 2), so:
//
//   - Every check the TypeScript code makes under a row lock is made again
//     inside the write job that depends on it (CheckLive). A read before
//     the job is advisory only, unless gates make it authoritative.
//   - In-process gates (this file) replace the advisory locks and the row
//     locks the TypeScript code holds across a call: named reader-writer
//     gates, taken in one order (Level, then name, then key), all at once,
//     before the job is queued and released after its answer. A job waits
//     only for the writer; the writer never waits for a gate. A gate taken
//     inside a job, or out of order, is refused (trace.go).
//   - An external effect runs in five parts around its outbound call
//     (effect.go), and an Idempotency-Key's claim, the domain write and the
//     stored response are one job (idempotency.go).
//
// Gates are process-local, so only the daemon writes: host commands that
// write go through its control socket, or run offline under its lock
// (feature-parity decision 11, go/server/daemon/control.go).
package write

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"sync"
)

// Level is a gate's place in the order: the TypeScript order's steps 0 to
// 2 and 10 (domain/liveness.ts), in that order.
type Level int

const (
	// LevelSingleton is step 0: createApproval's per-person gate, device
	// sign-in's, the report summary worker's.
	LevelSingleton Level = 1
	// LevelOrganization is step 1: the Organization row. Shared by an
	// external effect for its whole life; exclusive for the transitions
	// the TypeScript code makes under the Organization row FOR UPDATE
	// (freezing and lifting, deletion, a Security Control change).
	LevelOrganization Level = 2
	// LevelPerson is step 2: people, in identity id order. Shared, or
	// exclusive for a writer that takes the person FOR UPDATE.
	LevelPerson Level = 3
	// LevelResource is step 10: a resource the TypeScript code locks
	// across an effect's call (a GitHub App registration, an audit
	// export), exclusive, in id order.
	LevelResource Level = 4
)

// Mode is how a gate is held.
type Mode int

const (
	Shared Mode = iota
	Exclusive
)

func (m Mode) String() string {
	if m == Exclusive {
		return "exclusive"
	}
	return "shared"
}

// Gate names one gate and the mode it is wanted in.
type Gate struct {
	Level Level
	Name  string
	Key   string
	Mode  Mode
}

func (g Gate) String() string { return fmt.Sprintf("%d:%s:%s(%s)", g.Level, g.Name, g.Key, g.Mode) }

// Organization is the Organization gate.
func Organization(id string, m Mode) Gate {
	return Gate{Level: LevelOrganization, Name: "organization", Key: id, Mode: m}
}

// Person is a person's gate.
func Person(identityID string, m Mode) Gate {
	return Gate{Level: LevelPerson, Name: "person", Key: identityID, Mode: m}
}

// Resource is a resource's gate, always exclusive.
func Resource(name, id string) Gate {
	return Gate{Level: LevelResource, Name: name, Key: id, Mode: Exclusive}
}

// Singleton is a step-0 gate, always exclusive.
func Singleton(name, key string) Gate {
	return Gate{Level: LevelSingleton, Name: name, Key: key, Mode: Exclusive}
}

// compare is the order: level, then name, then key.
func compare(a, b Gate) int {
	if c := cmp.Compare(a.Level, b.Level); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Name, b.Name); c != 0 {
		return c
	}
	return cmp.Compare(a.Key, b.Key)
}

// normalize sorts gates into the order and merges repeats into the
// strongest mode asked for, as lockPeople takes each person once.
func normalize(gates []Gate) []Gate {
	out := slices.Clone(gates)
	slices.SortStableFunc(out, compare)
	merged := out[:0]
	for _, g := range out {
		if n := len(merged); n > 0 && compare(merged[n-1], g) == 0 {
			merged[n-1].Mode = max(merged[n-1].Mode, g.Mode)
			continue
		}
		merged = append(merged, g)
	}
	return merged
}

type slot struct {
	level     Level
	name, key string
}

// rw is one gate: a reader-writer lock a waiter can abandon. A waiting
// exclusive taker keeps new shared takers out, so a control change is not
// starved by a stream of effects.
type rw struct {
	readers, writersWaiting, users int
	writer                         bool
	changed                        chan struct{}
}

// Gates holds the process's gates. The zero value is not usable; use
// NewGates.
type Gates struct {
	mu   sync.Mutex
	held map[slot]*rw
	// observe, when set, sees every acquisition and release (tests).
	observe func(event string, g Gate)
}

// NewGates returns an empty set of gates.
func NewGates() *Gates { return &Gates{held: map[slot]*rw{}} }

// Observe sets a function that sees every acquisition ("acquired") and
// release ("released") of a gate, for tests.
func (gs *Gates) Observe(fn func(event string, g Gate)) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	gs.observe = fn
}

type heldKey struct{}

// held is what a context's caller holds, in the order taken.
type held []Gate

func heldOf(ctx context.Context) held {
	h, _ := ctx.Value(heldKey{}).(held)
	return h
}

// Held reports the gates ctx's caller holds, in the order taken.
func Held(ctx context.Context) []Gate { return slices.Clone(heldOf(ctx)) }

// Acquire takes gates in the order, waiting as long as ctx allows. It
// returns a context that records them (pass it on, so a later Acquire is
// checked against them) and the function that releases them, which must
// be called once the work they protect has its answer. Taking a gate
// inside a write job, or one that comes before a gate already held, is a
// programming error and is refused (*OrderError); so is asking for no
// gate at all with a nil Gates.
func (gs *Gates) Acquire(ctx context.Context, gates ...Gate) (context.Context, func(), error) {
	want := normalize(gates)
	if len(want) == 0 {
		return ctx, func() {}, nil
	}
	already := heldOf(ctx)
	if err := checkOrder(already, want); err != nil {
		return ctx, nil, err
	}
	var got []Gate
	release := func() {
		for i := len(got) - 1; i >= 0; i-- {
			gs.release(got[i])
		}
		got = nil
	}
	for _, g := range want {
		if err := gs.acquire(ctx, g); err != nil {
			release()
			return ctx, nil, err
		}
		got = append(got, g)
	}
	once := sync.Once{}
	return context.WithValue(ctx, heldKey{}, append(slices.Clone(already), want...)), func() { once.Do(release) }, nil
}

func (gs *Gates) acquire(ctx context.Context, g Gate) error {
	s := slot{g.Level, g.Name, g.Key}
	gs.mu.Lock()
	r := gs.held[s]
	if r == nil {
		r = &rw{changed: make(chan struct{})}
		gs.held[s] = r
	}
	r.users++
	if g.Mode == Exclusive {
		r.writersWaiting++
	}
	for {
		free := !r.writer && (g.Mode == Shared && r.writersWaiting == 0 || g.Mode == Exclusive && r.readers == 0)
		if free {
			if g.Mode == Exclusive {
				r.writersWaiting--
				r.writer = true
			} else {
				r.readers++
			}
			obs := gs.observe
			gs.mu.Unlock()
			if obs != nil {
				obs("acquired", g)
			}
			return nil
		}
		wait := r.changed
		gs.mu.Unlock()
		select {
		case <-wait:
			gs.mu.Lock()
		case <-ctx.Done():
			gs.mu.Lock()
			if g.Mode == Exclusive {
				r.writersWaiting--
			}
			gs.leave(s, r)
			gs.mu.Unlock()
			return ctx.Err()
		}
	}
}

func (gs *Gates) release(g Gate) {
	s := slot{g.Level, g.Name, g.Key}
	gs.mu.Lock()
	r := gs.held[s]
	if g.Mode == Exclusive {
		r.writer = false
	} else {
		r.readers--
	}
	gs.leave(s, r)
	obs := gs.observe
	gs.mu.Unlock()
	if obs != nil {
		obs("released", g)
	}
}

// leave wakes the gate's waiters and forgets a gate nobody uses. gs.mu is
// held.
func (gs *Gates) leave(s slot, r *rw) {
	r.users--
	close(r.changed)
	r.changed = make(chan struct{})
	if r.users == 0 {
		delete(gs.held, s)
	}
}
