// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

var (
	errHeld  = errors.New("held by another process")
	errOther = errors.New("another failure")
)

// moves is a directory as a mover sees it: what each name holds, the
// failures each rename meets in turn, and the waits it made.
type moves struct {
	files  map[string]string
	fails  map[string][]error // by "from>to", nil for one that succeeds
	always map[string]error
	calls  []string
	waited []time.Duration
	stopAt int // the wait that reports a done context, 0 for none
	during func()
}

func newMoves() *moves {
	return &moves{files: map[string]string{"target": "old", "staged": "new"}, fails: map[string][]error{}, always: map[string]error{}}
}

func (m *moves) mover() mover {
	return mover{
		rename: func(from, to string) error {
			step := from + ">" + to
			m.calls = append(m.calls, step)
			if err := m.always[step]; err != nil {
				return err
			}
			if f := m.fails[step]; len(f) > 0 {
				m.fails[step] = f[1:]
				if f[0] != nil {
					return f[0]
				}
			}
			if _, ok := m.files[from]; !ok {
				return errors.New(step + ": no such file")
			}
			m.files[to] = m.files[from]
			delete(m.files, from)
			return nil
		},
		held: func(err error) bool { return errors.Is(err, errHeld) },
		sleep: func(ctx context.Context, d time.Duration) bool {
			m.waited = append(m.waited, d)
			if m.during != nil {
				m.during()
			}
			return ctx.Err() == nil && (m.stopAt == 0 || len(m.waited) < m.stopAt)
		},
	}
}

func (m *moves) total() (sum time.Duration) {
	for _, d := range m.waited {
		sum += d
	}
	return sum
}

const (
	stepAside = "target>aside"
	stepPlace = "staged>target"
	stepBack  = "aside>target"
)

func TestSwapWaitsForAHeldFile(t *testing.T) {
	swapped := map[string]string{"target": "new", "aside": "old"}
	asItWas := map[string]string{"target": "old", "staged": "new"}
	for _, c := range []struct {
		name  string
		setup func(*moves)
		err   error
		files map[string]string
		calls []string
		waits int
	}{
		{name: "nothing held", setup: func(*moves) {}, files: swapped, calls: []string{stepAside, stepPlace}},
		{name: "the old file held", setup: func(m *moves) { m.fails[stepAside] = []error{errHeld, errHeld} },
			files: swapped, calls: []string{stepAside, stepAside, stepAside, stepPlace}, waits: 2},
		{name: "the new file held", setup: func(m *moves) { m.fails[stepPlace] = []error{errHeld} },
			files: swapped, calls: []string{stepAside, stepPlace, stepBack, stepAside, stepPlace}, waits: 1},
		{name: "the new file held, and the old one on its way back", setup: func(m *moves) {
			m.fails[stepPlace] = []error{errHeld}
			m.fails[stepBack] = []error{errHeld}
		}, files: swapped, calls: []string{stepAside, stepPlace, stepBack, stepBack, stepAside, stepPlace}, waits: 2},
		{name: "the old file, another failure", setup: func(m *moves) { m.fails[stepAside] = []error{errOther} },
			err: errOther, files: asItWas, calls: []string{stepAside}},
		{name: "the new file, another failure", setup: func(m *moves) { m.fails[stepPlace] = []error{errOther} },
			err: errOther, files: asItWas, calls: []string{stepAside, stepPlace, stepBack}},
		{name: "another failure, the old file held on its way back", setup: func(m *moves) {
			m.fails[stepPlace] = []error{errOther}
			m.fails[stepBack] = []error{errHeld, errHeld}
		}, err: errOther, files: asItWas, calls: []string{stepAside, stepPlace, stepBack, stepBack, stepBack}, waits: 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := newMoves()
			c.setup(m)
			err := m.mover().swap(context.Background(), "staged", "target", "aside")
			if !errors.Is(err, c.err) {
				t.Fatalf("%v, want %v", err, c.err)
			}
			if !maps.Equal(m.files, c.files) || !slices.Equal(m.calls, c.calls) || len(m.waited) != c.waits {
				t.Fatalf("files %v, renames %q, waits %v", m.files, m.calls, m.waited)
			}
		})
	}
}

// A file held throughout: the waits grow, are five seconds in all, and
// the target is in its place during each of them and after.
func TestSwapGivesUp(t *testing.T) {
	for _, step := range []string{stepAside, stepPlace} {
		t.Run(step, func(t *testing.T) {
			m := newMoves()
			m.always[step] = errHeld
			m.during = func() {
				if m.files["target"] != "old" {
					t.Errorf("wait %d: files %v", len(m.waited), m.files)
				}
			}
			if err := m.mover().swap(context.Background(), "staged", "target", "aside"); !errors.Is(err, errHeld) {
				t.Fatal(err)
			}
			if m.files["target"] != "old" || m.files["staged"] != "new" {
				t.Fatalf("files %v", m.files)
			}
			if m.total() != 5*time.Second || m.waited[0] != 25*time.Millisecond || m.waited[1] != 50*time.Millisecond || slices.Max(m.waited) != 500*time.Millisecond {
				t.Fatalf("waited %v, %v in all", m.waited, m.total())
			}
		})
	}
}

// Putting the old file back has its own five seconds, for all the times
// it is put back: a file held again and again does not add to them.
func TestSwapWaitsAreBounded(t *testing.T) {
	m := newMoves()
	m.always[stepPlace] = errHeld
	for range 100 { // each putting back waits 1.275 s
		m.fails[stepBack] = append(m.fails[stepBack], errHeld, errHeld, errHeld, errHeld, errHeld, errHeld, nil)
	}
	err := m.mover().swap(context.Background(), "staged", "target", "aside")
	if err == nil || m.files["aside"] != "old" || m.total() > 10*time.Second || m.total() < 5*time.Second {
		t.Fatalf("%v; files %v, %v in all", err, m.files, m.total())
	}
}

// The old file cannot be put back: the failure does not say that it was
// left as it was, but where it is. It is not tried as a held file again.
func TestSwapSaysWhereTheOldFileIs(t *testing.T) {
	for _, held := range []error{errHeld, errOther} {
		m := newMoves()
		m.always[stepPlace] = errHeld
		m.always[stepBack] = held
		err := writeError(m.mover().swap(context.Background(), "staged", "target", "aside"), "target", "0.50.0")
		var e *Error
		if !errors.As(err, &e) || !strings.Contains(err.Error(), "is at aside and could not be put back") || strings.Contains(err.Error(), "left as it was") {
			t.Fatalf("%v", err)
		}
		if m.files["aside"] != "old" || m.total() > 5*time.Second {
			t.Fatalf("files %v, waited %v", m.files, m.total())
		}
	}
}

// A done context ends the waits for the new file, not those for putting
// the old one back.
func TestSwapStopsWaitingWhenDone(t *testing.T) {
	m := newMoves()
	m.always[stepPlace] = errHeld
	m.stopAt = 1
	if err := m.mover().swap(context.Background(), "staged", "target", "aside"); !errors.Is(err, errHeld) || len(m.waited) != 1 {
		t.Fatalf("%v after %v", err, m.waited)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m = newMoves()
	m.always[stepPlace] = errHeld
	m.fails[stepBack] = []error{errHeld, errHeld}
	if err := m.mover().swap(ctx, "staged", "target", "aside"); !errors.Is(err, errHeld) || m.files["target"] != "old" {
		t.Fatalf("%v, files %v", err, m.files)
	}
	if len(m.waited) != 3 {
		t.Fatalf("waited %v", m.waited)
	}
}
