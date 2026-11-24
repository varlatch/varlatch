// SPDX-License-Identifier: Apache-2.0

//go:build linux

package migrate

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailhandoff"
)

// progressClock is the progress lines' clock: a time moved by hand, which
// ticks the innermost step every progressEvery of it and waits for what
// that says, and the lines said.
type progressClock struct {
	t     *testing.T
	mu    sync.Mutex
	at    time.Time
	ticks []chan time.Time
	made  int
	lines []string
	said  chan struct{}
}

// watch gives w's engine the clock and collects its progress lines.
func watch(t *testing.T, w *world) *progressClock {
	c := &progressClock{t: t, at: w.src.clock.t, said: make(chan struct{}, 1000)}
	w.eng.Options.Now, w.eng.sleep, w.eng.ticks = c.now, c.advance, c.ticker
	w.eng.Options.Progress = func(s string) {
		c.mu.Lock()
		c.lines = append(c.lines, s)
		c.mu.Unlock()
		c.said <- struct{}{}
	}
	return c
}

func (c *progressClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *progressClock) ticker(every time.Duration) (<-chan time.Time, func()) {
	if every != 15*time.Second {
		c.t.Errorf("a tick every %s", every)
	}
	ch := make(chan time.Time)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ticks, c.made = append(c.ticks, ch), c.made+1
	return ch, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.ticks = slices.DeleteFunc(c.ticks, func(o chan time.Time) bool { return o == ch })
	}
}

// advance moves the clock, a second at a time.
func (c *progressClock) advance(d time.Duration) {
	for range int(d / time.Second) {
		c.mu.Lock()
		c.at = c.at.Add(time.Second)
		var tick chan time.Time
		if c.at.Unix()%15 == 0 && len(c.ticks) > 0 {
			tick = c.ticks[len(c.ticks)-1]
		}
		c.mu.Unlock()
		if tick == nil {
			continue
		}
		for len(c.said) > 0 {
			<-c.said
		}
		tick <- c.now()
		select {
		case <-c.said:
		case <-time.After(10 * time.Second):
			c.t.Fatal("a tick said nothing")
		}
	}
}

func (c *progressClock) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.lines)
}

func sameLines(t *testing.T, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("said:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// A step is said as it starts, every 15 s while it lasts and as it ends;
// of steps within each other the innermost is the one said to go on.
func TestAStepIsSaid(t *testing.T) {
	w := newWorld(t)
	c := watch(t, w)
	err := w.eng.step("the outer", func() error {
		c.advance(16 * time.Second)
		outer := c.ticks[0]
		_ = w.eng.step("the inner", func() error {
			// The outer's ticks say nothing meanwhile (the second is taken
			// once the first was dealt with).
			outer <- c.now()
			outer <- c.now()
			c.advance(16 * time.Second)
			return errors.New("no")
		})
		_ = w.eng.step("the operator's", func() error { return &HumanStep{Instruction: "stop it"} })
		c.advance(14 * time.Second)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sameLines(t, c.all(), []string{
		"Step: the outer.",
		"Still going after 15s: the outer.",
		"Step: the inner.",
		"Still going after 14s: the inner.",
		"Failed after 16s: the inner.",
		"Step: the operator's.",
		"Left to you after 0s: the operator's.",
		"Still going after 45s: the outer.",
		"Done in 46s: the outer.",
	})
	if len(c.ticks) != 0 || len(w.eng.prog.steps) != 0 {
		t.Errorf("left: %d tickers, %d steps", len(c.ticks), len(w.eng.prog.steps))
	}
	// A panic ends the step's lines too.
	func() {
		defer func() { _ = recover() }()
		_ = w.eng.step("a panic", func() error { panic("here") })
	}()
	if len(c.ticks) != 0 || len(w.eng.prog.steps) != 0 || c.all()[len(c.all())-1] != "Step: a panic." {
		t.Errorf("after a panic: %d tickers, %d steps, %q", len(c.ticks), len(w.eng.prog.steps), c.all())
	}
	// With no Progress, f alone: no ticker, no line.
	made, lines := c.made, len(c.all())
	w.eng.Options.Progress = nil
	if err := w.eng.step("silent", func() error { return ErrOverBudget }); !errors.Is(err, ErrOverBudget) || c.made != made || len(c.all()) != lines {
		t.Errorf("a nil Progress: %v, %d tickers made, %q", err, c.made-made, c.all())
	}
}

// The forward undo in the transfer: each step, and the wait for the old
// installation's address as it goes on. Say's lines are what they were.
func TestTheUndoSaysItsSteps(t *testing.T) {
	lines := []string{
		"Step: stopping the target.",
		"Done in 0s: stopping the target.",
		"Step: lifting the source's barrier.",
		"Done in 0s: lifting the source's barrier.",
		"Step: starting the source's Caddy again.",
		"Done in 0s: starting the source's Caddy again.",
		"Step: waiting for https://vault.example.test to answer from the TypeScript release (about 3m0s at most).",
		"Still going after 15s: waiting for https://vault.example.test to answer from the TypeScript release (about 3m0s at most).",
		"Still going after 30s: waiting for https://vault.example.test to answer from the TypeScript release (about 3m0s at most).",
		"Done in 40s: waiting for https://vault.example.test to answer from the TypeScript release (about 3m0s at most).",
		"Step: discarding the target's database.",
		"Done in 0s: discarding the target's database.",
	}
	var said [2][]string
	for i, progress := range []bool{true, false} {
		w := interrupted(t, Transfer)
		setIngress(t, w, Public)
		w.prober.sourceLate = 20
		c := watch(t, w)
		if !progress {
			w.eng.Options.Progress = nil
		}
		j, err := w.eng.Abort(context.Background())
		if err != nil || j.Phase != Released {
			t.Fatalf("%+v %v", j, err)
		}
		if progress {
			sameLines(t, c.all(), lines)
		} else if len(c.all()) != 0 || c.made != 0 {
			t.Errorf("a nil Progress: %d tickers, %q", c.made, c.all())
		}
		said[i] = w.said
	}
	if !slices.Equal(said[0], said[1]) {
		t.Errorf("Say changed: %q, %q", said[0], said[1])
	}
}

// A rollback and its undo: each side's acts.
func TestTheRollbackSaysItsSteps(t *testing.T) {
	w, src, _ := rolledWorld(t, Open, Public)
	src.importErr = errors.New("no")
	c := watch(t, w)
	if _, err := w.eng.Rollback(t.Context()); !errors.Is(err, src.importErr) {
		t.Fatal(err)
	}
	var want []string
	for _, s := range []string{"having the images the rollback starts on this host", "Go's barrier", "writing the reverse bundle", "making the fresh volumes",
		"starting Postgres on its fresh volume", "importing the reverse bundle", "having the TypeScript installation's gate stand",
		"putting the TypeScript installation back on its own volumes", "checking that the TypeScript installation is held behind its gate",
		"checking that the TypeScript installation is held behind its gate", "lifting Go's barrier"} {
		end := "Done in 0s: "
		if strings.HasPrefix(s, "importing") {
			end = "Failed after 0s: "
		}
		want = append(want, "Step: "+s+".", end+s+".")
	}
	sameLines(t, c.all(), want)
}

// The waits for the operator's route and for the source's varlatchd once
// its sidecar runs, as they go on.
func TestTheRouteWaitIsSaid(t *testing.T) {
	w, src, j := rolledWorld(t, Open, Coolify)
	w.src.ingressDown = true
	src.importErr = errors.New("the reverse began")
	p, asked := &routeProber{w: w, id: j.ID}, 0
	p.route = func() string {
		if w.src.ingressDown {
			return "file: nothing"
		}
		if asked++; asked < 10 {
			return "down"
		}
		return "file: ts"
	}
	w.eng.Source, w.eng.Prober = routedFake{src}, p
	c := watch(t, w)
	if _, err := w.eng.Rollback(t.Context()); !errors.Is(err, src.importErr) {
		t.Fatal(err)
	}
	wait := "waiting for https://vault.example.test to answer from the TypeScript installation's gate, by the operator's route (about 3m0s at most)."
	for _, want := range []string{"Step: stopping the source's dashboard.", "Done in 0s: reading the TypeScript installation's gate.", "Step: starting the TypeScript installation behind its migrated-out gate.",
		"Done in 0s: starting the TypeScript dashboard.", "Still going after 15s: " + wait, "Done in 18s: " + wait, "Step: having the TypeScript installation's gate stand.", "Step: stopping what serves the TypeScript release's address."} {
		if !slices.Contains(c.all(), want) {
			t.Errorf("no %q in:\n%s", want, strings.Join(c.all(), "\n"))
		}
	}
	// What the undo of a route's check stops, and of a rebuild it could not
	// put back.
	n := len(c.all())
	if err := (steppedSource{src, w.eng}).StopStarted(t.Context(), []string{"postgres"}); err != nil {
		t.Fatal(err)
	}
	if err := (steppedSource{src, w.eng}).StopServers(t.Context()); err != nil {
		t.Fatal(err)
	}
	sameLines(t, c.all()[n:], []string{"Step: stopping what the route's check started.", "Done in 0s: stopping what the route's check started.",
		"Step: stopping the TypeScript installation's server.", "Done in 0s: stopping the TypeScript installation's server."})
}

// The tailnet name's move forward and back, and the sidecar's stop: said,
// without the tailnet's credentials.
func TestTheTailnetStepsAreSaid(t *testing.T) {
	w := newTailnetWorld(t)
	c := watch(t, w.world)
	if j, err := w.eng.Run(context.Background(), false); err != nil || j.Phase != Open {
		t.Fatalf("%+v %v", j, err)
	}
	lines := c.all()
	for _, want := range []string{"Step: waiting for the target's node to join the tailnet.", "Step: the tailnet name moves between the two nodes."} {
		if !slices.Contains(lines, want) || !slices.ContainsFunc(lines, func(l string) bool {
			return strings.HasPrefix(l, "Done in ") && strings.HasSuffix(l, strings.TrimPrefix(want, "Step: "))
		}) {
			t.Errorf("no %q, done, in:\n%s", want, strings.Join(lines, "\n"))
		}
	}
	if strings.Contains(strings.Join(lines, "\n"), w.cp.ClientSecret) {
		t.Error("a progress line holds the control plane's secret")
	}
	w.said = append(w.said, lines...)
	w.noSecrets(t)
}

// The wait for the source's varlatchd, restarted with its sidecar, as it
// goes on, between the sidecar's start and its stop.
func TestTheSidecarWaitIsSaid(t *testing.T) {
	w := newTailnetWorld(t)
	w.src.slowGates = 8
	c := watch(t, w.world)
	if j, err := w.eng.Run(context.Background(), false); err != nil || j.Phase != Open {
		t.Fatalf("%+v %v", j, err)
	}
	wait := "waiting for the source's varlatchd to answer (at most 1m0s)."
	lines, from := c.all(), 0
	for _, want := range []string{"Done in 0s: starting the source's tailnet sidecar.", "Step: " + wait, "Still going after 1", wait, "Done in 16s: " + wait, "Step: stopping the source's tailnet sidecar."} {
		i := slices.IndexFunc(lines[from:], func(l string) bool { return l == want || strings.HasPrefix(l, "Still") && strings.Contains(l, want) })
		if i < 0 {
			t.Fatalf("no %q after line %d of:\n%s", want, from, strings.Join(lines, "\n"))
		}
		from += i
	}
}

// Lines nobody reads hold nothing up: one pipe for Say and Progress, nearly
// full, or closed, and the undo of a transfer ends released and a migration's
// final copy open; no line of Say's is dropped, in its order.
func TestLinesNobodyReads(t *testing.T) {
	for _, how := range []string{"a pipe nobody reads, nearly full", "a closed pipe"} {
		for _, what := range []string{"abort", "run"} {
			t.Run(how+", "+what, func(t *testing.T) {
				w := newWorld(t)
				if what == "abort" {
					w = interrupted(t, Transfer)
					setIngress(t, w, Public)
				}
				r, out, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				defer out.Close()
				if how == "a closed pipe" {
					r.Close()
				} else {
					// Full, then room for one page of its own (a pipe takes
					// a short write into a page it can still add to).
					_ = out.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
					for err == nil {
						_, err = out.Write(make([]byte, 4096))
					}
					_ = out.SetWriteDeadline(time.Time{})
					if _, err := r.Read(make([]byte, 4096)); err != nil {
						t.Fatal(err)
					}
					if _, err := out.Write(make([]byte, 4000)); err != nil {
						t.Fatal(err)
					}
				}
				wrote := make(chan struct{}, 1000)
				lines := NewLines(func(s string) { _, _ = out.WriteString(s + "\n"); wrote <- struct{}{} })
				var said []string
				w.eng.Options.Say = func(s string) { said = append(said, s); lines.Say(s) }
				w.eng.Options.Progress = lines.Progress
				done := make(chan error, 1)
				go func() {
					var j *Journal
					var err error
					want := Released
					if what == "abort" {
						j, err = w.eng.Abort(context.Background())
					} else {
						want = Open
						j, err = w.eng.Run(context.Background(), false)
					}
					if err == nil && j.Phase != want {
						err = errors.New("ended in " + string(j.Phase))
					}
					done <- err
				}()
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(30 * time.Second):
					t.Fatal("it waits for its reader")
				}
				// What Say gave is all there still, but what was written.
				lines.mu.Lock()
				var left []string
				for _, q := range lines.queue {
					if slices.Contains(said, q.text) {
						left = append(left, q.text)
					}
				}
				lines.mu.Unlock()
				if how != "a closed pipe" && (len(left) == 0 || !slices.Equal(left, said[len(said)-len(left):])) {
					t.Errorf("queued still:\n%s\nsaid:\n%s", strings.Join(left, "\n"), strings.Join(said, "\n"))
				}
				if lines.Close(50*time.Millisecond) != (how == "a closed pipe") {
					t.Error("closed, against what the pipe is")
				}
			})
		}
	}
}

// A reader that reads gets every line, in the order they were given, and the
// writer ends with Close; what comes after is not written.
func TestLinesInOrder(t *testing.T) {
	var got []string
	lines := NewLines(func(s string) { got = append(got, s) })
	var want []string
	for i := range 300 {
		s := "line " + string(rune('a'+i%26))
		if i%3 == 0 {
			lines.Progress(s)
			if !lines.Flush(10 * time.Second) {
				t.Fatal("not flushed")
			}
		} else {
			lines.Say(s)
		}
		want = append(want, s)
	}
	if !lines.Close(10*time.Second) || !slices.Equal(got, want) {
		t.Errorf("%d lines of %d", len(got), len(want))
	}
	lines.Say("after")
	lines.Progress("after")
	if lines.Flush(20*time.Millisecond) || len(got) != 300 || currentLines.Load() != nil {
		t.Error("something after Close")
	}
}

// Progress is dropped over the backlog and while the writer is stuck; Say is
// not.
func TestLinesBacklog(t *testing.T) {
	go1 := make(chan struct{})
	var got []string
	lines := NewLines(func(s string) { <-go1; got = append(got, s) })
	lines.Say("first")
	for range 1000 {
		lines.Progress("p")
	}
	for range 200 {
		lines.Say("s")
	}
	lines.mu.Lock()
	if n := len(lines.queue); n > linesBacklog+200 || n < 200 {
		t.Errorf("%d queued", n)
	}
	// Stuck for longer than a write takes: none more.
	lines.since = time.Now().Add(-2 * linesStuck)
	lines.queue = nil
	lines.mu.Unlock()
	lines.Progress("p")
	lines.Say("s")
	lines.mu.Lock()
	if len(lines.queue) != 1 || lines.queue[0].text != "s" {
		t.Errorf("while stuck: %+v", lines.queue)
	}
	lines.mu.Unlock()
	close(go1)
	if !lines.Close(10*time.Second) || !slices.Equal(got, []string{"first", "s"}) {
		t.Errorf("wrote %q", got)
	}
}

// Checks that do not pass are no step that is done: forward and in the
// reverse. The forward final copy's parts are steps.
func TestTheChecksThatFailAreSaid(t *testing.T) {
	w := newWorld(t)
	w.tgt.pass = false
	c := watch(t, w)
	if _, err := w.eng.stepChecked("checks", func() (CheckSummary, error) { return CheckSummary{}, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := (steppedTarget{failingChecks{}, w.eng}).CheckReverse(t.Context(), "", "", nil); err != nil {
		t.Fatal(err)
	}
	sameLines(t, c.all(), []string{"Step: checks.", "Failed after 0s: checks.", "Step: the reverse checks.", "Failed after 0s: the reverse checks."})

	w = newWorld(t)
	c = watch(t, w)
	if j, err := w.eng.Run(t.Context(), false); err != nil || j.Phase != Open {
		t.Fatalf("%+v %v", j, err)
	}
	lines := strings.Join(c.all(), "\n")
	for _, what := range []string{"exporting the source at its frozen point", "importing it into the target", "checking the copy"} {
		if !strings.Contains(lines, "Step: "+what+".\nDone in ") {
			t.Errorf("no step %q in:\n%s", what, lines)
		}
	}
}

type failingChecks struct{ ReverseTarget }

func (failingChecks) CheckReverse(context.Context, string, string, []byte) (CheckSummary, error) {
	return CheckSummary{Passed: false, Faults: []string{"a table"}}, nil
}

// A handoff that moved nothing gives nothing back, and says nothing of it.
func TestANameThatDidNotMoveIsNotSaid(t *testing.T) {
	for phase, moved := range map[tailhandoff.Phase]bool{tailhandoff.Prepared: false, tailhandoff.Undone: false, tailhandoff.Switching: true, tailhandoff.Done: true} {
		if got := nameMoved(&Journal{Tailnet: &TailnetRecord{Handoff: &tailhandoff.State{Phase: phase}}}); got != moved {
			t.Errorf("%s: moved %v", phase, got)
		}
	}
	if nameMoved(&Journal{}) || nameMoved(&Journal{Tailnet: &TailnetRecord{}}) {
		t.Error("no handoff, moved")
	}
}
