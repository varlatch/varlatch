// SPDX-License-Identifier: Apache-2.0

package matcher

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// gatedSource gives the test's chunks one by one, waiting for each.
type gatedSource struct {
	ch     chan []byte
	closed chan struct{}
	once   sync.Once
}

func newGatedSource() *gatedSource {
	return &gatedSource{ch: make(chan []byte), closed: make(chan struct{})}
}

func (g *gatedSource) Read(p []byte) (int, error) {
	select {
	case b, ok := <-g.ch:
		if !ok {
			return 0, io.EOF
		}
		return copy(p, b), nil
	case <-g.closed:
		return 0, io.ErrClosedPipe
	}
}

func (g *gatedSource) Close() error {
	g.once.Do(func() { close(g.closed) })
	return nil
}

// lockedBuffer is a destination the test reads while the relay writes.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

const token = "super-secret-token-12345"

// TestRelayNeverReleasesOnATimer (A-R3): a value written in parts, with
// pauses well past any flush interval, is never released early.
func TestRelayNeverReleasesOnATimer(t *testing.T) {
	r := NewOutputRedaction([]SecretEntry{{Item: "API_TOKEN", Value: token}}, ModeRedact)
	src, dest := newGatedSource(), &lockedBuffer{}
	done := make(chan struct{})
	go func() { r.Relay([]Pair{{Source: src, Dest: dest}}); close(done) }()
	src.ch <- []byte("token=" + token[:2])
	time.Sleep(300 * time.Millisecond)
	if got := dest.String(); got != "token=" {
		t.Fatalf("after a pause: %q", got)
	}
	src.ch <- []byte(token[2:11])
	time.Sleep(300 * time.Millisecond)
	if got := dest.String(); got != "token=" {
		t.Fatalf("after a second pause: %q", got)
	}
	src.ch <- []byte(token[11:] + "\n")
	close(src.ch)
	<-done
	if got := dest.String(); got != "token=[REDACTED:API_TOKEN]\n" {
		t.Errorf("at the end: %q", got)
	}
}

// TestRelayInterruptDiscardsHeld: an interrupt during the run discards the
// held prefix when the stream ends; nothing of it is released.
func TestRelayInterruptDiscardsHeld(t *testing.T) {
	r := NewOutputRedaction([]SecretEntry{{Item: "API_TOKEN", Value: token}}, ModeRedact)
	src, dest := newGatedSource(), &lockedBuffer{}
	done := make(chan struct{})
	go func() { r.Relay([]Pair{{Source: src, Dest: dest}}); close(done) }()
	src.ch <- []byte("log line\n" + token[:len(token)-1])
	time.Sleep(50 * time.Millisecond)
	if got := dest.String(); got != "log line\n" {
		t.Fatalf("before the interrupt: %q", got)
	}
	r.Interrupt()
	close(src.ch)
	<-done
	if got := dest.String(); got != "log line\n" {
		t.Errorf("after the interrupt: %q", got)
	}
}

// failingDest fails every write after the first.
type failingDest struct {
	mu     sync.Mutex
	writes int
	got    bytes.Buffer
}

func (f *failingDest) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	if f.writes > 1 {
		return 0, errors.New("write EPIPE")
	}
	return f.got.Write(p)
}

// TestRelayStopsWhenTheDestinationFails: a destination that fails closes
// the source, as a closed pipe would, and the held prefix is never written.
func TestRelayStopsWhenTheDestinationFails(t *testing.T) {
	r := NewOutputRedaction([]SecretEntry{{Item: "API_TOKEN", Value: token}}, ModeRedact)
	src, dest := newGatedSource(), &failingDest{}
	done := make(chan struct{})
	go func() { r.Relay([]Pair{{Source: src, Dest: dest}}); close(done) }()
	src.ch <- []byte("first\n")
	src.ch <- []byte("second\n" + token[:6])
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay kept reading after its destination failed")
	}
	select {
	case <-src.closed:
	default:
		t.Error("the source was not closed")
	}
	if dest.writes != 2 || dest.got.String() != "first\n" {
		t.Errorf("%d writes, %q", dest.writes, dest.got.String())
	}
}

// TestClosedMatcherRefuses: after an end or an abort, a matcher and a
// scanner refuse more input, and a scanner's reset starts over.
func TestClosedMatcherRefuses(t *testing.T) {
	entries := []SecretEntry{{Item: "API_KEY", Value: "valueaaaaaaaaaaaaa"}}
	m := NewStreamMatcher(entries, Marker)
	if out, _ := m.Push([]byte("abc valueaaaaaaa")); string(out) != "abc " || m.HeldBytes() != 12 {
		t.Fatalf("%q, %d held", out, m.HeldBytes())
	}
	m.Abort()
	if _, err := m.End(); !errors.Is(err, ErrClosed) {
		t.Error("End after Abort")
	}
	if _, err := m.Push([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Error("Push after Abort")
	}
	s := NewStreamScanner(entries)
	if found, _ := s.Push([]byte("valueaaaaa")); len(found) != 0 {
		t.Fatal(found)
	}
	s.Reset()
	if found, _ := s.Push([]byte("aaaaaaaa")); len(found) != 0 {
		t.Error("state carried over a reset")
	}
	if end, _ := s.End(); end.IncompletePrefix != nil {
		t.Error(end.IncompletePrefix)
	}
	if _, err := s.Push([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Error("Push after End")
	}
	s.Reset()
	if found, _ := s.Push([]byte("valueaaaaaaaaaaaaa")); len(found) != 1 || found[0].Start != 0 || found[0].End != 18 {
		t.Errorf("%+v", found)
	}
}

// TestPushNeverKeepsTheCallersBuffer: what stays held is a copy, so a
// relay may reuse its read buffer.
func TestPushNeverKeepsTheCallersBuffer(t *testing.T) {
	m := NewStreamMatcher([]SecretEntry{{Item: "K", Value: "valueaaaaaaaaaaaaa"}}, Marker)
	buf := []byte("x valueaaaaa")
	out, _ := m.Push(buf)
	copy(buf, "ZZZZZZZZZZZZ")
	rest, _ := m.Push([]byte("aaaaaaaa!"))
	end, _ := m.End()
	if got := string(out) + string(rest) + string(end.Output); got != "x [REDACTED:K]!" {
		t.Errorf("%q", got)
	}
}

// growth times the small and the large work: each runs once untimed first
// (a cold or still clocking-up CPU would make whichever runs first look
// slow), then they are timed in turn, small, large, small, large, small,
// large, each run after a garbage collection, and the fastest of each is
// given. Noise (a shared runner's pauses, another job's load) only ever
// adds time, and timing the two in turn makes a busy spell slow both alike
// instead of one.
func growth(small, large func()) (time.Duration, time.Duration) {
	small()
	large()
	var bestSmall, bestLarge time.Duration
	for i := range 3 {
		for _, f := range []struct {
			run  func()
			best *time.Duration
		}{{small, &bestSmall}, {large, &bestLarge}} {
			runtime.GC()
			start := time.Now()
			f.run()
			if took := time.Since(start); i == 0 || took < *f.best {
				*f.best = took
			}
		}
	}
	return bestSmall, bestLarge
}

// growsLinearly is the timing tests' criterion: for an input eight times
// as large, the time may grow at most 24-fold. Linear work grows about
// eightfold and quadratic about 64-fold (on CI runners, where caches and
// load flatten the curve, nearer 38-fold), so 24 sits near the geometric
// middle, with room for noise on either side. It judges growth only, never
// a machine's absolute speed. A little slack keeps a shape that takes a few
// milliseconds from failing on jitter: 20 ms, but never more than twice the
// small run, so it cannot hide growth where the runs are short (the race
// detector's smaller inputs).
func growsLinearly(small, large time.Duration) bool {
	return large <= 24*small+min(20*time.Millisecond, 2*small)
}

// TestTheLinearityCriterion: growth an eighth of the input to all of it
// judged by growsLinearly. Linear growth, eight to thirteen times, passes;
// quadratic growth, forty to 64 times, fails; and so does a deliberately
// quadratic implementation, sized on this machine and timed the way
// TestMatcherIsLinear times the matcher.
func TestTheLinearityCriterion(t *testing.T) {
	ms := time.Millisecond
	for _, c := range []struct {
		small, large time.Duration
		linear       bool
	}{
		{100 * ms, 800 * ms, true},   // 8 times
		{100 * ms, 1300 * ms, true},  // 13 times
		{500 * ms, 6500 * ms, true},  // 13 times
		{100 * ms, 4000 * ms, false}, // 40 times
		{50 * ms, 1900 * ms, false},  // 38 times
		{100 * ms, 6400 * ms, false}, // 64 times
		{2 * ms, 60 * ms, false},     // 30 times, at a few milliseconds: the slack is at most twice the small run
	} {
		if growsLinearly(c.small, c.large) != c.linear {
			t.Errorf("%v then %v: judged linear %v", c.small, c.large, !c.linear)
		}
	}
	// A merge that walks everything it holds for each new item, as the
	// TypeScript matcher's does within a chunk.
	quadratic := func(n int) func() {
		return func() {
			var held []int
			sum := 0
			for i := range n {
				for _, h := range held {
					sum += h
				}
				held = append(held, i)
			}
			if sum < 0 {
				t.Log(sum)
			}
		}
	}
	// Sized on this machine: n doubles from 2000 until the small run takes
	// at least 50 ms (capped), so the 20 ms slack is negligible and the
	// growth decides. The faster of two probes decides: one stalled probe
	// never stops the sizing early and shrinks the control's margin.
	n := 2000
	for n < 32000 {
		probe := func() time.Duration {
			runtime.GC()
			start := time.Now()
			quadratic(n)()
			return time.Since(start)
		}
		if min(probe(), probe()) >= 50*time.Millisecond {
			break
		}
		n *= 2
	}
	small, large := growth(quadratic(n), quadratic(8*n))
	// Per operation (n(n-1)/2 steps each): equal when nothing biases one
	// size, so the growth is the work's own.
	perOp := func(d time.Duration, items int) float64 {
		return float64(d.Nanoseconds()) / (float64(items) * float64(items-1) / 2)
	}
	t.Logf("a quadratic merge, n = %d chosen: %d items %v (%.3f ns per step), %d items %v (%.3f ns per step), %.1fx",
		n, n, small, perOp(small, n), 8*n, large, perOp(large, 8*n), float64(large)/float64(small))
	if growsLinearly(small, large) {
		t.Errorf("a quadratic merge (%v then %v) was judged linear", small, large)
	}
}

// TestMatcherIsLinear: every adversarial shape (a match at every byte, a
// chain of overlaps, a hold that never completes, a chunk holding
// thousands of matches, many Secrets, every encoded form) takes time
// linear in the input, by growsLinearly: an eighth of the input against
// all of it, warmed up, then timed in turn, best of three each (growth). No absolute
// time bound: a slow runner is not a failure. Under the race detector the
// inputs are a quarter the size.
func TestMatcherIsLinear(t *testing.T) {
	many := make([]SecretEntry, 400)
	for i := range many {
		many[i] = SecretEntry{Item: fmt.Sprintf("ITEM_%03d", i), Value: fmt.Sprintf("secret-%03d-%08x", i, uint32(i)*2654435761)}
	}
	r := rand.New(rand.NewPCG(5, 4))
	var manyText strings.Builder
	for manyText.Len() < 64*1024 {
		manyText.WriteString(many[r.IntN(len(many))].Value + " secret-" + fmt.Sprint(r.IntN(999)) + " ")
	}
	encoded := "valueaaaaaaaaaaaaa"
	var forms strings.Builder
	for _, f := range FormsOf(encoded) {
		forms.Write(f)
		forms.WriteByte('|')
	}
	for _, c := range []struct {
		name    string
		entries []SecretEntry
		unit    string
	}{
		{"every byte matches", []SecretEntry{{Item: "A", Value: "aaaaaaaa"}}, "a"},
		{"a chain of overlaps", []SecretEntry{{Item: "P", Value: "abababab"}}, "ab"},
		{"a hold that never completes", []SecretEntry{{Item: "A", Value: strings.Repeat("a", 200) + "b"}}, "a"},
		{"touching matches", []SecretEntry{{Item: "A", Value: "valueaaaaaaaaaaaaa"}}, "valueaaaaaaaaaaaaa"},
		{"many Secrets", many, manyText.String()},
		{"every encoded form", []SecretEntry{{Item: "K", Value: encoded}}, forms.String()},
	} {
		stream := func(size, chunk int) func() {
			input := []byte(strings.Repeat(c.unit, size/len(c.unit)+1)[:size])
			return func() {
				m := NewStreamMatcher(c.entries, Marker)
				s := NewStreamScanner(c.entries)
				for at := 0; at < len(input); at += chunk {
					end := min(at+chunk, len(input))
					_, _ = m.Push(input[at:end])
					_, _ = s.Push(input[at:end])
				}
				_, _ = m.End()
			}
		}
		large := 4 << 20
		if raceSlowdown > 1 {
			large /= 4
		}
		small := large / 8
		for _, chunk := range []int{64 * 1024, 4 << 20} { // a pipe's reads, and one huge chunk
			tSmall, tLarge := growth(stream(small, chunk), stream(large, chunk))
			t.Logf("%s, %d-byte chunks: %d bytes %v, %d bytes %v (%.1fx)", c.name, chunk, small, tSmall, large, tLarge, float64(tLarge)/float64(tSmall))
			if !growsLinearly(tSmall, tLarge) {
				t.Errorf("%s, %d-byte chunks: %d bytes %v, %d bytes %v: not linear", c.name, chunk, small, tSmall, large, tLarge)
			}
		}
	}
}

// FuzzStreamEqualsWhole: any input with any Secrets, split anywhere, gives
// the whole-input reference's bytes, and the scanner finds the reference's
// occurrences.
func FuzzStreamEqualsWhole(f *testing.F) {
	f.Add([]byte("..xxxxYYYYzzzz.."), "xxxxYYYY", "YYYYzzzz", uint8(3))
	f.Add([]byte("start abababababababab end"), "abababab", "babababa", uint8(7))
	f.Add([]byte("Basic dXNlcjp2YWx1ZWFhYWFhYWFhYWFhYQ=="), "valueaaaaaaaaaaaaa", "user:val", uint8(9))
	f.Add([]byte("p\xc3\xa4ssword-XYZ-123 \xff\x00"), "p\xc3\xa4ssword-XYZ-123", "\xed\xa0\x80token-x", uint8(1))
	f.Fuzz(func(t *testing.T, input []byte, a, b string, seed uint8) {
		if len(input) > 2048 || len(a) > 64 || len(b) > 64 {
			return
		}
		entries := []SecretEntry{{Item: "A", Value: a}, {Item: "B", Value: b}}
		want := ScrubWhole(input, entries, Marker)
		r := rand.New(rand.NewPCG(uint64(seed), 1))
		for range 4 {
			steps, end, _ := stream(entries, input, randomCuts(r, len(input), r.IntN(12)))
			got := joined(steps, end)
			if !bytes.Equal(got, want) {
				t.Fatalf("got %q, want %q", got, want)
			}
			// The oracle finds the markers in the output by their text, so an
			// input that holds marker text itself would confuse it.
			if !bytes.Contains(input, []byte("[REDACTED:")) {
				noFormSurvives(t, got, entries)
			}
		}
		st, _, _ := scan(entries, input, randomCuts(r, len(input), r.IntN(12)))
		var found []Occurrence
		for _, s := range st {
			found = append(found, s...)
		}
		if sortedHash(found) != sortedHash(FindWhole(input, entries)) {
			t.Fatal("the scanner and the reference differ")
		}
	})
}

// noFormSurvives: no registered form of any entry is in the output, except
// where it overlaps a replacement marker. Bytes outside the markers are
// contiguous input, so a form there would have been an unreplaced match;
// a form overlapping a marker is the markers' own text (a Secret such as
// "D:A][RED", which two markers side by side spell). This holds whatever
// ScrubWhole does, which shares FormsOf with the matcher.
func noFormSurvives(t *testing.T, out []byte, entries []SecretEntry) {
	t.Helper()
	var spans [][2]int
	for _, e := range entries {
		marker := Marker(e.Item)
		for at := 0; ; at++ {
			i := bytes.Index(out[at:], marker)
			if i < 0 {
				break
			}
			at += i
			spans = append(spans, [2]int{at, at + len(marker)})
		}
	}
	for _, e := range entries {
		for _, form := range FormsOf(e.Value) {
			for at := 0; ; at++ {
				i := bytes.Index(out[at:], form)
				if i < 0 {
					break
				}
				at += i
				overlaps := false
				for _, sp := range spans {
					if sp[0] < at+len(form) && at < sp[1] {
						overlaps = true
						break
					}
				}
				if !overlaps {
					t.Fatalf("a form of %s survived at %d: %q", e.Item, at, out)
				}
			}
		}
	}
}

// TestNoStaleSegments: once addMatch rewrites the pending segments, and
// once emitFinal hands them on, no slot outside the live segments (past
// their length, or in the scratch space) still holds a segment, so none
// keeps a caller's chunk alive (#298's review).
func TestNoStaleSegments(t *testing.T) {
	entries := []SecretEntry{{Item: "A", Value: "abababab"}, {Item: "B", Value: "babababa"}}
	m := NewStreamMatcher(entries, Marker)
	stale := func(where string, slots []segment) {
		t.Helper()
		for i, s := range slots {
			if s.bytes != nil || s.region || s.start != 0 {
				t.Fatalf("%s: slot %d holds %+v", where, i, s)
			}
		}
	}
	for _, chunk := range []string{"xxabab", "ababab", "abxx yy abab", "abababababab", "zz"} {
		if _, err := m.Push([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
		stale("past the segments", m.segments[len(m.segments):cap(m.segments)])
		stale("the scratch space", m.scratch[:cap(m.scratch)])
	}
	if _, err := m.End(); err != nil {
		t.Fatal(err)
	}
}
