// SPDX-License-Identifier: Apache-2.0

package matcher

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
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

// TestMatcherIsLinear: every adversarial shape (a match at every byte, a
// chain of overlaps, a hold that never completes, a chunk holding
// thousands of matches, many Secrets, every encoded form) takes time
// linear in the input: four times the input takes at most about four times
// as long (eight, for a loaded machine's noise), and 4 MB of the worst shape
// (a match at every byte, each reported by the scanner too) stays inside a
// few seconds. Under the race detector the inputs are a quarter the size.
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
		run := func(size, chunk int) time.Duration {
			input := []byte(strings.Repeat(c.unit, size/len(c.unit)+1)[:size])
			m := NewStreamMatcher(c.entries, Marker)
			s := NewStreamScanner(c.entries)
			start := time.Now()
			for at := 0; at < len(input); at += chunk {
				end := min(at+chunk, len(input))
				_, _ = m.Push(input[at:end])
				_, _ = s.Push(input[at:end])
			}
			_, _ = m.End()
			return time.Since(start)
		}
		size, limit := 1<<20, 3*time.Second
		if raceSlowdown > 1 {
			size, limit = size/4, limit*raceSlowdown/2
		}
		for _, chunk := range []int{64 * 1024, 4 << 20} { // a pipe's reads, and one huge chunk
			_ = run(size/4, chunk) // warm up
			small, large := run(size, chunk), run(4*size, chunk)
			t.Logf("%s, %d-byte chunks: %d bytes %v, %d bytes %v", c.name, chunk, size, small, 4*size, large)
			if large > limit || large > 8*small+100*time.Millisecond {
				t.Errorf("%s, %d-byte chunks: %d bytes %v, %d bytes %v: not linear", c.name, chunk, size, small, 4*size, large)
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
			noFormSurvives(t, got, entries)
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
