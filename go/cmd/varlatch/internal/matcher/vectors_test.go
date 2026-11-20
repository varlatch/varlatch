// SPDX-License-Identifier: Apache-2.0

package matcher

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The vectors: testdata/vectors/matcher.json, recorded from packages/matcher
// and redact.ts by apps/cli/test/go-vectors-matcher.test.ts.

var (
	vectorsOnce sync.Once
	vectorsDoc  jsjson.Object
	vectorsErr  error
)

func vectors(t *testing.T) jsjson.Object {
	t.Helper()
	vectorsOnce.Do(func() {
		var data []byte
		data, vectorsErr = os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "matcher.json"))
		if vectorsErr != nil {
			return
		}
		var doc any
		doc, vectorsErr = jsjson.Parse(data)
		if vectorsErr == nil {
			vectorsDoc = doc.(jsjson.Object)
		}
	})
	if vectorsErr != nil {
		t.Fatal(vectorsErr)
	}
	return vectorsDoc
}

func field(o any, key string) any {
	v, _ := o.(jsjson.Object).Get(key)
	return v
}

func has(o any, key string) bool {
	_, ok := o.(jsjson.Object).Get(key)
	return ok
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

func num(v any) int { return int(v.(float64)) }

func b64(t *testing.T, v any) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(v.(string))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func entriesOf(v any) []SecretEntry {
	var out []SecretEntry
	for _, e := range list(v) {
		out = append(out, SecretEntry{Item: field(e, "item").(string), Value: field(e, "value").(string)})
	}
	return out
}

func strings_(v any) []string {
	var out []string
	for _, s := range list(v) {
		out = append(out, s.(string))
	}
	return out
}

func inputOf(t *testing.T, k any) []byte {
	t.Helper()
	var b []byte
	for _, p := range list(field(k, "parts")) {
		chunk := b64(t, field(p, "base64"))
		n := 1
		if has(p, "repeat") {
			n = num(field(p, "repeat"))
		}
		for range n {
			b = append(b, chunk...)
		}
	}
	return b
}

func cutsOf(v any) []int {
	var out []int
	for _, c := range list(v) {
		out = append(out, num(c))
	}
	return out
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type step struct {
	out                 []byte
	held, pending, hold int
	boundOK             bool
}

// stream pushes input through a fresh matcher at the given cuts, then ends.
func stream(entries []SecretEntry, input []byte, cuts []int) ([]step, EndReport, *StreamMatcher) {
	m := NewStreamMatcher(entries, Marker)
	var steps []step
	at := 0
	for _, cut := range append(slices.Clone(cuts), len(input)) {
		out, err := m.Push(input[at:cut])
		if err != nil {
			panic(err)
		}
		at = cut
		steps = append(steps, step{out, m.HeldBytes(), m.PendingRegions(), m.Hold(), m.PendingRegions() <= 1+m.Hold()/8})
	}
	end, err := m.End()
	if err != nil {
		panic(err)
	}
	return steps, end, m
}

func joined(steps []step, end EndReport) []byte {
	var out []byte
	for _, s := range steps {
		out = append(out, s.out...)
	}
	return append(out, end.Output...)
}

func randomCuts(r *rand.Rand, length, count int) []int {
	set := map[int]bool{}
	for i := 0; i < count && length > 1; i++ {
		set[1+r.IntN(length-1)] = true
	}
	var cuts []int
	for c := range set {
		cuts = append(cuts, c)
	}
	sort.Ints(cuts)
	return cuts
}

// TestFormsVectors: every registered form of every value, named, in order.
func TestFormsVectors(t *testing.T) {
	doc := vectors(t)
	if num(field(doc, "minLength")) != MinLength {
		t.Fatalf("MIN_LENGTH %v", field(doc, "minLength"))
	}
	for _, v := range list(field(doc, "forms")) {
		value := field(v, "value").(string)
		var want []string
		for _, f := range list(field(v, "forms")) {
			want = append(want, field(f, "form").(string)+" "+field(f, "text").(string))
		}
		var got []string
		for _, f := range LabelledFormsOf(value) {
			got = append(got, string(f.Form)+" "+string(f.Bytes))
		}
		if !slices.Equal(got, want) {
			t.Errorf("%q:\n got  %q\n want %q", value, got, want)
		}
		if f := FormsOf(value); len(f) != len(got) {
			t.Errorf("%q: FormsOf has %d forms", value, len(f))
		}
	}
}

// TestStreamVectors: each case's output is TypeScript's at every byte
// split, byte by byte, and at random chunkings; each recorded chunking emits
// the same bytes at each push, holding the same bytes and regions; the
// pending regions never exceed 1 + floor(hold / 8); and the whole-input
// reference agrees.
func TestStreamVectors(t *testing.T) {
	doc := vectors(t)
	cases := list(field(doc, "cases"))
	if len(cases) < 300 {
		t.Fatalf("%d cases", len(cases))
	}
	for index, k := range cases {
		name := field(k, "name").(string)
		entries := entriesOf(field(k, "entries"))
		input := inputOf(t, k)
		long := has(k, "outputSha256")
		check := func(what string, out []byte) {
			if long {
				if sha(out) != field(k, "outputSha256").(string) || len(out) != num(field(k, "outputLength")) {
					t.Errorf("%s (%s): output of %d bytes differs", name, what, len(out))
				}
				return
			}
			if want := b64(t, field(k, "output")); !bytes.Equal(out, want) {
				t.Errorf("%s (%s):\n got  %q\n want %q", name, what, out, want)
			}
		}
		steps, end, m := stream(entries, input, nil)
		check("whole", joined(steps, end))
		check("whole-input reference", ScrubWhole(input, entries, Marker))
		if !slices.Equal(m.Skipped, strings_(field(k, "skipped"))) {
			t.Errorf("%s: skipped %q", name, m.Skipped)
		}
		wantReplaced := map[string]int{}
		for _, r := range field(k, "replaced").(jsjson.Object) {
			wantReplaced[r.Key] = num(r.Value)
		}
		if fmt.Sprint(m.Replaced) != fmt.Sprint(wantReplaced) {
			t.Errorf("%s: replaced %v, want %v", name, m.Replaced, wantReplaced)
		}
		if p := field(k, "incompletePrefix"); p == nil {
			if end.IncompletePrefix != nil {
				t.Errorf("%s: an incomplete prefix %+v", name, *end.IncompletePrefix)
			}
		} else if end.IncompletePrefix == nil || end.IncompletePrefix.Item != field(p, "item").(string) || end.IncompletePrefix.Length != num(field(p, "length")) {
			t.Errorf("%s: incomplete prefix %+v, want %v", name, end.IncompletePrefix, p)
		}
		if len(input) <= 400 {
			for cut := 1; cut < len(input); cut++ {
				s, e, _ := stream(entries, input, []int{cut})
				check(fmt.Sprintf("split at %d", cut), joined(s, e))
			}
			all := make([]int, 0, len(input))
			for i := 1; i < len(input); i++ {
				all = append(all, i)
			}
			s, e, _ := stream(entries, input, all)
			check("byte by byte", joined(s, e))
		}
		r := rand.New(rand.NewPCG(uint64(index), 54))
		for range 4 {
			s, e, _ := stream(entries, input, randomCuts(r, len(input), 1+r.IntN(40)))
			check("random chunking", joined(s, e))
		}
		for ci, c := range list(field(k, "chunkings")) {
			s, e, _ := stream(entries, input, cutsOf(field(c, "cuts")))
			for i, st := range s {
				if !st.boundOK {
					t.Errorf("%s chunking %d push %d: %d pending regions, hold %d", name, ci, i, st.pending, st.hold)
				}
			}
			if !has(c, "steps") {
				check(fmt.Sprintf("chunking %d", ci), joined(s, e))
				continue
			}
			want := list(field(c, "steps"))
			if len(want) != len(s) {
				t.Errorf("%s chunking %d: %d pushes, want %d", name, ci, len(s), len(want))
				continue
			}
			for i, w := range want {
				got := s[i]
				if !bytes.Equal(got.out, b64(t, field(w, "out"))) || got.held != num(field(w, "held")) || got.pending != num(field(w, "pending")) || got.hold != num(field(w, "hold")) {
					t.Errorf("%s chunking %d push %d: out %q held %d pending %d hold %d, want %v", name, ci, i, got.out, got.held, got.pending, got.hold, w)
				}
			}
			if !bytes.Equal(e.Output, b64(t, field(c, "end"))) {
				t.Errorf("%s chunking %d: end %q", name, ci, e.Output)
			}
		}
	}
}

func occurrence(o Occurrence) string {
	return fmt.Sprintf("%d:%s:%d:%d", o.Entry, o.Form, o.Start, o.End)
}

func occurrencesOf(v any) []string {
	var out []string
	for _, o := range list(v) {
		l := list(o)
		out = append(out, fmt.Sprintf("%d:%s:%d:%d", num(l[0]), l[1].(string), num(l[2]), num(l[3])))
	}
	return out
}

// sortedHash is the recorder's occHash: the occurrences as
// start:end:entry:form, sorted, joined by newlines.
func sortedHash(found []Occurrence) string {
	keys := make([]string, len(found))
	for i, o := range found {
		keys[i] = fmt.Sprintf("%d:%d:%d:%s", o.Start, o.End, o.Entry, o.Form)
	}
	sort.Strings(keys)
	return sha([]byte(strings.Join(keys, "\n")))
}

func scan(entries []SecretEntry, input []byte, cuts []int) ([][]Occurrence, ScanEnd, *StreamScanner) {
	s := NewStreamScanner(entries)
	var steps [][]Occurrence
	at := 0
	for _, cut := range append(slices.Clone(cuts), len(input)) {
		found, err := s.Push(input[at:cut])
		if err != nil {
			panic(err)
		}
		steps = append(steps, found)
		at = cut
	}
	end, err := s.End()
	if err != nil {
		panic(err)
	}
	return steps, end, s
}

// TestScanVectors: the scanner reports TypeScript's occurrences, in its
// order, at each push of each recorded chunking; the same set at every byte
// split; its end, skipped entries and longest form; and the whole-input
// reference agrees.
func TestScanVectors(t *testing.T) {
	for _, k := range list(field(vectors(t), "cases")) {
		name := field(k, "name").(string)
		entries := entriesOf(field(k, "entries"))
		input := inputOf(t, k)
		sc := field(k, "scan")
		steps, end, s := scan(entries, input, nil)
		whole := slices.Concat(steps...)
		if has(sc, "occurrencesSha256") {
			if sortedHash(whole) != field(sc, "occurrencesSha256").(string) || len(whole) != num(field(sc, "occurrenceCount")) {
				t.Errorf("%s: %d occurrences differ", name, len(whole))
			}
		} else {
			var got []string
			for _, o := range whole {
				got = append(got, occurrence(o))
			}
			if want := occurrencesOf(field(sc, "occurrences")); !slices.Equal(got, want) {
				t.Errorf("%s: occurrences\n got  %q\n want %q", name, got, want)
			}
		}
		if sortedHash(FindWhole(input, entries)) != sortedHash(whole) {
			t.Errorf("%s: the whole-input reference finds other occurrences", name)
		}
		if p := field(sc, "end"); p == nil {
			if end.IncompletePrefix != nil {
				t.Errorf("%s: a scan prefix %+v", name, *end.IncompletePrefix)
			}
		} else if end.IncompletePrefix == nil || end.IncompletePrefix.Entry != num(field(p, "entry")) || end.IncompletePrefix.Item != field(p, "item").(string) || end.IncompletePrefix.Length != num(field(p, "length")) {
			t.Errorf("%s: scan prefix %+v, want %v", name, end.IncompletePrefix, p)
		}
		if !slices.Equal(s.Skipped, strings_(field(sc, "skipped"))) || !slices.Equal(s.SkippedEntries, cutsOf(field(sc, "skippedEntries"))) || s.MaxLength != num(field(sc, "maxLength")) {
			t.Errorf("%s: skipped %q %v, longest %d", name, s.Skipped, s.SkippedEntries, s.MaxLength)
		}
		if len(input) <= 400 {
			for cut := 1; cut < len(input); cut++ {
				st, _, _ := scan(entries, input, []int{cut})
				if sortedHash(slices.Concat(st...)) != sortedHash(whole) {
					t.Errorf("%s: split at %d finds other occurrences", name, cut)
				}
			}
		}
		for ci, c := range list(field(sc, "chunkings")) {
			st, _, _ := scan(entries, input, cutsOf(field(c, "cuts")))
			if !has(c, "steps") {
				if sortedHash(slices.Concat(st...)) != sortedHash(whole) {
					t.Errorf("%s chunking %d: other occurrences", name, ci)
				}
				continue
			}
			want := list(field(c, "steps"))
			for i := range want {
				var got []string
				if i < len(st) {
					for _, o := range st[i] {
						got = append(got, occurrence(o))
					}
				}
				if w := occurrencesOf(want[i]); !slices.Equal(got, w) {
					t.Errorf("%s chunking %d push %d:\n got  %q\n want %q", name, ci, i, got, w)
				}
			}
		}
	}
}

// chunkSource returns each chunk from one Read, then EOF (or a failure),
// as a pipe delivers the child's writes; Close stops it.
type chunkSource struct {
	mu     sync.Mutex
	chunks [][]byte
	fail   bool
	closed bool
}

func (s *chunkSource) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	if len(s.chunks) == 0 {
		if s.fail {
			return 0, fmt.Errorf("read failed")
		}
		return 0, io.EOF
	}
	n := copy(p, s.chunks[0])
	s.chunks[0] = s.chunks[0][n:]
	if len(s.chunks[0]) == 0 {
		s.chunks = s.chunks[1:]
	}
	return n, nil
}

func (s *chunkSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// TestRelayVectors: OutputRedaction's notices, skipped items and relays
// (each stream on its own, an interrupt, a failing stream) give
// TypeScript's bytes.
func TestRelayVectors(t *testing.T) {
	for _, k := range list(field(vectors(t), "relays")) {
		name := field(k, "name").(string)
		r := NewOutputRedaction(entriesOf(field(k, "entries")), RedactionMode(field(k, "mode").(string)))
		if has(k, "interrupt") {
			r.Interrupt()
		}
		if got, want := r.Notices(), strings_(field(k, "notices")); !slices.Equal(got, want) {
			t.Errorf("%s: notices %q, want %q", name, got, want)
		}
		if got, want := r.Skipped, strings_(field(k, "skipped")); !slices.Equal(got, want) {
			t.Errorf("%s: skipped %q, want %q", name, got, want)
		}
		var pairs []Pair
		var sinks []*bytes.Buffer
		for _, s := range list(field(k, "streams")) {
			src := &chunkSource{fail: has(s, "fail")}
			for _, c := range list(field(s, "chunks")) {
				src.chunks = append(src.chunks, b64(t, c))
			}
			sink := &bytes.Buffer{}
			pairs = append(pairs, Pair{Source: src, Dest: sink})
			sinks = append(sinks, sink)
		}
		r.Relay(pairs)
		for i, s := range list(field(k, "streams")) {
			if want := b64(t, field(s, "output")); !bytes.Equal(sinks[i].Bytes(), want) {
				t.Errorf("%s stream %d:\n got  %q\n want %q", name, i, sinks[i].Bytes(), want)
			}
		}
	}
}
