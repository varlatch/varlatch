// SPDX-License-Identifier: Apache-2.0

package matcher

import (
	"errors"
	"slices"
)

// SecretEntry is SecretEntry: a value and the item name reported in
// diagnostics and used for tie-breaks.
type SecretEntry struct {
	Item  string
	Value string
}

// ErrClosed is the error of a matcher or scanner used after its end.
var ErrClosed = errors.New("matcher already closed")

// key is a match's ordering key: the earliest start, then the longest,
// then the item name that sorts first (byte order, as Buffer.compare).
type key struct {
	start, length int
	item          string
}

func less(a, b key) bool {
	if a.start != b.start {
		return a.start < b.start
	}
	if a.length != b.length {
		return a.length > b.length
	}
	return a.item < b.item
}

// segment is held output: raw bytes not covered by any region, or a
// pending region (metadata only, never its bytes).
type segment struct {
	region bool
	start  int
	bytes  []byte // raw
	end    int    // region
	key    key    // region
}

// EndReport is what a clean end gives: the final bytes, and an incomplete
// trailing prefix of a registered value by item and byte length (never
// its bytes), or nil.
type EndReport struct {
	Output           []byte
	IncompletePrefix *Prefix
}

// Prefix is an incomplete trailing prefix of a registered value.
type Prefix struct {
	Item   string
	Length int
}

// StreamMatcher is matcher.ts's StreamMatcher (ADR-0039 Decisions 17 to 19):
//   - every occurrence of every registered form is found, overlapping ones
//     included; a region is a maximal union of matches sharing at least one
//     byte (matches that only touch stay separate);
//   - each region is replaced by exactly one replacement, that of the match
//     with the minimum key (start, -length, item);
//   - only what can still change is held: the raw bytes not covered by a
//     region in the last hold bytes, and the pending regions as metadata;
//     everything before min(now - hold, the earliest pending region) is
//     final and is emitted;
//   - nothing is released on a timer; a clean end emits the pending regions
//     as replacements and the held bytes outside them, and Abort discards
//     everything held.
type StreamMatcher struct {
	automaton   *automaton
	patterns    []pattern
	replacement func(item string) []byte
	state       int32
	now         int
	segments    []segment
	// scratch is addMatch's working space, reused so that a match costs no
	// allocation.
	scratch []segment
	// found is Push's list of the chunk's matches, reused.
	found  []key
	closed bool
	// Skipped are the items whose value is too short to register.
	Skipped []string
	// Replaced counts the regions replaced, by winning item.
	Replaced map[string]int
}

type pattern struct {
	item   string
	length int
}

// compiled is a set of entries registered once: the automaton (read-only
// once built, so streams may share it), its patterns, and the items too
// short to register.
type compiled struct {
	automaton *automaton
	patterns  []pattern
	skipped   []string
}

func compile(entries []SecretEntry) *compiled {
	c := &compiled{}
	var forms [][]byte
	for _, e := range entries {
		fs := FormsOf(e.Value)
		if len(fs) == 0 {
			c.skipped = append(c.skipped, e.Item)
			continue
		}
		for _, f := range fs {
			forms = append(forms, f)
			c.patterns = append(c.patterns, pattern{e.Item, len(f)})
		}
	}
	c.automaton = newAutomaton(forms)
	return c
}

// NewStreamMatcher registers every form of every entry.
func NewStreamMatcher(entries []SecretEntry, replacement func(item string) []byte) *StreamMatcher {
	return compile(entries).matcher(replacement)
}

// matcher is a fresh stream over the compiled entries.
func (c *compiled) matcher(replacement func(item string) []byte) *StreamMatcher {
	return &StreamMatcher{automaton: c.automaton, patterns: c.patterns, replacement: replacement, Replaced: map[string]int{}, Skipped: slices.Clone(c.skipped)}
}

// PendingRegions is the number of pending regions (the bound of ADR-0039
// Decision 19 is 1 + floor(hold / 8)).
func (m *StreamMatcher) PendingRegions() int {
	n := 0
	for _, s := range m.segments {
		if s.region {
			n++
		}
	}
	return n
}

// HeldBytes is the number of raw bytes held.
func (m *StreamMatcher) HeldBytes() int {
	n := 0
	for _, s := range m.segments {
		if !s.region {
			n += len(s.bytes)
		}
	}
	return n
}

// Hold is the current hold length d.
func (m *StreamMatcher) Hold() int { return m.automaton.hold(m.state) }

// Push consumes a chunk and returns the bytes that are final. Matches are
// found byte by byte and merged afterwards: the merge is order-independent
// and now - hold never decreases, so emitting once per chunk gives the
// bytes emitting after every byte would. The chunk is never kept: what
// stays held is copied.
func (m *StreamMatcher) Push(chunk []byte) ([]byte, error) {
	if m.closed {
		return nil, ErrClosed
	}
	base := m.now
	found := m.found[:0]
	state := m.state
	for i, b := range chunk {
		state = m.automaton.step(state, b)
		for _, id := range m.automaton.matches(state) {
			p := m.patterns[id]
			found = append(found, key{start: base + i + 1 - p.length, length: p.length, item: p.item})
		}
	}
	m.state = state
	m.now = base + len(chunk)
	if len(chunk) > 0 {
		m.segments = append(m.segments, segment{start: base, bytes: chunk})
	}
	for _, k := range found {
		m.addMatch(k)
	}
	m.found = found[:0]
	var out []byte
	m.emitFinal(m.now-m.automaton.hold(state), &out)
	// What stays held of this chunk still aliases the caller's buffer: copy
	// it (the segments from earlier chunks are copies already).
	for i := range m.segments {
		if !m.segments[i].region && m.segments[i].start >= base {
			m.segments[i].bytes = slices.Clone(m.segments[i].bytes)
		}
	}
	return out, nil
}

// End is a clean end: no match can complete any more.
func (m *StreamMatcher) End() (EndReport, error) {
	if m.closed {
		return EndReport{}, ErrClosed
	}
	m.closed = true
	var out []byte
	for _, s := range m.segments {
		m.emitSegment(s, &out)
	}
	m.segments = nil
	report := EndReport{Output: out}
	if held, hold := m.automaton.heldPrefixOf(m.state), m.automaton.hold(m.state); held >= 0 && hold > 0 {
		report.IncompletePrefix = &Prefix{Item: m.patterns[held].item, Length: hold}
	}
	return report, nil
}

// Abort is a cancellation, an aborted stream or a timeout: everything held
// is discarded and nothing is released.
func (m *StreamMatcher) Abort() {
	m.closed = true
	m.segments = nil
}

// addMatch merges a match into the pending segments. The segments are
// disjoint and ordered by start, so their ends are ordered too: only the
// trailing ones that end after the match's start can overlap it, and the
// rest are kept as they are without being looked at (matcher.ts walks
// them all, with the same result; a chunk with many matches would make
// that quadratic).
func (m *StreamMatcher) addMatch(match key) {
	start, end := match.start, match.start+match.length
	i := len(m.segments)
	for i > 0 && segmentEnd(m.segments[i-1]) > start {
		i--
	}
	mStart, mEnd, mKey := start, end, match
	tail := m.scratch[:0]
	for _, s := range m.segments[i:] {
		if s.region {
			// Overlap is sharing at least one byte; touching is not.
			if s.start < end && start < s.end {
				mStart, mEnd = min(mStart, s.start), max(mEnd, s.end)
				if less(s.key, mKey) {
					mKey = s.key
				}
				continue
			}
			tail = append(tail, s)
			continue
		}
		// Raw bytes inside the match are covered from now on; the rest stays.
		rawEnd := s.start + len(s.bytes)
		if rawEnd <= start || s.start >= end {
			tail = append(tail, s)
			continue
		}
		if s.start < start {
			tail = append(tail, segment{start: s.start, bytes: s.bytes[:start-s.start]})
		}
		if rawEnd > end {
			tail = append(tail, segment{start: end, bytes: s.bytes[end-s.start:]})
		}
	}
	region := segment{region: true, start: mStart, end: mEnd, key: mKey}
	// Segments stay ordered by start.
	at := len(tail)
	for j, s := range tail {
		if s.start > region.start {
			at = j
			break
		}
	}
	tail = slices.Insert(tail, at, region)
	// In place: tail is the scratch space, built before anything is
	// overwritten, and the head (every segment before i) stays where it is.
	m.segments = append(m.segments[:i], tail...)
	m.scratch = tail[:0]
}

func segmentEnd(s segment) int {
	if s.region {
		return s.end
	}
	return s.start + len(s.bytes)
}

// emitFinal emits, in order, every segment that ends before boundary.
func (m *StreamMatcher) emitFinal(boundary int, out *[]byte) {
	for len(m.segments) > 0 {
		first := m.segments[0]
		if first.region {
			if first.end > boundary {
				return
			}
			m.emitSegment(first, out)
			m.segments = m.segments[1:]
			continue
		}
		final := min(len(first.bytes), boundary-first.start)
		if final <= 0 {
			return
		}
		*out = append(*out, first.bytes[:final]...)
		if final == len(first.bytes) {
			m.segments = m.segments[1:]
			continue
		}
		m.segments[0] = segment{start: first.start + final, bytes: first.bytes[final:]}
		return
	}
}

func (m *StreamMatcher) emitSegment(s segment, out *[]byte) {
	if !s.region {
		*out = append(*out, s.bytes...)
		return
	}
	m.Replaced[s.key.item]++
	*out = append(*out, m.replacement(s.key.item)...)
}
