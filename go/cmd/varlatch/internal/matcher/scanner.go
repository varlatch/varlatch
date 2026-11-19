// SPDX-License-Identifier: Apache-2.0

package matcher

// Occurrence is one complete occurrence a scanner reports: the entry's
// index and item, the form, and its byte range from the stream's start.
type Occurrence struct {
	Entry      int
	Item       string
	Form       FormName
	Start, End int
}

// ScanEnd is what a scanner's clean end gives: a trailing possible start
// of a registered value by entry, item and byte length (never bytes), or
// nil.
type ScanEnd struct {
	IncompletePrefix *ScanPrefix
}

// ScanPrefix is a trailing possible start of a registered value.
type ScanPrefix struct {
	Entry  int
	Item   string
	Length int
}

type scanPattern struct {
	entry  int
	form   FormName
	length int
}

// StreamScanner is scanner.ts's StreamScanner, the reporting side of the
// shared matcher for local scanning: the same forms, minimum length and
// automaton as StreamMatcher, the same complete matches, but nothing is
// replaced or emitted. Every complete occurrence is reported, overlapping
// ones included; an occurrence split across chunks is found once it
// completes (the automaton's state carries its start; no byte is held); a
// trailing possible start is reported at the end by length only.
type StreamScanner struct {
	automaton *automaton
	patterns  []scanPattern
	items     []string
	state     int32
	now       int
	closed    bool
	// Skipped are the items whose value is too short to register, in entry
	// order; SkippedEntries their indexes.
	Skipped        []string
	SkippedEntries []int
	// MaxLength is the longest registered form in bytes: no occurrence is
	// longer.
	MaxLength int
}

// NewStreamScanner registers every form of every entry.
func NewStreamScanner(entries []SecretEntry) *StreamScanner {
	s := &StreamScanner{}
	var forms [][]byte
	for i, e := range entries {
		s.items = append(s.items, e.Item)
		labelled := LabelledFormsOf(e.Value)
		if len(labelled) == 0 {
			s.Skipped = append(s.Skipped, e.Item)
			s.SkippedEntries = append(s.SkippedEntries, i)
			continue
		}
		for _, f := range labelled {
			forms = append(forms, f.Bytes)
			s.patterns = append(s.patterns, scanPattern{entry: i, form: f.Form, length: len(f.Bytes)})
			s.MaxLength = max(s.MaxLength, len(f.Bytes))
		}
	}
	s.automaton = newAutomaton(forms)
	return s
}

// Offset is the number of bytes consumed since the start (or the last
// Reset).
func (s *StreamScanner) Offset() int { return s.now }

// Reset starts a new stream with the same registered values.
func (s *StreamScanner) Reset() {
	s.state, s.now, s.closed = 0, 0, false
}

// Push consumes a chunk and returns the occurrences that complete inside
// it, in the order of their end.
func (s *StreamScanner) Push(chunk []byte) ([]Occurrence, error) {
	if s.closed {
		return nil, ErrClosed
	}
	var found []Occurrence
	base := s.now
	state := s.state
	for i, b := range chunk {
		state = s.automaton.step(state, b)
		for _, id := range s.automaton.matches(state) {
			p := s.patterns[id]
			end := base + i + 1
			found = append(found, Occurrence{Entry: p.entry, Item: s.items[p.entry], Form: p.form, Start: end - p.length, End: end})
		}
	}
	s.state = state
	s.now = base + len(chunk)
	return found, nil
}

// End is a clean end: no occurrence can complete any more.
func (s *StreamScanner) End() (ScanEnd, error) {
	if s.closed {
		return ScanEnd{}, ErrClosed
	}
	s.closed = true
	held, length := s.automaton.heldPrefixOf(s.state), s.automaton.hold(s.state)
	if held < 0 || length == 0 {
		return ScanEnd{}, nil
	}
	entry := s.patterns[held].entry
	return ScanEnd{IncompletePrefix: &ScanPrefix{Entry: entry, Item: s.items[entry], Length: length}}, nil
}
