// SPDX-License-Identifier: Apache-2.0

package matcher

import (
	"bytes"
	"sort"
)

// ScrubWhole is reference.ts's scrubWhole, the whole-input reference for
// ADR-0039 Decision 18, written differently from the streaming matcher on
// purpose (a naive search over the complete input: no automaton, no
// hold-back) so that each checks the other. For tests: it needs the whole
// input in memory, and its search is not linear.
func ScrubWhole(input []byte, entries []SecretEntry, replacement func(item string) []byte) []byte {
	type match struct {
		start, end int
		item       string
	}
	var matches []match
	for _, e := range entries {
		for _, form := range FormsOf(e.Value) {
			for at := 0; ; at++ {
				i := bytes.Index(input[at:], form)
				if i < 0 {
					break
				}
				at += i
				matches = append(matches, match{at, at + len(form), e.Item})
			}
		}
	}
	// Regions: unions of matches sharing at least one byte.
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].start != matches[j].start {
			return matches[i].start < matches[j].start
		}
		return matches[i].end > matches[j].end
	})
	type region struct {
		start, end int
		members    []match
	}
	var regions []*region
	for _, m := range matches {
		if n := len(regions); n > 0 && m.start < regions[n-1].end {
			last := regions[n-1]
			last.end = max(last.end, m.end)
			last.members = append(last.members, m)
			continue
		}
		regions = append(regions, &region{m.start, m.end, []match{m}})
	}
	var out []byte
	at := 0
	for _, r := range regions {
		out = append(out, input[at:r.start]...)
		// Earliest start, then longest, then the item name that sorts first.
		winner := r.members[0]
		for _, m := range r.members[1:] {
			if m.start < winner.start || m.start == winner.start && (m.end-m.start > winner.end-winner.start ||
				m.end-m.start == winner.end-winner.start && m.item < winner.item) {
				winner = m
			}
		}
		out = append(out, replacement(winner.item)...)
		at = r.end
	}
	return append(out, input[at:]...)
}

// FindWhole is reference.ts's findWhole, the whole-input reference for
// scanning: every occurrence of every form of every entry, by a naive
// search over the complete input. For tests.
func FindWhole(input []byte, entries []SecretEntry) []Occurrence {
	var found []Occurrence
	for i, e := range entries {
		for _, f := range LabelledFormsOf(e.Value) {
			for at := 0; ; at++ {
				j := bytes.Index(input[at:], f.Bytes)
				if j < 0 {
					break
				}
				at += j
				found = append(found, Occurrence{Entry: i, Item: e.Item, Form: f.Form, Start: at, End: at + len(f.Bytes)})
			}
		}
	}
	return found
}
