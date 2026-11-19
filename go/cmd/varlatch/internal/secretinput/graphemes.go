// SPDX-License-Identifier: Apache-2.0

package secretinput

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"
	"sync"
)

// Extended grapheme clusters (Unicode Standard Annex #29, rules GB3 to
// GB999), as the hidden prompt's Backspace removes them. The TypeScript
// CLI asks Intl.Segmenter, that is the ICU inside Node.js; Go has no such
// table, so graphemes.json holds each code point's properties as that ICU
// shows them: written by apps/cli/test/go-vectors-values.test.ts, which
// probes Intl.Segmenter code point by code point, and checked there
// against the Node.js that runs it. The segmentation vectors
// (testdata/vectors/values.json, "dropLastCharacter") hold the two to the
// same answers.

//go:embed graphemes.json
var graphemeTable []byte

// Grapheme_Cluster_Break values.
const (
	gcbOther uint8 = iota
	gcbCR
	gcbLF
	gcbControl
	gcbExtend
	gcbZWJ
	gcbSpacingMark
	gcbPrepend
	gcbRI
	gcbL
	gcbV
	gcbT
	gcbLV
	gcbLVT
)

// Indic_Conjunct_Break values.
const (
	incbNone uint8 = iota
	incbConsonant
	incbExtend
	incbLinker
)

var gcbNames = map[string]uint8{
	"Other": gcbOther, "CR": gcbCR, "LF": gcbLF, "Control": gcbControl, "Extend": gcbExtend, "ZWJ": gcbZWJ,
	"SpacingMark": gcbSpacingMark, "Prepend": gcbPrepend, "RI": gcbRI, "L": gcbL, "V": gcbV, "T": gcbT, "LV": gcbLV, "LVT": gcbLVT,
}

var incbNames = map[string]uint8{"": incbNone, "Consonant": incbConsonant, "Extend": incbExtend, "Linker": incbLinker}

type graphemeProps struct {
	gcb  uint8
	incb uint8
	pict bool // Extended_Pictographic
}

type graphemeRange struct {
	lo, hi rune
	props  graphemeProps
}

var (
	graphemeOnce   sync.Once
	graphemeRanges []graphemeRange
)

func loadGraphemes() {
	var file struct {
		Ranges [][3]any `json:"ranges"`
	}
	if err := json.Unmarshal(graphemeTable, &file); err != nil {
		panic("secretinput: graphemes.json: " + err.Error())
	}
	for _, r := range file.Ranges {
		lo, _ := r[0].(float64)
		hi, _ := r[1].(float64)
		key, _ := r[2].(string)
		parts := strings.Split(key, "|")
		if len(parts) != 3 {
			panic("secretinput: graphemes.json: bad key " + key)
		}
		gcb, ok1 := gcbNames[parts[0]]
		incb, ok2 := incbNames[parts[1]]
		if !ok1 || !ok2 {
			panic("secretinput: graphemes.json: bad key " + key)
		}
		graphemeRanges = append(graphemeRanges, graphemeRange{lo: rune(lo), hi: rune(hi), props: graphemeProps{gcb: gcb, incb: incb, pict: parts[2] == "P"}})
	}
}

func propsOf(r rune) graphemeProps {
	graphemeOnce.Do(loadGraphemes)
	i := sort.Search(len(graphemeRanges), func(i int) bool { return graphemeRanges[i].hi >= r })
	if i < len(graphemeRanges) && graphemeRanges[i].lo <= r {
		return graphemeRanges[i].props
	}
	return graphemeProps{}
}

// Boundaries are the byte offsets where text's grapheme clusters start.
func Boundaries(text string) []int {
	var starts []int
	var s segmenter
	for i, r := range text {
		if s.next(propsOf(r)) {
			starts = append(starts, i)
		}
	}
	return starts
}

// lastClusterStart is the byte offset where text's last grapheme cluster
// starts, 0 for empty text.
func lastClusterStart(text string) int {
	last := 0
	var s segmenter
	for i, r := range text {
		if s.next(propsOf(r)) {
			last = i
		}
	}
	return last
}

// segmenter finds the boundaries one code point at a time.
type segmenter struct {
	started bool
	prev    graphemeProps
	// ri counts the regional indicators just before (GB12, GB13).
	ri int
	// emoji: 1 after Extended_Pictographic Extend*, 2 after that and a ZWJ (GB11).
	emoji int
	// conjunct: 1 after an InCB Consonant and InCB Extend*, 2 once an InCB
	// Linker has followed (GB9c).
	conjunct int
}

// next takes the next code point's properties and says whether a cluster
// starts at it.
func (s *segmenter) next(p graphemeProps) bool {
	starts := !s.started || s.breaks(p)
	s.started = true
	switch {
	case p.pict:
		s.emoji = 1
	case p.gcb == gcbExtend && s.emoji == 1:
	case p.gcb == gcbZWJ && s.emoji == 1:
		s.emoji = 2
	default:
		s.emoji = 0
	}
	switch {
	case p.incb == incbConsonant:
		s.conjunct = 1
	case p.incb == incbExtend && s.conjunct > 0:
	case p.incb == incbLinker && s.conjunct > 0:
		s.conjunct = 2
	default:
		s.conjunct = 0
	}
	if p.gcb == gcbRI {
		s.ri++
	} else {
		s.ri = 0
	}
	s.prev = p
	return starts
}

func (s *segmenter) breaks(cur graphemeProps) bool {
	prev := s.prev.gcb
	c := cur.gcb
	control := func(g uint8) bool { return g == gcbControl || g == gcbCR || g == gcbLF }
	switch {
	case prev == gcbCR && c == gcbLF: // GB3
		return false
	case control(prev) || control(c): // GB4, GB5
		return true
	case prev == gcbL && (c == gcbL || c == gcbV || c == gcbLV || c == gcbLVT): // GB6
		return false
	case (prev == gcbLV || prev == gcbV) && (c == gcbV || c == gcbT): // GB7
		return false
	case (prev == gcbLVT || prev == gcbT) && c == gcbT: // GB8
		return false
	case c == gcbExtend || c == gcbZWJ || c == gcbSpacingMark: // GB9, GB9a
		return false
	case prev == gcbPrepend: // GB9b
		return false
	case cur.incb == incbConsonant && s.conjunct == 2: // GB9c
		return false
	case prev == gcbZWJ && cur.pict && s.emoji == 2: // GB11
		return false
	case prev == gcbRI && c == gcbRI && s.ri%2 == 1: // GB12, GB13
		return false
	}
	return true // GB999
}
