// SPDX-License-Identifier: Apache-2.0

package matcher

// automaton is automaton.ts's Automaton: a byte-level Aho-Corasick
// automaton. Besides the goto and failure links and the outputs, each state
// records its hold: the length of the longest suffix of the input so far
// that is a proper prefix of some pattern (the deepest state on its failure
// chain that still has children). ADR-0039 Decision 19 proves that no future
// match can include a byte more than hold bytes before the current end.
//
// Stepping follows failure links, each of which shortens the matched
// suffix, so a stream of n bytes takes O(n) steps plus the matches it
// reports.
type automaton struct {
	next  []map[byte]int32
	fail  []int32
	depth []int32
	// own are the patterns ending exactly at a state; outputs every pattern
	// ending at it (its own, then its failure chain's), precomputed.
	own     [][]int32
	outputs [][]int32
	// rootNext is the root's transitions as a dense table: most input bytes
	// fail at the root. -1 is no transition (0, the root, is never a child).
	rootNext  [256]int32
	holdDepth []int32
	// below is some pattern reachable below a state with children: the
	// first one, in the patterns' order, that passes through it.
	below []int32
	// The transitions once built, flat: state s's are edgeByte and edgeTo
	// from edgeStart[s] to edgeStart[s+1]. Most states have one child, so
	// a scan beats a map; the root has rootNext.
	edgeStart []int32
	edgeByte  []byte
	edgeTo    []int32
}

func newAutomaton(patterns [][]byte) *automaton {
	a := &automaton{next: []map[byte]int32{{}}, fail: []int32{0}, depth: []int32{0}, own: [][]int32{nil}, outputs: [][]int32{nil}, holdDepth: []int32{0}, below: []int32{-1}}
	// The root's children in the order they were made, as a Map keeps them.
	var rootOrder []byte
	order := map[int32][]byte{} // each state's child bytes in insertion order
	for id, pattern := range patterns {
		state := int32(0)
		for _, b := range pattern {
			to, ok := a.next[state][b]
			if !ok {
				to = int32(len(a.next))
				a.next = append(a.next, map[byte]int32{})
				a.fail = append(a.fail, 0)
				a.depth = append(a.depth, a.depth[state]+1)
				a.own = append(a.own, nil)
				a.outputs = append(a.outputs, nil)
				a.holdDepth = append(a.holdDepth, 0)
				a.below = append(a.below, -1)
				a.next[state][b] = to
				if state == 0 {
					rootOrder = append(rootOrder, b)
				}
				order[state] = append(order[state], b)
			}
			if a.below[state] == -1 {
				a.below[state] = int32(id)
			}
			state = to
		}
		a.own[state] = append(a.own[state], int32(id))
	}
	for i := range a.rootNext {
		a.rootNext[i] = -1
	}
	for _, b := range rootOrder {
		a.rootNext[b] = a.next[0][b]
	}
	// Breadth-first: failure links, outputs and hold depths.
	var queue []int32
	for _, b := range rootOrder {
		queue = append(queue, a.next[0][b])
	}
	for i := 0; i < len(queue); i++ {
		state := queue[i]
		f := a.fail[state]
		// The failure state is shallower, so its outputs are complete.
		a.outputs[state] = append(append([]int32(nil), a.own[state]...), a.outputs[f]...)
		if len(a.next[state]) > 0 {
			a.holdDepth[state] = a.depth[state]
		} else {
			a.holdDepth[state] = a.holdDepth[f]
		}
		for _, b := range order[state] {
			child := a.next[state][b]
			g := f
			for g != 0 {
				if _, ok := a.next[g][b]; ok {
					break
				}
				g = a.fail[g]
			}
			if to, ok := a.next[g][b]; ok && to != child {
				a.fail[child] = to
			} else {
				a.fail[child] = 0
			}
			queue = append(queue, child)
		}
	}
	a.holdDepth[0] = 0
	a.edgeStart = make([]int32, len(a.next)+1)
	for st := range a.next {
		a.edgeStart[st] = int32(len(a.edgeByte))
		for _, b := range order[int32(st)] {
			a.edgeByte = append(a.edgeByte, b)
			a.edgeTo = append(a.edgeTo, a.next[st][b])
		}
	}
	a.edgeStart[len(a.next)] = int32(len(a.edgeByte))
	a.next = nil // the maps are only for building
	return a
}

// child is state s's transition on b, or -1.
func (a *automaton) child(s int32, b byte) int32 {
	for e := a.edgeStart[s]; e < a.edgeStart[s+1]; e++ {
		if a.edgeByte[e] == b {
			return a.edgeTo[e]
		}
	}
	return -1
}

// children is how many transitions state s has.
func (a *automaton) children(s int32) int32 { return a.edgeStart[s+1] - a.edgeStart[s] }

// step is the state after one more byte.
func (a *automaton) step(state int32, b byte) int32 {
	s := state
	for {
		if s == 0 {
			if to := a.rootNext[b]; to >= 0 {
				return to
			}
			return 0
		}
		if to := a.child(s, b); to >= 0 {
			return to
		}
		s = a.fail[s]
	}
}

// matches are the ids of every pattern ending at state; shared, never to
// be modified.
func (a *automaton) matches(state int32) []int32 { return a.outputs[state] }

// hold is the state's hold length.
func (a *automaton) hold(state int32) int { return int(a.holdDepth[state]) }

// heldPrefixOf is a pattern the held suffix at state is a proper prefix of,
// or -1.
func (a *automaton) heldPrefixOf(state int32) int {
	s := state
	for s != 0 && a.children(s) == 0 {
		s = a.fail[s]
	}
	if s == 0 {
		return -1
	}
	return int(a.below[s])
}
