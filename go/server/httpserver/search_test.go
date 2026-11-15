// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"fmt"
	"math"
	"testing"
	"unicode/utf16"
)

// utf16Order is the reference: JavaScript's a < b on the strings' UTF-16
// code units.
func utf16Order(a, b string) int {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			if ua[i] < ub[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(ua) < len(ub):
		return -1
	case len(ua) > len(ub):
		return 1
	}
	return 0
}

func TestJSCompareIsUTF16Order(t *testing.T) {
	// Supplementary code points against BMP ones on both sides of the
	// surrogate range, prefixes, an ill-formed byte, case and the empty
	// string.
	words := []string{"", "a", "A", "ab", "a\x00", "aé", "a퟿", "a", "a�", "a￿", "a😀", "a\U00010000", "a\U0010FFFF",
		"😀", "￿", "", "z", "Z", "a\xff", "\xffa", "API_KEY", "api_key", "PORT", "PORT_2"}
	for _, a := range words {
		for _, b := range words {
			if got, want := jsCompare(a, b), utf16Order(a, b); got != want {
				t.Errorf("jsCompare(%q, %q) = %d, want %d", a, b, got, want)
			}
		}
	}
}

// Every hit is sorted before the page is cut, so the sort must stay
// n log n on any input: names in reverse order were quadratic.
func TestSortHitsIsNLogN(t *testing.T) {
	const n = 20_000
	hits := make([]*searchHit, n)
	for i := range hits {
		name := fmt.Sprintf("ITEM_%06d", n-i)
		hits[i] = &searchHit{name: name, key: [3]string{"api", name, "prj_x"}}
	}
	comparisons := 0
	sortHits(hits, func(a, b [3]string) int { comparisons++; return compareKeys(a, b) })
	for i := 1; i < n; i++ {
		if compareKeys(hits[i-1].key, hits[i].key) >= 0 {
			t.Fatalf("not sorted at %d: %v then %v", i, hits[i-1].key, hits[i].key)
		}
	}
	// An insertion sort makes n²/2 (200,000,000) here.
	if bound := int(2 * n * math.Log2(n)); comparisons > bound {
		t.Fatalf("%d comparisons for %d reverse-ordered hits, more than 2 n log2 n (%d)", comparisons, n, bound)
	}
	t.Logf("%d comparisons", comparisons)
}

// Equal keys keep their order (one hit per Project and name, but the
// sort is stable regardless).
func TestSortHitsIsStable(t *testing.T) {
	hits := []*searchHit{
		{name: "b1", key: [3]string{"p", "B", "1"}},
		{name: "a1", key: [3]string{"p", "A", "1"}},
		{name: "b2", key: [3]string{"p", "B", "1"}},
		{name: "a2", key: [3]string{"p", "A", "1"}},
	}
	sortHits(hits, compareKeys)
	var got []string
	for _, h := range hits {
		got = append(got, h.name)
	}
	if fmt.Sprint(got) != "[a1 a2 b1 b2]" {
		t.Fatalf("order %v", got)
	}
}
