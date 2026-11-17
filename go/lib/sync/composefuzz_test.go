// SPDX-License-Identifier: Apache-2.0

package sync

import (
	"os"
	"strconv"
	"testing"
)

// TestComposeFuzzDifferential replays packages/sync/test/
// go-compose-fuzz.test.ts's mutants (the file VARLATCH_COMPOSE_FUZZ names;
// skipped without it) and fails on each one where Go's verdict is more
// confident than TypeScript's: Go checked the file where TypeScript could
// not (or threw), or both checked it and the verdicts differ. Unreadable in
// Go where TypeScript read the file is the safe side, and only counted.
func TestComposeFuzzDifferential(t *testing.T) {
	path := os.Getenv("VARLATCH_COMPOSE_FUZZ")
	if path == "" {
		t.Skip("VARLATCH_COMPOSE_FUZZ names no file of mutants")
	}
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := parseJSON(text)
	if err != nil {
		t.Fatal(err)
	}
	mutants := v.(Object).get("mutants").([]any)
	nSame, nSafer, nWorse := 0, 0, 0
	for i, m := range mutants {
		c := m.(Object)
		version, _ := decodeNumber(c.get("version"))
		var names []string
		for _, n := range c.get("names").([]any) {
			names = append(names, n.(string))
		}
		got := ClassifyComposeUsage(optString(c.get("raw")), optString(c.get("generated")), version, names)
		_, threw := c.Get("throws")
		want := c.get("result")
		switch {
		case !threw && same(encReport(got), want):
			nSame++
		case !got.Checked:
			nSafer++
		default:
			nWorse++
			if nWorse <= 30 {
				t.Errorf("mutant %d: Go %s\n  TypeScript %s (throws %s)\n  raw %s\n  generated %s", i, stringify(encReport(got)),
					stringify(want), stringify(c.get("throws")), strconv.Quote(*optString(c.get("raw"))), strconv.Quote(*optString(c.get("generated"))))
			}
		}
	}
	t.Logf("%d mutants: %d the same verdict, %d unreadable in Go only (the safe side), %d more confident in Go", len(mutants), nSame, nSafer, nWorse)
	if nWorse > 0 {
		t.Errorf("%d mutants where Go is more confident than TypeScript", nWorse)
	}
}
