// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import (
	"errors"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/domainerr"
)

func lookupIn(m map[string]string) func(string) (string, bool) {
	return func(n string) (string, bool) { v, ok := m[n]; return v, ok }
}

// The cases the fixtures do not reach: the limits, and what stays literal.
func TestExpandReferences(t *testing.T) {
	values := map[string]string{"A": "a", "B": "<${A}>", "SELF": "${SELF}"}
	for _, c := range []struct{ raw, want, literal string }{
		{"x${A}y", "xay", ""},
		{"${B}${B}", "<a><a>", ""},
		{"$${A} ${A}", "${A} a", ""},
		{"${MISSING}", "${MISSING}", "MISSING"},
		{"${SELF}", "${SELF}", "SELF"},
		{"${lower_case1}", "${lower_case1}", "lower_case1"},
		{"${1BAD} $ {A} ${A", "${1BAD} $ {A} ${A", ""},
	} {
		lit := literalSet{}
		got, err := ExpandReferences(c.raw, lookupIn(values), lit.add)
		if err != nil || got != c.want || strings.Join(lit.sorted(), ",") != c.literal {
			t.Errorf("%q: %q %v %v, want %q %q", c.raw, got, lit.sorted(), err, c.want, c.literal)
		}
	}
	// A chain deeper than eight stays literal where it stops.
	chain := map[string]string{}
	for i := 0; i < 12; i++ {
		chain[string(rune('A'+i))] = "${" + string(rune('A'+i+1)) + "}"
	}
	chain["M"] = "end"
	got, err := ExpandReferences("${A}", lookupIn(chain), nil)
	if err != nil || got != "${I}" {
		t.Errorf("deep chain: %q %v", got, err)
	}
	// Over 1 MiB expanded, or more than 10,000 references: VALIDATION_FAILED.
	big := map[string]string{"X": strings.Repeat("x", 300_000)}
	_, err = ExpandReferences(strings.Repeat("${X}", 4), lookupIn(big), nil)
	if de := (*domainerr.Error)(nil); !errors.As(err, &de) || de.Code != "VALIDATION_FAILED" || de.Message != "expanded value exceeds 1 MiB" {
		t.Errorf("size limit: %v", err)
	}
	_, err = ExpandReferences(strings.Repeat("${Z}", 10_001), lookupIn(nil), nil)
	if de := (*domainerr.Error)(nil); !errors.As(err, &de) || de.Message != "reference expansion exceeds work limit" {
		t.Errorf("work limit: %v", err)
	}
	if names := ReferencedNames("$${A}${B}${B}${C"); strings.Join(names, ",") != "B,B" {
		t.Errorf("ReferencedNames: %v", names)
	}
}

// decode is Node's Buffer.toString("utf8"): one U+FFFD per maximal
// subpart of an ill-formed sequence (the WHATWG decoder).
func TestDecodeLikeNode(t *testing.T) {
	for _, c := range []struct {
		in   []byte
		want string
	}{
		{[]byte("plain é ✓"), "plain é ✓"},
		{[]byte{0xff}, "�"},
		{[]byte{0xe2, 0x9c}, "�"},
		{[]byte{0xe2, 0x9c, 'a'}, "�a"},
		{[]byte{0xed, 0xa0, 0x80}, "���"}, // an encoded surrogate
		{[]byte{0xf0, 0x80, 0x80}, "���"}, // overlong
		{[]byte{0xf4, 0x90, 0x80, 0x80}, "����"},
		{[]byte{0xc0, 0xaf}, "��"},
		{[]byte{'a', 0xf0, 0x9f, 0x98}, "a�"},
	} {
		if got := decode(c.in); got != c.want {
			t.Errorf("%x: %q, want %q", c.in, got, c.want)
		}
	}
}

// The disclosure body as zod's union reads it (the fixtures hold the
// TypeScript server's answers to the same shapes).
func TestParseDisclosure(t *testing.T) {
	for _, c := range []struct {
		body string
		want string // the request, or the error message
	}{
		{`{"scope":"all-authorized-secrets"}`, "all"},
		{`{"items":["A","A"],"purpose":"scan"}`, "items A,A scan"},
		{`{"items":["A"],"scope":"all-authorized-secrets"}`, "items A "},
		{`{"items":[],"scope":"all-authorized-secrets"}`, "all"},
		{`{"items":["",""]}`, "items.0: Too small: expected string to have >=1 characters; items.1: Too small: expected string to have >=1 characters"},
		{`{"items":[],"purpose":"backup"}`, "(root): Invalid input"},
		{`{"items":[""],"scope":"x"}`, "items.0: Too small: expected string to have >=1 characters"},
		{`{"scope":"all-authorized-secrets","purpose":null}`, "(root): Invalid input"},
		{`"items"`, "(root): Invalid input"},
		{`{"items":["A"],"items":[]}`, "items: Too small: expected array to have >=1 items"},
	} {
		got, err := parseDisclosure([]byte(c.body))
		var s string
		switch {
		case err != nil:
			s = err.(*domainerr.Error).Message
		case got.all:
			s = "all"
		default:
			s = "items " + strings.Join(got.items, ",") + " " + got.purpose
		}
		if s != c.want {
			t.Errorf("%s: %q, want %q", c.body, s, c.want)
		}
	}
	if _, err := parseDisclosure([]byte("items=A")); !errors.Is(err, errNotJSON) {
		t.Errorf("not JSON: %v", err)
	}
}
