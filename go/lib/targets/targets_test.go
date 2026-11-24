// SPDX-License-Identifier: Apache-2.0

package targets

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// Compare is JavaScript's sort: by UTF-16 code units, so an astral
// character (a surrogate pair, D83D…) sorts before U+FF61, which byte
// order puts after it; a lone surrogate (WTF-8) is one unit.
func TestCompareIsJavaScriptsOrder(t *testing.T) {
	list := []string{"｡", "\U0001F600", "a", "B", "\xed\xa0\x80", ""}
	slices.SortFunc(list, Compare)
	want := []string{"", "B", "a", "\xed\xa0\x80", "\U0001F600", "｡"}
	if !slices.Equal(list, want) {
		t.Fatalf("%q, want %q", list, want)
	}
	if n := utf16Len("\U0001F600\xed\xa0\x80a"); n != 4 {
		t.Fatalf("%d UTF-16 units, want 4", n)
	}
}

func TestParse(t *testing.T) {
	for raw, want := range map[string]string{
		"header:X-Api-Key": "header:x-api-key",
		"query:Key":        "query:Key",
		"json:/a~0b/~1":    "json:/a~0b/~1",
		"form:f:g":         "form:f:g",
	} {
		if got, err := Parse(raw); err != nil || got != want {
			t.Errorf("Parse(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for raw, msg := range map[string]string{
		"header":                "\"header\" is not a target: expected header:, query:, json:, or form:",
		"header:Host":           "host is a transport-owned header and cannot be a target",
		"header:X-Forwarded-At": "x-forwarded-at is a transport-owned header and cannot be a target",
		"header:a:b":            "\"a:b\" is not a valid header name",
		"query:" + strings.Repeat("\U0001F600", 128) + "x": "a query target needs a name of 1 to 256 characters",
		"form:\x7f": "a form target name cannot contain control characters",
		"json:/a~":  "\"/a~\" is not a valid JSON Pointer: ~ must be ~0 or ~1",
		"%s:x":      "\"%s\" is not a target kind: expected header, query, json, or form",
	} {
		_, err := Parse(raw)
		var e *Error
		if !errors.As(err, &e) || e.Message != msg {
			t.Errorf("Parse(%q): %v, want %q", raw, err, msg)
		}
	}
}

func TestCanonical(t *testing.T) {
	got, err := Canonical([]string{"B", "A", "B"}, []Item{{"B", []string{"query:z", "header:X"}}, {"A", []string{"form:f"}}})
	if err != nil {
		t.Fatal(err)
	}
	want := []Item{{"A", []string{"form:f"}}, {"B", []string{"header:x", "query:z"}}}
	if !slices.EqualFunc(got, want, func(a, b Item) bool { return a.Name == b.Name && slices.Equal(a.Targets, b.Targets) }) {
		t.Fatalf("%v, want %v", got, want)
	}
	if d := Describe(got); d != "A=form:f;B=header:x;B=query:z" {
		t.Fatalf("Describe: %q", d)
	}
	for _, c := range []struct {
		items []string
		given []Item
		msg   string
	}{
		{[]string{"A"}, []Item{{"Z", []string{"form:f"}}, {"A", nil}}, "targets name Z, which is not an item of this Capability"},
		{[]string{"A", "B"}, []Item{{"A", []string{"form:f"}}}, "B has no substitution target"},
		{[]string{"A"}, []Item{{"A", []string{"form:a", "form:b", "form:c", "form:d", "form:e"}}}, "A has 5 targets; at most 4 are allowed"},
		{[]string{"A"}, []Item{{"A", []string{"header:K", "header:k"}}}, "A repeats a target"},
	} {
		_, err := Canonical(c.items, c.given)
		var e *Error
		if !errors.As(err, &e) || e.Message != c.msg {
			t.Errorf("%v %v: %v, want %q", c.items, c.given, err, c.msg)
		}
	}
}

// Parse is the CLI's Broker's, which sends requests alone: it refuses the
// kinds of a Broker that types or pipes (ADR-0064), and ParseAny takes them
// beside its own.
func TestParseAny(t *testing.T) {
	for raw, want := range map[string]string{
		"pipe:/token": "pipe:/token", "pipe:/a~0b/~1/0": "pipe:/a~0b/~1/0", "field:Password": "field:Password", "field:form:pw": "field:form:pw",
		"header:X-Api-Key": "header:x-api-key", "json:/a": "json:/a",
	} {
		if got, err := ParseAny(raw); err != nil || got != want {
			t.Errorf("ParseAny(%q) = %q, %v", raw, got, err)
		}
	}
	for _, raw := range []string{"pipe:", "pipe:token", "pipe:/a~2", "pipe:/a~", "pipe:/a\nb", "pipe:/" + strings.Repeat("a", 512), "field:", "field:a\x00", "field:" + strings.Repeat("a", 257),
		"PIPE:/a", "Field:a", "keyboard:a", "field", "", "header:host"} {
		if got, err := ParseAny(raw); err == nil {
			t.Errorf("ParseAny(%q) = %q", raw, got)
		}
	}
	for _, raw := range []string{"pipe:/token", "field:Password"} {
		var e *Error
		if _, err := Parse(raw); !errors.As(err, &e) || !strings.Contains(e.Message, "is not a target kind") {
			t.Errorf("Parse(%q): %v", raw, err)
		}
		if _, err := Canonical([]string{"A"}, []Item{{"A", []string{raw}}}); err == nil {
			t.Errorf("Canonical takes %q", raw)
		}
		if out, err := CanonicalAny([]string{"A"}, []Item{{"A", []string{raw}}}); err != nil || len(out) != 1 || Kind(out[0].Targets[0]) != Kind(raw) {
			t.Errorf("CanonicalAny(%q): %v, %v", raw, out, err)
		}
	}
}
