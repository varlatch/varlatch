// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf16"

	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// How a step-up approval's summary names things (ADR-0054 Decision 3;
// domain/approvallabels.ts): the approver must tell, from the words alone,
// exactly which rows an approval is for. A named item is always its name in
// JSON quotes, with every character a reader cannot see escaped, followed
// by the id the approval binds. A summary holds no free text (from the
// database or the request) that is not quoted: names and every other value
// go through Quoted, lists through QuotedList or LabelList, maps through
// QuotedMap; every existing item is named with LabelWithID. The later
// slices' summaries (Requirements, identities, access, people,
// integrations, deletion) build on these.

// invisible is INVISIBLE: controls (Cc), format characters (Cf), line and
// paragraph separators (Zl, Zp), the other default ignorable code points
// (Other_Default_Ignorable_Code_Point and the variation selectors; the rest
// of Default_Ignorable_Code_Point is Cf), U+2800, and every whitespace
// JavaScript's \s matches but the plain ASCII space. The vector test
// compares it with the TypeScript regular expression over every code point.
func invisible(r rune) bool {
	switch {
	case unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector):
		return true
	case r == 0x2800:
		return true
	case r == ' ':
		return false
	}
	return jsWhitespace(r)
}

// jsWhitespace is JavaScript's \s: WhiteSpace (tab, vertical tab, form
// feed, U+FEFF and every Zs) and LineTerminator (LF, CR, U+2028, U+2029).
func jsWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', 0xFEFF, 0x2028, 0x2029:
		return true
	}
	return unicode.Is(unicode.Zs, r)
}

// Quoted is quoted: the name JSON-quoted as JSON.stringify quotes it, then
// every invisible character the JSON text still holds written as
// \u{XXXX}. The escapes cannot be faked: a backslash in the name is
// already doubled.
func Quoted(name string) string {
	var b bytes.Buffer
	jsvalue.Quote(&b, name)
	var out strings.Builder
	for _, r := range b.String() {
		if invisible(r) {
			fmt.Fprintf(&out, `\u{%04X}`, r)
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

// LabelWithID is labelWithId: `role "reader" (rol_…)`, the kind optional.
func LabelWithID(kind, name, id string) string {
	prefix := ""
	if kind != "" {
		prefix = kind + " "
	}
	return prefix + Quoted(name) + " (" + id + ")"
}

// Unnamed is unnamed: an id no row of the Organization has, so free text
// from the request, quoted after words that say so.
func Unnamed(kind, id string) string {
	prefix := ""
	if kind != "" {
		prefix = kind + " "
	}
	return prefix + "with unknown id " + Quoted(id)
}

// LabelList is list: items already rendered, in brackets, separated by ", ".
func LabelList(items []string) string { return "[" + strings.Join(items, ", ") + "]" }

// QuotedList is quotedList: a list of free-text values.
func QuotedList(values []string) string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = Quoted(v)
	}
	return LabelList(out)
}

// jsLess is JavaScript's a < b on strings: by UTF-16 code units.
func jsLess(a, b string) bool {
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b))) < 0
}

// QuotedMap is quotedMap: free-text keys and values, keys in JavaScript's
// sorted order.
func QuotedMap(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int {
		switch {
		case jsLess(a, b):
			return -1
		case jsLess(b, a):
			return 1
		}
		return 0
	})
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = Quoted(k) + ": " + Quoted(m[k])
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
