// SPDX-License-Identifier: Apache-2.0

// Package targets is substitution targets (ADR-0039 Decisions 1 and 2), as
// packages/protocol/src/targets.ts defines them: where the Broker may
// substitute a Secret's Placeholder in an outbound request. varlatchd
// validates and records them on a Capability; the CLI parses them from the
// command line and enforces them in the Broker.
//
// Canonical syntax: header:<name> (lower-cased), query:<name>,
// json:<RFC 6901 pointer>, or form:<name>.
package targets

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxPerItem is MAX_TARGETS_PER_ITEM: at most this many targets per Secret.
const MaxPerItem = 4

// transportOwned are TRANSPORT_OWNED_HEADERS: headers that are never
// targets, since the Broker sets or removes them itself, or they decide
// how the request is framed, routed or parsed.
var transportOwned = []string{
	"host", "content-length", "transfer-encoding", "expect", "connection", "keep-alive", "upgrade", "te",
	"trailer", "proxy-authorization", "proxy-authenticate", "proxy-connection", "via", "forwarded",
	"content-type", "content-encoding", "accept-encoding", "range", "if-range",
}

// TransportOwnedHeader is isTransportOwnedHeader.
func TransportOwnedHeader(name string) bool {
	lower := strings.ToLower(name)
	return slices.Contains(transportOwned, lower) || strings.HasPrefix(lower, "x-forwarded-")
}

var (
	// headerName is an RFC 9110 token.
	headerName = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")
	// control is /[\u0000-\u001f\u007f]/.
	control = regexp.MustCompile(`[\x00-\x1f\x7f]`)
	// badTilde is /~[^01]|~$/: a ~ not followed by 0 or 1.
	badTilde = regexp.MustCompile(`~(?:[^01]|$)`)
)

// Error is TargetError: a target or a Capability's targets that are not
// valid, its message naming the problem.
type Error struct{ Message string }

func (e *Error) Error() string { return e.Message }

func fail(msg string) error { return &Error{msg} }

// Parse is parseTarget: one target, validated, in its canonical form.
func Parse(raw string) (string, error) {
	kind, location, found := strings.Cut(raw, ":")
	if !found {
		return "", fail(`"` + raw + `" is not a target: expected header:, query:, json:, or form:`)
	}
	switch kind {
	case "header":
		if !headerName.MatchString(location) {
			return "", fail(`"` + location + `" is not a valid header name`)
		}
		if TransportOwnedHeader(location) {
			return "", fail(strings.ToLower(location) + " is a transport-owned header and cannot be a target")
		}
		return kind + ":" + strings.ToLower(location), nil
	case "query", "form":
		if n := utf16Len(location); n == 0 || n > 256 {
			return "", fail("a " + kind + " target needs a name of 1 to 256 characters")
		}
		if control.MatchString(location) {
			return "", fail("a " + kind + " target name cannot contain control characters")
		}
		return raw, nil
	case "json":
		// RFC 6901: "" is the whole document, which is never a string target.
		if !strings.HasPrefix(location, "/") {
			return "", fail(`"` + location + `" is not a JSON Pointer: it must start with /`)
		}
		if badTilde.MatchString(location) {
			return "", fail(`"` + location + `" is not a valid JSON Pointer: ~ must be ~0 or ~1`)
		}
		return raw, nil
	}
	return "", fail(`"` + kind + `" is not a target kind: expected header, query, json, or form`)
}

// Kinds of target (ADR-0064) beside where in a request: a value in a JSON
// document that a Broker hands to a process over a pipe, at an RFC 6901
// pointer (pipe:/token), and one it types into a field, by the name the
// Broker knows the field by (field:Password).
const (
	KindPipe  = "pipe"
	KindField = "field"
)

// Kind is a target's kind.
func Kind(target string) string {
	kind, _, _ := strings.Cut(target, ":")
	return kind
}

// ParseAny is Parse, for a Broker that does more than send requests: pipe and
// field targets too. The CLI's Broker reads its own with Parse, which knows
// neither.
func ParseAny(raw string) (string, error) {
	kind, location, _ := strings.Cut(raw, ":")
	switch kind {
	case KindPipe:
		if len(location) > 512 {
			return "", fail("a pipe target is at most 512 bytes")
		}
		if _, err := Parse("json:" + location); err != nil {
			return "", err
		}
		if !name(location) {
			return "", fail("a pipe target cannot contain ; or =, nor characters that show as nothing")
		}
		return raw, nil
	case KindField:
		if n := utf16Len(location); n == 0 || n > 256 || len(location) > 512 {
			return "", fail("a field target needs a name of 1 to 256 characters, at most 512 bytes")
		}
		if !name(location) || strings.TrimSpace(location) != location {
			return "", fail("a field target name cannot contain ; or =, nor characters that show as nothing, nor begin or end with a blank")
		}
		return raw, nil
	}
	return Parse(raw)
}

// name is whether a field's or a pipe's location can be read as nothing but
// itself, in a list of targets (Describe) too.
func name(location string) bool {
	return Plain(location) && !strings.ContainsAny(location, ";=")
}

// Plain is whether s is text that shows as it is: valid UTF-8, with no
// control, format or blank character but the space, and none that shows as
// nothing.
func Plain(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool { return !plainRune(r) })
}

func plainRune(r rune) bool {
	return unicode.IsPrint(r) && !unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) && !unicode.Is(unicode.Variation_Selector, r)
}

// Recorded is a target as a list of them names it (Describe): what separates
// the list's entries, and what does not show as it is, percent-encoded. The
// targets of a request may hold such characters.
func Recorded(target string) string {
	if Plain(target) && !strings.Contains(target, ";") {
		return target
	}
	var b strings.Builder
	for i := 0; i < len(target); {
		r, n := utf8.DecodeRuneInString(target[i:])
		if r == utf8.RuneError && n <= 1 || r == ';' || !plainRune(r) {
			for _, c := range []byte(target[i : i+n]) {
				fmt.Fprintf(&b, "%%%02X", c)
			}
		} else {
			b.WriteString(target[i : i+n])
		}
		i += n
	}
	return b.String()
}

// Item is one item's targets as sent: the item's name and its targets.
type Item struct {
	Name    string
	Targets []string
}

// Canonical is canonicalTargets: every item has at least one target and at
// most MaxPerItem, none is repeated, and no target names an item outside
// the Capability. given is the targets in the order a JavaScript object
// enumerates them. The result is per item, items and targets sorted as
// JavaScript sorts strings.
func Canonical(items []string, given []Item) ([]Item, error) {
	return canonical(items, given, Parse)
}

// CanonicalAny is Canonical with ParseAny's kinds.
func CanonicalAny(items []string, given []Item) ([]Item, error) {
	return canonical(items, given, ParseAny)
}

func canonical(items []string, given []Item, parse func(string) (string, error)) ([]Item, error) {
	for _, g := range given {
		if !slices.Contains(items, g.Name) {
			return nil, fail("targets name " + g.Name + ", which is not an item of this Capability")
		}
	}
	names := slices.Clone(items)
	slices.SortFunc(names, Compare)
	names = slices.Compact(names)
	out := make([]Item, 0, len(names))
	for _, name := range names {
		var raw []string
		for _, g := range given {
			if g.Name == name {
				raw = g.Targets
			}
		}
		if len(raw) == 0 {
			return nil, fail(name + " has no substitution target")
		}
		if len(raw) > MaxPerItem {
			return nil, fail(name + " has " + strconv.Itoa(len(raw)) + " targets; at most " + strconv.Itoa(MaxPerItem) + " are allowed")
		}
		list := make([]string, len(raw))
		for i, t := range raw {
			c, err := parse(t)
			if err != nil {
				return nil, err
			}
			list[i] = c
		}
		sorted := slices.Clone(list)
		slices.SortFunc(sorted, Compare)
		if len(slices.Compact(slices.Clone(sorted))) != len(sorted) {
			return nil, fail(name + " repeats a target")
		}
		out = append(out, Item{name, sorted})
	}
	return out, nil
}

// Describe is describeTargets, the audit form: ITEM=kind:location;…, names
// and locations only, items sorted, each as Recorded.
func Describe(targets []Item) string {
	sorted := slices.Clone(targets)
	slices.SortStableFunc(sorted, func(a, b Item) int { return Compare(a.Name, b.Name) })
	var parts []string
	for _, it := range sorted {
		for _, t := range it.Targets {
			parts = append(parts, it.Name+"="+Recorded(t))
		}
	}
	return strings.Join(parts, ";")
}

// Compare orders strings as JavaScript's default sort does: by UTF-16 code
// units.
func Compare(a, b string) int {
	ua, ub := units(a), units(b)
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			if ua[i] < ub[i] {
				return -1
			}
			return 1
		}
	}
	return len(ua) - len(ub)
}

func utf16Len(s string) int { return len(units(s)) }

// units is s's UTF-16 code units. A lone surrogate, which JSON text can
// carry and a JavaScript string holds, is in WTF-8 here (its three-byte
// encoding, as Go's JSON value parsing keeps it), and is one unit.
func units(s string) []uint16 {
	var out []uint16
	for i := 0; i < len(s); {
		if i+2 < len(s) && s[i] == 0xed && s[i+1] >= 0xa0 && s[i+1] <= 0xbf && s[i+2] >= 0x80 && s[i+2] <= 0xbf {
			out = append(out, uint16(0xd000|uint16(s[i+1]&0x3f)<<6|uint16(s[i+2]&0x3f)))
			i += 3
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		out = utf16.AppendRune(out, r)
		i += n
	}
	return out
}
