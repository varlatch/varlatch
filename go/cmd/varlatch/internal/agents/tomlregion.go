// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/toml"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The CLI's tables in a TOML file (ADR-0043 Decisions 8 and 9), a port of
// apps/cli/src/agents/toml.ts: one marked region at the end of the file,
// changed only when the parser (smol-toml 1.9.0's, internal/toml) confirms
// the file then says what it said before plus exactly the change.

const (
	regionBegin = "# varlatch:begin: added by varlatch agents install; varlatch agents install --remove takes it out"
	regionEnd   = "# varlatch:end"
)

// The tables the CLI writes, by header, in the order it writes them.
const (
	partEnv = "[shell_environment_policy.set]"
	partMCP = "[mcp_servers.varlatch]"
)

var tomlParts = []string{partEnv, partMCP}

// partPaths is where each of the CLI's tables lives in the parsed document.
var partPaths = map[string][2]string{
	partEnv: {"shell_environment_policy", "set"},
	partMCP: {"mcp_servers", "varlatch"},
}

// parseTOML is parseTomlOrNull.
func parseTOML(text string) *toml.Table {
	t, err := toml.ParseString(text)
	if err != nil {
		return nil
	}
	return t
}

// isTable is toml.ts's isTable for a parsed TOML value.
func isTable(v any) bool {
	_, ok := v.(*toml.Table)
	return ok
}

// tget is t[k] for a value that may not be a table.
func tget(v any, k string) (any, bool) {
	if t, ok := v.(*toml.Table); ok {
		return t.Get(k)
	}
	return nil, false
}

// canonical is canonicalData: JSON with every table's keys in one order,
// so equal data gives equal text. ok is false for undefined (a value that
// is not there), which JSON.stringify gives no text for.
func canonical(v any, present bool) (string, bool) {
	if !present {
		return "", false
	}
	return string(jsjson.Stringify(canonicalValue(v))), true
}

func canonicalValue(v any) any {
	switch x := v.(type) {
	case *toml.Table:
		keys := x.Keys()
		slices.SortFunc(keys, jsval.CompareUTF16)
		o := jsjson.Object{}
		for _, k := range keys {
			value, _ := x.Get(k)
			o = append(o, jsjson.Member{Key: k, Value: canonicalValue(value)})
		}
		return o
	case *toml.Array:
		out := make([]any, len(x.Items))
		for i, item := range x.Items {
			out[i] = canonicalValue(item)
		}
		return out
	case toml.Other:
		return x.Value
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out
	}
	return v
}

// sameData is canonicalData(a) === canonicalData(b).
func sameData(a any, aPresent bool, b any, bPresent bool) bool {
	x, okA := canonical(a, aPresent)
	y, okB := canonical(b, bPresent)
	return okA == okB && x == y
}

// region is the CLI's region in a file.
type region struct {
	start int
	// end is just after the end marker.
	end   int
	order []string
	parts map[string][]string
}

func (r *region) has(header string) bool { _, ok := r.parts[header]; return ok }

// regionOf finds the CLI's region: nil when there is none; damaged when a
// marker is missing or it holds something else.
func regionOf(text string) (r *region, damaged bool) {
	begin, innerStart := -1, -1
	for from := 0; ; {
		i := strings.Index(text[from:], regionBegin)
		if i < 0 {
			break
		}
		i += from
		if i == 0 || text[i-1] == '\n' {
			after := text[i+len(regionBegin):]
			if strings.HasPrefix(after, "\r\n") {
				begin, innerStart = i, i+len(regionBegin)+2
				break
			}
			if strings.HasPrefix(after, "\n") {
				begin, innerStart = i, i+len(regionBegin)+1
				break
			}
		}
		from = i + 1
	}
	hasEnd := strings.Contains(text, regionEnd)
	if begin < 0 {
		return nil, hasEnd
	}
	endAt := strings.Index(text[innerStart:], regionEnd)
	if endAt < 0 {
		return nil, true
	}
	endAt += innerStart
	if endAt > 0 && text[endAt-1] != '\n' {
		return nil, true
	}
	r = &region{start: begin, end: endAt + len(regionEnd), parts: map[string][]string{}}
	current := ""
	for _, line := range splitCRLF(text[innerStart:endAt]) {
		switch {
		case slices.Contains(tomlParts, line):
			if r.has(line) {
				return nil, true
			}
			current = line
			r.order = append(r.order, line)
			r.parts[line] = []string{}
		case opensTable.MatchString(line):
			return nil, true
		case line != "":
			if current == "" {
				return nil, true
			}
			r.parts[current] = append(r.parts[current], line)
		}
	}
	return r, false
}

var opensTable = jsRegexp(`^\s*\[`)

// splitCRLF is text.split(/\r?\n/).
func splitCRLF(text string) []string {
	parts := strings.Split(text, "\n")
	for i := range len(parts) - 1 {
		parts[i] = strings.TrimSuffix(parts[i], "\r")
	}
	return parts
}

func regionText(parts map[string][]string, eol string) string {
	var tables []string
	for _, h := range tomlParts {
		if lines, ok := parts[h]; ok {
			tables = append(tables, strings.Join(append([]string{h}, lines...), eol))
		}
	}
	return strings.Join([]string{regionBegin, strings.Join(tables, eol+eol), regionEnd}, eol)
}

// tomlEdit is an edit of a TOML file: the text to write (nil: delete the
// file, which held only what the CLI added), or why the CLI leaves the file
// to the human.
type tomlEdit struct {
	next    desired
	refused string
}

const damagedRegion = "its varlatch:begin/varlatch:end block is damaged, or holds a table the CLI did not write"

// withTOMLPart is withTomlPart: current with the CLI's table header set to
// body, when the whole file then parses to expected(before).
func withTOMLPart(current desired, header string, body []string, expected func(before *toml.Table) *toml.Table) tomlEdit {
	text := ""
	if current != nil {
		text = *current
	}
	r, damaged := regionOf(text)
	if damaged {
		return tomlEdit{refused: damagedRegion}
	}
	before := parseTOML(text)
	if before == nil {
		return tomlEdit{refused: "it does not parse as TOML"}
	}
	if r != nil {
		lines, ok := r.parts[header]
		if sameData(lines, ok, body, true) {
			return tomlEdit{next: current}
		}
	}
	parts := map[string][]string{}
	if r != nil {
		for k, v := range r.parts {
			parts[k] = v
		}
	}
	parts[header] = body
	var next string
	if r == nil {
		next = appendOwned(current, regionText(parts, eolOf(text))+eolOf(text))
	} else {
		next = text[:r.start] + regionText(parts, ownedEol(text, r.start, r.end)) + text[r.end:]
	}
	after := parseTOML(next)
	if after == nil || !sameData(after, true, expected(before), true) {
		return tomlEdit{refused: "adding to it would change what it says"}
	}
	return tomlEdit{next: ptr(next)}
}

// withoutTOMLPart is withoutTomlPart: current without the CLI's table
// header, when that table is exactly what the CLI writes and the rest of
// the file then says exactly what it said.
func withoutTOMLPart(current string, header string, owned []string) tomlEdit {
	r, damaged := regionOf(current)
	if damaged {
		return tomlEdit{refused: damagedRegion}
	}
	if r == nil || !r.has(header) {
		return tomlEdit{next: ptr(current)}
	}
	customized := tomlEdit{refused: "its " + header + " table holds settings the CLI did not write"}
	if !sameData(r.parts[header], true, owned, true) {
		return customized
	}
	before := parseTOML(current)
	if before == nil {
		return tomlEdit{refused: "it does not parse as TOML"}
	}
	path := partPaths[header]
	parent, key := path[0], path[1]
	parentValue, _ := before.Get(parent)
	parentTable, ok := parentValue.(*toml.Table)
	if !ok {
		return customized
	}
	ours, oursPresent := parentTable.Get(key)
	var ownedDoc any
	if t := parseTOML(strings.Join(owned, "\n")); t != nil {
		ownedDoc = t
	}
	if !sameData(ours, oursPresent, ownedDoc, true) {
		return customized
	}
	delete(r.parts, header)
	eol := ownedEol(current, r.start, r.end)
	var next desired
	if len(r.parts) == 0 {
		next = withoutOwned(current, r.start, r.end)
	} else {
		next = ptr(current[:r.start] + regionText(r.parts, eol) + current[r.end:])
	}
	siblings := parentTable.Without(key)
	rest := before.Without(parent)
	withSiblings := rest.Clone()
	withSiblings.Set(parent, siblings)
	allowed := []any{withSiblings}
	if len(siblings.Keys()) == 0 {
		allowed = append(allowed, rest)
	}
	afterText := ""
	if next != nil {
		afterText = *next
	}
	after := parseTOML(afterText)
	if after == nil || !slices.ContainsFunc(allowed, func(a any) bool { return sameData(after, true, a, true) }) {
		return tomlEdit{refused: "taking it out would change what the rest of the file says"}
	}
	return tomlEdit{next: next}
}
