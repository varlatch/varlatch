// SPDX-License-Identifier: Apache-2.0

// Package typegen is `varlatch types`' generators (slice 5.3c of internal
// docs/design/go-cli.md, decision 7): apps/cli/src/typegen.ts and
// typegenPython.ts, giving their bytes for every revision. A generated
// module depends on the revision and the generator version only: never on
// an Environment, a value, the clock or the machine.
package typegen

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/contract"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// Error is TypesError: no module can be generated, for a reason that holds
// no value.
type Error struct{ Message string }

func (e *Error) Error() string { return e.Message }

func fail(message string) error { return &Error{Message: message} }

// Revision is RevisionInput: the server's answer's fields, as JSON values
// (Absent marks a field the answer did not have).
type Revision struct {
	ID, ContentHash, SemanticsVersion, Contract any
	// Shown is the ID as a message shows it, when not the ID itself (the
	// CLI shows only an ID of the server's shape). Never in the module.
	Shown string
}

// Absent is a field the server's answer did not have (JavaScript's
// undefined).
var Absent any = absent{}

type absent struct{}

var (
	identifier  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	contentHash = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// version is typegen.ts's VERSION: a printable generator version.
	version = regexp.MustCompile(`^[0-9A-Za-z.+-]{1,64}$`)
)

// ValidGeneratorVersion is VERSION.test(v).
func ValidGeneratorVersion(v string) bool { return version.MatchString(v) }

// jsString is String(v) for a field of the answer.
func jsString(v any) string {
	if v == Absent {
		return "undefined"
	}
	return jsjson.String(v)
}

// joinInts is Array.prototype.join(sep) for numbers.
func joinInts(list []int, sep string) string {
	parts := make([]string, len(list))
	for i, n := range list {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, sep)
}

// checked is a revision checkRevision accepted.
type checked struct {
	id, hash string
	version  int
	items    []contract.Item
	// values are the items as the TypeScript package holds them (Object
	// members in normalizeContract's order), by index.
	values []contract.Object
}

// checkRevision is typegen.ts's checkRevision: the revision's items, after
// checking its ID, hash, semantics version and content.
func checkRevision(r Revision, implemented []int) (*checked, error) {
	id, ok := r.ID.(string)
	if !ok || !identifier.MatchString(id) {
		return nil, fail("the server returned a Contract Revision ID this CLI does not accept")
	}
	shown := id
	if r.Shown != "" {
		shown = r.Shown
	}
	hash, ok := r.ContentHash.(string)
	if !ok || !contentHash.MatchString(hash) {
		return nil, fail("Contract Revision " + shown + " has a content hash this CLI does not accept")
	}
	// SEMANTICS_VERSIONS.includes(version): a number, exactly one of them.
	n, ok := r.SemanticsVersion.(float64)
	known := ok && slices.ContainsFunc(contract.SemanticsVersions, func(v int) bool { return float64(v) == n })
	if !known {
		return nil, fail("Contract Revision " + shown + " uses Contract Semantics version " + jsString(r.SemanticsVersion) +
			", which this CLI does not implement (it generates types for version " + joinInts(implemented, ", ") +
			"). Upgrade the CLI, or activate a revision at a version it implements")
	}
	v := int(n)
	if !slices.Contains(implemented, v) {
		return nil, fail("Contract Revision " + shown + " uses Contract Semantics version " + strconv.Itoa(v) +
			", which defines no conversion, so no types can be generated from it. Activate a revision at version " +
			joinInts(implemented, " or ") + ": push it with varlatch contract push --semantics latest, then activate it")
	}
	var c contract.Contract
	var err error
	if r.Contract == Absent {
		// normalizeContract(undefined), as zod reports it.
		err = &contract.ValidationError{Issues: []string{"(root): Invalid input: expected object, received undefined"}}
	} else {
		c, err = contract.Normalize(toContract(r.Contract), contract.Options{})
	}
	if err != nil {
		if verr, ok := err.(*contract.ValidationError); ok {
			return nil, fail("Contract Revision " + shown + " is not a valid Contract: " + strings.Join(verr.Issues, "; "))
		}
		return nil, err
	}
	if c.Version() != v || c.Hash() != hash {
		return nil, fail("Contract Revision " + shown + " does not match its content hash")
	}
	out := &checked{id: id, hash: hash, version: v, items: c.Items}
	if list, ok := memberOf(c.Value(), "items").([]any); ok {
		for _, e := range list {
			o, _ := e.(contract.Object)
			out.values = append(out.values, o)
		}
	}
	return out, nil
}

// toContract is a lib/jsjson value as a lib/contract one, members in order.
func toContract(v any) any {
	switch x := v.(type) {
	case jsjson.Object:
		out := make(contract.Object, len(x))
		for i, m := range x {
			out[i] = contract.Member{Key: m.Key, Value: toContract(m.Value)}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = toContract(e)
		}
		return out
	}
	return v
}

// toJSON is a lib/contract value as a lib/jsjson one, members in order.
func toJSON(v any) any {
	switch x := v.(type) {
	case contract.Object:
		out := make(jsjson.Object, len(x))
		for i, m := range x {
			out[i] = jsjson.Member{Key: m.Key, Value: toJSON(m.Value)}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = toJSON(e)
		}
		return out
	}
	return v
}

func memberOf(o contract.Object, key string) any {
	for _, m := range o {
		if m.Key == key {
			return m.Value
		}
	}
	return nil
}

// schemaItem is the accessor schema's item: name, type, required, and
// enumValues and defaultValue when the item has them.
func schemaItem(it contract.Item, value contract.Object) contract.Object {
	o := contract.Object{{Key: "name", Value: it.Name}, {Key: "type", Value: it.Type}, {Key: "required", Value: memberOf(value, "required")}}
	if it.EnumValues != nil {
		vs := make([]any, len(it.EnumValues))
		for i, v := range it.EnumValues {
			vs[i] = v
		}
		o = append(o, contract.Member{Key: "enumValues", Value: vs})
	}
	if it.DefaultValue != nil {
		o = append(o, contract.Member{Key: "defaultValue", Value: *it.DefaultValue})
	}
	return o
}

// runes calls f with each code point of s and its bytes: a lone surrogate
// (its WTF-8 bytes) as one code point, as JavaScript iterates a string,
// and any other byte that is not UTF-8 as itself.
func runes(s string, f func(r rune, raw string)) {
	for i := 0; i < len(s); {
		if r, ok := jsjson.SurrogateAt(s, i); ok {
			f(r, s[i:i+3])
			i += 3
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		f(r, s[i:i+n])
		i += n
	}
}

// isLineTerminator is LINE_TERMINATORS' character class.
func isLineTerminator(r rune) bool {
	return r == '\n' || r == '\r' || r == 0x85 || r == 0x2028 || r == 0x2029
}

// isControl is CONTROLS: C0 and C1 controls but the newline, DEL, and the
// bidirectional formatting characters.
func isControl(r rune) bool {
	return r <= 0x09 || r >= 0x0b && r <= 0x1f || r >= 0x7f && r <= 0x9f || r == 0x061c || r == 0x200e || r == 0x200f ||
		r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069
}

// isLiteralEscape is LITERAL_ESCAPES: what a string literal escapes.
func isLiteralEscape(r rune) bool {
	return r >= 0x7f && r <= 0x9f || r == 0x061c || r == 0x200e || r == 0x200f || r == 0x2028 || r == 0x2029 ||
		r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069
}

// isJSSpace is what String.prototype.trimEnd removes: WhiteSpace and
// LineTerminator.
func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// trimEnd is String.prototype.trimEnd.
func trimEnd(s string) string {
	for len(s) > 0 {
		r, n := utf8.DecodeLastRuneInString(s)
		if r == utf8.RuneError || !isJSSpace(r) {
			break
		}
		s = s[:len(s)-n]
	}
	return s
}

// cleanLines is typegen.ts's cleanLines: every line terminator normalized,
// tabs made spaces, control and bidirectional formatting characters
// removed, each line's end trimmed, and the blank lines around the text
// dropped.
func cleanLines(text string) []string {
	var b strings.Builder
	text = strings.ReplaceAll(text, "\r\n", "\n")
	runes(text, func(r rune, raw string) {
		switch {
		case isLineTerminator(r):
			b.WriteByte('\n')
		case r == '\t':
			b.WriteByte(' ')
		case isControl(r):
		default:
			b.WriteString(raw)
		}
	})
	lines := strings.Split(b.String(), "\n")
	for i, l := range lines {
		lines[i] = trimEnd(l)
	}
	for len(lines) > 0 && lines[0] == "" {
		lines = lines[1:]
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// commentLines is typegen.ts's commentLines: cleaned, and */ neutralized.
func commentLines(text string) []string {
	lines := cleanLines(text)
	for i, l := range lines {
		lines[i] = strings.ReplaceAll(l, "*/", `*\/`)
	}
	return lines
}

// escapeLiteral escapes LITERAL_ESCAPES in JSON text as \uXXXX.
func escapeLiteral(text string) string {
	var b strings.Builder
	runes(text, func(r rune, raw string) {
		if isLiteralEscape(r) {
			b.WriteString(`\u`)
			h := strconv.FormatInt(int64(r), 16)
			b.WriteString(strings.Repeat("0", 4-len(h)) + h)
			return
		}
		b.WriteString(raw)
	})
	return b.String()
}

// literal is typegen.ts's literal: JSON.stringify(value), every invisible
// or line-ending character escaped.
func literal(v any) string { return escapeLiteral(string(jsjson.Stringify(toJSON(v)))) }

// commentLiteral is a literal that is also safe inside a comment.
func commentLiteral(s string) string { return strings.ReplaceAll(literal(s), "*/", `*\/`) }

// isOptional: non-optional only when required in every Environment with
// nothing, not even a default, to satisfy it otherwise.
func isOptional(it contract.Item) bool {
	return it.Required.Kind != "always" || it.DefaultValue != nil
}

// requirednessLine is typegen.ts's requirednessLine.
func requirednessLine(it contract.Item) string {
	satisfied := ""
	if it.DefaultValue != nil {
		satisfied = ", or satisfied by the Contract default"
	}
	switch it.Required.Kind {
	case "always":
		return "Required in every environment" + satisfied + "."
	case "never":
		return "Optional in every environment."
	}
	where := ""
	if s := it.Required.Selector; s != nil && s.Kind == "tier" {
		where = "in environments of tier " + s.Tier
	} else if s != nil {
		where = "in the environments with root ID " + strings.Join(s.EnvironmentIDs, ", ")
	}
	return "Required only " + where + satisfied + "; checked when a run context names the environment."
}

// GeneratorOf is typesCommand.ts's generatorOf: the release a generated
// file names on its first Generator line (/^(?:\/\/|#) Generator: +varlatch
// (\S+)$/m over the file as UTF-8 text), or false.
func GeneratorOf(file []byte) (string, bool) {
	text := string(file)
	for len(text) > 0 {
		// A line ends at any JavaScript line terminator (the m flag).
		end, next := len(text), len(text)
		for i, r := range text {
			if r == '\n' || r == '\r' || r == 0x2028 || r == 0x2029 {
				end, next = i, i+utf8.RuneLen(r)
				break
			}
		}
		if v, ok := generatorLine(text[:end]); ok {
			return v, true
		}
		text = text[next:]
	}
	return "", false
}

func generatorLine(line string) (string, bool) {
	rest, ok := strings.CutPrefix(line, "//")
	if !ok {
		if rest, ok = strings.CutPrefix(line, "#"); !ok {
			return "", false
		}
	}
	rest, ok = strings.CutPrefix(rest, " Generator:")
	if !ok || !strings.HasPrefix(rest, " ") {
		return "", false
	}
	rest, ok = strings.CutPrefix(strings.TrimLeft(rest, " "), "varlatch ")
	if !ok || rest == "" {
		return "", false
	}
	for _, r := range rest {
		if isJSSpace(r) {
			return "", false // \S+ to the end of the line
		}
	}
	return rest, true
}
