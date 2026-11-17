// SPDX-License-Identifier: Apache-2.0

package sync

import (
	"errors"
	"io"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// How a Coolify service's compose file uses the names a Sync Target
// manages (ADR-0031 amendment 2026-10-21), as coolifyCompose.ts reads it:
// the compose file as written (how each name is used) and the one Coolify
// generated at its last parse (whether each container loads the service's
// .env), with the rules of Coolify's service parser and Docker Compose's
// precedence. The verdicts are hints, and conservative: a form the rules
// do not cover reads as unknown. The compose text never leaves this file.
//
// The YAML is read as the TypeScript code reads it with the `yaml` package
// (YAML 1.2, the core schema, merge keys, at most 200 alias expansions,
// repeated keys allowed): go.yaml.in/yaml/v3 parses, and this file turns
// its nodes into JavaScript's values with that package's rules. Where it
// cannot follow them (any directive but "%YAML 1.2", a byte order mark
// past the first, the YAML 1.1 types binary, timestamp, set, omap and
// pairs, a mapping or sequence as a key, an alias inside its own anchor)
// the file reads as unreadable, which makes every verdict unknown.

// MaxComposeBytes is MAX_COMPOSE_BYTES: larger compose files are not
// inspected.
const MaxComposeBytes = 512 * 1024

// maxAliases is MAX_ALIASES (the package's maxAliasCount).
const maxAliases = 200

var coolifyOwnedPrefixes = []string{"SERVICE_FQDN_", "SERVICE_URL_", "SERVICE_NAME_", "COOLIFY_"}

// CoolifyOwnsName reports a name Coolify sets itself on a service.
func CoolifyOwnsName(name string) bool {
	for _, p := range coolifyOwnedPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// CoolifyGeneratesName reports Coolify's generated-once magic names.
func CoolifyGeneratesName(name string) bool {
	return strings.HasPrefix(name, "SERVICE_") && !CoolifyOwnsName(name)
}

// errUnreadable is a YAML document this file does not read.
var errUnreadable = errors.New("unreadable YAML")

// ---------------------------------------------------------------------------
// YAML to JavaScript values.

var (
	yamlNull     = regexp.MustCompile(`^(?:~|[Nn]ull|NULL)?$`)
	yamlBool     = regexp.MustCompile(`^(?:[Tt]rue|TRUE|[Ff]alse|FALSE)$`)
	yamlIntOct   = regexp.MustCompile(`^0o[0-7]+$`)
	yamlInt      = regexp.MustCompile(`^[-+]?[0-9]+$`)
	yamlIntHex   = regexp.MustCompile(`^0x[0-9a-fA-F]+$`)
	yamlFloatNaN = regexp.MustCompile(`^(?:[-+]?\.(?:inf|Inf|INF)|\.nan|\.NaN|\.NAN)$`)
	yamlFloatExp = regexp.MustCompile(`^[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)[eE][-+]?[0-9]+$`)
	yamlFloat    = regexp.MustCompile(`^[-+]?(?:\.[0-9]+|[0-9]+\.[0-9]*)$`)
)

// yaml11Tags are the YAML 1.1 types the `yaml` package knows by name and
// turns into objects other than JSON's; this file does not read them.
var yaml11Tags = map[string]bool{"!!binary": true, "!!timestamp": true, "!!set": true, "!!omap": true, "!!pairs": true}

// mergeSymbol is a value tagged !!merge outside a key: the `yaml` package
// makes it the merge key's Symbol, which no rule reads (not a string, not
// in JSON), so a container setting a name to it is unknown.
type mergeSymbol struct{}

func plainStyle(n *yaml.Node) bool {
	return n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) == 0
}

func explicitTag(n *yaml.Node) (string, bool) {
	if n.Style&yaml.TaggedStyle != 0 {
		return n.ShortTag(), true
	}
	return "", false
}

// parseInt is parseInt(digits, radix) for the digits a test admitted.
func parseInt(digits string, radix int) float64 {
	neg := false
	switch {
	case strings.HasPrefix(digits, "-"):
		neg, digits = true, digits[1:]
	case strings.HasPrefix(digits, "+"):
		digits = digits[1:]
	}
	var f float64
	if radix == 10 {
		f, _ = strconv.ParseFloat(digits, 64)
	} else {
		for _, c := range digits {
			d, _ := strconv.ParseUint(string(c), radix, 8)
			f = f*float64(radix) + float64(d)
		}
	}
	if neg {
		return -f
	}
	return f
}

// scalarByTests resolves a scalar by the core schema's tests, in its
// order; ok is false when none matches.
func scalarByTests(v string, tags ...string) (any, bool) {
	for _, tag := range tags {
		switch tag {
		case "null":
			if yamlNull.MatchString(v) {
				return nil, true
			}
		case "bool":
			if yamlBool.MatchString(v) {
				return v[0] == 't' || v[0] == 'T', true
			}
		case "intOct":
			if yamlIntOct.MatchString(v) {
				return parseInt(v[2:], 8), true
			}
		case "int":
			if yamlInt.MatchString(v) {
				return parseInt(v, 10), true
			}
		case "intHex":
			if yamlIntHex.MatchString(v) {
				return parseInt(v[2:], 16), true
			}
		case "floatNaN":
			if yamlFloatNaN.MatchString(v) {
				switch {
				case strings.ToLower(v[len(v)-3:]) == "nan":
					return math.NaN(), true
				case v[0] == '-':
					return math.Inf(-1), true
				}
				return math.Inf(1), true
			}
		case "floatExp", "float":
			re := yamlFloat
			if tag == "floatExp" {
				re = yamlFloatExp
			}
			if re.MatchString(v) {
				f, err := strconv.ParseFloat(v, 64)
				if err != nil && !errors.Is(err, strconv.ErrRange) {
					return nil, false
				}
				return f, true
			}
		}
	}
	return nil, false
}

var coreTests = []string{"null", "bool", "intOct", "int", "intHex", "floatNaN", "floatExp", "float"}

// scalarValue is a scalar node's JavaScript value. nonSpecific is a plain
// scalar written with the non-specific tag "!", which the `yaml` package
// reads as a string (yaml.v3 does not report it; see converter.nonSpecific).
func scalarValue(n *yaml.Node, nonSpecific bool) (any, error) {
	if nonSpecific {
		return n.Value, nil
	}
	if tag, ok := explicitTag(n); ok {
		var tests []string
		switch tag {
		case "!!str", "!!map", "!!seq":
			return n.Value, nil
		case "!!null":
			tests = []string{"null"}
		case "!!bool":
			tests = []string{"bool"}
		case "!!int":
			tests = []string{"intOct", "int", "intHex"}
		case "!!float":
			tests = []string{"floatNaN", "floatExp", "float"}
		case "!!merge":
			return mergeSymbol{}, nil
		default:
			if yaml11Tags[tag] {
				return nil, errUnreadable
			}
			return n.Value, nil // an unknown tag: a string, with a warning
		}
		if v, ok := scalarByTests(n.Value, tests...); ok {
			return v, nil
		}
		return n.Value, nil
	}
	if plainStyle(n) {
		if v, ok := scalarByTests(n.Value, coreTests...); ok {
			return v, nil
		}
	}
	return n.Value, nil
}

type anchorData struct {
	aliasCount int
	count      int
	res        any
	hasRes     bool
}

// converter is the `yaml` package's toJS with its alias bookkeeping.
type converter struct {
	anchors map[*yaml.Node]*anchorData
	active  map[*yaml.Node]bool
	// lines is the document's text by line, for nonSpecific.
	lines []string
}

// nonSpecific reports a node written with the non-specific tag "!" (as in
// "! null"). yaml.v3 reads "!" as no tag and resolves the scalar by its
// own rules, where the `yaml` package makes it a string; so the node's
// properties are read from the text: yaml.v3 places a node at its first
// property, counting characters.
func (c *converter) nonSpecific(n *yaml.Node) bool {
	if n.Style&yaml.TaggedStyle != 0 || n.Line < 1 || n.Line > len(c.lines) || n.Column < 1 {
		return false
	}
	line := []rune(strings.TrimSuffix(c.lines[n.Line-1], "\r"))
	if n.Column-1 >= len(line) {
		return false
	}
	rest := line[n.Column-1:]
	isBreak := func(r rune) bool { return r == ' ' || r == '\t' }
	for len(rest) > 0 {
		switch {
		case rest[0] == '&':
			i := 1
			for i < len(rest) && !isBreak(rest[i]) {
				i++
			}
			for i < len(rest) && isBreak(rest[i]) {
				i++
			}
			rest = rest[i:]
		case rest[0] == '!':
			return len(rest) == 1 || isBreak(rest[1]) || strings.ContainsRune(",[]{}", rest[1])
		default:
			return false
		}
	}
	return false
}

// toJS is toJS(node): an anchored node registers its data first.
func (c *converter) toJS(n *yaml.Node) (any, error) {
	if n.Kind == yaml.AliasNode {
		return c.alias(n)
	}
	if n.Anchor == "" {
		return c.toJSON(n)
	}
	data := &anchorData{count: 1}
	c.anchors[n] = data
	res, err := c.toJSON(n)
	if err != nil {
		return nil, err
	}
	data.res, data.hasRes = res, true
	return res, nil
}

// toJSON is a node's own conversion (Node.toJSON).
func (c *converter) toJSON(n *yaml.Node) (any, error) {
	if c.active[n] {
		return nil, errUnreadable // an alias inside its own anchor: a cycle
	}
	c.active[n] = true
	defer delete(c.active, n)
	switch n.Kind {
	case yaml.ScalarNode:
		return scalarValue(n, c.nonSpecific(n))
	case yaml.SequenceNode:
		if tag, ok := explicitTag(n); ok && (tag == "!!omap" || tag == "!!pairs") {
			return nil, errUnreadable
		}
		seq := []any{}
		for _, item := range n.Content {
			v, err := c.toJS(item)
			if err != nil {
				return nil, err
			}
			seq = append(seq, v)
		}
		return seq, nil
	case yaml.MappingNode:
		if tag, ok := explicitTag(n); ok && tag == "!!set" {
			return nil, errUnreadable
		}
		return c.object(n)
	}
	return nil, errUnreadable
}

// resolve is Alias.resolve with a context: the anchored node, counted
// against maxAliases.
func (c *converter) resolve(n *yaml.Node) (*yaml.Node, error) {
	found := n.Alias
	if found == nil {
		return nil, errUnreadable
	}
	data := c.anchors[found]
	if data == nil {
		if _, err := c.toJS(found); err != nil {
			return nil, err
		}
		data = c.anchors[found]
	}
	if data == nil || !data.hasRes {
		return nil, errUnreadable // an alias inside its own anchor
	}
	data.count++
	if data.aliasCount == 0 {
		data.aliasCount = c.aliasCount(found)
	}
	if data.count*data.aliasCount > maxAliases {
		return nil, errUnreadable
	}
	return found, nil
}

func (c *converter) alias(n *yaml.Node) (any, error) {
	found, err := c.resolve(n)
	if err != nil {
		return nil, err
	}
	return c.anchors[found].res, nil
}

// aliasCount is getAliasCount.
func (c *converter) aliasCount(n *yaml.Node) int {
	switch n.Kind {
	case yaml.AliasNode:
		if d := c.anchors[n.Alias]; d != nil {
			return d.count * d.aliasCount
		}
		return 0
	case yaml.SequenceNode, yaml.MappingNode:
		most := 0
		for _, item := range n.Content {
			if v := c.aliasCount(item); v > most {
				most = v
			}
		}
		return most
	}
	return 1
}

// isMergeKey is a merge key: a plain << (whatever its tag), or any scalar
// tagged !!merge, quoted or not (the `yaml` package resolves an explicit
// !!merge to the merge key whatever the text).
func isMergeKey(k *yaml.Node) bool {
	if k.Kind != yaml.ScalarNode {
		return false
	}
	if tag, ok := explicitTag(k); ok && tag == "!!merge" {
		return true
	}
	return plainStyle(k) && k.Value == "<<"
}

// scalarKey is a converted key, as a JavaScript value that is not an
// object; a mapping or sequence as a key is unreadable here.
func scalarKey(v any) (any, error) {
	switch v.(type) {
	case []any, Object:
		return nil, errUnreadable
	}
	return v, nil
}

// object is YAMLMap.toJSON into a plain object.
func (c *converter) object(n *yaml.Node) (Object, error) {
	o := Object{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if isMergeKey(k) {
			entries, err := c.mergeSources(v)
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				key := propertyKey(e.key)
				if _, has := o.Get(key); !has {
					o = o.set(key, e.value)
				}
			}
			continue
		}
		jsKey, err := c.toJS(k)
		if err != nil {
			return nil, err
		}
		if jsKey, err = scalarKey(jsKey); err != nil {
			return nil, err
		}
		key := ""
		if jsKey != nil {
			key = jsString(jsKey)
		}
		value, err := c.toJS(v)
		if err != nil {
			return nil, err
		}
		o = o.set(key, value)
	}
	return o, nil
}

// mapEntry is one entry of a JavaScript Map.
type mapEntry struct {
	key   any
	value any
}

// sameValueZero is Map's key equality, for keys that are not objects.
func sameValueZero(a, b any) bool {
	if fa, ok := a.(float64); ok {
		fb, ok := b.(float64)
		return ok && (fa == fb || (math.IsNaN(fa) && math.IsNaN(fb)))
	}
	return a == b
}

func mapSet(entries []mapEntry, key, value any, onlyNew bool) []mapEntry {
	for i := range entries {
		if sameValueZero(entries[i].key, key) {
			if !onlyNew {
				entries[i].value = value
			}
			return entries
		}
	}
	return append(entries, mapEntry{key, value})
}

// mapEntries is YAMLMap.toJSON into a Map, as a merge reads its source.
func (c *converter) mapEntries(n *yaml.Node) ([]mapEntry, error) {
	var entries []mapEntry
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if isMergeKey(k) {
			merged, err := c.mergeSources(v)
			if err != nil {
				return nil, err
			}
			for _, e := range merged {
				entries = mapSet(entries, e.key, e.value, true)
			}
			continue
		}
		jsKey, err := c.toJS(k)
		if err != nil {
			return nil, err
		}
		if jsKey, err = scalarKey(jsKey); err != nil {
			return nil, err
		}
		value, err := c.toJS(v)
		if err != nil {
			return nil, err
		}
		entries = mapSet(entries, jsKey, value, false)
	}
	return entries, nil
}

// resolveAliasValue is an alias's anchored node (counted), or the node.
func (c *converter) resolveAliasValue(n *yaml.Node) (*yaml.Node, error) {
	if n.Kind == yaml.AliasNode {
		return c.resolve(n)
	}
	return n, nil
}

// mergeSources is addMergeToJSMap's sources, each read into a Map, in
// order: the entries to add where the target lacks the key.
func (c *converter) mergeSources(v *yaml.Node) ([]mapEntry, error) {
	source, err := c.resolveAliasValue(v)
	if err != nil {
		return nil, err
	}
	items := []*yaml.Node{source}
	if source.Kind == yaml.SequenceNode {
		items = source.Content
	}
	var out []mapEntry
	for _, item := range items {
		src, err := c.resolveAliasValue(item)
		if err != nil {
			return nil, err
		}
		if src.Kind != yaml.MappingNode {
			return nil, errUnreadable // "Merge sources must be maps or map aliases"
		}
		if tag, ok := explicitTag(src); ok && tag == "!!set" {
			return nil, errUnreadable
		}
		if c.active[src] {
			return nil, errUnreadable
		}
		c.active[src] = true
		entries, err := c.mapEntries(src)
		delete(c.active, src)
		if err != nil {
			return nil, err
		}
		out = append(out, entries...)
	}
	return out, nil
}

// propertyKey is ToPropertyKey of a Map key that is not an object.
func propertyKey(v any) string {
	return jsString(v)
}

// yamlDirective is the one directive line read here: "%YAML 1.2", with
// spaces or tabs, and an optional comment after a separating blank.
var yamlDirective = regexp.MustCompile(`^%YAML[ \t]+1\.2(?:[ \t]+(?:#.*)?)?$`)

// The subset. yaml.v3 and the `yaml` package read some texts differently,
// and where they do, Go must never give a more confident verdict than
// TypeScript. Rather than follow each difference, this reader reads a
// conservative subset of YAML and calls everything else unreadable (every
// verdict unknown, which is always safe): the characters subsetCharacters
// allows, the directives normalize allows, and scalars that start and end
// on one line or are block scalars, flow collections on one line, and
// well-formed properties (inSubset). Compose files as people and Coolify
// usually write them stay inside it (a flow list spread over lines does
// not: its verdicts are unknown).

// subsetCharacters reports that the text holds only printable characters,
// tab, line feed, and carriage return before a line feed: no other
// control character (C0, DEL, C1, NEL), no line or paragraph separator
// (U+2028, U+2029), no byte order mark (one leading one is dropped
// before), no U+FFFE or U+FFFF, and nothing that is not UTF-8 (a lone
// surrogate the JavaScript string held).
func subsetCharacters(text string) bool {
	if !utf8.ValidString(text) {
		return false
	}
	for i, r := range text {
		switch {
		case r == '\t' || r == '\n':
		case r == '\r':
			if i+1 >= len(text) || text[i+1] != '\n' {
				return false
			}
		case r < 0x20 || (r >= 0x7f && r <= 0x9f):
			return false
		case r == 0x2028 || r == 0x2029 || r == 0xfeff || r == 0xfffe || r == 0xffff:
			return false
		}
	}
	return true
}

// inSubset reports that the tree's structure is in the subset:
//   - every quoted or plain scalar, keys included, starts and ends on its
//     line, nothing is run into a quoted one's closing quote, and a
//     double-quoted one holds only YAML 1.2's escapes (yaml.v3 and the `yaml` package fold and indent continuation
//     lines by different rules); block scalars (| and >) span lines by
//     design and are read;
//   - in a block mapping, a scalar or alias value on a later line than
//     its key is indented more than the key;
//   - every flow collection ({…} or […]) closes on the line it opens on
//     (nothing run into its closing bracket),
//     holds no '?' outside quotes (an explicit key, "{?:}"), and no plain
//     scalar in it is empty or holds a ':' (where one ends a key, as in
//     "{7:, A: x}", the parsers disagree);
//   - every property and alias is well formed: an anchor or alias name of
//     letters, digits, '_', '-' and '.', a tag "!", "!name" or "!!name"
//     with a name of letters, digits and '-', and none of the YAML 1.1
//     types (on a key too: "!!binary <<" is read two ways);
//   - a block scalar's header is strict: no comment run into it (">#-").
//
// Aliases are read where their anchor is.
func (c *converter) inSubset(n *yaml.Node, inFlow bool) bool {
	if n.Kind == yaml.DocumentNode {
		for _, child := range n.Content {
			if !c.inSubset(child, false) {
				return false
			}
		}
		return true
	}
	line, ok := c.lineAt(n)
	if !ok {
		return false
	}
	if n.Kind == yaml.AliasNode {
		name, _ := nextToken(line)
		return len(name) > 1 && name[0] == '*' && anchorName.MatchString(string(name[1:]))
	}
	rest, ok := afterProperties(line)
	if !ok {
		return false
	}
	switch n.Kind {
	case yaml.MappingNode, yaml.SequenceNode:
		flow := inFlow || n.Style&yaml.FlowStyle != 0
		if n.Style&yaml.FlowStyle != 0 {
			if end := flowEnd(rest); end < 0 || !inFlow && !quotedTail(rest[end:]) {
				return false
			}
		}
		if n.Kind == yaml.MappingNode && !flow && !valuesIndented(n) {
			return false
		}
		for _, child := range n.Content {
			if !c.inSubset(child, flow) {
				return false
			}
		}
		return true
	case yaml.ScalarNode:
		switch {
		case n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0:
			return blockHeader.MatchString(string(rest))
		case n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0:
			end := quotedEnd(rest)
			return end >= 0 && quotedTail(rest[end:]) && (rest[0] != '"' || validEscapes(rest[1:end-1]))
		case inFlow && n.Value == "":
			// An empty key or value in a flow collection ("{: a}", "{a: }").
			return false
		case n.Value == "":
			return true // an empty plain scalar has no text
		case inFlow && strings.ContainsRune(n.Value, ':'):
			// Where a ':' ends a key in a flow collection ("{7:, A: x}")
			// the two parsers disagree: such a scalar is quoted in the
			// subset.
			return false
		default:
			return strings.HasPrefix(string(rest), n.Value)
		}
	}
	return false
}

var (
	// blockHeader is a block scalar's header line: the indicator, an
	// indentation and a chomping indicator in either order, then a comment
	// after a blank ("|", ">-", "|2+ # c"; not ">#-").
	blockHeader = regexp.MustCompile(`^[|>](?:[1-9][+-]?|[+-][1-9]?)?(?:[ \t]+(?:#.*)?)?$`)
	anchorName  = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	tagToken    = regexp.MustCompile(`^!(?:!?[A-Za-z0-9-]+)?$`)
)

// lineAt is the node's line from the node's position on: yaml.v3 places a
// node at its first property, counting characters.
func (c *converter) lineAt(n *yaml.Node) ([]rune, bool) {
	if n.Line < 1 || n.Line > len(c.lines) || n.Column < 1 {
		return nil, false
	}
	line := []rune(strings.TrimSuffix(c.lines[n.Line-1], "\r"))
	if n.Column-1 > len(line) {
		return nil, false
	}
	return line[n.Column-1:], true
}

func isBlank(r rune) bool { return r == ' ' || r == '\t' }

// nextToken is the text up to the next blank or flow indicator, and what
// follows it.
func nextToken(rest []rune) ([]rune, []rune) {
	i := 0
	for i < len(rest) && !isBlank(rest[i]) && !strings.ContainsRune(",[]{}", rest[i]) {
		i++
	}
	return rest[:i], rest[i:]
}

// afterProperties is the text after the node's properties (anchors, tags)
// and the blanks after each; not ok when one is not well formed. It may be
// empty: a block collection's content starts on the next line.
func afterProperties(rest []rune) ([]rune, bool) {
	for len(rest) > 0 && (rest[0] == '&' || rest[0] == '!') {
		t, after := nextToken(rest)
		if t[0] == '&' && !anchorName.MatchString(string(t[1:])) || t[0] == '!' && (!tagToken.MatchString(string(t)) || yaml11Tags[string(t)]) {
			return nil, false
		}
		if len(after) > 0 && !isBlank(after[0]) {
			return nil, false // a property runs into a flow indicator
		}
		for len(after) > 0 && isBlank(after[0]) {
			after = after[1:]
		}
		rest = after
	}
	return rest, true
}

// quotedEnd is the index just past the quoted scalar the text starts with,
// or -1 when it does not end on this line: ” is a quote in single
// quotes, a backslash escapes the next character in double quotes (at the
// line's end, a line break).
func quotedEnd(rest []rune) int {
	if len(rest) == 0 || (rest[0] != '"' && rest[0] != '\'') {
		return -1
	}
	q := rest[0]
	for i := 1; i < len(rest); i++ {
		switch {
		case q == '"' && rest[i] == '\\':
			i++
		case rest[i] == q && q == '\'' && i+1 < len(rest) && rest[i+1] == '\'':
			i++
		case rest[i] == q:
			return i + 1
		}
	}
	return -1
}

// quotedTail reports that what follows a quoted scalar, or a flow
// collection outside any other, on its line is read alike: nothing, a
// comment after a blank, a ':' (a key), or a flow collection's ',', ']'
// or '}' (after blanks or not). Text run into the closing quote or
// bracket ("\"a\"#", "{a: b}#") is read two ways.

// valuesIndented reports that in a block mapping every scalar or alias
// value that starts on a later line than its key is indented more than
// the key: yaml.v3 also reads one at the key's column ("a:\n>\n  x"),
// where the `yaml` package refuses it. (A block sequence there is
// ordinary YAML and is read.)
func valuesIndented(n *yaml.Node) bool {
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if (v.Kind == yaml.ScalarNode || v.Kind == yaml.AliasNode) && v.Line > k.Line && v.Column <= k.Column {
			return false
		}
	}
	return true
}
func quotedTail(tail []rune) bool {
	i := 0
	for i < len(tail) && isBlank(tail[i]) {
		i++
	}
	switch {
	case i == len(tail):
		return true
	case tail[i] == '#':
		return i > 0
	default:
		return strings.ContainsRune(":,]}", tail[i])
	}
}

// validEscapes reports that every escape in a double-quoted scalar's text
// is one of YAML 1.2's: an unknown one ("\\'") is read two ways.
func validEscapes(text []rune) bool {
	hex := func(from, n int) bool {
		if from+n > len(text) {
			return false
		}
		for _, r := range text[from : from+n] {
			if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(text); i++ {
		if text[i] != '\\' {
			continue
		}
		if i+1 == len(text) {
			return false
		}
		switch c := text[i+1]; {
		case strings.ContainsRune("0abtnvfre \"/\\N_LP\t", c):
			i++
		case c == 'x' && hex(i+2, 2):
			i += 3
		case c == 'u' && hex(i+2, 4):
			i += 5
		case c == 'U' && hex(i+2, 8):
			i += 9
		default:
			return false
		}
	}
	return true
}

// flowEnd is the index just past the flow collection the text starts
// with, or -1 when it does not close on this line (or a quote in it is
// not read as one here).
func flowEnd(rest []rune) int {
	if len(rest) == 0 || (rest[0] != '{' && rest[0] != '[') {
		return -1
	}
	depth := 0
	for i := 0; i < len(rest); i++ {
		switch r := rest[i]; {
		case r == '{' || r == '[':
			depth++
		case r == '}' || r == ']':
			depth--
			if depth == 0 {
				return i + 1
			}
		case r == '"' || r == '\'':
			end := quotedEnd(rest[i:])
			if end < 0 {
				return -1
			}
			i += end - 1
		case r == '#' && i > 0 && isBlank(rest[i-1]):
			return -1 // a comment before the collection closes
		case r == '?':
			// An explicit key ("? a", "?:") or a '?' in a plain scalar:
			// the parsers read "{?:}" differently.
			return -1
		}
	}
	return -1
}

// normalize is the compose text as yaml.v3 is given it, so that it and
// every lookup into the text (nonSpecific) see the same text:
//   - one leading byte order mark dropped, as the `yaml` package drops it
//     (yaml.v3 counts columns without it too);
//   - the directives before the document, read strictly: only "%YAML 1.2"
//     (repeated or not), which is the `yaml` package's own version, read
//     here with its 1.2 rules. yaml.v3 accepts only "%YAML 1.1", which
//     changes nothing its nodes report, so the first is given to it as
//     1.1 and any repeat as a comment, at the same length. Any other
//     directive (another version, %TAG, a reserved one, trailing text),
//     and directives with no "---" after them, make the file unreadable:
//     the conservative reading;
//   - only the characters of the subset (subsetCharacters);
//   - no document end marker ("...").
func normalize(text string) (string, bool) {
	text = strings.TrimPrefix(text, "\ufeff")
	if !subsetCharacters(text) {
		return "", false
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if rest, marker := strings.CutPrefix(line, "..."); marker && (rest == "" || rest[0] == ' ' || rest[0] == '\t') {
			// A document end marker: the parsers read what follows it
			// differently ("...\n..." is one document to yaml.v3).
			return "", false
		}
	}
	lines := strings.Split(text, "\n")
	seen := false
	for i, raw := range lines {
		line := strings.TrimSuffix(raw, "\r")
		trimmed := strings.TrimLeft(line, " \t")
		switch {
		case strings.HasPrefix(line, "%"):
			if !yamlDirective.MatchString(line) {
				return "", false
			}
			if !seen {
				lines[i] = "%YAML" + strings.Replace(raw[len("%YAML"):], "1.2", "1.1", 1)
				seen = true
			} else {
				lines[i] = "#" + raw[1:]
			}
		case trimmed == "" || strings.HasPrefix(trimmed, "#"):
		default:
			if seen && line != "---" && !strings.HasPrefix(line, "--- ") && !strings.HasPrefix(line, "---\t") {
				return "", false
			}
			return strings.Join(lines, "\n"), true
		}
	}
	if seen {
		return "", false // directives, and no document after them
	}
	return text, true
}

// parseBounded is the compose file as a JavaScript object, or false when
// it is too large, malformed, not a mapping, or unreadable here.
func parseBounded(text string) (Object, bool) {
	if len(wellFormed(text)) > MaxComposeBytes {
		return nil, false
	}
	parsed, ok := normalize(text)
	if !ok {
		return nil, false
	}
	dec := yaml.NewDecoder(strings.NewReader(parsed))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, false // an empty document is null, not a mapping
	}
	// Anything after the first document, even an empty one after a
	// trailing "---", is "Source contains multiple documents".
	var next yaml.Node
	if err := dec.Decode(&next); !errors.Is(err, io.EOF) {
		return nil, false
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, false
	}
	c := &converter{anchors: map[*yaml.Node]*anchorData{}, active: map[*yaml.Node]bool{}, lines: strings.Split(parsed, "\n")}
	if !c.inSubset(doc.Content[0], false) {
		return nil, false
	}
	v, err := c.toJS(doc.Content[0])
	if err != nil {
		return nil, false
	}
	o, ok := v.(Object)
	return o, ok
}

// ---------------------------------------------------------------------------
// The rules.

// phpNumeric is PHP's is_numeric: what Coolify's normalisation treats as a
// list position.
var phpNumeric = regexp.MustCompile(`^[ \t\n\r\x0b\f]*[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)([eE][+-]?[0-9]+)?[ \t\n\r\x0b\f]*$`)

var phpIntegerKey = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)

// envMap is a JavaScript Map of names to values, in insertion order.
type envMap struct {
	keys   []string
	values map[string]any
}

func (m *envMap) set(k string, v any) {
	if _, ok := m.values[k]; !ok {
		m.keys = append(m.keys, k)
	}
	m.values[k] = v
}

func (m *envMap) has(k string) bool {
	_, ok := m.values[k]
	return ok
}

type phpEntry struct {
	key    string
	hasKey bool
	value  any
}

func phpEntries(source any) []phpEntry {
	switch x := source.(type) {
	case []any:
		out := make([]phpEntry, len(x))
		for i, v := range x {
			out[i] = phpEntry{value: v}
		}
		return out
	case Object:
		out := make([]phpEntry, len(x))
		for i, m := range x {
			out[i] = phpEntry{key: m.Key, hasKey: !phpIntegerKey.MatchString(m.Key), value: m.Value}
		}
		return out
	}
	return nil
}

// environmentOf is a container's environment: merged with its build.args,
// as Coolify's serviceParser reads them. opaque is a numeric key, read in
// an order JavaScript does not reproduce.
func environmentOf(service any) (env *envMap, opaque bool) {
	env = &envMap{values: map[string]any{}}
	o, ok := service.(Object)
	if !ok {
		return env, false
	}
	var build any
	if b, ok := o.get("build").(Object); ok {
		build = b.get("args")
	}
	numericKey := func(source any) bool {
		s, ok := source.(Object)
		return ok && slices.ContainsFunc(s, func(m Member) bool { return phpNumeric.MatchString(m.Key) })
	}
	environment := o.get("environment")
	if numericKey(environment) || numericKey(build) {
		return env, true
	}
	var merged []phpEntry
	for _, entry := range append(phpEntries(environment), phpEntries(build)...) {
		at := -1
		if entry.hasKey {
			at = slices.IndexFunc(merged, func(m phpEntry) bool { return m.hasKey && m.key == entry.key })
		}
		if at >= 0 {
			merged[at] = entry
		} else {
			merged = append(merged, entry)
		}
	}
	associative := slices.ContainsFunc(merged, func(m phpEntry) bool { return m.hasKey })
	for _, m := range merged {
		if m.hasKey {
			env.set(m.key, m.value)
			continue
		}
		value, ok := m.value.(string)
		if !ok {
			continue
		}
		eq := strings.IndexByte(value, '=')
		switch {
		case !associative:
			name, v := value, ""
			if eq >= 0 {
				name, v = value[:eq], value[eq+1:]
			}
			if name != "" {
				env.set(name, v)
			}
		case eq >= 0:
			env.set(value[:eq], value[eq+1:])
		case value != "":
			if env.has(value) {
				env.set(value, env.values[value])
			} else {
				env.set(value, nil)
			}
		}
	}
	return env, false
}

// scalarsOf is every string a parsed document holds, keys included.
func scalarsOf(v any, out []string) []string {
	switch x := v.(type) {
	case string:
		out = append(out, x)
	case []any:
		for _, item := range x {
			out = scalarsOf(item, out)
		}
	case Object:
		for _, m := range x {
			out = append(out, m.Key)
			out = scalarsOf(m.Value, out)
		}
	}
	return out
}

// jsonScalars is the strings JSON.stringify writes of a parsed value, keys
// included: as scalarsOf, but a member whose value is the merge Symbol is
// left out, key and all, as JSON.stringify leaves it out (TypeScript reads
// a container's other settings from JSON.stringify(service)).
func jsonScalars(v any, out []string) []string {
	switch x := v.(type) {
	case string:
		out = append(out, x)
	case []any:
		for _, item := range x {
			out = jsonScalars(item, out)
		}
	case Object:
		for _, m := range x {
			if _, symbol := m.Value.(mergeSymbol); symbol {
				continue
			}
			out = append(out, m.Key)
			out = jsonScalars(m.Value, out)
		}
	}
	return out
}

// loadsDotEnv is whether the generated compose file has the container
// load .env.
func loadsDotEnv(service any) bool {
	o, ok := service.(Object)
	if !ok {
		return false
	}
	files, isArray := o.get("env_file").([]any)
	if !isArray {
		files = []any{o.get("env_file")}
	}
	for _, f := range files {
		path, ok := f.(string)
		if fo, isObject := f.(Object); isObject {
			path, ok = fo.get("path").(string)
		}
		if ok && (path == ".env" || path == "./.env") {
			return true
		}
	}
	return false
}

func identChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
}

// referencesName is /(?<!\$)\$(?:\{NAME(?=[}:?-])|NAME(?![A-Za-z0-9_]))/:
// $NAME or ${NAME…} anywhere, $$ escapes excluded.
func referencesName(text, name string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] != '$' || (i > 0 && text[i-1] == '$') {
			continue
		}
		rest := text[i+1:]
		if strings.HasPrefix(rest, "{"+name) {
			after := rest[1+len(name):]
			if after != "" && strings.IndexByte("}:?-", after[0]) >= 0 {
				return true
			}
		}
		if strings.HasPrefix(rest, name) {
			after := rest[len(name):]
			if after == "" || !identChar(after[0]) {
				return true
			}
		}
	}
	return false
}

// referencesAny is referencesName over the strings of a parsed value, as
// over its JSON text (JSON's escapes never add or remove a $ next to a
// name).
func referencesAny(strs []string, name string) bool {
	return slices.ContainsFunc(strs, func(s string) bool { return referencesName(s, name) })
}

// referenceContent is what Coolify's replaceVariables reads out of a $…
// value.
func referenceContent(value string) string {
	if strings.HasPrefix(value, "${") {
		depth := 0
		for i := 1; i < len(value); i++ {
			switch value[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					return value[2:i]
				}
			}
		}
		return value[2:]
	}
	return value[1:]
}

var defaultOrRequired = regexp.MustCompile(`^(:?-|:?\?)`)

// isSelfReference is ${NAME}, $NAME, or ${NAME with a default or required
// marker.
func isSelfReference(value, name string) bool {
	if value == "$"+name {
		return true
	}
	if !strings.HasPrefix(value, "${") {
		return false
	}
	content := referenceContent(value)
	if value != "${"+content+"}" {
		return false
	}
	return content == name || (strings.HasPrefix(content, name) && defaultOrRequired.MatchString(content[len(name):]))
}

var (
	identHead   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)
	bracedIdent = regexp.MustCompile(`^\{([A-Za-z_][A-Za-z0-9_]*)`)
)

// copiedNames is the names whose stored value Coolify copies into the
// generated compose file for this entry.
func copiedNames(key string, value any) []string {
	s, ok := value.(string)
	if ok && s == "" {
		return []string{key}
	}
	if !ok || !strings.HasPrefix(s, "$") {
		return nil
	}
	content := referenceContent(s)
	if content == key || strings.HasPrefix(content, "SERVICE_") {
		return nil
	}
	var names []string
	if head := identHead.FindString(content); head != "" {
		names = append(names, head)
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '$' || (i > 0 && s[i-1] == '$') {
			continue
		}
		if m := bracedIdent.FindStringSubmatch(s[i+1:]); m != nil {
			names = append(names, m[1])
		}
	}
	return names
}

type verdict int

const (
	verdictDelivered verdict = iota
	verdictShadowed
	verdictOwned
	verdictUnknown
)

// verdictFor is one container's reading of a name its environment sets.
func verdictFor(name string, value any) verdict {
	switch x := value.(type) {
	case nil:
		return verdictUnknown
	case float64, bool:
		return verdictShadowed
	case string:
		if x == "" {
			return verdictDelivered
		}
		if strings.HasPrefix(x, "$") {
			if strings.HasPrefix(referenceContent(x), "SERVICE_") {
				return verdictOwned
			}
			if isSelfReference(x, name) {
				return verdictDelivered
			}
		}
		return verdictShadowed
	}
	return verdictUnknown
}

func unknownUsage(reason string, names []string) *UsageReport {
	return uncheckedUsage(reason, names)
}

// ClassifyComposeUsage is classifyComposeUsage: raw is the compose file as
// written, generated the one Coolify produced at its last parse,
// parsingVersion the service's compose_parsing_version (nil when it is not
// a finite number).
func ClassifyComposeUsage(raw, generated *string, parsingVersion *float64, names []string) *UsageReport {
	if parsingVersion == nil || *parsingVersion < 3 {
		return unknownUsage("this service uses Coolify's older compose parser, whose rules Varlatch does not check", names)
	}
	if raw == nil || *raw == "" {
		return unknownUsage("Coolify did not return the service's compose file", names)
	}
	if generated == nil || *generated == "" {
		return unknownUsage("Coolify has not generated this service's compose file yet (it does at the first start)", names)
	}
	rawDoc, rawOK := parseBounded(*raw)
	genDoc, genOK := parseBounded(*generated)
	if !rawOK || !genOK {
		return unknownUsage("the service's compose file is too large or could not be read", names)
	}
	rawServices, _ := rawDoc.get("services").(Object)
	genServices, _ := genDoc.get("services").(Object)
	containers := make([]string, len(rawServices))
	for i, m := range rawServices {
		containers[i] = m.Key
	}
	slices.SortStableFunc(containers, compareUnits)
	if len(containers) == 0 {
		return unknownUsage("the service's compose file defines no containers", names)
	}

	decoded := scalarsOf(rawDoc, nil)
	copied := map[string]bool{}
	for _, container := range containers {
		env, _ := environmentOf(rawServices.get(container))
		for _, k := range env.keys {
			for _, n := range copiedNames(k, env.values[k]) {
				copied[n] = true
			}
		}
	}

	report := &UsageReport{Checked: true}
	for _, name := range names {
		var usage NameUsage
		var shadowed, unknownIn []string
		reaches := false
		for _, container := range containers {
			service := rawServices.get(container)
			env, opaque := environmentOf(service)
			if opaque {
				unknownIn = append(unknownIn, container)
				continue
			}
			switch {
			case env.has(name):
				switch verdictFor(name, env.values[name]) {
				case verdictOwned:
					usage.Owned = true
				case verdictShadowed:
					shadowed = append(shadowed, container)
				case verdictUnknown:
					unknownIn = append(unknownIn, container)
				default:
					reaches = true
				}
			case loadsDotEnv(genServices.get(container)):
				reaches = true
			case referencesAny(jsonScalars(service, nil), name):
				// The container uses the stored value inside another setting.
				reaches = true
			}
		}
		if referencesName(*raw, name) || referencesAny(decoded, name) {
			usage.Referenced = true
		}
		usage.GeneratedOnce = CoolifyGeneratesName(name)
		usage.CopiedIntoCompose = copied[name]
		usage.ShadowedIn = shadowed
		usage.UnknownIn = unknownIn
		if !reaches && !usage.Owned && len(shadowed) == 0 && len(unknownIn) == 0 {
			usage.NotDeliveredTo = slices.Clone(containers)
		}
		report.set(name, usage)
	}
	return report
}
