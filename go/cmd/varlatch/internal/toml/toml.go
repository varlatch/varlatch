// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
// Ported from smol-toml 1.9.0 (dist/parse.js, struct.js, extract.js,
// primitive.js, util.js, date.js and error.js), Copyright (c) Squirrel Chat
// et al., All rights reserved, under the BSD 3-Clause License
// (LICENSE-smol-toml-BSD-3-Clause, next to this file).

// Package toml reads a TOML document exactly as smol-toml 1.9.0's parse()
// reads it with its default options, which is how the TypeScript CLI reads
// varlatch.toml (packages/context): the same documents accepted, the same
// documents refused with the same message, the same string values. Positions
// and columns count UTF-16 code units, as JavaScript's do, so the message's
// line, column and caret are the same.
//
// The values the CLI reads are strings; the others are kept only as far as
// the parser's own checks need them (a number or a date is "other").
package toml

import (
	"math/big"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
)

// Error is smol-toml's TomlError: Message is the whole of its message,
// "Invalid TOML document: <what>\n\n<code block>"; What is <what>, a
// constant of the parser that never quotes the document, and Line and
// Column (from 1) are where it is, as TomlError's line and column.
type Error struct {
	Message      string
	What         string
	Line, Column int
}

func (e *Error) Error() string { return e.Message }

// Table is a TOML table, its keys in the order the document gives them.
type Table struct {
	keys   []string
	values map[string]any
}

func newTable() *Table { return &Table{values: map[string]any{}} }

// Get is the value of key: a string, *Table, *Array or Other.
func (t *Table) Get(key string) (any, bool) {
	v, ok := t.values[key]
	return v, ok
}

// Keys lists the table's keys in order.
func (t *Table) Keys() []string { return append([]string(nil), t.keys...) }

func (t *Table) has(k string) bool { _, ok := t.values[k]; return ok }

func (t *Table) set(k string, v any) {
	if !t.has(k) {
		t.keys = append(t.keys, k)
	}
	t.values[k] = v
}

// Array is a TOML array.
type Array struct{ Items []any }

// Other is a boolean, number or date: a value the CLI never reads.
type Other struct{ Kind string }

// nan stands for charCodeAt past the end, which is NaN in JavaScript: it
// equals nothing and is neither less nor greater than anything.
const nan = -1

type ctx struct {
	s []uint16
	p int
	d int
}

func (c *ctx) at(i int) int {
	if i < 0 || i >= len(c.s) {
		return nan
	}
	return int(c.s[i])
}

func (c *ctx) slice(from, to int) []uint16 {
	from = max(0, min(from, len(c.s)))
	to = max(from, min(to, len(c.s)))
	return c.s[from:to]
}

// fail throws TomlError.x(message, ctx, ptr).
func (c *ctx) fail(message string, ptr int) {
	panic(newError(c.s, message, ptr))
}

func (c *ctx) failHere(message string) { c.fail(message, c.p) }

// Parse is smol-toml's parse(toml) with the default options, for the text
// as JavaScript holds it: UTF-16 code units.
func Parse(text []uint16) (table *Table, err error) {
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(*Error)
			if !ok {
				panic(r)
			}
			table, err = nil, e
		}
	}()
	return parse(text), nil
}

// ParseString is Parse for a Go string, read as JavaScript reads UTF-8.
func ParseString(text string) (*Table, error) { return Parse(utf16.Encode([]rune(text))) }

// The kinds of a table's metadata (smol-toml's Type).
const (
	typeDotted = iota
	typeExplicit
	typeArray
	typeArrayDotted
)

type meta struct {
	t int
	d bool
	i int
	c map[string]*meta
}

func newMeta(t int) *meta { return &meta{t: t, c: map[string]*meta{}} }

type peeked struct {
	key   string
	table *Table
	c     map[string]*meta
}

// peekTable is parse.js's peekTable; nil is its null. The table being
// walked is a *Table, or the *Array of a table array whose last element
// the walk then takes, as JavaScript's does.
func peekTable(key []string, table *Table, m map[string]*meta, typ int) *peeked {
	t := table
	var k string
	hasOwn := false
	var state *meta
	for i := 0; i < len(key); i++ {
		if i > 0 {
			var next any
			if hasOwn {
				next = t.values[k]
			} else {
				nt := newTable()
				t.set(k, nt)
				next = nt
			}
			state = m[k]
			m = state.c
			if typ == typeDotted && (state.t == typeExplicit || state.t == typeArray) {
				return nil
			}
			if state.t == typeArray {
				arr, ok := next.(*Array)
				if !ok || len(arr.Items) == 0 {
					return nil
				}
				l := len(arr.Items) - 1
				next = arr.Items[l]
				m = m[strconv.Itoa(l)].c
			}
			nt, ok := next.(*Table)
			if !ok {
				// Not reached: a value's own entry is a defined dotted key,
				// refused below before the walk goes into it.
				return nil
			}
			t = nt
		}
		k = key[i]
		hasOwn = t.has(k)
		if hasOwn {
			if mk := m[k]; mk != nil && mk.t == typeDotted && mk.d {
				return nil
			}
		}
		if !hasOwn {
			t2 := typ
			if i < len(key)-1 && typ == typeArray {
				t2 = typeArrayDotted
			}
			m[k] = newMeta(t2)
		}
	}
	state = m[k]
	if state.t != typ && !(typ == typeExplicit && state.t == typeArrayDotted) {
		return nil
	}
	if typ == typeArray {
		if !state.d {
			state.d = true
			t.set(k, &Array{})
		}
		arr, ok := t.values[k].(*Array)
		if !ok {
			return nil
		}
		elem := newTable()
		arr.Items = append(arr.Items, elem)
		t = elem
		next := newMeta(typeExplicit)
		state.c[strconv.Itoa(state.i)] = next
		state.i++
		state = next
	}
	if state.d {
		return nil
	}
	state.d = true
	if typ == typeExplicit {
		if hasOwn {
			nt, ok := t.values[k].(*Table)
			if !ok {
				return nil
			}
			t = nt
		} else {
			nt := newTable()
			t.set(k, nt)
			t = nt
		}
	} else if typ == typeDotted && hasOwn {
		return nil
	}
	return &peeked{key: k, table: t, c: state.c}
}

func parse(s []uint16) *Table {
	c := &ctx{s: s, d: 1000}
	res := newTable()
	metaRoot := map[string]*meta{}
	tbl := res
	m := metaRoot
	if c.at(0) == 0xfeff {
		c.p++
	}
	skipVoid(c, false, false)
	for c.p < len(s) {
		if c.at(c.p) == '[' {
			c.p++
			isTableArray := c.at(c.p) == '['
			if isTableArray {
				c.p++
			}
			tmp := c.p
			k := parseKey(c, ']')
			if isTableArray {
				if c.at(c.p) != ']' {
					c.failHere("expected end of table array declaration")
				}
				c.p++
			}
			typ := typeExplicit
			if isTableArray {
				typ = typeArray
			}
			p := peekTable(k, res, metaRoot, typ)
			if p == nil {
				c.fail("trying to redefine an already defined table or value", tmp)
			}
			m = p.c
			tbl = p.table
		} else {
			tmp := c.p
			k := parseKey(c, '=')
			p := peekTable(k, tbl, m, typeDotted)
			if p == nil {
				c.fail("trying to redefine an already defined table or value", tmp)
			}
			skipVoid(c, true, true)
			v := extractValue(c, 0)
			p.table.set(p.key, v)
		}
		skipVoid(c, true, false)
		if c.p < len(s) {
			if ch := c.at(c.p); ch != '\n' && (ch != '\r' || c.at(c.p+1) != '\n') {
				c.failHere("each key-value declaration must be followed by an end-of-line")
			}
		}
		skipVoid(c, false, false)
	}
	return res
}

// util.js

func skipComment(c *ctx) {
	for ; c.p < len(c.s); c.p++ {
		ch := c.at(c.p)
		if ch == '\n' {
			break
		}
		if ch == '\r' && c.at(c.p+1) == '\n' {
			c.p++
			break
		}
		if (ch < 0x20 && ch != '\t') || ch == 0x7f {
			c.failHere("control characters are not allowed in comments")
		}
	}
}

func skipVoid(c *ctx, banNewLines, banComments bool) {
	ch := nan
	for c.p < len(c.s) {
		for c.p < len(c.s) {
			ch = c.at(c.p)
			if ch == ' ' || ch == '\t' || (!banNewLines && (ch == '\n' || (ch == '\r' && c.at(c.p+1) == '\n'))) {
				c.p++
				continue
			}
			break
		}
		if banComments || ch != '#' {
			break
		}
		skipComment(c)
	}
}

// struct.js

func parseKey(c *ctx, end int) []string {
	startPtr := c.p
	state := 0
	var parsed []string
	sliceStart := 0
	ch := c.at(c.p)
	for {
		switch {
		case ch == end:
			if state == 0 {
				c.failHere("unexpected end of key")
			}
			if state == 1 {
				parsed = append(parsed, str(c.slice(sliceStart, c.p)))
			}
			c.p++
			return parsed
		case ch == '.':
			if state == 0 {
				c.failHere("illegal empty bare key")
			}
			if state == 1 {
				parsed = append(parsed, str(c.slice(sliceStart, c.p)))
			}
			state = 0
		case state == 0 && (ch == '"' || ch == '\''):
			if ch == c.at(c.p+1) && ch == c.at(c.p+2) {
				c.failHere("illegal quoted key: multiline strings are not allowed")
			}
			parsed = append(parsed, parseString(c))
			state = 2
			c.p--
		case ch == ' ' || ch == '\t':
			if state == 1 {
				parsed = append(parsed, str(c.slice(sliceStart, c.p)))
				state = 2
			}
		case state == 2 || ch != nan && ((ch < 0x30 && ch != '-') || (ch > 0x39 && ch < 0x41) || (ch > 0x5a && ch < 0x61 && ch != '_') || ch > 0x7a):
			c.failHere("illegal character in key")
		case state == 0:
			state = 1
			sliceStart = c.p
		}
		c.p++
		ch = c.at(c.p)
		if ch == nan || ch == 0 {
			break
		}
	}
	c.fail("incomplete key-value: cannot find end of key", startPtr)
	return nil
}

func parseInlineTable(c *ctx) *Table {
	startPtr := c.p
	c.p++
	res := newTable()
	// smol-toml keeps a Set of the object values it assigned; an own entry
	// that is an object and not in it is a table made by a dotted key. Here
	// those tables are the ones remembered.
	implicit := map[*Table]bool{}
	for c.p < len(c.s) {
		skipVoid(c, false, false)
		if c.at(c.p) == '}' {
			c.p++
			return res
		}
		var k string
		t := res
		hasOwn := false
		errPtr := c.p
		key := parseKey(c, '=')
		for i := 0; i < len(key); i++ {
			if i > 0 {
				if hasOwn {
					t = t.values[k].(*Table) // an implicit table: anything else was refused
				} else {
					nt := newTable()
					t.set(k, nt)
					implicit[nt] = true
					t = nt
				}
			}
			k = key[i]
			if hasOwn = t.has(k); hasOwn {
				if nt, ok := t.values[k].(*Table); !ok || !implicit[nt] {
					c.fail("trying to redefine an already defined value", errPtr)
				}
			}
		}
		if hasOwn {
			c.fail("trying to redefine an already defined value", errPtr)
		}
		skipVoid(c, true, true)
		t.set(k, extractValue(c, '}'))
		skipVoid(c, false, false)
		ch := c.at(c.p)
		c.p++
		if ch == '}' {
			return res
		}
		if ch != ',' {
			c.fail("expected comma or end of structure", c.p-1)
		}
	}
	c.fail("unfinished table", startPtr)
	return nil
}

func parseArray(c *ctx) *Array {
	startPtr := c.p
	c.p++
	res := &Array{Items: []any{}}
	for c.p < len(c.s) {
		skipVoid(c, false, false)
		if c.at(c.p) == ']' {
			c.p++
			return res
		}
		res.Items = append(res.Items, extractValue(c, ']'))
		skipVoid(c, false, false)
		ch := c.at(c.p)
		c.p++
		if ch == ']' {
			return res
		}
		if ch != ',' {
			c.fail("expected comma or end of structure", c.p-1)
		}
	}
	c.fail("unfinished array", startPtr)
	return nil
}

// extract.js

func isDigit(ch int, base int) bool {
	if base == 16 {
		return (ch > 0x2f && ch < 0x3a) || (ch > 0x40 && ch < 0x47) || (ch > 0x60 && ch < 0x67)
	}
	return ch > 0x2f && ch < 0x30+base
}

func isEndOfValue(ch int, delim int) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' ||
		(delim != 0 && (ch == delim || ch == ',')) ||
		ch == '#'
}

func extractValue(c *ctx, end int) any {
	errPtr := c.p
	ch := c.at(c.p)
	if ch == '[' || ch == '{' {
		if c.d == 0 {
			c.failHere("document contains excessively nested structures. aborting.")
		}
		c.d--
		var v any
		if ch == '[' {
			v = parseArray(c)
		} else {
			v = parseInlineTable(c)
		}
		c.d++
		return v
	}
	if ch == '"' || ch == '\'' {
		return parseString(c)
	}
	if ch == 't' {
		c.p++
		if c.at(c.p) != 'r' {
			c.fail("invalid value", errPtr)
		}
		c.p++
		if c.at(c.p) != 'u' {
			c.fail("invalid value", errPtr)
		}
		c.p++
		if c.at(c.p) != 'e' {
			c.fail("invalid value", errPtr)
		}
		c.p++
		return Other{Kind: "boolean"}
	}
	if ch == 'f' {
		for _, want := range "alse" {
			c.p++
			if c.at(c.p) != int(want) {
				c.fail("invalid value", errPtr)
			}
		}
		c.p++
		return Other{Kind: "boolean"}
	}
	if ch == '+' || ch == '-' {
		sign := 1
		if ch == '-' {
			sign = -1
		}
		start := c.p
		c.p++
		return parseNumber(c, start, c.at(c.p), sign, end)
	}
	if c.at(c.p+4) == '-' && c.at(c.p+7) == '-' {
		return parseDate(c, ch, end)
	}
	if c.at(c.p+2) == ':' {
		return parseTime(c, ch, end)
	}
	return parseNumber(c, c.p, ch, 0, end)
}

// parseNumber is extract.js's parseNumber; see its comments for the states.
func parseNumber(c *ctx, startPtr int, startChr int, sign int, endChr int) any {
	ch := startChr
	state := 0
	hasUnderscores := false
	if ch == 'i' {
		c.p++
		if c.at(c.p) != 'n' {
			c.fail("invalid value", startPtr)
		}
		c.p++
		if c.at(c.p) != 'f' {
			c.fail("invalid value", startPtr)
		}
		c.p++
		return Other{Kind: "number"}
	}
	if ch == 'n' {
		c.p++
		if c.at(c.p) != 'a' {
			c.fail("invalid value", startPtr)
		}
		c.p++
		if c.at(c.p) != 'n' {
			c.fail("invalid value", startPtr)
		}
		c.p++
		return Other{Kind: "number"}
	}
	if ch == '0' {
		c.p++
		if c.p >= len(c.s) {
			return Other{Kind: "number"}
		}
		ch = c.at(c.p)
		if isEndOfValue(ch, endChr) {
			return Other{Kind: "number"}
		}
		if sign == 0 {
			switch ch {
			case 'x':
				return parseIntegerBaseN(c, startPtr, 16, endChr)
			case 'b':
				return parseIntegerBaseN(c, startPtr, 2, endChr)
			case 'o':
				return parseIntegerBaseN(c, startPtr, 8, endChr)
			}
		}
		switch {
		case ch == '.':
			state = 2
		case ch == 'e' || ch == 'E':
			state = 4
		default:
			c.fail("illegal leading zero", startPtr)
		}
	} else if !isDigit(ch, 10) {
		c.fail("invalid value", startPtr)
	}
	for {
		c.p++
		if c.p >= len(c.s) {
			break
		}
		ch = c.at(c.p)
		if isEndOfValue(ch, endChr) {
			break
		}
		if state == 0 {
			state = 1
		}
		switch {
		case ch == '_':
			if state&1 == 0 {
				c.failHere("illegal underscore")
			}
			state += 11
			hasUnderscores = true
		case state == 1 && ch == '.':
			state = 2
		case (state == 1 || state == 3) && (ch == 'e' || ch == 'E'):
			state = 4
		case state == 4 && (ch == '+' || ch == '-'):
		case !isDigit(ch, 10):
			c.failHere("illegal character in numeric literal")
		case state > 9:
			state -= 11
		case state&1 == 0:
			state++
		}
	}
	if state == 0 {
		return Other{Kind: "number"}
	}
	if state&1 == 0 {
		c.fail("unfinished numeric value", startPtr)
	}
	if state > 1 {
		return Other{Kind: "number"} // parseFloat: never refused
	}
	text := str(c.slice(startPtr, c.p))
	if hasUnderscores {
		text = strings.ReplaceAll(text, "_", "")
	}
	parseInteger(c, text, 10, startPtr)
	return Other{Kind: "number"}
}

func parseIntegerBaseN(c *ctx, startPtr int, base int, endChr int) any {
	underscore := 1
	for {
		c.p++
		if c.p >= len(c.s) {
			break
		}
		ch := c.at(c.p)
		if isEndOfValue(ch, endChr) {
			break
		}
		switch {
		case ch == '_':
			if underscore&1 != 0 {
				c.failHere("illegal underscore")
			}
			underscore = 3
		case !isDigit(ch, base):
			c.failHere("illegal character in numeric literal")
		case underscore&1 != 0:
			underscore--
		}
	}
	if underscore&1 != 0 {
		c.failHere("unfinished numeric value")
	}
	text := strings.ReplaceAll(str(c.slice(startPtr+2, c.p)), "_", "")
	parseInteger(c, text, base, startPtr)
	return Other{Kind: "number"}
}

// maxSafe is Number.MAX_SAFE_INTEGER.
var maxSafe = big.NewInt(1<<53 - 1)

// parseInteger refuses what parseInt(str, base) cannot hold exactly
// (Number.isSafeInteger): an integer beyond 2^53 - 1 rounds to 2^53 or more.
// str holds an optional sign and then digits of the base only.
func parseInteger(c *ctx, text string, base int, startPtr int) {
	digits := strings.TrimLeft(text, "+-")
	n, ok := new(big.Int).SetString(digits, base)
	if !ok || n.CmpAbs(maxSafe) > 0 {
		c.fail("integer value cannot be represented losslessly", startPtr)
	}
}

func parseDate(c *ctx, ch int, endChr int) any {
	startPtr := c.p
	c.p++
	unsafeSeparator := false
	if !isDigit(ch, 10) {
		c.p = startPtr
		return parseNumber(c, startPtr, ch, 0, endChr)
	}
	for range 3 {
		d := c.at(c.p)
		c.p++
		if !isDigit(d, 10) {
			c.p = startPtr
			return parseNumber(c, startPtr, ch, 0, endChr)
		}
	}
	c.p += 5
	d := c.at(c.p)
	c.p++
	if !isDigit(d, 10) {
		c.fail("invalid date-time: date part is malformed", startPtr)
	}
	if c.p >= len(c.s) {
		return readDate(c, c.slice(startPtr, c.p), 3, false, startPtr)
	}
	ch = c.at(c.p)
	// (c !== ' ' || (unsafe = true, !isDigit(next))) && c !== 'T' && c !== 't'
	notTime := ch != ' '
	if !notTime {
		unsafeSeparator = true
		notTime = !isDigit(c.at(c.p+1), 10)
	}
	if notTime && ch != 'T' && ch != 't' {
		return readDate(c, c.slice(startPtr, c.p), 3, false, startPtr)
	}
	c.p += 3
	if c.at(c.p) != ':' {
		c.fail("invalid date-time: time part is malformed", startPtr)
	}
	c.p += 3
	if c.at(c.p) == ':' {
		c.p += 3
	}
	if c.at(c.p) == '.' {
		for {
			c.p++
			if !isDigit(c.at(c.p), 10) {
				break
			}
		}
	}
	if ch = c.at(c.p); ch != nan && ch != 0 {
		if ch == 'Z' || ch == 'z' {
			c.p++
			return readDate(c, c.slice(startPtr, c.p), 1, unsafeSeparator, startPtr)
		}
		if ch == '+' || ch == '-' {
			c.p += 6
			return readDate(c, c.slice(startPtr, c.p), 1, unsafeSeparator, startPtr)
		}
	}
	return readDate(c, c.slice(startPtr, c.p), 2, unsafeSeparator, startPtr)
}

func parseTime(c *ctx, ch int, endChr int) any {
	start := c.p
	c.p++
	if !isDigit(ch, 10) || !isDigit(c.at(c.p), 10) {
		c.p--
		return parseNumber(c, c.p, ch, 0, endChr)
	}
	c.p += 4
	if c.at(c.p) == ':' {
		c.p += 3
	}
	if c.at(c.p) == '.' {
		for {
			c.p++
			if !isDigit(c.at(c.p), 10) {
				break
			}
		}
	}
	return readDate(c, c.slice(start, c.p), 4, false, start)
}

// readDate is extract.js's readDate with useLegacyDate (the default): a
// TomlDate, refused when it is not a valid Date.
func readDate(c *ctx, text []uint16, typ int, unsafeDelim bool, errPtr int) any {
	if !tomlDateValid(text, typ, unsafeDelim) {
		c.fail("invalid date", errPtr)
	}
	return Other{Kind: "date"}
}

// tomlDateValid is date.js's TomlDate constructor for a "fast type"
// followed by isValid(): whether new Date(...) of the string it builds is
// a valid time.
func tomlDateValid(u []uint16, fasttype int, unsafeDelim bool) bool {
	date := u
	sl := func(from, to int) []uint16 {
		from = max(0, min(from, len(date)))
		to = max(from, min(to, len(date)))
		return date[from:to]
	}
	if fasttype < 3 {
		if h, ok := jsval.ToNumber(sl(11, 13)); ok && h > 23 {
			return false // new Date('') is invalid
		}
		if fasttype == 2 {
			date = append(append([]uint16(nil), date...), 'Z')
		}
		if unsafeDelim {
			date = append(append(append([]uint16(nil), sl(0, 10)...), 'T'), sl(11, len(date))...)
		}
	} else if fasttype == 4 {
		if h, ok := jsval.ToNumber(sl(0, 2)); ok && h > 23 {
			return false
		}
		date = append(append(utf16.Encode([]rune("0000-01-01T")), date...), 'Z')
	}
	_, ok := jsval.DateParse(str(date))
	return ok
}

// primitive.js

func parseString(c *ctx) string {
	startPtr := c.p
	ch := c.at(c.p)
	c.p++
	first := ch
	isLiteral := ch == '\''
	isMultiline := ch == c.at(c.p) && ch == c.at(c.p+1)
	if isMultiline {
		c.p += 2
		ch = c.at(c.p)
		if ch == '\n' {
			c.p++
		} else if ch == '\r' && c.at(c.p+1) == '\n' {
			c.p += 2
		}
	}
	var parsed []uint16
	sliceStart := c.p
	state := 0
	for ; c.p < len(c.s); c.p++ {
		ch = c.at(c.p)
		switch {
		case isMultiline && (ch == '\n' || (ch == '\r' && c.at(c.p+1) == '\n')):
			if state != 0 {
				state = 3
			}
		case (ch < 0x20 && ch != '\t') || ch == 0x7f:
			c.failHere("control characters are not allowed in strings")
		case (state == 0 || state == 3) && ch == first && (!isMultiline || (c.at(c.p+1) == first && c.at(c.p+2) == first)):
			if isMultiline {
				if c.at(c.p+3) == first {
					c.p++
				}
				if c.at(c.p+3) == first {
					c.p++
				}
			}
			if state == 0 {
				parsed = append(parsed, c.slice(sliceStart, c.p)...)
			}
			if isMultiline {
				c.p += 3
			} else {
				c.p++
			}
			return str(parsed)
		case state == 0:
			if !isLiteral && ch == '\\' {
				parsed = append(parsed, c.slice(sliceStart, c.p)...)
				sliceStart = c.p
				state = 1
			}
		case state == 1:
			switch {
			case ch == 'x' || ch == 'u' || ch == 'U':
				errPtr := c.p - 1
				c.p++
				var value int32
				n := 8
				if ch == 'x' {
					n = 2
				} else if ch == 'u' {
					n = 4
				}
				for j := 0; j < n; j, c.p = j+1, c.p+1 {
					hex := c.at(c.p)
					digit := -1
					switch {
					case hex >= '0' && hex <= '9':
						digit = hex - '0'
					case hex >= 'A' && hex <= 'F':
						digit = hex - 'A' + 10
					case hex >= 'a' && hex <= 'f':
						digit = hex - 'a' + 10
					}
					if digit < 0 {
						c.failHere("invalid non-hex character in unicode escape")
					}
					value = value<<4 | int32(digit) // JavaScript's 32-bit signed bitwise or
				}
				if value < 0 || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff) {
					c.fail("invalid unicode escape", errPtr)
				}
				parsed = append(parsed, utf16.Encode([]rune{rune(value)})...)
				sliceStart = c.p
				c.p--
				state = 0
			case isMultiline && (ch == ' ' || ch == '\t'):
				state = 2
			default:
				switch ch {
				case 'b':
					parsed = append(parsed, '\b')
				case 't':
					parsed = append(parsed, '\t')
				case 'n':
					parsed = append(parsed, '\n')
				case 'f':
					parsed = append(parsed, '\f')
				case 'r':
					parsed = append(parsed, '\r')
				case 'e':
					parsed = append(parsed, 0x1b)
				case '"':
					parsed = append(parsed, '"')
				case '\\':
					parsed = append(parsed, '\\')
				default:
					c.failHere("unrecognised escape sequence")
				}
				sliceStart = c.p + 1
				state = 0
			}
		default:
			if ch != ' ' && ch != '\t' {
				if state == 2 {
					c.fail("invalid escape: only line-ending whitespace may be escaped", sliceStart)
				}
				if !isLiteral && ch == '\\' {
					state = 1
				} else {
					state = 0
				}
				sliceStart = c.p
			}
		}
	}
	c.fail("unfinished string", startPtr)
	return ""
}

// str is a UTF-16 string as Go text, a lone surrogate (which a decoded
// file cannot hold) in its WTF-8 bytes, as lib/jsjson keeps one.
func str(u []uint16) string { return jsval.FromUTF16(u) }

// error.js

// newError is TomlError for ptr in the document.
func newError(s []uint16, message string, ptr int) *Error {
	before := s[:max(0, min(ptr, len(s)))]
	lines := splitLines(before)
	line := len(lines)
	column := len(lines[len(lines)-1]) + 1
	return &Error{
		Message: "Invalid TOML document: " + message + "\n\n" + codeBlock(s, line, column),
		What:    message,
		Line:    line,
		Column:  column,
	}
}

// splitLines is .split(/\r?\n/).
func splitLines(s []uint16) [][]uint16 {
	var out [][]uint16
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			end := i
			if end > start && s[end-1] == '\r' {
				end--
			}
			out = append(out, s[start:end])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func codeBlock(s []uint16, line, column int) string {
	lines := splitLines(s)
	var b strings.Builder
	numberLen := len(strconv.Itoa(line + 1)) // (Math.log10(line + 1) | 0) + 1
	for i := line - 1; i <= line+1; i++ {
		if i-1 < 0 || i-1 >= len(lines) || len(lines[i-1]) == 0 {
			continue
		}
		n := strconv.Itoa(i)
		b.WriteString(n + strings.Repeat(" ", max(0, numberLen-len(n))))
		b.WriteString(":  ")
		b.WriteString(str(lines[i-1]))
		b.WriteString("\n")
		if i == line {
			b.WriteString(strings.Repeat(" ", numberLen+column+2))
			b.WriteString("^\n")
		}
	}
	return b.String()
}
