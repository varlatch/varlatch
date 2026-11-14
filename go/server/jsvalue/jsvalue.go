// SPDX-License-Identifier: AGPL-3.0-or-later

// Package jsvalue is JSON as the TypeScript server reads and writes it, so
// that what varlatchd stores and answers matches it byte for byte (ADR-0059
// step 3.3):
//
//   - Stringify is JSON.stringify: object members in insertion order, no
//     HTML escaping, U+2028 and U+2029 left as they are, numbers in
//     ECMAScript's Number.prototype.toString form, lone surrogates escaped.
//   - Parse is JSON.parse with JavaScript's property order: numbers become
//     float64 (as JavaScript's numbers), a repeated key keeps its first
//     position and its last value, and keys that are array indexes ("0",
//     "17") come first, in numeric order (JSOrder).
//   - Jsonb reorders a value as PostgreSQL's jsonb stores it: within each
//     object, shorter keys first, keys of one length by their UTF-8 bytes,
//     and a repeated key's last value. The TypeScript server's audit
//     columns are jsonb, so every nested object it reads back (and answers
//     with) is in that order, whatever order it was written in.
//
// A value is nil (null), bool, float64 (or any Go integer, when building
// one), string, Object, []any, []string, or a type with a JSValue method.
package jsvalue

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Member is one member of an Object.
type Member struct {
	Key   string
	Value any
}

// Object is a JSON object with its members in order. Keys are unique in an
// Object built by Parse, Jsonb or Set.
type Object []Member

// Get returns the value of key.
func (o Object) Get(key string) (any, bool) {
	for _, m := range o {
		if m.Key == key {
			return m.Value, true
		}
	}
	return nil, false
}

// Set replaces key's value in place, or appends the member: JavaScript's
// assignment to an object property.
func (o Object) Set(key string, value any) Object {
	for i := range o {
		if o[i].Key == key {
			o[i].Value = value
			return o
		}
	}
	return append(o, Member{key, value})
}

// Valuer is a type with a JSON form of its own.
type Valuer interface {
	JSValue() any
}

// Stringify is JSON.stringify(v).
func Stringify(v any) []byte {
	var b bytes.Buffer
	write(&b, v)
	return b.Bytes()
}

func write(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		Quote(b, x)
	case float64:
		b.WriteString(Number(x))
	case int:
		b.WriteString(Number(float64(x)))
	case int32:
		b.WriteString(Number(float64(x)))
	case int64:
		b.WriteString(Number(float64(x)))
	case Object:
		b.WriteByte('{')
		for i, m := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			Quote(b, m.Key)
			b.WriteByte(':')
			write(b, m.Value)
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			write(b, e)
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			Quote(b, e)
		}
		b.WriteByte(']')
	case Valuer:
		write(b, x.JSValue())
	default:
		panic(fmt.Sprintf("jsvalue: %T is not a JSON value", v))
	}
}

const hex = "0123456789abcdef"

// Quote writes s as JSON.stringify quotes a string. A lone UTF-16
// surrogate, which Parse keeps as its WTF-8 bytes (ED A0..BF 80..BF), is
// written as JSON.stringify writes one: \udxxx. Any other byte that is not
// UTF-8 counts as U+FFFD, as decoding it into a JavaScript string would.
func Quote(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			if sur, ok := surrogateAt(s, i); ok {
				fmt.Fprintf(b, `\u%04x`, sur)
				i += 3
				continue
			}
		}
		i += size
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte(hex[r>>4])
			b.WriteByte(hex[r&0xf])
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// surrogateAt reads a surrogate code point's WTF-8 encoding at s[i:].
func surrogateAt(s string, i int) (rune, bool) {
	if i+2 < len(s) && s[i] == 0xed && s[i+1] >= 0xa0 && s[i+1] <= 0xbf && s[i+2] >= 0x80 && s[i+2] <= 0xbf {
		return 0xd000 | rune(s[i+1]&0x3f)<<6 | rune(s[i+2]&0x3f), true
	}
	return 0, false
}

// appendWTF8 appends a surrogate code point's WTF-8 encoding: the bytes
// UTF-8 would give it, which no valid UTF-8 text holds.
func appendWTF8(b []byte, r rune) []byte {
	return append(b, 0xe0|byte(r>>12), 0x80|byte(r>>6)&0x3f, 0x80|byte(r)&0x3f)
}

// JsonbRefuses reports why PostgreSQL's jsonb would refuse v's JSON text,
// or nil: a string (key or value) with a lone surrogate, which jsonb's
// input refuses as invalid syntax, or with U+0000, an unsupported escape.
func JsonbRefuses(v any) error {
	check := func(s string) error {
		if HasLoneSurrogate(s) {
			return errors.New("jsvalue: jsonb refuses a lone surrogate")
		}
		if strings.IndexByte(s, 0) >= 0 {
			return errors.New("jsvalue: jsonb refuses \\u0000")
		}
		return nil
	}
	switch x := v.(type) {
	case string:
		return check(x)
	case Object:
		for _, m := range x {
			if err := check(m.Key); err != nil {
				return err
			}
			if err := JsonbRefuses(m.Value); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range x {
			if err := JsonbRefuses(e); err != nil {
				return err
			}
		}
	case []string:
		for _, e := range x {
			if err := check(e); err != nil {
				return err
			}
		}
	case Valuer:
		return JsonbRefuses(x.JSValue())
	}
	return nil
}

// HasLoneSurrogate reports whether s holds a lone surrogate (from Parse).
func HasLoneSurrogate(s string) bool {
	for i := 0; i < len(s); i++ {
		if _, ok := surrogateAt(s, i); ok {
			return true
		}
	}
	return false
}

// Number is ECMAScript's Number::toString(x) in radix 10, which
// JSON.stringify uses; NaN and the infinities are null.
func Number(x float64) string {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return "null"
	}
	if x == 0 {
		return "0" // -0 too
	}
	sign := ""
	if x < 0 {
		sign, x = "-", -x
	}
	// The shortest digits that round-trip, as ECMAScript requires: d.ddde+x.
	e := strconv.FormatFloat(x, 'e', -1, 64)
	mant, exp, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	p, _ := strconv.Atoi(exp)
	k, n := len(digits), p+1 // x = 0.digits * 10^n
	var s string
	switch {
	case k <= n && n <= 21:
		s = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		s = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		s = "0." + strings.Repeat("0", -n) + digits
	default:
		es := "+"
		if n-1 < 0 {
			es = "-"
		}
		ev := strconv.Itoa(abs(n - 1))
		if k == 1 {
			s = digits + "e" + es + ev
		} else {
			s = digits[:1] + "." + digits[1:] + "e" + es + ev
		}
	}
	return sign + s
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// Parse is JSON.parse(text), keeping JavaScript's property order (see the
// package comment). Strings are kept as UTF-16 code units are: a \u escape
// of a lone surrogate (one not in a high-low pair) stays a lone surrogate,
// held as its WTF-8 bytes, which Quote writes back as JSON.stringify does.
// The text itself must be UTF-8.
func Parse(text []byte) (any, error) {
	if !utf8.Valid(text) {
		return nil, errors.New("jsvalue: the text is not UTF-8")
	}
	p := &parser{s: text}
	p.space()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.i != len(p.s) {
		return nil, p.fail("text after the value")
	}
	return JSOrder(v), nil
}

type parser struct {
	s []byte
	i int
}

const maxDepth = 10000

func (p *parser) fail(what string) error {
	return fmt.Errorf("jsvalue: %s at offset %d", what, p.i)
}

func (p *parser) space() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) literal(word string, v any) (any, error) {
	if !bytes.HasPrefix(p.s[p.i:], []byte(word)) {
		return nil, p.fail("unexpected input")
	}
	p.i += len(word)
	return v, nil
}

func (p *parser) value(depth int) (any, error) {
	if depth > maxDepth {
		return nil, p.fail("nesting too deep")
	}
	if p.i >= len(p.s) {
		return nil, p.fail("unexpected end")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		p.i++
		o := Object{}
		p.space()
		if p.i < len(p.s) && p.s[p.i] == '}' {
			p.i++
			return o, nil
		}
		for {
			p.space()
			if p.i >= len(p.s) || p.s[p.i] != '"' {
				return nil, p.fail("expected a key")
			}
			k, err := p.str()
			if err != nil {
				return nil, err
			}
			p.space()
			if p.i >= len(p.s) || p.s[p.i] != ':' {
				return nil, p.fail("expected ':'")
			}
			p.i++
			p.space()
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			o = o.Set(k, v)
			p.space()
			if p.i < len(p.s) && p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.i < len(p.s) && p.s[p.i] == '}' {
				p.i++
				return o, nil
			}
			return nil, p.fail("expected ',' or '}'")
		}
	case c == '[':
		p.i++
		a := []any{}
		p.space()
		if p.i < len(p.s) && p.s[p.i] == ']' {
			p.i++
			return a, nil
		}
		for {
			p.space()
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
			p.space()
			if p.i < len(p.s) && p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.i < len(p.s) && p.s[p.i] == ']' {
				p.i++
				return a, nil
			}
			return nil, p.fail("expected ',' or ']'")
		}
	case c == '"':
		return p.str()
	case c == 't':
		return p.literal("true", true)
	case c == 'f':
		return p.literal("false", false)
	case c == 'n':
		return p.literal("null", nil)
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	return nil, p.fail("unexpected input")
}

func digits(s []byte, i int) int {
	j := i
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	return j
}

// number reads JSON's number grammar. JSON.parse gives the nearest double,
// an infinity beyond its range.
func (p *parser) number() (any, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	switch {
	case p.i < len(p.s) && p.s[p.i] == '0':
		p.i++
	case p.i < len(p.s) && p.s[p.i] >= '1' && p.s[p.i] <= '9':
		p.i = digits(p.s, p.i)
	default:
		return nil, p.fail("bad number")
	}
	if p.i < len(p.s) && p.s[p.i] == '.' {
		j := digits(p.s, p.i+1)
		if j == p.i+1 {
			return nil, p.fail("bad number")
		}
		p.i = j
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		j := p.i + 1
		if j < len(p.s) && (p.s[j] == '+' || p.s[j] == '-') {
			j++
		}
		k := digits(p.s, j)
		if k == j {
			return nil, p.fail("bad number")
		}
		p.i = k
	}
	f, err := strconv.ParseFloat(string(p.s[start:p.i]), 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return nil, err
	}
	return f, nil
}

func (p *parser) hex4() (rune, bool) {
	if p.i+4 > len(p.s) {
		return 0, false
	}
	var r rune
	for _, c := range p.s[p.i : p.i+4] {
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(d)
	}
	p.i += 4
	return r, true
}

// str reads a string. A high surrogate escape followed by a low one is one
// code point; any other surrogate escape stays a lone surrogate (WTF-8).
func (p *parser) str() (string, error) {
	p.i++ // the opening quote
	var b []byte
	for {
		if p.i >= len(p.s) {
			return "", p.fail("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return string(b), nil
		case c < 0x20:
			return "", p.fail("control character in a string")
		case c != '\\':
			b = append(b, c)
			p.i++
			continue
		}
		p.i++
		if p.i >= len(p.s) {
			return "", p.fail("unterminated escape")
		}
		e := p.s[p.i]
		p.i++
		switch e {
		case '"', '\\', '/':
			b = append(b, e)
		case 'b':
			b = append(b, '\b')
		case 'f':
			b = append(b, '\f')
		case 'n':
			b = append(b, '\n')
		case 'r':
			b = append(b, '\r')
		case 't':
			b = append(b, '\t')
		case 'u':
			r, ok := p.hex4()
			if !ok {
				return "", p.fail("bad \\u escape")
			}
			if r >= 0xd800 && r <= 0xdbff && p.i+1 < len(p.s) && p.s[p.i] == '\\' && p.s[p.i+1] == 'u' {
				save := p.i
				p.i += 2
				if lo, ok := p.hex4(); ok && lo >= 0xdc00 && lo <= 0xdfff {
					b = utf8.AppendRune(b, 0x10000+(r-0xd800)<<10+(lo-0xdc00))
					continue
				}
				p.i = save
			}
			if r >= 0xd800 && r <= 0xdfff {
				b = appendWTF8(b, r)
			} else {
				b = utf8.AppendRune(b, r)
			}
		default:
			return "", p.fail("bad escape")
		}
	}
}

// arrayIndex reports whether k is an array index, which a JavaScript
// object orders before its other keys: "0", or a decimal without leading
// zeros below 2^32 - 1.
func arrayIndex(k string) (uint64, bool) {
	if k == "" || len(k) > 10 || (len(k) > 1 && k[0] == '0') {
		return 0, false
	}
	n, err := strconv.ParseUint(k, 10, 64)
	if err != nil || n >= 1<<32-1 {
		return 0, false
	}
	return n, true
}

// JSOrder returns v with every object's members in the order a JavaScript
// object built from it enumerates them: array indexes first, ascending,
// then the other keys in their order.
func JSOrder(v any) any {
	switch x := v.(type) {
	case Object:
		o := make(Object, len(x))
		for i, m := range x {
			o[i] = Member{m.Key, JSOrder(m.Value)}
		}
		slices.SortStableFunc(o, func(a, b Member) int {
			na, ia := arrayIndex(a.Key)
			nb, ib := arrayIndex(b.Key)
			switch {
			case ia && ib:
				return cmp.Compare(na, nb)
			case ia:
				return -1
			case ib:
				return 1
			}
			return 0
		})
		return o
	case []any:
		a := make([]any, len(x))
		for i, e := range x {
			a[i] = JSOrder(e)
		}
		return a
	}
	return v
}

// Jsonb returns v as PostgreSQL's jsonb holds it (see the package comment).
func Jsonb(v any) any {
	switch x := v.(type) {
	case Object:
		o := make(Object, 0, len(x))
		for _, m := range x {
			o = o.Set(m.Key, Jsonb(m.Value))
		}
		slices.SortStableFunc(o, func(a, b Member) int {
			if len(a.Key) != len(b.Key) {
				return len(a.Key) - len(b.Key)
			}
			return strings.Compare(a.Key, b.Key)
		})
		return o
	case []any:
		a := make([]any, len(x))
		for i, e := range x {
			a[i] = Jsonb(e)
		}
		return a
	case []string:
		a := make([]any, len(x))
		for i, e := range x {
			a[i] = e
		}
		return a
	case Valuer:
		return Jsonb(x.JSValue())
	case int:
		return float64(x)
	case int32:
		return float64(x)
	case int64:
		return float64(x)
	default:
		return v
	}
}

// Canonical is Stringify(Jsonb(Parse(text))): two texts with the same
// canonical form hold the same jsonb value. For tests and comparisons.
func Canonical(text []byte) (string, error) {
	v, err := Parse(text)
	if err != nil {
		return "", err
	}
	return string(Stringify(Jsonb(v))), nil
}
