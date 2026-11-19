// SPDX-License-Identifier: Apache-2.0

// Package jsjson reads and writes JSON as JavaScript's JSON.parse and
// JSON.stringify do, for Go code that must give the TypeScript code's bytes:
// the Platform Adapters (lib/sync) and the CLI (cmd/varlatch). Objects keep
// JavaScript's property order (array indexes first, then insertion order; a
// repeated key keeps its first place and takes its last value), and a lone
// UTF-16 surrogate in a string is kept, in its WTF-8 bytes.
//
// A JSON value here is nil (null), bool, float64, string, []any or Object.
// The writers also take int and []string, for values Go code builds.
package jsjson

import (
	"bytes"
	"cmp"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Member is one property of an Object. It is an unnamed struct type, so
// packages that build Objects may write members as {"key", value}.
type Member = struct {
	Key   string
	Value any
}

// Object is a JSON object with its properties in JavaScript's order.
type Object []Member

// Get is the value of key, and whether the object has it ("key in o").
func (o Object) Get(key string) (any, bool) {
	for _, m := range o {
		if m.Key == key {
			return m.Value, true
		}
	}
	return nil, false
}

// Value is o[key], nil when absent.
func (o Object) Value(key string) any {
	v, _ := o.Get(key)
	return v
}

// Set is o[key] = value: in place when present, else appended in
// JavaScript's order. It returns the object, as append does.
func (o Object) Set(key string, value any) Object {
	for i := range o {
		if o[i].Key == key {
			o[i].Value = value
			return o
		}
	}
	o = append(o, Member{key, value})
	if _, ok := arrayIndex(key); ok {
		slices.SortStableFunc(o, compareKeys)
	}
	return o
}

func compareKeys(a, b Member) int {
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
}

// arrayIndex reports whether k is an array index: "0", or a decimal
// without leading zeros below 2^32 - 1.
func arrayIndex(k string) (uint64, bool) {
	if k == "" || len(k) > 10 || (len(k) > 1 && k[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(k); i++ {
		if k[i] < '0' || k[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(k, 10, 64)
	if err != nil || n >= 1<<32-1 {
		return 0, false
	}
	return n, true
}

// ErrSyntax is JSON.parse's SyntaxError; its text is not V8's.
var ErrSyntax = errors.New("not valid JSON")

// Parse is JSON.parse(text) after fetch's UTF-8 decoding (a leading
// byte order mark is dropped). Bytes that are not UTF-8 read as U+FFFD.
// Nesting deeper than MaxDepth is refused: code that walks the value
// recursively afterwards (Stringify among it) stays within Go's stack.
func Parse(text []byte) (any, error) {
	return parse(text, MaxDepth)
}

// ParseDeep is Parse with no bound on nesting, as V8's JSON.parse has
// none of its own short of memory. The caller must not walk the value
// recursively.
func ParseDeep(text []byte) (any, error) {
	return parse(text, -1)
}

// MaxDepth is how deeply Parse lets values nest.
const MaxDepth = 10000

func parse(text []byte, maxDepth int) (any, error) {
	text = bytes.TrimPrefix(text, []byte("\xef\xbb\xbf"))
	p := jsonParser{s: text}
	p.space()
	v, err := p.value(maxDepth)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.i != len(p.s) {
		return nil, ErrSyntax
	}
	return v, nil
}

type jsonParser struct {
	s []byte
	i int
}

func (p *jsonParser) space() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *jsonParser) literal(word string, v any) (any, error) {
	if !bytes.HasPrefix(p.s[p.i:], []byte(word)) {
		return nil, ErrSyntax
	}
	p.i += len(word)
	return v, nil
}

// container is an array or object being read.
type container struct {
	isObject bool
	array    []any
	object   objectBuilder
	key      string // the key whose value comes next
}

// objectBuilder builds an Object as Object.Set would, key by key, in
// linear time: an index finds a repeated key, and array-index keys are
// sorted once at the end (a stable sort of the first-insertion order is
// what sorting after each insertion gives).
type objectBuilder struct {
	members  Object
	index    map[string]int
	numbered bool
}

func (b *objectBuilder) set(key string, value any) {
	if b.index == nil {
		b.index = map[string]int{}
	}
	if i, ok := b.index[key]; ok {
		b.members[i].Value = value
		return
	}
	b.index[key] = len(b.members)
	b.members = append(b.members, Member{key, value})
	if _, ok := arrayIndex(key); ok {
		b.numbered = true
	}
}

func (b *objectBuilder) done() Object {
	if b.numbered {
		slices.SortStableFunc(b.members, compareKeys)
	}
	return b.members
}

// key reads an object key and its colon.
func (p *jsonParser) key() (string, error) {
	p.space()
	if p.i >= len(p.s) || p.s[p.i] != '"' {
		return "", ErrSyntax
	}
	k, err := p.str()
	if err != nil {
		return "", err
	}
	p.space()
	if p.i >= len(p.s) || p.s[p.i] != ':' {
		return "", ErrSyntax
	}
	p.i++
	p.space()
	return k, nil
}

// value reads one value, its containers on a stack of its own rather than
// Go's, refusing nesting deeper than maxDepth (none when negative).
func (p *jsonParser) value(maxDepth int) (any, error) {
	var stack []*container
	for {
		if maxDepth >= 0 && len(stack) > maxDepth || p.i >= len(p.s) {
			return nil, ErrSyntax
		}
		var v any
		var err error
		switch c := p.s[p.i]; {
		case c == '{':
			p.i++
			p.space()
			if p.i < len(p.s) && p.s[p.i] == '}' {
				p.i++
				v = Object{}
				break
			}
			k, err := p.key()
			if err != nil {
				return nil, err
			}
			stack = append(stack, &container{isObject: true, key: k})
			continue
		case c == '[':
			p.i++
			p.space()
			if p.i < len(p.s) && p.s[p.i] == ']' {
				p.i++
				v = []any{}
				break
			}
			stack = append(stack, &container{})
			p.space()
			continue
		case c == '"':
			v, err = p.str()
		case c == 't':
			v, err = p.literal("true", true)
		case c == 'f':
			v, err = p.literal("false", false)
		case c == 'n':
			v, err = p.literal("null", nil)
		case c == '-' || (c >= '0' && c <= '9'):
			v, err = p.number()
		default:
			err = ErrSyntax
		}
		if err != nil {
			return nil, err
		}
		// v is complete: put it in its container, closing the containers
		// it completes, until one has more to read.
		for {
			if len(stack) == 0 {
				return v, nil
			}
			top := stack[len(stack)-1]
			closer := byte(']')
			if top.isObject {
				top.object.set(top.key, v)
				closer = '}'
			} else {
				top.array = append(top.array, v)
			}
			p.space()
			if p.i >= len(p.s) {
				return nil, ErrSyntax
			}
			if p.s[p.i] == closer {
				p.i++
				stack = stack[:len(stack)-1]
				if top.isObject {
					v = top.object.done()
				} else {
					v = top.array
				}
				continue
			}
			if p.s[p.i] != ',' {
				return nil, ErrSyntax
			}
			p.i++
			if top.isObject {
				if top.key, err = p.key(); err != nil {
					return nil, err
				}
			} else {
				p.space()
			}
			break
		}
	}
}

func digitsAt(s []byte, i int) int {
	j := i
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	return j
}

func (p *jsonParser) number() (any, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	if p.i >= len(p.s) {
		return nil, ErrSyntax
	}
	if p.s[p.i] == '0' {
		p.i++
	} else if p.s[p.i] >= '1' && p.s[p.i] <= '9' {
		p.i = digitsAt(p.s, p.i)
	} else {
		return nil, ErrSyntax
	}
	if p.i < len(p.s) && p.s[p.i] == '.' {
		j := digitsAt(p.s, p.i+1)
		if j == p.i+1 {
			return nil, ErrSyntax
		}
		p.i = j
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		j := digitsAt(p.s, p.i)
		if j == p.i {
			return nil, ErrSyntax
		}
		p.i = j
	}
	f, err := strconv.ParseFloat(string(p.s[start:p.i]), 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return nil, ErrSyntax
	}
	return f, nil // out of range: ±Infinity or ±0, as JavaScript rounds
}

func (p *jsonParser) hex4() (rune, bool) {
	if p.i+4 > len(p.s) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(p.s[p.i:p.i+4]), 16, 32)
	if err != nil {
		return 0, false
	}
	p.i += 4
	return rune(n), true
}

func (p *jsonParser) str() (string, error) {
	p.i++ // the opening quote
	var b []byte
	for {
		if p.i >= len(p.s) {
			return "", ErrSyntax
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return string(b), nil
		case c < 0x20:
			return "", ErrSyntax
		case c == '\\':
			p.i++
			if p.i >= len(p.s) {
				return "", ErrSyntax
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
					return "", ErrSyntax
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
					b = AppendWTF8(b, r)
				} else {
					b = utf8.AppendRune(b, r)
				}
			default:
				return "", ErrSyntax
			}
		default:
			r, size := utf8.DecodeRune(p.s[p.i:])
			p.i += size
			b = utf8.AppendRune(b, r) // invalid UTF-8: U+FFFD
		}
	}
}

// AppendWTF8 appends a surrogate code point's WTF-8 bytes.
func AppendWTF8(b []byte, r rune) []byte {
	return append(b, 0xe0|byte(r>>12), 0x80|byte(r>>6)&0x3f, 0x80|byte(r)&0x3f)
}

// SurrogateAt reads a surrogate code point's WTF-8 bytes at s[i:].
func SurrogateAt(s string, i int) (rune, bool) {
	if i+2 < len(s) && s[i] == 0xed && s[i+1] >= 0xa0 && s[i+1] <= 0xbf && s[i+2] >= 0x80 && s[i+2] <= 0xbf {
		return 0xd000 | rune(s[i+1]&0x3f)<<6 | rune(s[i+2]&0x3f), true
	}
	return 0, false
}

// Stringify is JSON.stringify(v) for a JSON value.
func Stringify(v any) []byte {
	var b bytes.Buffer
	writeJSON(&b, v)
	return b.Bytes()
}

// StringifyIndent is JSON.stringify(v, null, indent) for a JSON value: an
// empty array or object stays "[]" or "{}", every other one puts each
// element on its own line, indented by indent spaces per level, and a key is
// followed by ": ". indent is clamped to 0..10, as JavaScript clamps it; 0
// is Stringify.
func StringifyIndent(v any, indent int) []byte {
	indent = max(0, min(indent, 10))
	if indent == 0 {
		return Stringify(v)
	}
	var b bytes.Buffer
	writeIndented(&b, v, strings.Repeat(" ", indent), "")
	return b.Bytes()
}

func writeIndented(b *bytes.Buffer, v any, gap, current string) {
	inner := current + gap
	switch x := v.(type) {
	case []any:
		if len(x) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, e := range x {
			if i > 0 {
				b.WriteString(",\n")
			}
			b.WriteString(inner)
			writeIndented(b, e, gap, inner)
		}
		b.WriteString("\n" + current + "]")
	case []string:
		a := make([]any, len(x))
		for i, e := range x {
			a[i] = e
		}
		writeIndented(b, a, gap, current)
	case Object:
		if len(x) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, m := range x {
			if i > 0 {
				b.WriteString(",\n")
			}
			b.WriteString(inner)
			quote(b, m.Key)
			b.WriteString(": ")
			writeIndented(b, m.Value, gap, inner)
		}
		b.WriteString("\n" + current + "}")
	default:
		writeJSON(b, v)
	}
}

func writeJSON(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case float64:
		b.WriteString(NumberJSON(x))
	case int:
		b.WriteString(strconv.Itoa(x))
	case string:
		quote(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSON(b, e)
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			quote(b, e)
		}
		b.WriteByte(']')
	case Object:
		b.WriteByte('{')
		for i, m := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			quote(b, m.Key)
			b.WriteByte(':')
			writeJSON(b, m.Value)
		}
		b.WriteByte('}')
	default:
		panic("jsjson: not a JSON value")
	}
}

const hexDigits = "0123456789abcdef"

// quote writes s as JSON.stringify does: a lone surrogate (WTF-8) as
// \udxxx, other bytes that are not UTF-8 as U+FFFD.
func quote(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			if sur, ok := SurrogateAt(s, i); ok {
				b.WriteString(`\u`)
				b.WriteString(strconv.FormatInt(int64(sur), 16))
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
			b.WriteByte(hexDigits[r>>4])
			b.WriteByte(hexDigits[r&0xf])
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// NumberJSON is a number as JSON.stringify writes it: NaN and the
// infinities are null.
func NumberJSON(x float64) string {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return "null"
	}
	return Number(x)
}

// Number is Number::toString(x) in radix 10.
func Number(x float64) string {
	switch {
	case math.IsNaN(x):
		return "NaN"
	case math.IsInf(x, 1):
		return "Infinity"
	case math.IsInf(x, -1):
		return "-Infinity"
	case x == 0:
		return "0"
	}
	sign := ""
	if x < 0 {
		sign, x = "-", -x
	}
	mant, exp, _ := strings.Cut(strconv.FormatFloat(x, 'e', -1, 64), "e")
	digits := strings.Replace(mant, ".", "", 1)
	p, _ := strconv.Atoi(exp)
	k, n := len(digits), p+1
	var s string
	switch {
	case k <= n && n <= 21:
		s = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		s = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		s = "0." + strings.Repeat("0", -n) + digits
	default:
		es, ev := "+", n-1
		if ev < 0 {
			es, ev = "-", -ev
		}
		if k == 1 {
			s = digits + "e" + es + strconv.Itoa(ev)
		} else {
			s = digits[:1] + "." + digits[1:] + "e" + es + strconv.Itoa(ev)
		}
	}
	return sign + s
}

// String is String(v) for a JSON value.
func String(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return Number(x)
	case string:
		return x
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			if e != nil {
				parts[i] = String(e)
			}
		}
		return strings.Join(parts, ",")
	case Object:
		return "[object Object]"
	}
	return ""
}

// Truthy is JavaScript's ToBoolean for a JSON value; absent is falsy.
func Truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case float64:
		return x != 0 && !math.IsNaN(x)
	case string:
		return x != ""
	}
	return true
}

// IsRecord is a non-null, non-array object.
func IsRecord(v any) bool {
	_, ok := v.(Object)
	return ok
}
