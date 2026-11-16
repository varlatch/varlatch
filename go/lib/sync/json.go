// SPDX-License-Identifier: Apache-2.0

package sync

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

// The adapters read platform answers and write request bodies as the
// TypeScript adapters do with JSON.parse and JSON.stringify: objects keep
// JavaScript's property order (array indexes first, then insertion order;
// a repeated key keeps its first place and takes its last value), and a
// lone UTF-16 surrogate in a string is kept, in its WTF-8 bytes.
//
// A JSON value here is nil (null), bool, float64, string, []any or Object.

// Member is one property of an Object.
type Member struct {
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

// get is o[key], nil when absent.
func (o Object) get(key string) any {
	v, _ := o.Get(key)
	return v
}

// set is o[key] = value: in place when present, else appended in
// JavaScript's order.
func (o Object) set(key string, value any) Object {
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

// errSyntax is JSON.parse's SyntaxError; its text is not V8's.
var errSyntax = errors.New("not valid JSON")

// parseJSON is JSON.parse(text) after fetch's UTF-8 decoding (a leading
// byte order mark is dropped). Bytes that are not UTF-8 read as U+FFFD.
func parseJSON(text []byte) (any, error) {
	text = bytes.TrimPrefix(text, []byte("\xef\xbb\xbf"))
	p := jsonParser{s: text}
	p.space()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.i != len(p.s) {
		return nil, errSyntax
	}
	return v, nil
}

type jsonParser struct {
	s []byte
	i int
}

// maxDepth bounds nesting; V8 has a stack limit of its own, far deeper.
const maxDepth = 10000

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
		return nil, errSyntax
	}
	p.i += len(word)
	return v, nil
}

func (p *jsonParser) value(depth int) (any, error) {
	if depth > maxDepth || p.i >= len(p.s) {
		return nil, errSyntax
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
				return nil, errSyntax
			}
			k, err := p.str()
			if err != nil {
				return nil, err
			}
			p.space()
			if p.i >= len(p.s) || p.s[p.i] != ':' {
				return nil, errSyntax
			}
			p.i++
			p.space()
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			o = o.set(k, v)
			p.space()
			if p.i >= len(p.s) {
				return nil, errSyntax
			}
			if p.s[p.i] == '}' {
				p.i++
				return o, nil
			}
			if p.s[p.i] != ',' {
				return nil, errSyntax
			}
			p.i++
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
			if p.i >= len(p.s) {
				return nil, errSyntax
			}
			if p.s[p.i] == ']' {
				p.i++
				return a, nil
			}
			if p.s[p.i] != ',' {
				return nil, errSyntax
			}
			p.i++
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
	return nil, errSyntax
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
		return nil, errSyntax
	}
	if p.s[p.i] == '0' {
		p.i++
	} else if p.s[p.i] >= '1' && p.s[p.i] <= '9' {
		p.i = digitsAt(p.s, p.i)
	} else {
		return nil, errSyntax
	}
	if p.i < len(p.s) && p.s[p.i] == '.' {
		j := digitsAt(p.s, p.i+1)
		if j == p.i+1 {
			return nil, errSyntax
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
			return nil, errSyntax
		}
		p.i = j
	}
	f, err := strconv.ParseFloat(string(p.s[start:p.i]), 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return nil, errSyntax
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
			return "", errSyntax
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return string(b), nil
		case c < 0x20:
			return "", errSyntax
		case c == '\\':
			p.i++
			if p.i >= len(p.s) {
				return "", errSyntax
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
					return "", errSyntax
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
				return "", errSyntax
			}
		default:
			r, size := utf8.DecodeRune(p.s[p.i:])
			p.i += size
			b = utf8.AppendRune(b, r) // invalid UTF-8: U+FFFD
		}
	}
}

// appendWTF8 appends a surrogate code point's WTF-8 bytes.
func appendWTF8(b []byte, r rune) []byte {
	return append(b, 0xe0|byte(r>>12), 0x80|byte(r>>6)&0x3f, 0x80|byte(r)&0x3f)
}

// surrogateAt reads a surrogate code point's WTF-8 bytes at s[i:].
func surrogateAt(s string, i int) (rune, bool) {
	if i+2 < len(s) && s[i] == 0xed && s[i+1] >= 0xa0 && s[i+1] <= 0xbf && s[i+2] >= 0x80 && s[i+2] <= 0xbf {
		return 0xd000 | rune(s[i+1]&0x3f)<<6 | rune(s[i+2]&0x3f), true
	}
	return 0, false
}

// stringify is JSON.stringify(v) for a JSON value, an Object, or one of
// the adapters' own ordered bodies.
func stringify(v any) []byte {
	var b bytes.Buffer
	writeJSON(&b, v)
	return b.Bytes()
}

func writeJSON(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case float64:
		b.WriteString(jsNumberJSON(x))
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
		panic("sync: not a JSON value")
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
			if sur, ok := surrogateAt(s, i); ok {
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

// jsNumberJSON is a number as JSON.stringify writes it: NaN and the
// infinities are null.
func jsNumberJSON(x float64) string {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return "null"
	}
	return jsNumber(x)
}

// jsNumber is Number::toString(x) in radix 10.
func jsNumber(x float64) string {
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

// jsString is String(v) for a JSON value.
func jsString(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return jsNumber(x)
	case string:
		return x
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			if e != nil {
				parts[i] = jsString(e)
			}
		}
		return strings.Join(parts, ",")
	case Object:
		return "[object Object]"
	}
	return ""
}

// truthy is JavaScript's ToBoolean for a JSON value; absent is falsy.
func truthy(v any) bool {
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

// isRecord is a non-null, non-array object.
func isRecord(v any) bool {
	_, ok := v.(Object)
	return ok
}
