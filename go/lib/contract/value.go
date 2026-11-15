// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"bytes"
	"math"
	"strconv"
	"unicode/utf8"
)

// A Contract as a client sends it is a JSON value. Its object members keep
// their order: zod reports unrecognized keys in the order JavaScript
// enumerates them. The values are nil (null), bool, float64 (any JSON
// number, ±Inf beyond a double, as JSON.parse reads it), string, []any and
// Object. A string may hold a lone UTF-16 surrogate as its WTF-8 bytes
// (ED A0..BF 80..BF), as varlatchd's JSON.parse keeps it; everything here
// measures and orders strings as JavaScript does.

// Object is a JSON object, its members in the order the text gave them.
type Object []Member

// Member is one member of an Object.
type Member struct {
	Key   string
	Value any
}

// get is the member's value as JSON.parse leaves it: a repeated key's last
// value.
func (o Object) get(key string) (any, bool) {
	var v any
	found := false
	for _, m := range o {
		if m.Key == key {
			v, found = m.Value, true
		}
	}
	return v, found
}

// keys are the object's keys once each, in the order a JavaScript object
// built by JSON.parse enumerates them: array indexes ascending first, then
// the others in the order they first appear.
func (o Object) keys() []string {
	seen := map[string]bool{}
	var index, other []string
	for _, m := range o {
		if seen[m.Key] {
			continue
		}
		seen[m.Key] = true
		if isArrayIndex(m.Key) {
			index = append(index, m.Key)
		} else {
			other = append(other, m.Key)
		}
	}
	for i := 1; i < len(index); i++ {
		for j := i; j > 0 && arrayIndexLess(index[j], index[j-1]); j-- {
			index[j], index[j-1] = index[j-1], index[j]
		}
	}
	return append(index, other...)
}

func isArrayIndex(k string) bool {
	if k == "" || len(k) > 10 || (len(k) > 1 && k[0] == '0') {
		return false
	}
	for i := 0; i < len(k); i++ {
		if k[i] < '0' || k[i] > '9' {
			return false
		}
	}
	n, err := strconv.ParseUint(k, 10, 64)
	return err == nil && n < 1<<32-1
}

func arrayIndexLess(a, b string) bool {
	x, _ := strconv.ParseUint(a, 10, 64)
	y, _ := strconv.ParseUint(b, 10, 64)
	return x < y
}

// jsType is a value's type as zod names it after "received".
func jsType(v any, present bool) string {
	if !present {
		return "undefined"
	}
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		switch {
		case math.IsNaN(x):
			return "NaN"
		case math.IsInf(x, 1):
			return "Infinity"
		case math.IsInf(x, -1):
			return "-Infinity"
		}
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case Object:
		return "object"
	}
	return "unknown"
}

// units are a string's UTF-16 code units, a WTF-8 surrogate as one unit.
func units(s string) []uint16 {
	out := make([]uint16, 0, len(s))
	for i := 0; i < len(s); {
		if r, n := surrogateAt(s, i); n > 0 {
			out = append(out, uint16(r))
			i += n
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		if r >= 0x10000 {
			r -= 0x10000
			out = append(out, uint16(0xd800+(r>>10)), uint16(0xdc00+(r&0x3ff)))
		} else {
			out = append(out, uint16(r))
		}
		i += n
	}
	return out
}

// surrogateAt reads a surrogate's WTF-8 bytes at s[i:]: the code point and
// 3, or 0.
func surrogateAt(s string, i int) (rune, int) {
	if i+2 < len(s) && s[i] == 0xed && s[i+1] >= 0xa0 && s[i+1] <= 0xbf && s[i+2] >= 0x80 && s[i+2] <= 0xbf {
		return rune(s[i]&0x0f)<<12 | rune(s[i+1]&0x3f)<<6 | rune(s[i+2]&0x3f), 3
	}
	return 0, 0
}

// codePoints is [...s].length: a pair of surrogates is one, a lone one one.
func codePoints(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if _, k := surrogateAt(s, i); k > 0 {
			i += k
		} else {
			_, k := utf8.DecodeRuneInString(s[i:])
			i += k
		}
		n++
	}
	return n
}

// less is JavaScript's a < b on strings: by UTF-16 code units.
func less(a, b string) bool {
	ua, ub := units(a), units(b)
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// quote writes s as JSON.stringify writes a string: ", \ and the C0
// controls escaped (\b \f \n \r \t, else \u00xx), a lone surrogate as
// \udxxx, everything else as it is.
func quote(b *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); {
		if r, n := surrogateAt(s, i); n > 0 {
			b.WriteString(`\u`)
			b.WriteByte(hex[r>>12&0xf])
			b.WriteByte(hex[r>>8&0xf])
			b.WriteByte(hex[r>>4&0xf])
			b.WriteByte(hex[r&0xf])
			i += n
			continue
		}
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\b':
			b.WriteString(`\b`)
		case c == '\f':
			b.WriteString(`\f`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
		default:
			b.WriteByte(c)
		}
		i++
	}
	b.WriteByte('"')
}
