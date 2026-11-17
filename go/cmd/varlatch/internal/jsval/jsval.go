// SPDX-License-Identifier: Apache-2.0

// Package jsval holds what the CLI's port needs of JavaScript's own
// semantics where the TypeScript CLI's answer depends on them: reading a
// property of a parsed JSON value (whatever its shape), strict equality,
// Date.parse (V8's date parser, date.go), Number(string), the default sort
// order, and how Node.js decodes a file's bytes as UTF-8. JSON values are
// lib/jsjson's.
package jsval

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// Get is v[key] for a JSON value v that is not null: an object's own
// property, an array's element or length, a string's code unit or length.
// false is undefined. Properties an object inherits (constructor, toString,
// ...) are not modelled: the CLI reads fixed field names, which no
// prototype has, and server URLs.
func Get(v any, key string) (any, bool) {
	switch x := v.(type) {
	case jsjson.Object:
		return x.Get(key)
	case []any:
		if key == "length" {
			return float64(len(x)), true
		}
		if i, ok := index(key); ok && i < len(x) {
			return x[i], true
		}
	case string:
		u := UTF16(x)
		if key == "length" {
			return float64(len(u)), true
		}
		if i, ok := index(key); ok && i < len(u) {
			return FromUTF16(u[i : i+1]), true
		}
	}
	return nil, false
}

// index is key as a canonical array index.
func index(key string) (int, bool) {
	if key == "" || len(key) > 10 || len(key) > 1 && key[0] == '0' {
		return 0, false
	}
	n, err := strconv.ParseUint(key, 10, 32)
	if err != nil || n == math.MaxUint32 {
		return 0, false
	}
	return int(n), true
}

// Nullish is whether a value read with Get is null or undefined.
func Nullish(v any, present bool) bool { return !present || v == nil }

// StrictEqual is a === b for JSON values. Two objects or arrays are never
// equal here: the CLI only compares values from separate parses.
func StrictEqual(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	}
	return false
}

// UTF16 is s as JavaScript holds it: UTF-16 code units, a lone surrogate
// kept in its WTF-8 bytes (lib/jsjson) being one unit. Bytes that are not
// UTF-8 count as U+FFFD.
func UTF16(s string) []uint16 {
	out := make([]uint16, 0, len(s))
	for i := 0; i < len(s); {
		if r, ok := jsjson.SurrogateAt(s, i); ok {
			out = append(out, uint16(r))
			i += 3
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r > 0xffff {
			hi, lo := utf16.EncodeRune(r)
			out = append(out, uint16(hi), uint16(lo))
		} else {
			out = append(out, uint16(r))
		}
	}
	return out
}

// FromUTF16 is the Go string for UTF-16 code units, a lone surrogate in
// its WTF-8 bytes.
func FromUTF16(u []uint16) string {
	var b []byte
	for i := 0; i < len(u); i++ {
		c := rune(u[i])
		if c >= 0xd800 && c <= 0xdbff && i+1 < len(u) && u[i+1] >= 0xdc00 && u[i+1] <= 0xdfff {
			b = utf8.AppendRune(b, utf16.DecodeRune(c, rune(u[i+1])))
			i++
			continue
		}
		if c >= 0xd800 && c <= 0xdfff {
			b = jsjson.AppendWTF8(b, c)
			continue
		}
		b = utf8.AppendRune(b, c)
	}
	return string(b)
}

// CompareUTF16 orders two strings as Array.prototype.sort does by default:
// by UTF-16 code units.
func CompareUTF16(a, b string) int {
	ua, ub := UTF16(a), UTF16(b)
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return int(ua[i]) - int(ub[i])
		}
	}
	return len(ua) - len(ub)
}

// NodeText is s as Node.js writes a string: UTF-8, with a lone surrogate
// as U+FFFD.
func NodeText(s string) string {
	if !strings.Contains(s, "\xed") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if _, ok := jsjson.SurrogateAt(s, i); ok {
			b.WriteString("�")
			i += 3
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// DecodeUTF8 is Buffer#toString("utf8") (readFileSync(path, "utf8")): the
// bytes decoded as the WHATWG Encoding Standard decodes UTF-8, each maximal
// ill-formed subsequence read as one U+FFFD. A byte order mark is kept.
func DecodeUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var out strings.Builder
	for i := 0; i < len(b); {
		c := b[i]
		if c < 0x80 {
			out.WriteByte(c)
			i++
			continue
		}
		need, lower, upper := 0, byte(0x80), byte(0xbf)
		switch {
		case c >= 0xc2 && c <= 0xdf:
			need = 1
		case c == 0xe0:
			need, lower = 2, 0xa0
		case c == 0xed:
			need, upper = 2, 0x9f
		case c >= 0xe1 && c <= 0xef:
			need = 2
		case c == 0xf0:
			need, lower = 3, 0x90
		case c == 0xf4:
			need, upper = 3, 0x8f
		case c >= 0xf1 && c <= 0xf3:
			need = 3
		default:
			out.WriteString("�")
			i++
			continue
		}
		j := i + 1
		ok := true
		for k := 0; k < need; k++ {
			if j >= len(b) || b[j] < lower || b[j] > upper {
				ok = false
				break
			}
			lower, upper = 0x80, 0xbf
			j++
		}
		if !ok {
			out.WriteString("�")
			i = j
			continue
		}
		out.Write(b[i:j])
		i = j
	}
	return out.String()
}

var (
	decimalLiteral = regexp.MustCompile(`^[+-]?(?:Infinity|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)$`)
	radixLiteral   = regexp.MustCompile(`^0(?:[xX][0-9a-fA-F]+|[oO][0-7]+|[bB][01]+)$`)
)

// ToNumber is Number(string) for UTF-16 text; false is NaN.
func ToNumber(u []uint16) (float64, bool) {
	s := strings.TrimFunc(FromUTF16(u), isJSSpace)
	switch {
	case s == "":
		return 0, true
	case radixLiteral.MatchString(s):
		base := map[byte]int{'x': 16, 'X': 16, 'o': 8, 'O': 8, 'b': 2, 'B': 2}[s[1]]
		n, err := strconv.ParseUint(s[2:], base, 64)
		if err != nil {
			return math.Inf(1), true
		}
		return float64(n), true
	case decimalLiteral.MatchString(s):
		t := strings.Replace(s, "Infinity", "Inf", 1)
		f, err := strconv.ParseFloat(t, 64)
		if err != nil && !math.IsInf(f, 0) {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

// isJSSpace is String.prototype.trim's set: WhiteSpace and LineTerminator.
func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}
