// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"
)

// ParseJSON reads JSON text into the value model as JSON.parse reads the
// text the TypeScript CLI decodes from a Contract file
// (readFileSync(file, "utf8")), so that a Contract read here hashes as the
// TypeScript package hashes it:
//
//   - the bytes are decoded as UTF-8 the way Node's Buffer decodes them:
//     each maximal invalid subpart becomes U+FFFD, and a byte order mark is
//     kept (so JSON.parse, and this, refuse it);
//   - a \u escape of a lone UTF-16 surrogate stays a lone surrogate, kept
//     as its WTF-8 bytes (ED A0..BF 80..BF), and an escaped high surrogate
//     followed by an escaped low one is the code point they make;
//   - numbers are doubles, ±Inf beyond the range, as JSON.parse reads them;
//   - an object keeps every member in the text's order (Object.get takes
//     a repeated key's last value, as JSON.parse does).
func ParseJSON(text []byte) (any, error) {
	r := jsonReader{s: decodeUTF8(text)}
	r.space()
	v, err := r.value(0)
	if err != nil {
		return nil, err
	}
	r.space()
	if r.i != len(r.s) {
		return nil, r.fail("text after the JSON value")
	}
	return v, nil
}

// maxDepth bounds nesting; JSON.parse's own limit is the stack's.
const maxDepth = 10_000

type jsonReader struct {
	s string
	i int
}

func (r *jsonReader) fail(what string) error {
	return fmt.Errorf("contract: invalid JSON at offset %d: %s", r.i, what)
}

// space skips JSON's whitespace: space, tab, line feed, carriage return.
func (r *jsonReader) space() {
	for r.i < len(r.s) {
		switch r.s[r.i] {
		case ' ', '\t', '\n', '\r':
			r.i++
		default:
			return
		}
	}
}

func (r *jsonReader) literal(word string, v any) (any, error) {
	if len(r.s)-r.i < len(word) || r.s[r.i:r.i+len(word)] != word {
		return nil, r.fail("unexpected token")
	}
	r.i += len(word)
	return v, nil
}

func (r *jsonReader) value(depth int) (any, error) {
	if depth > maxDepth {
		return nil, r.fail("nested too deeply")
	}
	if r.i >= len(r.s) {
		return nil, r.fail("unexpected end")
	}
	switch c := r.s[r.i]; {
	case c == '{':
		r.i++
		o := Object{}
		r.space()
		if r.i < len(r.s) && r.s[r.i] == '}' {
			r.i++
			return o, nil
		}
		for {
			r.space()
			if r.i >= len(r.s) || r.s[r.i] != '"' {
				return nil, r.fail("expected a string key")
			}
			k, err := r.str()
			if err != nil {
				return nil, err
			}
			r.space()
			if r.i >= len(r.s) || r.s[r.i] != ':' {
				return nil, r.fail("expected ':'")
			}
			r.i++
			r.space()
			v, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			o = append(o, Member{k, v})
			r.space()
			if r.i < len(r.s) && r.s[r.i] == ',' {
				r.i++
				continue
			}
			if r.i < len(r.s) && r.s[r.i] == '}' {
				r.i++
				return o, nil
			}
			return nil, r.fail("expected ',' or '}'")
		}
	case c == '[':
		r.i++
		a := []any{}
		r.space()
		if r.i < len(r.s) && r.s[r.i] == ']' {
			r.i++
			return a, nil
		}
		for {
			r.space()
			v, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
			r.space()
			if r.i < len(r.s) && r.s[r.i] == ',' {
				r.i++
				continue
			}
			if r.i < len(r.s) && r.s[r.i] == ']' {
				r.i++
				return a, nil
			}
			return nil, r.fail("expected ',' or ']'")
		}
	case c == '"':
		return r.str()
	case c == 't':
		return r.literal("true", true)
	case c == 'f':
		return r.literal("false", false)
	case c == 'n':
		return r.literal("null", nil)
	case c == '-' || c >= '0' && c <= '9':
		return r.number()
	}
	return nil, r.fail("unexpected token")
}

func (r *jsonReader) digits() int {
	start := r.i
	for r.i < len(r.s) && r.s[r.i] >= '0' && r.s[r.i] <= '9' {
		r.i++
	}
	return r.i - start
}

// number is JSON's number grammar, read as a double.
func (r *jsonReader) number() (any, error) {
	start := r.i
	if r.s[r.i] == '-' {
		r.i++
	}
	switch n := r.digits(); {
	case n == 0:
		return nil, r.fail("expected a digit")
	case n > 1 && r.s[r.i-n] == '0':
		return nil, r.fail("a leading zero")
	}
	if r.i < len(r.s) && r.s[r.i] == '.' {
		r.i++
		if r.digits() == 0 {
			return nil, r.fail("expected a digit after '.'")
		}
	}
	if r.i < len(r.s) && (r.s[r.i] == 'e' || r.s[r.i] == 'E') {
		r.i++
		if r.i < len(r.s) && (r.s[r.i] == '+' || r.s[r.i] == '-') {
			r.i++
		}
		if r.digits() == 0 {
			return nil, r.fail("expected a digit in the exponent")
		}
	}
	f, err := strconv.ParseFloat(r.s[start:r.i], 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return nil, err
	}
	return f, nil
}

// hex4 reads the four hex digits of a \u escape at r.i.
func (r *jsonReader) hex4() (rune, bool) {
	if len(r.s)-r.i < 4 {
		return 0, false
	}
	n, err := strconv.ParseUint(r.s[r.i:r.i+4], 16, 16)
	if err != nil {
		return 0, false
	}
	r.i += 4
	return rune(n), true
}

// str reads a string at the opening quote.
func (r *jsonReader) str() (string, error) {
	r.i++
	var b []byte
	for {
		if r.i >= len(r.s) {
			return "", r.fail("unterminated string")
		}
		c := r.s[r.i]
		switch {
		case c == '"':
			r.i++
			return string(b), nil
		case c < 0x20:
			return "", r.fail("a control character in a string")
		case c != '\\':
			b = append(b, c)
			r.i++
			continue
		}
		r.i++
		if r.i >= len(r.s) {
			return "", r.fail("unterminated escape")
		}
		e := r.s[r.i]
		r.i++
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
			u, ok := r.hex4()
			if !ok {
				return "", r.fail("a bad \\u escape")
			}
			if u >= 0xd800 && u <= 0xdbff && len(r.s)-r.i >= 6 && r.s[r.i] == '\\' && r.s[r.i+1] == 'u' {
				save := r.i
				r.i += 2
				if lo, ok := r.hex4(); ok && lo >= 0xdc00 && lo <= 0xdfff {
					b = utf8.AppendRune(b, 0x10000+(u-0xd800)<<10+(lo-0xdc00))
					continue
				}
				r.i = save
			}
			if u >= 0xd800 && u <= 0xdfff {
				// A lone surrogate, as WTF-8.
				b = append(b, 0xed, byte(0x80|u>>6&0x3f), byte(0x80|u&0x3f))
			} else {
				b = utf8.AppendRune(b, u)
			}
		default:
			return "", r.fail("a bad escape")
		}
	}
}

// decodeUTF8 is Node's Buffer#toString("utf8"), the WHATWG Encoding
// Standard's UTF-8 decoder without its BOM removal: each maximal subpart of
// an invalid sequence becomes one U+FFFD.
func decodeUTF8(text []byte) string {
	if utf8.Valid(text) {
		return string(text)
	}
	out := make([]byte, 0, len(text)+8)
	for i := 0; i < len(text); {
		c := text[i]
		if c < 0x80 {
			out = append(out, c)
			i++
			continue
		}
		need, lo, hi := 0, byte(0x80), byte(0xbf)
		switch {
		case c >= 0xc2 && c <= 0xdf:
			need = 1
		case c == 0xe0:
			need, lo = 2, 0xa0
		case c == 0xed:
			need, hi = 2, 0x9f
		case c >= 0xe1 && c <= 0xef:
			need = 2
		case c == 0xf0:
			need, lo = 3, 0x90
		case c == 0xf4:
			need, hi = 3, 0x8f
		case c >= 0xf1 && c <= 0xf3:
			need = 3
		default:
			out = utf8.AppendRune(out, utf8.RuneError)
			i++
			continue
		}
		k := 1
		for ; k <= need; k++ {
			if i+k >= len(text) {
				break
			}
			if d := text[i+k]; d < lo || d > hi {
				break
			}
			lo, hi = 0x80, 0xbf
		}
		if k <= need {
			// The sequence ends early: its bytes so far are one U+FFFD,
			// and the byte that ended it is read again.
			out = utf8.AppendRune(out, utf8.RuneError)
			i += k
			continue
		}
		out = append(out, text[i:i+need+1]...)
		i += need + 1
	}
	return string(out)
}
