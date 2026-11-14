// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import (
	"unicode/utf16"
	"unicode/utf8"
)

// utf16Less is JavaScript's a < b for strings: by UTF-16 code units.
func utf16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// decode is Buffer.toString("utf8"), the WHATWG UTF-8 decoder: every
// maximal subpart of an ill-formed sequence becomes one U+FFFD. Plaintext
// the TypeScript server wrote is valid UTF-8 already (a JavaScript string's
// lone surrogates were replaced when it was encoded), so this matters only
// for bytes that are not.
func decode(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	out := make([]byte, 0, len(b)+8)
	for i := 0; i < len(b); {
		c := b[i]
		if c < 0x80 {
			out = append(out, c)
			i++
			continue
		}
		need, lower, upper := 0, byte(0x80), byte(0xbf)
		switch {
		case c >= 0xc2 && c <= 0xdf:
			need = 1
		case c >= 0xe0 && c <= 0xef:
			need = 2
			if c == 0xe0 {
				lower = 0xa0
			} else if c == 0xed {
				upper = 0x9f
			}
		case c >= 0xf0 && c <= 0xf4:
			need = 3
			if c == 0xf0 {
				lower = 0x90
			} else if c == 0xf4 {
				upper = 0x8f
			}
		default:
			out = utf8.AppendRune(out, utf8.RuneError)
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
			// The maximal subpart b[i:j] is one replacement; the byte that
			// broke it is read again.
			out = utf8.AppendRune(out, utf8.RuneError)
			i = j
			continue
		}
		out = append(out, b[i:j]...)
		i = j
	}
	return string(out)
}
