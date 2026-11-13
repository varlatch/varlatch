// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// jsonStringUnits decodes a JSON string literal into the UTF-16 code units
// JavaScript's JSON.parse would produce, keeping lone surrogates that Go's
// own decoding replaces with U+FFFD. It reports false if raw is not a JSON
// string.
func jsonStringUnits(raw []byte) ([]uint16, bool) {
	i := 0
	for i < len(raw) && isJSONSpace(raw[i]) {
		i++
	}
	if i >= len(raw) || raw[i] != '"' {
		return nil, false
	}
	i++
	var out []uint16
	for i < len(raw) {
		c := raw[i]
		switch {
		case c == '"':
			for j := i + 1; j < len(raw); j++ {
				if !isJSONSpace(raw[j]) {
					return nil, false
				}
			}
			if out == nil {
				out = []uint16{}
			}
			return out, true
		case c == '\\':
			if i+1 >= len(raw) {
				return nil, false
			}
			switch raw[i+1] {
			case '"', '\\', '/':
				out = append(out, uint16(raw[i+1]))
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				if i+6 > len(raw) {
					return nil, false
				}
				v, err := strconv.ParseUint(string(raw[i+2:i+6]), 16, 16)
				if err != nil {
					return nil, false
				}
				out = append(out, uint16(v))
				i += 6
				continue
			default:
				return nil, false
			}
			i += 2
		case c < 0x20:
			return nil, false // JSON does not allow raw control characters
		default:
			r, size := utf8.DecodeRune(raw[i:])
			out = append(out, utf16.Encode([]rune{r})...)
			i += size
		}
	}
	return nil, false
}

func isJSONSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
