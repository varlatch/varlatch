// SPDX-License-Identifier: AGPL-3.0-or-later

package jsvalue

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// IsWhitespace is StrWhiteSpaceChar: ECMAScript's WhiteSpace and
// LineTerminator code points, which Number(string) trims.
func IsWhitespace(r rune) bool {
	switch r {
	case '\t', '\v', '\f', ' ', 0xA0, 0xFEFF, '\n', '\r', 0x2028, 0x2029:
		return true
	}
	return unicode.Is(unicode.Zs, r)
}

var (
	decimalLiteral = regexp.MustCompile(`^[+-]?(?:Infinity|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)$`)
	radixLiteral   = regexp.MustCompile(`^0(?:[xX][0-9a-fA-F]+|[oO][0-7]+|[bB][01]+)$`)
)

// ToNumber is Number(string) (StringToNumber): whitespace trimmed, empty
// is 0, a decimal literal with an optional sign or Infinity, or an
// unsigned 0x, 0o or 0b integer; anything else is NaN.
func ToNumber(s string) float64 {
	t := strings.TrimFunc(s, IsWhitespace)
	switch {
	case t == "":
		return 0
	case radixLiteral.MatchString(t):
		base := map[byte]int{'x': 16, 'X': 16, 'o': 8, 'O': 8, 'b': 2, 'B': 2}[t[1]]
		n := 0.0
		for _, c := range t[2:] {
			d, _ := strconv.ParseInt(string(c), base, 64)
			n = n*float64(base) + float64(d)
		}
		return n
	case decimalLiteral.MatchString(t):
		if strings.HasSuffix(t, "Infinity") {
			if t[0] == '-' {
				return math.Inf(-1)
			}
			return math.Inf(1)
		}
		// Beyond a double's range: ±Inf, or 0 below its smallest.
		f, _ := strconv.ParseFloat(t, 64)
		return f
	}
	return math.NaN()
}
