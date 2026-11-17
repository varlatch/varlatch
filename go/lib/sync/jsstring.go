// SPDX-License-Identifier: Apache-2.0

package sync

import (
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// wellFormed is s as JavaScript's UTF-8 encoding writes it
// (Buffer.from(s, "utf8"), TextEncoder): a lone surrogate (WTF-8) and any
// byte that is not UTF-8 become U+FFFD.
func wellFormed(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if _, ok := surrogateAt(s, i); ok {
			b.WriteRune(utf8.RuneError)
			i += 3
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		b.WriteRune(r)
		i += size
	}
	return b.String()
}

// upperSpecial is SpecialCasing.txt's unconditional uppercase mappings
// whose result is ASCII: the ones that decide whether an uppercased name
// is a valid ASCII name. Other non-ASCII characters keep Go's simple
// mapping, which can differ from JavaScript's only in a result that is
// not ASCII, which no name pattern accepts.
var upperSpecial = map[rune]string{
	0xdf:   "SS",
	0xfb00: "FF",
	0xfb01: "FI",
	0xfb02: "FL",
	0xfb03: "FFI",
	0xfb04: "FFL",
	0xfb05: "ST",
	0xfb06: "ST",
}

// jsToUpper is String.prototype.toUpperCase, exact wherever the result is
// ASCII (see upperSpecial).
func jsToUpper(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if _, ok := surrogateAt(s, i); ok {
			b.WriteString(s[i : i+3])
			i += 3
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r < utf8.RuneSelf:
			if 'a' <= r && r <= 'z' {
				r -= 'a' - 'A'
			}
			b.WriteRune(r)
		case upperSpecial[r] != "":
			b.WriteString(upperSpecial[r])
		default:
			b.WriteRune(unicode.ToUpper(r))
		}
	}
	return b.String()
}

var (
	jsDecimal = regexp.MustCompile(`^[+-]?(?:Infinity|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)$`)
	jsRadix   = regexp.MustCompile(`^0(?:[xX][0-9a-fA-F]+|[oO][0-7]+|[bB][01]+)$`)
)

// jsToNumber is Number(v) for a JSON value; present is false for
// undefined.
func jsToNumber(v any, present bool) float64 {
	if !present {
		return math.NaN()
	}
	switch x := v.(type) {
	case nil:
		return 0
	case bool:
		if x {
			return 1
		}
		return 0
	case float64:
		return x
	case string:
		return stringToNumber(x)
	case []any:
		return stringToNumber(jsString(x))
	}
	return math.NaN()
}

// stringToNumber is StringToNumber.
func stringToNumber(s string) float64 {
	s = whatwg.Trim(s)
	switch {
	case s == "":
		return 0
	case jsRadix.MatchString(s):
		radix := map[byte]int{'x': 16, 'X': 16, 'o': 8, 'O': 8, 'b': 2, 'B': 2}[s[1]]
		return parseInt(s[2:], radix)
	case jsDecimal.MatchString(s):
		switch strings.TrimLeft(s, "+-") {
		case "Infinity":
			if s[0] == '-' {
				return math.Inf(-1)
			}
			return math.Inf(1)
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return math.NaN()
		}
		return f
	}
	return math.NaN()
}

func isNaNOrInf(f float64) bool { return math.IsNaN(f) || math.IsInf(f, 0) }
