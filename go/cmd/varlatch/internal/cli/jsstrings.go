// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"unicode/utf8"
)

// String functions as JavaScript's behave, where the TypeScript CLI's
// answer depends on them.

// jsSpace is String.prototype.trim's set: WhiteSpace and LineTerminator.
func jsSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// jsTrim is String.prototype.trim.
func jsTrim(s string) string { return strings.TrimFunc(s, jsSpace) }

// jsLower is String.prototype.toLowerCase for the comparisons the CLI makes
// with it: Go's per-rune mapping, except U+0130, which JavaScript maps to
// "i" and a combining dot above.
func jsLower(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "İ", "i̇"))
}

// utf16Len is a string's .length in JavaScript: UTF-16 code units. A lone
// surrogate kept in its WTF-8 bytes (lib/jsjson) is one unit.
func utf16Len(s string) int {
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 && i+2 < len(s) && s[i] == 0xed && s[i+1] >= 0xa0 && s[i+1] <= 0xbf {
			n++
			i += 3
			continue
		}
		if r > 0xffff {
			n += 2
		} else {
			n++
		}
		i += size
	}
	return n
}
