// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"regexp"
	"strings"
)

// JavaScript's text rules where the TypeScript code's answer depends on
// them: its \s (WhiteSpace and LineTerminator, the set trim() removes), and
// what a multiline regular expression takes as a line break.

// ws is the body of a character class matching JavaScript's \s.
const ws = `\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`

// jsRegexp compiles a pattern in which `\s` and `\S` mean JavaScript's.
func jsRegexp(pattern string) *regexp.Regexp {
	pattern = strings.ReplaceAll(pattern, `\s`, "["+ws+"]")
	pattern = strings.ReplaceAll(pattern, `\S`, "[^"+ws+"]")
	return regexp.MustCompile(pattern)
}

func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// trim is String.prototype.trim.
func trim(s string) string { return strings.TrimFunc(s, isJSSpace) }

// trimEnd is String.prototype.trimEnd.
func trimEnd(s string) string { return strings.TrimRightFunc(s, isJSSpace) }

// isLineTerminator is what ^ and $ of a multiline regular expression
// treat as a line break.
func isLineTerminator(r rune) bool { return r == '\n' || r == '\r' || r == 0x2028 || r == 0x2029 }

// jsLines splits text at every JavaScript line terminator, as a multiline
// regular expression sees its lines, leaving out empty ones.
func jsLines(text string) []string { return strings.FieldsFunc(text, isLineTerminator) }

// lineStartsWith reports the first index i where text has prefix at a line
// start (the start, or after a line terminator) and is followed by a line
// end (`(?=\r?\n|$)` in a multiline expression: the end, or a terminator),
// or -1.
func lineStartsWith(text, prefix string) int {
	for from := 0; ; {
		i := strings.Index(text[from:], prefix)
		if i < 0 {
			return -1
		}
		i += from
		atStart := i == 0 || endsWithTerminator(text[:i])
		rest := text[i+len(prefix):]
		atEnd := rest == "" || startsWithTerminator(rest)
		if atStart && atEnd {
			return i
		}
		from = i + 1
	}
}

func endsWithTerminator(s string) bool {
	for _, t := range []string{"\n", "\r", "\u2028", "\u2029"} {
		if strings.HasSuffix(s, t) {
			return true
		}
	}
	return false
}

func startsWithTerminator(s string) bool {
	for _, t := range []string{"\n", "\r", "\u2028", "\u2029"} {
		if strings.HasPrefix(s, t) {
			return true
		}
	}
	return false
}
