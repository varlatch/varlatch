// SPDX-License-Identifier: Apache-2.0

// Package termtext is apps/cli/src/scan.ts's text for a terminal:
// displayPath, which quotes a text holding a control character, and
// terminalJson, JSON with the controls JSON.stringify leaves as they are
// escaped too.
package termtext

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// isControl is scan.ts's CONTROL: C0, DEL and C1.
func isControl(r rune) bool { return r <= 0x1f || r >= 0x7f && r <= 0x9f }

// hasControl is CONTROL.test(text). A byte that is not UTF-8 is no
// control (JavaScript holds the text decoded).
func hasControl(text string) bool {
	for _, r := range text {
		if r != utf8.RuneError && isControl(r) {
			return true
		}
	}
	return false
}

// escapeDELAndC1 is `.replace(DEL_AND_C1, escapeControl)`: DEL and each C1
// control as `\u00XX`.
func escapeDELAndC1(text string) string {
	if !strings.ContainsFunc(text, func(r rune) bool { return r >= 0x7f && r <= 0x9f }) {
		return text
	}
	var b strings.Builder
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if r >= 0x7f && r <= 0x9f {
			b.WriteString(`\u00` + strconv.FormatInt(int64(r), 16))
		} else {
			b.WriteString(text[i : i+size]) // bytes that are not UTF-8 kept as they are
		}
		i += size
	}
	return b.String()
}

// DisplayPath is displayPath: a path (or any text) as shown on a terminal.
// When it holds a control character (C0, DEL, or C1 such as U+009B), it is
// shown quoted with every control escaped; otherwise as it is.
func DisplayPath(text string) string {
	if !hasControl(text) {
		return text
	}
	return escapeDELAndC1(string(jsjson.Stringify(text)))
}

// TerminalJSON is terminalJson: JSON.stringify(value, null, 2), with DEL
// and C1 controls escaped too (still the same JSON).
func TerminalJSON(value any) string {
	return escapeDELAndC1(string(jsjson.StringifyIndent(value, 2)))
}
