// SPDX-License-Identifier: AGPL-3.0-or-later

package write

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// What PostgreSQL does with the TypeScript server's strings, which every
// write of a text or jsonb column must do the same way (step 4.1a; see
// go/README.md, "Known TypeScript defects"):
//
//   - U+0000 is refused, in text ("invalid byte sequence for encoding
//     UTF8: 0x00") and in jsonb ("unsupported Unicode escape sequence"):
//     the statement fails, the transaction rolls back, and the route
//     answers 500 INTERNAL;
//   - a lone surrogate (a string jsvalue.Parse kept as WTF-8) reaches a
//     text column as U+FFFD, since Node encodes strings to UTF-8 that way;
//     in jsonb, as a \ud8xx escape, it is refused like U+0000
//     (jsvalue.JsonbRefuses, which audit.Record and Idempotent apply).

// ErrPostgresText is the refusal of U+0000 in text: an internal error (500
// INTERNAL), raised where the TypeScript server's statement fails.
var ErrPostgresText = errors.New("write: PostgreSQL refuses U+0000 in text (the TypeScript server answers 500 INTERNAL)")

// Text is s as PostgreSQL stores it in a text column, or ErrPostgresText.
func Text(s string) (string, error) {
	if strings.IndexByte(s, 0) >= 0 {
		return "", ErrPostgresText
	}
	if utf8.ValidString(s) {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n <= 1 {
			// A surrogate's WTF-8 bytes (ED A0..BF 80..BF) are one U+FFFD,
			// as Node writes a lone surrogate; any other invalid byte too.
			if i+2 < len(s) && s[i] == 0xED && s[i+1] >= 0xA0 && s[i+1] <= 0xBF {
				n = 3
			}
			b.WriteRune(utf8.RuneError)
			i += max(n, 1)
			continue
		}
		b.WriteString(s[i : i+n])
		i += n
	}
	return b.String(), nil
}
