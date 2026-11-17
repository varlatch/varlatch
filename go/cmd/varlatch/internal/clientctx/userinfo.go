// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/jsjson"
	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// The Go CLI never prints a URL's user name and password (go/README.md,
// the accepted difference "Diagnostics never print credential values"): a
// server URL is shown with [redacted] in their place, in human output,
// --json documents and messages alike. A URL without them is shown as it
// is.

// MaskUserinfo is a server value with its user name and password replaced
// by [redacted].
//
// Text that parses as a URL (lib/whatwg, as new URL reads it) is masked by
// its parsed authority: only when it has a user name or a password, and
// then exactly the span WHATWG reads as them, so every other URL keeps its
// bytes ("https://example.com\\path@segment" has none: for a special
// scheme the backslash starts the path).
//
// Text that does not parse is masked conservatively, from where its
// authority would start to the last "@" before the first "?" or "#" (a
// password may hold "/" or a backslash):
//
//   - for a special scheme (http, https, ws, wss, ftp, file, in any case),
//     after any run of "/" and "\\" that follows the scheme, none
//     included: "http:/u:p@[::1" and "http:\\\\u:p@[bad" are masked;
//   - otherwise after the first "//" (tabs and newlines between its
//     slashes allowed, as WHATWG parsing drops them), or at the start.
func MaskUserinfo(text string) string {
	if u, ok := whatwg.ParseURL(text); ok {
		if u.Username == "" && u.Password == "" {
			return text
		}
		start, special := authorityStart(text)
		delims := "/?#"
		if special {
			delims = "/\\?#"
		}
		return maskTo(text, start, delims)
	}
	start, _ := authorityStart(text)
	return maskTo(text, start, "?#") // a password may hold "/"
}

// maskTo masks text from start to the last "@" before the first of delims.
func maskTo(text string, start int, delims string) string {
	end := len(text)
	if i := strings.IndexAny(text[start:], delims); i >= 0 {
		end = start + i
	}
	at := strings.LastIndexByte(text[start:end], '@')
	if at <= 0 {
		return text
	}
	return text[:start] + "[redacted]" + text[start+at:]
}

var specialSchemes = map[string]bool{"http": true, "https": true, "ws": true, "wss": true, "ftp": true, "file": true}

// authorityStart is where a user name and password would start, and
// whether the text's scheme is a special one.
func authorityStart(text string) (int, bool) {
	i := 0
	for i < len(text) && text[i] <= 0x20 { // WHATWG trims leading C0 controls and spaces
		i++
	}
	j := i
	if j < len(text) && isAlpha(text[j]) {
		for j++; j < len(text) && (isAlpha(text[j]) || text[j] >= '0' && text[j] <= '9' || strings.IndexByte("+.-\t\n\r", text[j]) >= 0); j++ {
		}
		if j < len(text) && text[j] == ':' {
			scheme := strings.ToLower(strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(text[i:j]))
			if specialSchemes[scheme] {
				k := j + 1
				for k < len(text) && strings.IndexByte("/\\\t\n\r", text[k]) >= 0 {
					k++
				}
				return k, true
			}
		}
	}
	// The first "//", tabs and newlines between the two slashes included.
	for k := 0; k < len(text); k++ {
		if text[k] != '/' {
			continue
		}
		m := k + 1
		for m < len(text) && strings.IndexByte("\t\n\r", text[m]) >= 0 {
			m++
		}
		if m < len(text) && text[m] == '/' {
			return m + 1, false
		}
	}
	return 0, false
}

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// MaskServer is a server value as the CLI shows it: a string with
// MaskUserinfo, and any other JSON value (a hand-edited local override)
// with every string in it masked the same way.
func MaskServer(v any) any {
	switch x := v.(type) {
	case string:
		return MaskUserinfo(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = MaskServer(e)
		}
		return out
	case jsjson.Object:
		out := make(jsjson.Object, len(x))
		for i, m := range x {
			out[i] = jsjson.Member{Key: m.Key, Value: MaskServer(m.Value)}
		}
		return out
	}
	return v
}

// Two layers keep a URL's user name and password out of what the CLI
// prints (the orchestrator's design, after #265's review):
//
//  1. Precise, per value, where its boundaries are known: every echo site
//     masks the one value it prints (an argument, a command, a help topic,
//     an approval id, a server, a string of varlatch.toml in a parse error,
//     verify-release's --file value and path) with MaskUserinfo (a server)
//     or MaskURLInValue (an echoed value) before formatting it into its
//     message. A value without a user name and password keeps its bytes.
//  2. A dumb fail-safe on the final text of every failure (Run.finish,
//     verify-release's failures): MaskUserinfoInText. It is the net, not
//     the only defence.

// MaskUserinfoInText is the fail-safe: one linear pass over the whole
// message, with no quoting, scheme, list or line rules. For detection, tab,
// CR and LF are dropped (as WHATWG drops them from a URL), and "@", "\u0040",
// "\x40", "\U00000040" and "%40" are at-signs. If the message has a ":" that
// follows a letter and an at-sign anywhere after it, everything from just
// after the FIRST such ":" up to and including the LAST at-sign of the
// message, newlines included, becomes "[redacted]@"; what comes before and
// after is kept. A message with no such pair keeps its bytes.
//
// Error output may over-mask: the whole message is masked from the first
// scheme colon to the last at-sign, so an email after a colon, or a second
// already-masked URL, takes the text between them with it. That is
// accepted for failure text, where never leaking comes before byte parity;
// ordinary output keeps the precise layer's exact bytes.
func MaskUserinfoInText(text string) string {
	if !strings.ContainsAny(text, "@%\\") {
		return text // no at-sign of any form
	}
	// The message without tab, CR and LF, and where each of its bytes is in text.
	kept := make([]byte, 0, len(text))
	at := make([]int, 0, len(text))
	for i := 0; i < len(text); i++ {
		if c := text[i]; c != '\t' && c != '\r' && c != '\n' {
			kept = append(kept, c)
			at = append(at, i)
		}
	}
	colon := -1
	for i := 1; i < len(kept); i++ {
		if kept[i] == ':' && isAlpha(kept[i-1]) {
			colon = i
			break
		}
	}
	if colon < 0 {
		return text
	}
	last, size := -1, 0
	for i := colon + 1; i < len(kept); i++ {
		if n := atSignAt(kept, i); n > 0 {
			last, size = i, n
			i += n - 1
		}
	}
	if last < 0 {
		return text
	}
	return text[:at[colon]+1] + "[redacted]@" + text[at[last+size-1]+1:]
}

// HasAtSign is whether s holds an at-sign as the fail-safe sees one. A
// message whose echoed value holds one puts its explanation after the
// value, since the fail-safe keeps only what follows the last at-sign (the
// explanation follows the URL).
func HasAtSign(s string) bool {
	b := []byte(s)
	for i := range b {
		if atSignAt(b, i) > 0 {
			return true
		}
	}
	return false
}

// atSignAt is the length of the at-sign at s[i] ("@", "\u0040", "\x40",
// "\U00000040" or "%40", any case of hex digits), 0 when there is none.
func atSignAt(s []byte, i int) int {
	switch s[i] {
	case '@':
		return 1
	case '%':
		if i+3 <= len(s) && s[i+1] == '4' && s[i+2] == '0' {
			return 3
		}
	case '\\':
		for _, e := range []string{"\\" + "u0040", "\\" + "x40", "\\" + "U00000040"} {
			if i+len(e) <= len(s) && strings.EqualFold(string(s[i:i+len(e)]), e) {
				return len(e)
			}
		}
	}
	return 0
}

// MaskURLInValue is the precise layer for one value echoed in a message
// (an argument, a command, a help topic, an approval id, a string of
// varlatch.toml): MaskUserinfo when the value is a URL or shows an
// authority (a special scheme, or "//"); any other value as it is, an email
// included (the fail-safe sees the whole message).
func MaskURLInValue(v string) string {
	if _, ok := whatwg.ParseURL(v); ok {
		return MaskUserinfo(v)
	}
	if start, special := authorityStart(v); special || start > 0 {
		return MaskUserinfo(v)
	}
	return v
}

// MaskTOMLStrings is the precise layer for a varlatch.toml parse error,
// whose code block quotes the file's lines: each string on a line (basic,
// literal, and their triple-quoted forms, closed on that line) is decoded
// and masked with MaskURLInValue, and shown re-quoted only when masking
// changed it. A string not closed on its line is left to the fail-safe.
func MaskTOMLStrings(text string) string {
	var b strings.Builder
	last := 0
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c != '"' && c != '\'' {
			continue
		}
		q := 1
		if strings.HasPrefix(text[i:], strings.Repeat(string(c), 3)) {
			q = 3
		}
		quote := text[i : i+q]
		j := i + q
		closed := false
		for j < len(text) && text[j] != '\n' {
			if c == '"' && text[j] == '\\' {
				j += 2
				continue
			}
			if strings.HasPrefix(text[j:], quote) {
				closed = true
				break
			}
			j++
		}
		if !closed {
			i = min(j, len(text)) - 1 // the rest of the line is the fail-safe's
			continue
		}
		value := text[i+q : j]
		if c == '"' {
			value = decodeQuoted(value)
		}
		if masked := MaskURLInValue(value); masked != value {
			b.WriteString(text[last:i])
			b.WriteString(requote(masked))
			last = j + q
		}
		i = j + q - 1
	}
	b.WriteString(text[last:])
	return b.String()
}

// decodeQuoted is a quoted string's value: TOML's and Go's escapes
// decoded; an escape it does not know is kept as written.
func decodeQuoted(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		c := s[i+1]
		simple := map[byte]string{'"': "\"", '\\': "\\", '/': "/", '\'': "'", 'b': "\b", 't': "\t", 'n': "\n", 'f': "\f", 'r': "\r", 'e': "\x1b", 'a': "\a", 'v': "\v"}
		if r, ok := simple[c]; ok {
			b.WriteString(r)
			i++
			continue
		}
		n := map[byte]int{'x': 2, 'u': 4, 'U': 8}[c]
		if n > 0 && i+2+n <= len(s) {
			if v, err := strconv.ParseUint(s[i+2:i+2+n], 16, 32); err == nil {
				if c == 'x' {
					b.WriteByte(byte(v))
				} else if utf8.ValidRune(rune(v)) {
					b.WriteRune(rune(v))
				} else {
					b.WriteString(s[i : i+2+n])
				}
				i += 1 + n
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// requote quotes a masked value again: backslash, quote and control
// characters escaped.
func requote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			b.WriteString(`\u00`)
			b.WriteString(strconv.FormatInt(int64(r)+0x100, 16)[1:])
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
