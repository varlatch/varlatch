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

// Free text: failure messages, which echo arguments, quote lines of
// varlatch.toml, and quote values with %q. There a URL's end is not known,
// so the rules are (the orchestrator's design, after #265's review):
//
//   - A URL starts at a scheme (tabs and newlines in it dropped, as WHATWG
//     drops them) whose authority follows: a special scheme and any run of
//     "/" and "\", or another scheme and "//". Once inside an authority,
//     no other URL starts there (a password holding "ftp:" is still the
//     password), unless a space, comma, semicolon or line end followed by
//     another "scheme:" ends it first (a list of servers or values).
//   - A double-quoted string (opened after a space, "=", "(", "[", "{", ","
//     or ":" or at the start, closed before a space, punctuation or the end,
//     on one line) is decoded (\", \\, \n, \t, \uXXXX, \UXXXXXXXX, \xHH
//     and the rest), masked, and shown re-quoted only when masking changed
//     it: a URL in it ends with the string, so the next string's "@" is
//     never taken, and an escaped quote or "@" never hides a password.
//   - Outside such strings an authority runs to the first "/", "?" or "#",
//     across quotes and lines (a user name or password may hold spaces,
//     quotes and newlines), and is masked to its last "@"; where that does
//     not parse, on to the first "?" or "#" (a password may hold "/").
//   - Where the URL text parses (lib/whatwg), WHATWG decides whether it has a
//     user name or password and where they end (a special scheme's
//     backslash starts the path); where it does not, the span is masked
//     conservatively. When in doubt, more is masked: in error text, never
//     leaking comes first, and text with no URL credentials keeps its bytes.

// MaskUserinfoInText masks every URL's user name and password in free text.
func MaskUserinfoInText(text string) string {
	segments := quotedSegments(text)
	var b strings.Builder
	last, pos, k := 0, 0, 0
	for pos < len(text) {
		for k < len(segments) && segments[k][0] < pos {
			k++ // consumed by an authority that ran across it
		}
		limit := len(text)
		if k < len(segments) {
			limit = segments[k][0]
		}
		if p, authStart, special, ok := nextURL(text, pos, limit); ok {
			bound := urlBound(text, authStart, len(text))
			end := min(authorityEnd(text, authStart), bound)
			if from, to, mask := credentialSpan(text, p, authStart, end, bound, special); mask {
				b.WriteString(text[last:from])
				b.WriteString("[redacted]")
				last = to
				pos = last // on from the "@": what follows is a host, and strings after it are read
			} else {
				pos = min(end, limit) // nothing masked: a string it ran into is still read
			}
			continue
		}
		if k == len(segments) {
			break
		}
		open, close := segments[k][0], segments[k][1]
		decoded := decodeQuoted(text[open+1 : close])
		if masked := MaskUserinfoInArgument(decoded); masked != decoded {
			b.WriteString(text[last:open])
			b.WriteString(requote(masked))
			last = close + 1
		}
		pos = close + 1
	}
	b.WriteString(text[last:])
	return b.String()
}

// MaskUserinfoInArgument masks every URL's user name and password in one
// value given as it is (an argument, a decoded string): no quoting rules,
// an authority runs to the first "/", "?" or "#".
func MaskUserinfoInArgument(text string) string {
	var b strings.Builder
	last, pos := 0, 0
	for pos < len(text) {
		p, authStart, special, ok := nextURL(text, pos, len(text))
		if !ok {
			break
		}
		bound := urlBound(text, authStart, len(text))
		end := min(authorityEnd(text, authStart), bound)
		pos = end // never a URL inside the authority read
		if from, to, mask := credentialSpan(text, p, authStart, end, bound, special); mask {
			b.WriteString(text[last:from])
			b.WriteString("[redacted]")
			last = to
			pos = last
		}
	}
	b.WriteString(text[last:])
	return b.String()
}

// credentialSpan is the span of text to mask for the URL at p whose
// authority starts at authStart and runs to end (the first "/", "?" or
// "#"), and whether there is one. Where text[p:end] parses, WHATWG
// decides. Where it does not (a password holding "/", a host that does not
// parse), the span runs on to the first "?" or "#" before limit (the end of
// the string the URL is in, or of the text), and is masked to its last "@":
// more is masked rather than any of a password.
func credentialSpan(text string, p, authStart, end, limit int, special bool) (from, to int, mask bool) {
	stop := end
	if u, ok := whatwg.ParseURL(text[p:end]); ok {
		if u.Username == "" && u.Password == "" {
			return 0, 0, false
		}
		if special {
			if i := strings.IndexByte(text[authStart:end], '\\'); i >= 0 {
				stop = authStart + i // WHATWG: a special scheme's backslash starts the path
			}
		}
	} else {
		stop = limit
		if i := strings.IndexAny(text[authStart:limit], "?#"); i >= 0 {
			stop = authStart + i
		}
	}
	at := strings.LastIndexByte(text[authStart:stop], '@')
	if at <= 0 {
		return 0, 0, false
	}
	return authStart, authStart + at, true
}

// nextURL finds the next URL start in text[pos:limit]: the scheme's
// start, where its authority starts, and whether the scheme is special.
func nextURL(text string, pos, limit int) (p, authStart int, special, ok bool) {
	for p = pos; p < limit; p++ {
		if !isAlpha(text[p]) || p > 0 && isSchemeChar(text[p-1]) {
			continue
		}
		j := p + 1
		for j < len(text) && (isSchemeChar(text[j]) || isTabNewline(text[j])) {
			j++
		}
		if j >= len(text) || text[j] != ':' {
			continue
		}
		scheme := strings.ToLower(strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(text[p:j]))
		k := j + 1
		if specialSchemes[scheme] {
			for k < len(text) && (text[k] == '/' || text[k] == '\\' || isTabNewline(text[k])) {
				k++
			}
			return p, k, true, true
		}
		slashes := 0
		for k < len(text) && slashes < 2 && (text[k] == '/' || isTabNewline(text[k])) {
			if text[k] == '/' {
				slashes++
			}
			k++
		}
		if slashes == 2 {
			return p, k, false, true
		}
	}
	return 0, 0, false, false
}

// urlBound is where the text after the authority starting at authStart
// stops belonging to it: at a "scheme:" token that follows a space, comma,
// semicolon or line end, as in a list of servers
// ("http://[redacted]@h1, http:\\[redacted]@h2") or of values. A scheme
// right inside a user name or password ("alice:ftp:@h") follows no
// separator, and a password with spaces ("fake pass@h") has no scheme after
// them, so both stay in the authority. limit when there is no such token.
//
// The limit, chosen on purpose (correct lists of servers matter more): a
// password that contains a separator followed by a URL scheme ("fake
// ftp:x") is split there, and its part before the separator may be shown.
func urlBound(text string, authStart, limit int) int {
	for s := authStart; s < limit; s++ {
		if !strings.ContainsRune(" \t\r\n,;", rune(text[s])) {
			continue
		}
		t := s
		for t < limit && strings.ContainsRune(" \t\r\n,;", rune(text[t])) {
			t++
		}
		if t < limit && isAlpha(text[t]) {
			u := t + 1
			for u < limit && (isSchemeChar(text[u]) || isTabNewline(text[u])) {
				u++ // tabs and newlines inside a scheme are dropped, as WHATWG drops them
			}
			if u < limit && text[u] == ':' {
				return t
			}
		}
		s = t - 1
	}
	return limit
}

// authorityEnd is the first "/", "?" or "#" from start, or the end.
func authorityEnd(text string, start int) int {
	if i := strings.IndexAny(text[start:], "/?#"); i >= 0 {
		return start + i
	}
	return len(text)
}

func isSchemeChar(c byte) bool {
	return isAlpha(c) || c >= '0' && c <= '9' || c == '+' || c == '.' || c == '-'
}

func isTabNewline(c byte) bool { return c == '\t' || c == '\n' || c == '\r' }

// quotedSegments lists the double-quoted strings of text, as [open, close]
// quote positions: opened at the start or after whitespace or one of
// "=([{,:", closed on the same line before the end, whitespace or one of
// ",;:)]}#.", a backslash escaping the next character. A quote that does
// not fit both sides is ordinary text.
func quotedSegments(text string) [][2]int {
	var out [][2]int
	for i := 0; i < len(text); i++ {
		if text[i] != '"' || i > 0 && !strings.ContainsRune(" \t\r\n=([{,:", rune(text[i-1])) {
			continue
		}
		for j := i + 1; j < len(text); j++ {
			if text[j] == '\\' {
				j++
				continue
			}
			if text[j] == '\n' {
				break
			}
			if text[j] == '"' {
				if j+1 == len(text) || strings.ContainsRune(" \t\r\n,;:)]}#.", rune(text[j+1])) {
					out = append(out, [2]int{i, j})
					i = j
				}
				break
			}
		}
	}
	return out
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
