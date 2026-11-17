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
//   - A URL starts at a scheme that may begin at any letter (after "--",
//     inside a word: when unsure it is a URL), tabs and newlines in it
//     dropped as WHATWG drops them, whose authority follows: a special
//     scheme and any run of "/" and "\", or another scheme and "//". No
//     other URL starts inside an authority (a password holding "ftp:" is
//     still the password), unless a space, comma or semicolon followed by
//     another "scheme:" ends it first (a list of servers or values). Tab,
//     CR and LF never end it: WHATWG drops them from a password.
//   - A quoted string (double-quoted, single-line or triple; or a triple
//     single-quoted literal) opened after a space, "=", "(", "[", "{", ","
//     or ":" or at the start, and closed on its line before a space,
//     punctuation or the end (a quote with no closing one on its line is
//     plain text), is decoded (\", \\, \n, \t, \uXXXX, \UXXXXXXXX, \xHH and the rest) and
//     masked as text again, so quoting nested in quoting is read layer by
//     layer; it is shown re-quoted only when masking changed it. A URL in it
//     ends with the string, so the next string's "@" is never taken; but
//     when its authority runs to the string's end with no "@" and an "@"
//     follows on the line before any "/", "?", "#" or other string, the
//     string is read as plain text.
//   - Outside such strings an authority runs to the first "/", "?" or "#",
//     across quotes and lines (a user name or password may hold spaces,
//     quotes and newlines), and is masked to its last "@"; where that does
//     not parse, on to the first "?" or "#" (a password may hold "/"). An
//     escape that decodes to "@" (@, \x40, \U00000040) counts as one.
//   - Where the URL text parses (lib/whatwg), WHATWG decides whether it has a
//     user name or password and where they end (a special scheme's
//     backslash starts the path); where it does not, the span is masked
//     conservatively. When in doubt, more is masked: in error text, never
//     leaking comes first, and text with no URL credentials keeps its bytes.
//   - One forward pass finds every scheme, delimiter and "@" (scanFor), so
//     masking takes time linear in the text (per layer of quoting).
//
// The limit, chosen on purpose (correct lists of servers matter more): a
// password that contains a space, comma or semicolon followed by a URL
// scheme ("fake ftp:x") is split there, and its part before may be shown.

// maxQuoteDepth is how many layers of quoting are decoded (a TOML line in a
// %q value in a message is two).
const maxQuoteDepth = 4

// MaskUserinfoInText masks every URL's user name and password in free text.
func MaskUserinfoInText(text string) string { return maskText(text, maxQuoteDepth) }

// MaskUserinfoInArgument masks every URL's user name and password in one
// value given as it is (an argument): no quoting rules.
func MaskUserinfoInArgument(text string) string {
	sc := scanFor(text)
	var b strings.Builder
	last, pos := 0, 0
	for _, st := range sc.starts {
		if st.p < pos {
			continue // inside an authority already read
		}
		from, to, end, mask := sc.span(st, len(text))
		pos = end
		if mask {
			b.WriteString(text[last:from])
			b.WriteString("[redacted]")
			last, pos = to, to
		}
	}
	b.WriteString(text[last:])
	return b.String()
}

func maskText(text string, depth int) string {
	sc := scanFor(text)
	segs := quotedSegments(text)
	var b strings.Builder
	last, pos, k, si := 0, 0, 0, 0
	for pos < len(text) {
		for k < len(segs) && segs[k].open < pos {
			k++ // read as part of an authority that ran across it
		}
		limit := len(text)
		if k < len(segs) {
			limit = segs[k].open
		}
		for si < len(sc.starts) && sc.starts[si].p < pos {
			si++
		}
		if si < len(sc.starts) && sc.starts[si].p < limit {
			st := sc.starts[si]
			si++
			from, to, end, mask := sc.span(st, len(text))
			if mask {
				b.WriteString(text[last:from])
				b.WriteString("[redacted]")
				last, pos = to, to // on from the "@": what follows is a host, and strings after it are read
			} else {
				pos = min(end, limit) // nothing masked: a string it ran into is still read
			}
			continue
		}
		if k == len(segs) {
			break
		}
		sg := segs[k]
		decoded := text[sg.contentStart:sg.contentEnd]
		if sg.escapes {
			decoded = decodeQuoted(decoded)
		}
		if sc.atFollows(sg, segs[k+1:]) && unterminatedURL(decoded) {
			k++ // its URL goes on past the quote to an "@": read the string as plain text
			continue
		}
		var masked string
		if depth > 1 {
			masked = maskText(decoded, depth-1)
		} else {
			masked = MaskUserinfoInArgument(decoded)
		}
		if masked != decoded {
			b.WriteString(text[last:sg.open])
			b.WriteString(requote(masked))
			last = sg.close
		}
		pos = sg.close
	}
	b.WriteString(text[last:])
	return b.String()
}

// urlStart is a URL's start: its scheme at p, its authority at authStart.
type urlStart struct {
	p, authStart int
	special      bool
}

// scanned is what one forward pass over a text finds, for masking in
// linear time.
type scanned struct {
	text   string
	starts []urlStart
	// nextDelim[i]: the first "/", "?" or "#" at or after i (len(text) if
	// none); nextQH[i]: the first "?" or "#"; nextBound[i]: the first list
	// entry's scheme (a "scheme:" after a space, comma or semicolon);
	// prevAt[i]: the last "@" (or an escape of one) before i, -1 if none.
	nextDelim, nextQH, nextBound, prevAt []int
}

func scanFor(text string) *scanned {
	n := len(text)
	sc := &scanned{text: text, nextDelim: make([]int, n+1), nextQH: make([]int, n+1), nextBound: make([]int, n+1), prevAt: make([]int, n+1)}
	bound := make([]bool, n+1)
	runStart := -1 // the current run of scheme characters, tabs and newlines
	for i := 0; i < n; i++ {
		c := text[i]
		if isSchemeChar(c) || isTabNewline(c) {
			if runStart < 0 {
				runStart = i
			}
			continue
		}
		if c == ':' && runStart >= 0 {
			if st, ok := startAt(text, runStart, i); ok {
				sc.starts = append(sc.starts, st)
			}
			if runStart > 0 && strings.IndexByte(" ,;", text[runStart-1]) >= 0 && isAlpha(text[runStart]) {
				bound[runStart] = true
			}
		}
		runStart = -1
	}
	sc.nextDelim[n], sc.nextQH[n], sc.nextBound[n] = n, n, n
	for i := n - 1; i >= 0; i-- {
		sc.nextDelim[i], sc.nextQH[i], sc.nextBound[i] = sc.nextDelim[i+1], sc.nextQH[i+1], sc.nextBound[i+1]
		switch text[i] {
		case '/':
			sc.nextDelim[i] = i
		case '?', '#':
			sc.nextDelim[i], sc.nextQH[i] = i, i
		}
		if bound[i] {
			sc.nextBound[i] = i
		}
	}
	at := -1
	for i := 0; i < n; i++ {
		sc.prevAt[i] = at
		if text[i] == '@' || text[i] == '\\' && escapedAt(text[i:]) {
			at = i
		}
	}
	sc.prevAt[n] = at
	return sc
}

// escapedAt is whether s starts with an escape of "@": @, \x40,
// \U00000040 (any case of hex digits).
func escapedAt(s string) bool {
	for _, e := range []string{`@`, `\x40`, `\U00000040`} {
		if len(s) >= len(e) && strings.EqualFold(s[:len(e)], e) {
			return true
		}
	}
	return false
}

// startAt is the URL start whose scheme is in the run text[runStart:colon]
// (scheme characters, tabs and newlines), if one is: a special scheme
// ending the run (its last letters, tabs and newlines dropped), or the run
// from its first letter when "//" follows the colon.
func startAt(text string, runStart, colon int) (urlStart, bool) {
	var last [5]byte
	var lastAt [5]int
	m := 0 // the run's last letters, at most "https", in reverse
	for j := colon - 1; j >= runStart && m < 5; j-- {
		if isTabNewline(text[j]) {
			continue
		}
		last[m], lastAt[m] = text[j]|0x20, j
		m++
	}
	for k := m; k >= 2; k-- { // the longest special suffix first
		var name [5]byte
		for x := 0; x < k; x++ {
			name[x] = last[k-1-x]
		}
		if isAlpha(text[lastAt[k-1]]) && specialSchemes[string(name[:k])] {
			a := colon + 1
			for a < len(text) && (text[a] == '/' || text[a] == '\\' || isTabNewline(text[a])) {
				a++
			}
			return urlStart{p: lastAt[k-1], authStart: a, special: true}, true
		}
	}
	p := runStart
	for p < colon && !isAlpha(text[p]) {
		p++
	}
	if p == colon {
		return urlStart{}, false
	}
	a, slashes := colon+1, 0
	for a < len(text) && slashes < 2 && (text[a] == '/' || isTabNewline(text[a])) {
		if text[a] == '/' {
			slashes++
		}
		a++
	}
	if slashes < 2 {
		return urlStart{}, false
	}
	return urlStart{p: p, authStart: a}, true
}

// span is what to mask for the URL st, limit being where the text the URL
// is in ends: the span [from, to), the end of its authority, and whether
// there is one. Where text[p:end] parses, WHATWG decides. Where it does not
// (a password holding "/", a host that does not parse), the span runs on
// to the first "?" or "#", and is masked to its last "@": more is masked
// rather than any of a password.
func (sc *scanned) span(st urlStart, limit int) (from, to, end int, mask bool) {
	bound := min(sc.nextBound[st.authStart], limit)
	end = min(sc.nextDelim[st.authStart], bound)
	stop := end
	if u, ok := whatwg.ParseURL(sc.text[st.p:end]); ok {
		if u.Username == "" && u.Password == "" {
			return 0, 0, end, false
		}
		if st.special {
			if i := strings.IndexByte(sc.text[st.authStart:end], '\\'); i >= 0 {
				stop = st.authStart + i // WHATWG: a special scheme's backslash starts the path
			}
		}
	} else {
		stop = min(sc.nextQH[st.authStart], bound)
	}
	at := sc.prevAt[stop]
	if at <= st.authStart {
		return 0, 0, end, false
	}
	return st.authStart, at, end, true
}

// atFollows is whether, after the string sg on its line, an "@" comes
// before any "/", "?", "#", the next string or the line's end.
func (sc *scanned) atFollows(sg segment, after []segment) bool {
	if sg.close >= len(sc.text) {
		return false
	}
	stop := sc.nextDelim[sg.close]
	if len(after) > 0 {
		stop = min(stop, after[0].open) // first, so the line's end is looked for only up to the next string
	}
	if nl := strings.IndexByte(sc.text[sg.close:stop], '\n'); nl >= 0 {
		stop = sg.close + nl
	}
	return sc.prevAt[stop] >= sg.close
}

// unterminatedURL is whether the last URL in s runs to its end with no "/",
// "?", "#" or "@" in its authority.
func unterminatedURL(s string) bool {
	sc := scanFor(s)
	if len(sc.starts) == 0 {
		return false
	}
	st := sc.starts[len(sc.starts)-1]
	return sc.nextDelim[st.authStart] == len(s) && sc.prevAt[len(s)] < st.authStart
}

func isSchemeChar(c byte) bool {
	return isAlpha(c) || c >= '0' && c <= '9' || c == '+' || c == '.' || c == '-'
}

func isTabNewline(c byte) bool { return c == '\t' || c == '\n' || c == '\r' }

// segment is a quoted string: its opening quote, its content, and the
// position after its closing quote (or its line's end when it has none).
type segment struct {
	open, contentStart, contentEnd, close int
	escapes                               bool
}

// quotedSegments lists the quoted strings of text (see the rules above).
// A closing quote glued to more text is no string: its quotes are ordinary
// text. One pass.
func quotedSegments(text string) []segment {
	var out []segment
	n := len(text)
	for i := 0; i < n; i++ {
		c := text[i]
		if c != '"' && c != '\'' || i > 0 && !strings.ContainsRune(" \t\r\n=([{,:", rune(text[i-1])) {
			continue
		}
		q := 1
		if strings.HasPrefix(text[i:], strings.Repeat(string(c), 3)) {
			q = 3
		} else if c == '\'' {
			continue // a single quote alone is too often an apostrophe
		}
		quote := text[i : i+q]
		escapes := c == '"'
		j := i + q
		closed := false
		for j < n && text[j] != '\n' {
			if escapes && text[j] == '\\' {
				j += 2
				continue
			}
			if strings.HasPrefix(text[j:], quote) {
				closed = true
				break
			}
			j++
		}
		j = min(j, n)
		if !closed {
			// No closing quote on its line: no string (a newline may be inside a
			// password, which WHATWG drops), so its text stays plain.
			i = j - 1
			continue
		}
		after := j + q
		if after == n || strings.ContainsRune(" \t\r\n,;:)]}#.", rune(text[after])) {
			out = append(out, segment{open: i, contentStart: i + q, contentEnd: j, close: after, escapes: escapes})
			i = after - 1
			continue
		}
		i = j // glued: the quotes are ordinary text
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
