// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"strings"
	"unicode"
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
	start, end, ok := userinfoSpan(text)
	if !ok {
		return text
	}
	return text[:start] + "[redacted]" + text[end:]
}

// userinfoSpan is the bytes MaskUserinfo replaces: [start, end), end at
// the "@" that follows them; false when it replaces nothing.
func userinfoSpan(text string) (int, int, bool) {
	if u, ok := whatwg.ParseURL(text); ok {
		if u.Username == "" && u.Password == "" {
			return 0, 0, false
		}
		start, special := authorityStart(text)
		delims := "/?#"
		if special {
			delims = "/\\?#"
		}
		return spanTo(text, start, delims)
	}
	start, _ := authorityStart(text)
	return spanTo(text, start, "?#") // a password may hold "/"
}

// spanTo is text from start to the last "@" before the first of delims.
func spanTo(text string, start int, delims string) (int, int, bool) {
	end := len(text)
	if i := strings.IndexAny(text[start:], delims); i >= 0 {
		end = start + i
	}
	at := strings.LastIndexByte(text[start:end], '@')
	if at <= 0 {
		return 0, 0, false
	}
	return start, start + at, true
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
		return MaskURLInValue(x)
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
//     an approval id, a server, verify-release's --file value and path)
//     with MaskUserinfo (a server) or MaskURLInValue (an echoed value)
//     before formatting it into its message. A value without a user name
//     and password keeps its bytes. A varlatch.toml parse error quotes no
//     line of a file that holds an at-sign (LoadRepoConfig).
//  2. A dumb fail-safe on the final text of every failure (Run.finish,
//     verify-release's failures): MaskUserinfoInText. It is the net, not
//     the only defence.

// MaskUserinfoInText is the fail-safe: one linear pass over the whole
// message, with no quoting, scheme, list or line rules. For detection, tab,
// CR and LF are dropped (as WHATWG drops them from a URL), and "@", "\u0040",
// "\x40", "\U00000040" and "%40" are at-signs. If the message has a ":" that
// follows a letter or a digit (any script) and an at-sign anywhere after it, everything from just
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
	from, _, atEnd, ok := failSafeSpan(text)
	if !ok {
		return text
	}
	return text[:from] + "[redacted]@" + text[atEnd:]
}

// failSafeSpan is what the fail-safe masks, in text's own bytes: from just
// after the first ":" that follows a letter or a digit (any script) to the
// last at-sign of any form after it, which starts at atStart and ends at
// atEnd; false when the text has no such pair.
func failSafeSpan(text string) (from, atStart, atEnd int, ok bool) {
	kept, at := forAtSigns(text)
	if kept == nil {
		return 0, 0, 0, false // no at-sign of any form
	}
	colon := -1
	for i := 1; i < len(kept); i++ {
		if kept[i] == ':' {
			if r, _ := utf8.DecodeLastRune(kept[:i]); unicode.IsLetter(r) || unicode.IsDigit(r) {
				colon = i
				break
			}
		}
	}
	if colon < 0 {
		return 0, 0, 0, false
	}
	last, size := -1, 0
	for i, n := nextAtSign(kept, colon+1); i >= 0; i, n = nextAtSign(kept, i+n) {
		last, size = i, n
	}
	if last < 0 {
		return 0, 0, 0, false
	}
	return at[colon] + 1, at[last], at[last+size-1] + 1, true
}

// HasAtSign is whether s holds an at-sign as the fail-safe sees one, by
// the fail-safe's own detection (forAtSigns, nextAtSign): tab, CR and LF
// ignored, and "@", "\u0040", "\x40", "\U00000040" and "%40" counted. A
// message whose echoed value holds one puts its explanation after the
// value, since the fail-safe keeps only what follows the last at-sign (the
// explanation follows the URL); a varlatch.toml that holds one has its
// parse errors shown without the file's lines (LoadRepoConfig).
func HasAtSign(s string) bool {
	kept, _ := forAtSigns(s)
	i, _ := nextAtSign(kept, 0)
	return i >= 0
}

// forAtSigns is text as the at-sign detection reads it: without tab, CR
// and LF (WHATWG drops them from a URL), with where each kept byte is in
// text; nil when text has no byte an at-sign of any form starts with.
func forAtSigns(text string) (kept []byte, at []int) {
	if !strings.ContainsAny(text, "@%\\") {
		return nil, nil
	}
	kept = make([]byte, 0, len(text))
	at = make([]int, 0, len(text))
	for i := 0; i < len(text); i++ {
		if c := text[i]; c != '\t' && c != '\r' && c != '\n' {
			kept = append(kept, c)
			at = append(at, i)
		}
	}
	return kept, at
}

// nextAtSign is the first at-sign in kept (from forAtSigns) at or after
// from, and its length; -1 when there is none.
func nextAtSign(kept []byte, from int) (int, int) {
	for i := from; i < len(kept); i++ {
		if n := atSignAt(kept, i); n > 0 {
			return i, n
		}
	}
	return -1, 0
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

// MaskURLInValue is the masker for every string the CLI shows that comes
// from outside it: a server's answer, stored configuration, the command
// line, the environment, an API client's refusal. It composes both
// maskers on the original value, never one on the other's output: the
// precise authority span (MaskUserinfo's, when the value parses as a URL
// or is scheme-relative, starting with "//") and the whole-text
// fail-safe's span (from the first ":" after a letter or a digit to the
// last at-sign). Their union is replaced once with [redacted], each
// at-sign kept, so a credentialed URL anywhere in the value (a query, a
// fragment, text around it) is masked, whatever the other masker removed.
// Token redaction is the output's own last step (cli.RedactOutput,
// cli.RedactDiagnostic). Already-masked text may be masked again
// (`https://[redacted]@h` reads `https:[redacted]@h`): cosmetic, never a
// leak. A value without an at-sign keeps its bytes.
func MaskURLInValue(v string) string {
	// Both maskers' spans, each computed on the original value, never on
	// the other's output; their union is replaced once.
	var spans [][2]int
	if _, ok := whatwg.ParseURL(v); ok || strings.HasPrefix(v, "//") {
		if start, end, ok := userinfoSpan(v); ok {
			spans = append(spans, [2]int{start, end})
		}
	}
	if from, atStart, _, ok := failSafeSpan(v); ok {
		spans = append(spans, [2]int{from, atStart})
	}
	if len(spans) == 0 {
		return v
	}
	if len(spans) == 2 && spans[1][0] < spans[0][0] {
		spans[0], spans[1] = spans[1], spans[0]
	}
	if len(spans) == 2 && spans[1][0] <= spans[0][1] {
		spans = [][2]int{{spans[0][0], max(spans[0][1], spans[1][1])}}
	}
	var b strings.Builder
	at := 0
	for _, sp := range spans {
		b.WriteString(v[at:sp[0]])
		b.WriteString("[redacted]")
		at = sp[1]
	}
	b.WriteString(v[at:])
	return b.String()
}
