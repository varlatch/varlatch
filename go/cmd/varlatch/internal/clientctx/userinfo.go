// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"regexp"
	"strings"

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
	kept, at := forAtSigns(text)
	if kept == nil {
		return text // no at-sign of any form
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
	for i, n := nextAtSign(kept, colon+1); i >= 0; i, n = nextAtSign(kept, i+n) {
		last, size = i, n
	}
	if last < 0 {
		return text
	}
	return text[:at[colon]+1] + "[redacted]@" + text[at[last+size-1]+1:]
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

// MaskURLInValue is the layer for one value: an argument, a command, a
// topic or an approval id a failure echoes, or a string a server's answer,
// the tier cache or stored metadata gives output. A value that is exactly
// one URL is masked precisely with MaskUserinfo: it has a URL's shape (it
// starts with a scheme followed by "//", a special scheme, or "//", and
// holds no space), it parses as a URL, and nothing after its authority
// holds an at-sign in any form. Any other value holding an at-sign goes
// through the whole-text fail-safe, MaskUserinfoInText: free text may be
// over-masked, never under-masked. The value's content never exempts it;
// text a masker already made is marked by its type (Sanitized) instead,
// where the caller knows it. Any other value is kept as it is.
func MaskURLInValue(v string) string {
	if isOneURL(v) {
		return MaskUserinfo(v)
	}
	if HasAtSign(v) {
		return MaskUserinfoInText(v)
	}
	return v
}

// Sanitized is text a masker made, every URL in it already shown without
// its user name and password (an API client's refusal, built with
// MaskUserinfo). The output fail-safes pass it as it is, masking it again
// only for tokens, so it is never masked twice; nothing else is ever
// trusted for what it contains.
type Sanitized string

// leadingScheme matches a URL scheme and its colon at the start of a value.
var leadingScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)

// isOneURL is whether v is one URL as a whole: no space in it, and it
// starts with "//", or with a scheme that is special or followed by "//"
// (tabs and newlines between, as WHATWG drops them).
func isOneURL(v string) bool {
	if strings.ContainsRune(v, ' ') {
		return false
	}
	if _, ok := whatwg.ParseURL(v); !ok && !strings.HasPrefix(v, "//") {
		return false
	}
	special := false
	if !strings.HasPrefix(v, "//") {
		loc := leadingScheme.FindStringIndex(v)
		if loc == nil {
			return false
		}
		special = specialSchemes[strings.ToLower(v[:loc[1]-1])]
		rest := strings.NewReplacer("\t", "", "\r", "", "\n", "").Replace(v[loc[1]:min(len(v), loc[1]+16)])
		if !special && !strings.HasPrefix(rest, "//") {
			return false
		}
	}
	// Nothing after the authority may hold an at-sign: a query or path
	// naming a second, credentialed URL takes the fail-safe.
	start, _ := authorityStart(v)
	delims := "/?#"
	if special {
		delims = "/\\?#"
	}
	end := len(v)
	if i := strings.IndexAny(v[start:], delims); i >= 0 {
		end = start + i
	}
	return !HasAtSign(v[end:])
}
