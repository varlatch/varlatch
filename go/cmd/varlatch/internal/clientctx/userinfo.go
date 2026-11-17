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
// authority would start to the last "@" before the first "/", "?" or "#"
// (a backslash does not end it there):
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
	return maskTo(text, start, "/?#")
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

// urlStart is where a URL's authority starts inside longer text: a
// special scheme followed by any run of "/" and "\\" (tabs too), none
// included, or any scheme followed by "//".
var urlStart = regexp.MustCompile(`(?i)\b(https?|wss?|ftp|file):[/\\\t]*|\b[A-Za-z][A-Za-z0-9+.-]*:/\t*/`)

// MaskUserinfoInText masks every URL's user name and password in text that
// holds URLs among other words: an argument echoed in a usage error, a line
// of varlatch.toml quoted in a parse error, any failure message. Where a URL
// ends in such text is unknown, and a user name or password may hold spaces
// and quotes, so each URL's authority runs to the first "/", "?", "#" or
// line end ("\\" too for a special scheme, as WHATWG reads it), or to the
// next URL, and is masked to its last "@". Text with no URL, and URLs whose authority holds
// no "@", keep their bytes.
func MaskUserinfoInText(text string) string {
	matches := urlStart.FindAllStringSubmatchIndex(text, -1)
	if matches == nil {
		return text
	}
	var b strings.Builder
	last := 0
	for n, m := range matches {
		start := m[1]
		if m[0] < last {
			continue // inside the authority already masked
		}
		delims := "/?#\n"
		if m[2] >= 0 {
			delims = "/\\?#\n"
		}
		end := len(text)
		if n+1 < len(matches) {
			end = matches[n+1][0] // the next URL ends this one
		}
		if i := strings.IndexAny(text[start:end], delims); i >= 0 {
			end = start + i
		}
		at := strings.LastIndexByte(text[start:end], '@')
		if at <= 0 {
			continue
		}
		b.WriteString(text[last:start])
		b.WriteString("[redacted]")
		last = start + at
	}
	b.WriteString(text[last:])
	return b.String()
}
