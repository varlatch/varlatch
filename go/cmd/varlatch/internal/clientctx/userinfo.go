// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"regexp"
	"strings"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The Go CLI never prints a URL's user name and password (go/README.md,
// the accepted difference "Diagnostics never print credential values"): a
// server URL is shown with [redacted] in their place, in human output,
// --json documents and messages alike. A URL without them is shown as it
// is.

// MaskUserinfo is text that may be a URL with what could be its user name
// and password replaced by [redacted]. It assumes the text may not parse,
// so it errs towards masking more:
//
//   - For a special scheme (http, https, ws, wss, ftp, file, in any case),
//     the authority starts after any run of "/" and "\" (and the tabs and
//     newlines WHATWG parsing drops) that follows the scheme, none
//     included: "http:/u:p@h", "http:\\u:p@h", "http:u:p@h" and
//     "http:///u:p@h" all have u:p as user name and password.
//   - Otherwise it starts after the first "//" (tabs and newlines between
//     its slashes allowed, as WHATWG parsing drops them), or at the start
//     of the text.
//
// Everything from there to the last "@" before the first "/", "?" or "#"
// is masked; a backslash does not end it, so a URL that does not parse is
// masked through it rather than shown.
func MaskUserinfo(text string) string {
	start := authorityStart(text)
	end := len(text)
	if i := strings.IndexAny(text[start:], "/?#"); i >= 0 {
		end = start + i
	}
	at := strings.LastIndexByte(text[start:end], '@')
	if at <= 0 {
		return text
	}
	return text[:start] + "[redacted]" + text[start+at:]
}

var specialSchemes = map[string]bool{"http": true, "https": true, "ws": true, "wss": true, "ftp": true, "file": true}

// authorityStart is where MaskUserinfo looks for a user name and password.
func authorityStart(text string) int {
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
				return k
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
			return m + 1
		}
	}
	return 0
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

// urlInText is a URL's scheme and authority up to its last "@", inside
// longer text (a quoted line of varlatch.toml): a special scheme followed by
// any run of "/" and "\\", none included, or any scheme followed by "//".
var urlInText = regexp.MustCompile(`(?i)(\b(?:https?|wss?|ftp|file):[/\\\t]*|[A-Za-z][A-Za-z0-9+.-]*:/\t*/)[^/?#\s"']*@`)

// MaskUserinfoInText masks every URL's user name and password in text that
// holds URLs among other words.
func MaskUserinfoInText(text string) string {
	return urlInText.ReplaceAllString(text, "${1}[redacted]@")
}
