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
// and password replaced by [redacted]: everything between "//" (or the
// start) and the authority's last "@". It assumes nothing else about the
// text, so it serves URLs that do not parse too.
func MaskUserinfo(text string) string {
	start := 0
	if i := strings.Index(text, "//"); i >= 0 {
		start = i + 2
	}
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

// urlInText is a URL's scheme, "//" and authority up to its last "@",
// inside longer text (a quoted line of varlatch.toml).
var urlInText = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/?#\s"']*@`)

// MaskUserinfoInText masks every URL's user name and password in text that
// holds URLs among other words.
func MaskUserinfoInText(text string) string {
	return urlInText.ReplaceAllString(text, "${1}[redacted]@")
}
