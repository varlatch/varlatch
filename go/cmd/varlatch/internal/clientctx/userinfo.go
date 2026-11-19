// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"bytes"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/jsjson"
	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// The Go CLI never prints a URL's user name and password (go/README.md,
// the accepted difference "Diagnostics never print credential values"). A
// server URL is shown through DisplayServer, an allow-list of its parts
// (display.go, "server-display"); any other value that may hold a URL (an
// echoed argument, a server's answer) through MaskURLInValue, with
// [redacted] in their place. A value without them is shown as it is.

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

// DisplayServerValue is a server value as the CLI shows it: a string through
// DisplayServer, and any other JSON value (a hand-edited local override)
// with every string in it shown the same way.
func DisplayServerValue(v any) any {
	switch x := v.(type) {
	case string:
		return DisplayServer(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = DisplayServerValue(e)
		}
		return out
	case jsjson.Object:
		out := make(jsjson.Object, len(x))
		for i, m := range x {
			out[i] = jsjson.Member{Key: m.Key, Value: DisplayServerValue(m.Value)}
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
//     an approval id, verify-release's --file value and path) with
//     MaskURLInValue before formatting it into its message; a server is
//     shown through DisplayServer instead, never masked. A value without a user name
//     and password keeps its bytes. A varlatch.toml parse error quotes no
//     line of a file that holds an at-sign (LoadRepoConfig).
//  2. A dumb fail-safe on the final text of every failure (Run.finish,
//     verify-release's failures): MaskUserinfoInText. It is the net, not
//     the only defence.

// MaskUserinfoInText is the fail-safe: one linear pass over the whole
// text, with no scheme, list or line rules. For detection, tab, CR and LF
// are dropped (as WHATWG drops them from a URL), and "@", "\u0040", "\x40",
// "\U00000040" and "%40" are at-signs. For each at-sign, it looks back
// within the same run of the text (a run ends at whitespace or a quote).
// When that stretch holds any colon, it is masked from just after the
// nearest preceding "//", or from the run's start when there is none, up
// to the at-sign. The at-sign is kept, and nothing about what precedes the
// colon matters. On top of these per-at-sign spans, the whole-text span:
// from just after the first colon of the text, whatever precedes it, to
// its last at-sign (so a password holding "//", whitespace, quotes or line
// breaks is covered too). The union is replaced once, each span with
// "[redacted]@". Error text may be over-masked, never under-masked. A
// stretch without a colon (an email, `@AGENTS.md`) keeps its bytes;
// `mailto:a@b` reads `[redacted]@b`, an accepted over-mask.
func MaskUserinfoInText(text string) string {
	return replaceSpans(text, failSafeSpans(text))
}

// failSafeSpans is what the fail-safe masks, in text's own bytes, each
// span ending just after an at-sign, possibly overlapping.
func failSafeSpans(text string) [][2]int {
	kept, at := forAtSigns(text)
	if kept == nil {
		return nil // no at-sign of any form
	}
	var spans [][2]int
	runStart := 0     // where the current run starts, in kept
	lastSlashes := -1 // the latest "//" of the run (its first byte)
	lastColon := -1   // the latest colon of the run
	for i := 0; i < len(kept); {
		c := kept[i]
		if c == '"' || c == '\'' || c == '`' {
			runStart, lastSlashes, lastColon = i+1, -1, -1
			i++
			continue
		}
		if r, size := utf8.DecodeRune(kept[i:]); unicode.IsSpace(r) {
			runStart, lastSlashes, lastColon = i+size, -1, -1
			i += size
			continue
		}
		if n := atSignAt(kept, i); n > 0 {
			from := -1
			if lastColon >= runStart { // any colon before it in the run
				from = runStart
				if lastSlashes >= runStart {
					from = lastSlashes + 2 // just after the nearest "//"
				}
			}
			if from >= 0 && from < i {
				spans = append(spans, [2]int{at[from], at[i+n-1] + 1})
			}
			i += n
			continue
		}
		switch {
		case c == '/' && i+1 < len(kept) && kept[i+1] == '/':
			lastSlashes = i
			i += 2
			continue
		case c == ':':
			lastColon = i
		}
		i++
	}
	// And the whole-text span: from just after the first colon of the text,
	// whatever precedes it, to the last at-sign after it, so a password
	// holding whitespace, quotes or line breaks is masked too.
	colon := bytes.IndexByte(kept, ':')
	if colon >= 0 {
		last, size := -1, 0
		for i, n := nextAtSign(kept, colon+1); i >= 0; i, n = nextAtSign(kept, i+n) {
			last, size = i, n
		}
		if last >= 0 {
			spans = append(spans, [2]int{at[colon] + 1, at[last+size-1] + 1})
		}
	}
	return spans
}

// replaceSpans is text with the union of spans (byte offsets, in any order,
// possibly overlapping, each ending just after an at-sign) each replaced
// once by "[redacted]@".
func replaceSpans(text string, spans [][2]int) string {
	if len(spans) == 0 {
		return text
	}
	sorted := slices.Clone(spans)
	slices.SortFunc(sorted, func(a, b [2]int) int { return a[0] - b[0] })
	var b strings.Builder
	at := 0
	for i := 0; i < len(sorted); {
		start, end := sorted[i][0], sorted[i][1]
		for i++; i < len(sorted) && sorted[i][0] <= end; i++ {
			end = max(end, sorted[i][1])
		}
		start = max(start, at)
		b.WriteString(text[at:start])
		b.WriteString("[redacted]@")
		at = end
	}
	b.WriteString(text[at:])
	return b.String()
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
// line, the environment, an API client's refusal. It composes both maskers'
// spans on the original value, never one on the other's output, and
// replaces their union once with [redacted], each at-sign kept:
//   - the precise authority span (MaskUserinfo's), when the value, with its
//     leading and trailing whitespace trimmed, parses as a URL or starts
//     with "//" (offsets mapped back to the original);
//   - the fail-safe's spans (MaskUserinfoInText's), always.
//
// Token redaction is the output's own last step (cli.RedactOutput,
// cli.RedactDiagnostic). Already-masked text may be masked again:
// cosmetic, never a leak. A value without an at-sign keeps its bytes.
func MaskURLInValue(v string) string {
	return replaceSpans(v, valueSpans(v))
}

// valueSpans is MaskURLInValue's spans.
func valueSpans(v string) [][2]int {
	spans := failSafeSpans(v)
	trimmed := strings.TrimSpace(v)
	off := strings.Index(v, trimmed)
	if _, ok := whatwg.ParseURL(trimmed); ok || strings.HasPrefix(trimmed, "//") {
		if start, end, ok := userinfoSpan(trimmed); ok {
			spans = append(spans, [2]int{off + start, off + end + 1}) // the "@" after it included
		}
	}
	return spans
}

// FailSafeSpans are the spans MaskUserinfoInText replaces, each by
// "[redacted]@", in text's own bytes: for a caller that adds spans of its
// own (cli's values in flight and token formats) and replaces the union
// once, on the original text.
func FailSafeSpans(text string) [][2]int { return failSafeSpans(text) }

// ValueSpans are the spans MaskURLInValue replaces, each by "[redacted]@",
// in v's own bytes, for the same use.
func ValueSpans(v string) [][2]int { return valueSpans(v) }
