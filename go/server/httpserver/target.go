// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"net/http"
	"strings"
	"unicode/utf8"
)

// The paths a request is routed on, derived from its request target as the
// TypeScript deployment derives them, so that routing, authentication and
// the request window see the same path in both servers:
//
//   - honoPath: what varlatchd's router saw. @hono/node-server hands Hono
//     the request URL as the WHATWG URL parser normalizes it (dot segments
//     resolved, "%2e" counted as a dot, other escapes kept, characters
//     outside the path set percent-encoded, slashes never merged), and
//     Hono's getPath applies decodeURI to it (reserved characters such as
//     "%2f" stay encoded; "%25" stays "%25"; a malformed sequence stays as
//     written).
//   - nginxPath: what the dashboard's nginx chose a location with: the URI
//     fully decoded, dot segments resolved and slashes merged. It decides
//     whether a request reaches the API side at all (nginx forwarded the
//     request target unchanged to varlatchd) or the dashboard.

// requestTarget is the path part of the request target as the client sent
// it: RequestURI for a request the server read, or the URL's escaped path
// for one built in code.
func requestTarget(r *http.Request) string {
	t := r.RequestURI
	if !strings.HasPrefix(t, "/") {
		t = r.URL.EscapedPath()
	}
	if i := strings.IndexAny(t, "?#"); i >= 0 {
		t = t[:i]
	}
	if t == "" {
		t = "/"
	}
	return t
}

// isPathPercentEncoded is the WHATWG path percent-encode set.
func isPathPercentEncoded(c byte) bool {
	return c <= 0x20 || c >= 0x7f || c == '"' || c == '#' || c == '<' || c == '>' || c == '?' || c == '`' || c == '{' || c == '}'
}

func isSingleDot(s string) bool { return s == "." || strings.EqualFold(s, "%2e") }

func isDoubleDot(s string) bool {
	switch strings.ToLower(s) {
	case "..", ".%2e", "%2e.", "%2e%2e":
		return true
	}
	return false
}

// normalizeTarget is the path of new URL("http://host" + target), as the
// WHATWG URL parser leaves it.
func normalizeTarget(target string) string {
	var b strings.Builder
	for i := 0; i < len(target); i++ {
		c := target[i]
		switch {
		case c == '\\':
			b.WriteByte('/') // a special scheme's path separator
		case isPathPercentEncoded(c):
			const hex = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		default:
			b.WriteByte(c)
		}
	}
	segs := strings.Split(strings.TrimPrefix(b.String(), "/"), "/")
	out := make([]string, 0, len(segs))
	for i, seg := range segs {
		last := i == len(segs)-1
		switch {
		case isDoubleDot(seg):
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "")
			}
		case isSingleDot(seg):
			if last {
				out = append(out, "")
			}
		default:
			out = append(out, seg)
		}
	}
	return "/" + strings.Join(out, "/")
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// decodeURI is JavaScript's decodeURI: ok is false where it throws (a "%"
// without two hex digits, or bytes that are not UTF-8). An escape of one
// of ";/?:@&=+$,#" is kept as written.
func decodeURI(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '%' {
			b.WriteByte(s[i])
			i++
			continue
		}
		var buf []byte
		start := i
		for {
			if i+2 >= len(s) {
				return "", false
			}
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if !ok1 || !ok2 {
				return "", false
			}
			buf = append(buf, hi<<4|lo)
			i += 3
			if buf[0] < 0x80 || utf8.FullRune(buf) {
				break
			}
			if i >= len(s) || s[i] != '%' {
				return "", false
			}
		}
		if buf[0] < 0x80 {
			if strings.IndexByte(";/?:@&=+$,#", buf[0]) >= 0 {
				b.WriteString(s[start:i])
			} else {
				b.WriteByte(buf[0])
			}
			continue
		}
		r, size := utf8.DecodeRune(buf)
		if (r == utf8.RuneError && size <= 1) || size != len(buf) {
			return "", false
		}
		b.WriteRune(r)
	}
	return b.String(), true
}

// tryDecodeURI is Hono's: decodeURI on the whole string, or, where that
// throws, on each run of escapes, keeping a run that throws as written.
func tryDecodeURI(s string) string {
	if out, ok := decodeURI(s); ok {
		return out
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		j := i
		for j+2 < len(s) && s[j] == '%' {
			if _, ok := unhex(s[j+1]); !ok {
				break
			}
			if _, ok := unhex(s[j+2]); !ok {
				break
			}
			j += 3
		}
		if j == i {
			b.WriteByte(s[i])
			i++
			continue
		}
		if out, ok := decodeURI(s[i:j]); ok {
			b.WriteString(out)
		} else {
			b.WriteString(s[i:j])
		}
		i = j
	}
	return b.String()
}

// honoPath is the path Hono routes a normalized target on (getPath).
func honoPath(normalized string) string {
	if !strings.Contains(normalized, "%") {
		return normalized
	}
	return tryDecodeURI(strings.ReplaceAll(normalized, "%25", "%2525"))
}

// nginxPath is the URI nginx matches its locations with: every escape
// decoded, dot segments resolved, slashes merged.
func nginxPath(normalized string) string {
	var b strings.Builder
	for i := 0; i < len(normalized); i++ {
		if normalized[i] == '%' && i+2 < len(normalized) {
			hi, ok1 := unhex(normalized[i+1])
			lo, ok2 := unhex(normalized[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(normalized[i])
	}
	decoded := b.String()
	segs := strings.Split(strings.TrimPrefix(decoded, "/"), "/")
	var out []string
	for _, seg := range segs {
		switch seg {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	p := "/" + strings.Join(out, "/")
	if last := segs[len(segs)-1]; len(out) > 0 && (last == "" || last == "." || last == "..") {
		p += "/"
	}
	return p
}
