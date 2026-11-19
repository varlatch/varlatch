// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"strings"
	"unicode"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// Every server URL the CLI shows (a stored server, a --server or
// VARLATCH_SERVER value, the remembered default, the server a refusal
// names) is shown through DisplayServer: an allow-list of its parts, never
// the value with parts masked out (go/README.md, the accepted difference
// "server-display").

// UnrecognisedServer is what the CLI shows for a server URL it cannot
// read as one.
const UnrecognisedServer = "[unrecognised server URL]"

// The markers for parts DisplayServer leaves out, so the reader can tell
// something was there: a path it does not show, a query, a fragment.
const (
	hiddenPath     = "/[redacted]"
	hiddenQuery    = "?[redacted]"
	hiddenFragment = "#[redacted]"
)

// DisplayServer is a server URL as the CLI shows it: its scheme and its
// host and port, its path when the path is made only of allow-listed
// characters (otherwise "/[redacted]"), and nothing else. A user name and
// password are left out; a query or a fragment is left out with a marker
// ("?[redacted]", "#[redacted]"). Every part shown keeps its bytes, so an
// ordinary URL (https://h.example, http://127.0.0.1:1234/) is shown as it
// is, and a scheme-relative one keeps its "//". Leading and trailing
// spaces and C0 controls, which URL parsing ignores, are left out too.
// A value that does not parse as a URL (lib/whatwg, as `new URL` reads it,
// against https: for a scheme-relative one), that holds a space or a
// control character, that has no authority, whose host and port are not
// made of allow-listed characters, or whose authority ends at a backslash
// with an at-sign of any form after it is shown as UnrecognisedServer.
func DisplayServer(raw string) string {
	s := strings.TrimFunc(raw, func(r rune) bool { return r <= 0x20 })
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] == 0x7f {
			return UnrecognisedServer
		}
	}
	var prefix, rest string
	special := true
	if strings.HasPrefix(s, "//") {
		if _, ok := whatwg.ParseURL("https:" + s); !ok {
			return UnrecognisedServer
		}
		prefix, rest = "//", s[2:]
	} else {
		colon := strings.IndexByte(s, ':')
		if colon <= 0 || !isScheme(s[:colon]) {
			return UnrecognisedServer
		}
		if _, ok := whatwg.ParseURL(s); !ok {
			return UnrecognisedServer
		}
		special = specialSchemes[strings.ToLower(s[:colon])]
		i := colon + 1
		if special {
			for i < len(s) && (s[i] == '/' || s[i] == '\\') {
				i++
			}
		} else if strings.HasPrefix(s[i:], "//") {
			i += 2
		} else {
			return UnrecognisedServer // no authority: no server
		}
		prefix, rest = s[:i], s[i:]
	}
	ends := "/?#"
	if special {
		ends = "/\\?#"
	}
	end := len(rest)
	if i := strings.IndexAny(rest, ends); i >= 0 {
		end = i
	}
	hostPort := rest[:end]
	if at := strings.LastIndexByte(hostPort, '@'); at >= 0 {
		hostPort = hostPort[at+1:] // the user name and password: never shown
	}
	if !allowedHostPort(hostPort) {
		return UnrecognisedServer
	}
	rest = rest[end:]
	// A backslash ends a special scheme's authority for WHATWG, but not for
	// a reader that takes it for an escape or for part of the authority:
	// with an at-sign of any form after it ("https://TOKEN\u0040host"),
	// such a reader sees a user name where WHATWG sees the host, so neither
	// is shown (as HasUserinfo counts it).
	if strings.HasPrefix(rest, "\\") && HasAtSign(rest) {
		return UnrecognisedServer
	}
	path, query, fragment := rest, "", ""
	hasQuery, hasFragment := false, false
	if i := strings.IndexByte(path, '#'); i >= 0 {
		path, fragment, hasFragment = path[:i], path[i+1:], true
	}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path, query, hasQuery = path[:i], path[i+1:], true
	}
	if !allowedPath(path) {
		path = hiddenPath
	}
	out := prefix + hostPort + path
	if hasQuery {
		out += marker("?", query, hiddenQuery)
	}
	if hasFragment {
		out += marker("#", fragment, hiddenFragment)
	}
	if HasAtSign(out) { // never: no allow-listed part holds one
		return UnrecognisedServer
	}
	return out
}

// marker is an empty query or fragment as it is, any other as its marker.
func marker(sign, part, hidden string) string {
	if part == "" {
		return sign
	}
	return hidden
}

func isScheme(s string) bool {
	if s == "" || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !isAlpha(c) && !(c >= '0' && c <= '9') && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// allowedHostPort: letters and digits (any script, for an international
// domain name), ".", "-", "_", "~", and the "[", "]" and ":" of an IPv6
// address and a port. No "%", no at-sign, no escape.
func allowedHostPort(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsMark(r) && !strings.ContainsRune(".-_~[]:", r) {
			return false
		}
	}
	return true
}

// allowedPath: ASCII letters and digits, "/", and "-._~!$&'()*+,;=:". No
// "%", no "@", no backslash, so no user name and password can be read out
// of a path that is shown, escaped or not.
func allowedPath(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlpha(c) && !(c >= '0' && c <= '9') && !strings.ContainsRune("/-._~!$&'()*+,;=:", rune(c)) {
			return false
		}
	}
	return true
}

// DisplayServers is each of servers through DisplayServer.
func DisplayServers(servers []string) []string {
	out := make([]string, len(servers))
	for i, s := range servers {
		out[i] = DisplayServer(s)
	}
	return out
}
