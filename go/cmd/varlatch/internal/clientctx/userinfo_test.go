// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

func TestMaskUserinfo(t *testing.T) {
	for in, want := range map[string]string{
		"not a url":              "not a url",
		"https://a.example/team": "https://a.example/team",
		"http://u:p@h:1/x@y":     "http://[redacted]@h:1/x@y",
		"http://a@b@c?d@e":       "http://[redacted]@c?d@e",
		"http://h/path@x":        "http://h/path@x",
		"@h":                     "@h",
		// WHATWG's authority variants for special schemes (Sol, 5.1c review).
		`http:\\user:hunter2pass@h/x`:     `http:\\[redacted]@h/x`,
		`https:\user:hunter2pass@h`:       `https:\[redacted]@h`,
		"http:user:hunter2pass@h":         "http:[redacted]@h",
		"http:///user:hunter2pass@h/p@q":  "http:///[redacted]@h/p@q",
		`https:/\/user:hunter2pass@h?x@y`: `https:/\/[redacted]@h?x@y`,
		"HTTPS:user:hunter2pass@h":        "HTTPS:[redacted]@h",
		"ws:/user:hunter2pass@h":          "ws:/[redacted]@h",
		"ht\ttp:/user:hunter2pass@h":      "ht\ttp:/[redacted]@h",
		"http:/\n/user:hunter2pass@h":     "http:/\n/[redacted]@h",
		"  http:user:hunter2pass@h":       "  http:[redacted]@h",
		"foo:/\n/user:hunter2pass@h":      "foo:/\n/[redacted]@h",
		"https://alice:fake pass@h":       "https://[redacted]@h",
		`https://alice:fa"ke@h`:           `https://[redacted]@h`,
		// No user name or password where WHATWG reads none: the bytes are kept
		// (Sol, 5.1b round 2: a special scheme's backslash starts the path).
		`https://example.com\path@segment`: `https://example.com\path@segment`,
		`http://h\user:hunter2pass@x/y`:    `http://h\user:hunter2pass@x/y`,
		"mailto:user:hunter2pass@h":        "mailto:user:hunter2pass@h",
		"file:user:hunter2pass@h":          "file:user:hunter2pass@h",
		"u:p@h":                            "u:p@h",
		// Text that does not parse: masked conservatively, a backslash included.
		"http:/user:hunter2pass@[::1":    "http:/[redacted]@[::1",
		"https://:secret@[::1/v1/me":     "https://[redacted]@[::1/v1/me",
		`http://[bad\user:hunter2pass@x`: `http://[redacted]@x`,
		"a b:hunter2pass@h":              "[redacted]@h",
	} {
		if got := MaskUserinfo(in); got != want {
			t.Errorf("MaskUserinfo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskUserinfoInText(t *testing.T) {
	for in, want := range map[string]string{
		"3:  server = \"https://u:p@a@h.example/x@y\" # and http://k@h2 or http:/u:p@h3, http:\\\\u:p@h4, HTTP:u:p@h5\n": "3:  server = \"https://[redacted]@h.example/x@y\" # and http://[redacted]@h2 or http:/[redacted]@h3, http:\\\\[redacted]@h4, HTTP:[redacted]@h5\n",
		// Sol, 5.1b round 2: a user name or password with spaces or quotes.
		`3:  server = "https://alice:fake pass@example.com" x`:                                                      `3:  server = "https://[redacted]@example.com" x`,
		`3:  server = "https://alice:fa"ke@example.com" x`:                                                          `3:  server = "https://[redacted]@example.com" x`,
		"varlatch server: unexpected argument https://alice:fake-pass@example.com\nUsage: varlatch server [--json]": "varlatch server: unexpected argument https://[redacted]@example.com\nUsage: varlatch server [--json]",
		// Kept: no URL, no "@" in an authority, a special scheme's backslash path.
		"server = \"https://h.example\" # mail@example.com":      "server = \"https://h.example\" # mail@example.com",
		"[-d <data>|@<file>|@-]":                                 "[-d <data>|@<file>|@-]",
		`server = "https://example.com\path@segment"`:            `server = "https://example.com\path@segment"`,
		"me@example.com and https://h.example/a@b":               "me@example.com and https://h.example/a@b",
		"line one https://h.example\nnext line has me@x.example": "line one https://h.example\nnext line has me@x.example",
	} {
		if got := MaskUserinfoInText(in); got != want {
			t.Errorf("MaskUserinfoInText(%q) =\n %q, want\n %q", in, got, want)
		}
	}
}

// TestMaskUserinfoAgreesWithWHATWG: for every scheme, separator, authority
// and tail below, MaskUserinfo agrees with new URL (lib/whatwg) both ways.
// Where it reads a user name or password, the masked text shows neither,
// nor any of the authority's secret. Where it reads none, the text is kept
// byte for byte. Text that does not parse never shows the secret before
// an "@".
func TestMaskUserinfoAgreesWithWHATWG(t *testing.T) {
	schemes := []string{"http", "HTTPS", "ws", "wss", "ftp", "file", "foo", "mailto", " http", "ht\ttp", "h\ttp"}
	separators := []string{"", "/", "//", "///", `\`, `\\`, `/\`, `\/`, "/\n/", "\t//"}
	authorities := []string{"usr:pw9secret@h", "usr:pw9secret@h:8080", ":pw9secret@[::1]", "usr9secret@h", "a@b:pw9secret@h", "usr:pw9secret@[::1", "usr:pw9 secret@h", `usr:pw9"secret@h`, "h", "h:8080"}
	tails := []string{"", "/x", "/x@y", "?q@r", "#f@g", `\p`, `\path@seg`, `\u:pw9secret@seg`}
	with, without, unparsed := 0, 0, 0
	for _, s := range schemes {
		for _, sep := range separators {
			for _, a := range authorities {
				for _, tail := range tails {
					text := s + ":" + sep + a + tail
					masked := MaskUserinfo(text)
					u, ok := whatwg.ParseURL(text)
					switch {
					case !ok:
						unparsed++
						if strings.Contains(a, "@") && strings.Contains(masked, "9secret@") {
							t.Errorf("MaskUserinfo(%q) = %q: text that does not parse shows its secret", text, masked)
						}
					case u.Username == "" && u.Password == "":
						without++
						if masked != text {
							t.Errorf("MaskUserinfo(%q) = %q, but WHATWG reads no user name or password: want it kept", text, masked)
						}
					default:
						with++
						// The scheme and separators are kept as they are: look past them.
						after := masked[len(s)+1+len(sep):]
						for _, part := range []string{u.Username, u.Password, "9secret", "9 secret", `9"secret`} {
							if part != "" && strings.Contains(after, part) && !strings.Contains(u.Pathname+u.Search+u.Hash, part) {
								t.Errorf("MaskUserinfo(%q) = %q still shows %q", text, masked, part)
							}
						}
						if !strings.Contains(masked, "[redacted]@") {
							t.Errorf("MaskUserinfo(%q) = %q masks nothing", text, masked)
						}
					}
				}
			}
		}
	}
	t.Logf("%d with credentials, %d without, %d not parsed", with, without, unparsed)
	if with < 200 || without < 200 || unparsed < 50 {
		t.Fatalf("too few cases: %d with credentials, %d without, %d not parsed", with, without, unparsed)
	}
}
