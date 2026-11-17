// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

func TestMaskUserinfo(t *testing.T) {
	for in, want := range map[string]string{
		"not a url":                  "not a url",
		"https://a.example/team":     "https://a.example/team",
		"http://u:p@h:1/x@y":         "http://[redacted]@h:1/x@y",
		"u:p@h":                      "[redacted]@h",
		"http://a@b@c?d@e":           "http://[redacted]@c?d@e",
		"http://h/path@x":            "http://h/path@x",
		"@h":                         "@h",
		"https://:secret@[::1/v1/me": "https://[redacted]@[::1/v1/me",
		// WHATWG's authority variants for special schemes (Sol, 5.1c review).
		"http:/user:hunter2pass@[::1":     "http:/[redacted]@[::1",
		`http:\\user:hunter2pass@h/x`:     `http:\\[redacted]@h/x`,
		`https:\user:hunter2pass@h`:       `https:\[redacted]@h`,
		"http:user:hunter2pass@h":         "http:[redacted]@h",
		"http:///user:hunter2pass@h/p@q":  "http:///[redacted]@h/p@q",
		`https:/\/user:hunter2pass@h?x@y`: `https:/\/[redacted]@h?x@y`,
		"HTTPS:user:hunter2pass@h":        "HTTPS:[redacted]@h",
		"ws:/user:hunter2pass@h":          "ws:/[redacted]@h",
		"file:user:hunter2pass@h":         "file:[redacted]@h",
		"ht\ttp:/user:hunter2pass@h":      "ht\ttp:/[redacted]@h",
		"http:/\n/user:hunter2pass@h":     "http:/\n/[redacted]@h",
		"  http:user:hunter2pass@h":       "  http:[redacted]@h",
		// A backslash does not end the authority: a URL that does not parse is masked through it.
		`http://h\user:hunter2pass@x/y`: `http://[redacted]@x/y`,
		// Not a special scheme and no "//": masked from the start.
		"mailto:user:hunter2pass@h":  "[redacted]@h",
		"foo:/\n/user:hunter2pass@h": "foo:/\n/[redacted]@h",
		"https://h.example/a@b":      "https://h.example/a@b",
	} {
		if got := MaskUserinfo(in); got != want {
			t.Errorf("MaskUserinfo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskUserinfoInText(t *testing.T) {
	in := "3:  server = \"https://u:p@a@h.example/x@y\" # and http://k@h2 or http:/u:p@h3, http:\\\\u:p@h4, HTTP:u:p@h5\n"
	want := "3:  server = \"https://[redacted]@h.example/x@y\" # and http://[redacted]@h2 or http:/[redacted]@h3, http:\\\\[redacted]@h4, HTTP:[redacted]@h5\n"
	if got := MaskUserinfoInText(in); got != want {
		t.Errorf("%q, want %q", got, want)
	}
	if plain := "server = \"https://h.example\" # mail@example.com"; MaskUserinfoInText(plain) != plain {
		t.Errorf("changed text with no URL credentials: %q", MaskUserinfoInText(plain))
	}
}

// TestMaskUserinfoWhereverWHATWGFindsOne: for every scheme, separator and
// authority below, whenever new URL (lib/whatwg) reads a user name or a
// password, the masked text holds neither.
func TestMaskUserinfoWhereverWHATWGFindsOne(t *testing.T) {
	schemes := []string{"http", "HTTPS", "ws", "wss", "ftp", "file", "foo", " http", "h\ttp"}
	separators := []string{"", "/", "//", "///", `\`, `\\`, `/\`, `\/`, "/\n/", "\t//"}
	authorities := []string{"usr:pw9secret@h", "usr:pw9secret@h:8080", ":pw9secret@[::1]", "usr9secret@h", "a@b:pw9secret@h", "usr:pw9secret@[::1"}
	tails := []string{"", "/x", "/x@y", "?q@r", "#f@g", `\p`}
	checked := 0
	for _, s := range schemes {
		for _, sep := range separators {
			for _, a := range authorities {
				for _, tail := range tails {
					text := s + ":" + sep + a + tail
					u, ok := whatwg.ParseURL(text)
					if !ok || u.Username == "" && u.Password == "" {
						continue
					}
					checked++
					masked := MaskUserinfo(text)
					for _, part := range []string{u.Username, u.Password} {
						if part != "" && strings.Contains(masked, part) {
							t.Errorf("MaskUserinfo(%q) = %q still shows %q", text, masked, part)
						}
					}
				}
			}
		}
	}
	if checked < 100 {
		t.Fatalf("only %d texts with credentials checked", checked)
	}
}
