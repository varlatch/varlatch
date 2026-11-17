// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"strconv"
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
		"https://alice:pa/ss@h/x":        "https://[redacted]@h/x",
		"a b:hunter2pass@h":              "[redacted]@h",
	} {
		if got := MaskUserinfo(in); got != want {
			t.Errorf("MaskUserinfo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskUserinfoInText(t *testing.T) {
	for in, want := range map[string]string{
		"3:  server = \"https://u:p@a@h.example/x@y\" # and http://k@h2": "3:  server = \"https://[redacted]@h.example/x@y\" # and http://[redacted]@h2",
		// A list: each URL's host ends at the separator after its "@", so each is masked on its own.
		"or http:/u:p@h3, http:\\\\u:p@h4, HTTP:u:p@h5":                                              "or http:/[redacted]@h3, http:\\\\[redacted]@h4, HTTP:[redacted]@h5",
		"Multiple servers stored (http:///[redacted]@127.0.0.1:2, http:\\\\[redacted]@127.0.0.1:3).": "Multiple servers stored (http:///[redacted]@127.0.0.1:2, http:\\\\[redacted]@127.0.0.1:3).",
		"stored for http:///u:p@127.0.0.1:2, http:u:p@127.0.0.1:4; pass":                             "stored for http:///[redacted]@127.0.0.1:2, http:[redacted]@127.0.0.1:4; pass",
		// But a scheme with no "@" before it is still inside the user name or password.
		"https://alice:ftp: x@h, http:/u:p@h2": "https://[redacted]@h, http:/[redacted]@h2",
		// Sol, 5.1b round 2 (#265): a user name or password with spaces or quotes.
		`3:  server = "https://alice:fake pass@example.com" x`:                                                      `3:  server = "https://[redacted]@example.com" x`,
		`3:  server = "https://alice:fa"ke@example.com" x`:                                                          `3:  server = "https://[redacted]@example.com" x`,
		"varlatch server: unexpected argument https://alice:fake-pass@example.com\nUsage: varlatch server [--json]": "varlatch server: unexpected argument https://[redacted]@example.com\nUsage: varlatch server [--json]",
		// Sol, #265 round 1, P1: a URL-like string inside the password does not start a second URL.
		"varlatch server: unexpected argument https://alice:ftp:@example.com\nUsage: varlatch server [--json]": "varlatch server: unexpected argument https://[redacted]@example.com\nUsage: varlatch server [--json]",
		`3:  server = "https://alice:ftp:@example.com" x`:                                                      `3:  server = "https://[redacted]@example.com" x`,
		`3:  server = "https://alice:ftp://x:@example.com"`:                                                    `3:  server = "https://[redacted]@example.com"`,
		// P2: escaped quotes and escaped "@" (TOML, Go's %q); the value is shown decoded, masked and quoted again.
		`3:  server = "https://alice:fake\"pass@example.com" x`:        `3:  server = "https://[redacted]@example.com" x`,
		`3:  server = "https://alice:fake\u0040pass@example.com" x`:    `3:  server = "https://[redacted]@example.com" x`,
		`--file needs <path>=<name>, got "https://alice:fake\"pass@h"`: `--file needs <path>=<name>, got "https://[redacted]@h"`,
		`got "https://alice:fake\\pass@h=x"`:                           `got "https://[redacted]@h=x"`,
		// P2: authority forms: a tab in the scheme, a newline in the password, a host that does not parse.
		"https\t:/alice:fake-pass@h":                     "https\t:/[redacted]@h",
		"ht\ttps:/alice:fake-pass@h and more":            "ht\ttps:/[redacted]@h and more",
		"https://alice:fa\nke-pass@h":                    "https://[redacted]@h",
		`3:  server = "https://alice:fa\nke@h" x`:        `3:  server = "https://[redacted]@h" x`,
		`https://[bad\alice:fake-pass@h`:                 `https://[redacted]@h`,
		`3:  server = "https://[bad\\alice:fake-pass@h"`: `3:  server = "https://[redacted]@h"`,
		// P2: an unescaped closing quote ends the authority: the next string's "@" is not taken.
		`server = "https://example.com" "ops@example.net"`:  `server = "https://example.com" "ops@example.net"`,
		`server = "https://example.com", "ops@example.net"`: `server = "https://example.com", "ops@example.net"`,
		// A quote glued inside a value is no string boundary: masked through it.
		`server = "https://alice:fa"ke"@example.com" x`: `server = "https://[redacted]@example.com" x`,
		// A plain URL that runs into a quoted string masks across it.
		`reach https://alice:fake pass "x@h"`: `reach https://[redacted]@h"`,
		// Kept: no URL, no "@" in an authority, a special scheme's backslash path, a URL in a string followed by an email.
		"server = \"https://h.example\" # mail@example.com":            "server = \"https://h.example\" # mail@example.com",
		"[-d <data>|@<file>|@-]":                                       "[-d <data>|@<file>|@-]",
		`server = "https://example.com\\path@segment"`:                 `server = "https://example.com\\path@segment"`,
		`https://example.com\path@segment`:                             `https://example.com\path@segment`,
		"me@example.com and https://h.example/a@b":                     "me@example.com and https://h.example/a@b",
		`mailto:user:ftp:pw@h is not one`:                              `mailto:user:ftp:[redacted]@h is not one`,
		"varlatch: unknown command https://h.example\n\nUsage: # x @y": "varlatch: unknown command https://h.example\n\nUsage: # x @y",
		// WHATWG reads a user name across a line break (it drops newlines): masked.
		"line one https://h.example\nnext line has me@x.example": "line one https://[redacted]@x.example",
	} {
		if got := MaskUserinfoInText(in); got != want {
			t.Errorf("MaskUserinfoInText(%q) =\n %q, want\n %q", in, got, want)
		}
	}
}

func TestMaskUserinfoInArgument(t *testing.T) {
	for in, want := range map[string]string{
		"https://alice:ftp:@example.com":     "https://[redacted]@example.com",
		`https://alice:fa"ke@h`:              `https://[redacted]@h`,
		"--server=https://alice:fake-pass@h": "--server=https://[redacted]@h",
		"x=https://a:b@h,y=http:/c:d@h2":     "x=https://[redacted]@h,y=http:/[redacted]@h2",
		"https://alice:pa/ss@h":              "https://[redacted]@h",
		"me@example.com":                     "me@example.com",
		`https://example.com\path@segment`:   `https://example.com\path@segment`,
	} {
		if got := MaskUserinfoInArgument(in); got != want {
			t.Errorf("MaskUserinfoInArgument(%q) = %q, want %q", in, got, want)
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

// TestMaskUserinfoInTextAgreesWithWHATWG: URLs (with and without credentials,
// nested schemes, quotes, escaped quotes, "@", spaces, tabs and newlines in
// their parts, hosts that do not parse) in the contexts failure text puts
// them: alone, in a quoted varlatch.toml line, next to another quoted
// string holding an email, quoted with Go's %q, in prose before an email,
// glued to a quote, and in a list of servers. It fails on any leak, and on
// any change to text
// where the URL has no user name or password and the context is not
// ambiguous.
func TestMaskUserinfoInTextAgreesWithWHATWG(t *testing.T) {
	schemes := []string{"https", "HTTPS", "ht\ttps", "http", "ftp", "foo", "mailto"}
	separators := []string{"//", "/", "", `\`, "///", "/\n/"}
	userinfos := []string{"", "Us3r:Pa55word@", "Us3r:ftp:Pa55@", `Us3r:Pa55"q@`, "Us3r:Pa55 sp@", "Us3r:Pa\n55@", "Us3r:Pa\t55@", "Us3r@", ":Pa55@", "Us3r:Pa55@x@", "Us3r:ftp://Pa55:@"}
	hosts := []string{"example.com", "[bad", "h:8080"}
	tails := []string{"", "/p", `\path@seg`, "?q@r"}
	tomlQuote := func(v string) string {
		r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`)
		return `"` + r.Replace(v) + `"`
	}
	contexts := []struct {
		name      string
		build     func(string) string
		ambiguous bool
	}{
		{"alone", func(v string) string { return v }, false},
		{"toml", func(v string) string { return "3:  server = " + tomlQuote(v) + " # note" }, false},
		{"toml-email", func(v string) string { return "3:  server = " + tomlQuote(v) + ` "ops@example.net"` }, false},
		{"go-quoted", func(v string) string { return "--file needs <path>=<name>, got " + strconv.Quote(v) }, false},
		{"prose-email", func(v string) string { return "reach " + v + " or mail ops@example.net" }, true},
		{"glued", func(v string) string { return `server = "` + v + `"x@y` }, true},
		{"list-after", func(v string) string { return "servers: https://h0.example, " + v + "; done" }, false},
		{"list-before", func(v string) string { return "stored for " + v + ", http:///[redacted]@127.0.0.1:3." }, false},
	}
	checked := map[string]int{}
	for _, sc := range schemes {
		for _, sep := range separators {
			for _, ui := range userinfos {
				for _, h := range hosts {
					for _, tail := range tails {
						v := sc + ":" + sep + ui + h + tail
						u, parsed := whatwg.ParseURL(v)
						creds := parsed && (u.Username != "" || u.Password != "")
						// A URL whose own path holds a scheme (mailto:...ftp:...) is ambiguous in free text.
						nestedInPath := !creds && strings.Contains(ui, "ftp:")
						for _, c := range contexts {
							text := c.build(v)
							masked := MaskUserinfoInText(text)
							switch {
							case creds:
								checked["credentials"]++
								for _, secret := range []string{"Us3r", "Pa55", "Pa\n55", "Pa\t55"} {
									if strings.Contains(v, secret) && strings.Contains(masked, secret) {
										t.Errorf("%s: MaskUserinfoInText(%q) = %q shows %q", c.name, text, masked, secret)
									}
								}
							case parsed && !c.ambiguous && !nestedInPath:
								checked["kept"]++
								if masked != text {
									t.Errorf("%s: MaskUserinfoInText(%q) = %q, but %q has no user name or password", c.name, text, masked, v)
								}
							case !parsed && strings.Contains(ui, "@"):
								checked["not parsed"]++
								for _, secret := range []string{"Pa55", "Us3r"} {
									if strings.Contains(masked, secret) {
										t.Errorf("%s: MaskUserinfoInText(%q) = %q shows %q of a URL that does not parse", c.name, text, masked, secret)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	t.Logf("%v", checked)
	if checked["credentials"] < 1000 || checked["kept"] < 1000 || checked["not parsed"] < 300 {
		t.Fatalf("too few cases: %v", checked)
	}
}

// FuzzMaskUserinfoInText: no text makes the maskers panic. (Masking twice
// may mask more: an escaped "@" in a quoted string is literal once the
// string is shown decoded. Never less.)
func FuzzMaskUserinfoInText(f *testing.F) {
	for _, seed := range []string{
		`3:  server = "https://alice:fake\"pass@example.com" x`,
		"https://alice:ftp:@example.com, http:\\\\u:p@h\n\"x\\u0040y\"",
		`server = "https://example.com" "ops@example.net"`,
		"ht\ttps:/a:b@[bad\\c@d?e#f",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		_ = MaskUserinfoInText(MaskUserinfoInText(text))
		_ = MaskUserinfoInArgument(text)
		_ = MaskUserinfo(text)
	})
}
