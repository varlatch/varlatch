// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

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

// failSafeReproducers are every leak a reviewer found in a free-text masker
// (#251 round 2, #265 rounds 1 to 3), each with what must never show. The
// fail-safe alone must mask every one, whatever the precise layer did.
var failSafeReproducers = []struct{ text, secret string }{
	// #251 round 2 and #265 round 1.
	{`3:  server = "https://alice:fake pass@example.com" x`, "fake pass"},
	{"varlatch server: unexpected argument https://alice:fake-pass@example.com\nUsage: varlatch server [--json]", "fake-pass"},
	{"varlatch server: unexpected argument https://alice:ftp:@example.com", "alice"},
	{`3:  server = "https://alice:ftp:@example.com" x`, "alice"},
	{`3:  server = "https://alice:fake\"pass@example.com" x`, "fake"},
	{`3:  server = "https://alice:fake\u0040pass@example.com" x`, "fake"},
	{`--file needs <path>=<name>, got "https://alice:fake\"pass@h"`, "fake"},
	{`got "https://alice:fake\\pass@h=x"`, "fake"},
	{"https\t:/alice:fake-pass@h", "fake-pass"},
	{"ht\ttps:/alice:fake-pass@h and more", "fake-pass"},
	{"https://alice:fa\nke-pass@h", "alice"},
	{`3:  server = "https://alice:fa\nke@h" x`, "alice"},
	{`https://[bad\alice:fake-pass@h`, "fake-pass"},
	{`server = "https://alice:fa"ke"@example.com" x`, "alice"},
	{`reach https://alice:fake pass "x@h"`, "fake"},
	{"http:/user:hunter2pass@[::1", "hunter2pass"},
	{`http:\\user:hunter2pass@h/x`, "hunter2pass"},
	{"http:user:hunter2pass@h", "hunter2pass"},
	{"http:///user:hunter2pass@h/p@q", "hunter2pass"},
	{"https://alice:pa/ss@h", "alice"},
	{"https://alice:fake%40h", "fake"},
	// #265 round 2.
	{"varlatch server: unknown option --https://alice:fake-review-pass@example.com", "fake-review-pass"},
	{"https://alice:pass\tlabel:tail@example.com", "label:tail"},
	{"https://alice:pass\r\nlabel:tail@example.com", "label:tail"},
	{`server = "https://alice:fake" @=x`, "fake"},
	{`server = "https://alice:fake"@=x`, "fake"},
	{"3:  server = \"\"\"https://alice:fake\\U00000040h\"\"\"\n4:  x = = 1", "fake"},
	{`got "server = \"https://alice:fake\\u0040x\""`, "fake"},
	{`got "server = \"https://alice:fa\\\"ke@x\""`, "alice"},
	{"3:  server = '''https://alice:fake@h'''", "fake"},
	// #265 round 3.
	{`foohttps://alice\part:fake@host`, "fake"},
	{"https://host,\thttps://bob:fake@host", "bob:fake"},
	{`''' "https://alice:fake@h"`, "fake"},
	{"https://host, https://bob:fake@host2; ftp://carol:fake3@h3", "fake"},
	// What the fuzzer and the precise layer's own output led to: a URL with a
	// newline in its password after one the precise layer masked.
	{"https://[redacted]@h, https://u:fake\n@h2", "fake"},
	{"A:[redacted]@\nhttps://u:fa\nke@h", "fa"},
	{"https://a:b\n@h https://c:fake\n@h2", "fake"},
	// #265 round 4: the marker can be imitated, and a join could stop before the delimiter.
	{"https://alice:fake [redacted]@h", "fake"},
	{"https://alice:fake/[redacted]@h", "fake"},
	{"https://alice:fake:[redacted]@h", "fake"},
	{"varlatch verify-release: open https:/alice:fake/[redacted]@h/SHA256SUMS: no such file or directory", "fake"},
	{`open https://alice:fa ke\[redacted]@x: permission denied`, "fa ke"},
	{"https://alice:fake\nmore words\nstill-pass@h", "still-pass"},
	{"https://u:Pa55\nnope\n\nmore\n@h", "Pa55"},
	{"see https://alice:pa\nss word\n\nx@h and more", "alice"},
}

func TestFailSafeMasksEveryReproducer(t *testing.T) {
	cases := failSafeReproducers
	// #265 round 3, P2: an "@" five layers of quoting deep (escaped or not).
	for _, inner := range []string{"https://alice:fake@h", `https://alice:fake\u0040h`} {
		v := inner
		for range 5 {
			v = strconv.Quote(v)
		}
		cases = append(cases, struct{ text, secret string }{"got " + v, "fake"})
	}
	for _, c := range cases {
		got := MaskUserinfoInText(c.text)
		if strings.Contains(got, c.secret) {
			t.Errorf("MaskUserinfoInText(%q) = %q shows %q", c.text, got, c.secret)
		}
		if again := MaskUserinfoInText(got); again != got {
			t.Errorf("MaskUserinfoInText is not stable on %q: %q then %q", c.text, got, again)
		}
	}
}

// TestFailSafeRule: what the fail-safe does, exactly: from just after the
// first ":" that follows a letter (tab, CR and LF passed over) to the last
// at-sign of the whole message.
func TestFailSafeRule(t *testing.T) {
	for in, want := range map[string]string{
		"https://u:p@h":                     "https:[redacted]@h",
		"error: see https://u:p@h/x@y here": "error:[redacted]@y here",
		"varlatch server: unexpected argument https://alice:pw@example.com\nUsage: varlatch server [--json]": "varlatch server:[redacted]@example.com\nUsage: varlatch server [--json]",
		"https://alice:fake%40h":        "https:[redacted]@h",
		`https://alice:fake\x40h`:       "https:[redacted]@h",
		`https://alice:fake\U00000040h`: "https:[redacted]@h",
		"ht\ttps:/alice:pw@h":           "ht\ttps:[redacted]@h",
		"https\t:/alice:pw@h":           "https\t:[redacted]@h",
		"https\n:/alice:pw@h":           "https\n:[redacted]@h",
		"line https://alice:fa\nke@h":   "line https:[redacted]@h",
		// The whole message: newlines inside the span go too.
		"a: b\n\nc@d":     "a:[redacted]@d",
		"Usage: x\n  y@z": "Usage:[redacted]@z",
		// Over-masking, accepted for error text: an email after a colon, and an
		// already-masked message with a later at-sign (no exemption for the marker).
		"contact: ops@example.net": "contact:[redacted]@example.net",
		"Multiple servers stored (http:///[redacted]@127.0.0.1:2, http:\\\\[redacted]@127.0.0.1:3). Pass --server <url> or --all.": "Multiple servers stored (http:[redacted]@127.0.0.1:3). Pass --server <url> or --all.",
		"https://u:p[redacted]@h": "https:[redacted]@h",
		// Kept: no ":" after a letter before an at-sign, or no at-sign.
		"me@example.com and then: more":      "me@example.com and then: more",
		"3:  server = \"https://h.example\"": "3:  server = \"https://h.example\"",
		"  varlatch request [-X <method>] [-H '<name>: <value>']... [-d <data>|@<file>|@-] [--json <data>|@<file>|@-]": "  varlatch request [-X <method>] [-H '<name>: <value>']... [-d <data>|@<file>|@-] [--json <data>|@<file>|@-]",
	} {
		if got := MaskUserinfoInText(in); got != want {
			t.Errorf("MaskUserinfoInText(%q) =\n %q, want\n %q", in, got, want)
		}
	}
}

// TestFailSafeMultiLinePasswords: a password broken over lines whose "@"
// comes one to six lines later, with blank lines, lines without a colon and
// lines with their own colons between, is masked whole.
func TestFailSafeMultiLinePasswords(t *testing.T) {
	fillers := []string{"", "plain words", "  indented", "with: a colon", "\t", "x"}
	for lines := 1; lines <= 6; lines++ {
		for _, filler := range fillers {
			var b strings.Builder
			b.WriteString("varlatch: open https://alice:SeCrEt0")
			for i := range lines {
				b.WriteString("\n" + filler + " SeCrEt" + strconv.Itoa(i+1))
			}
			b.WriteString("@example.com: denied\nnext line")
			got := MaskUserinfoInText(b.String())
			if strings.Contains(got, "SeCrEt") || strings.Contains(got, "alice") {
				t.Errorf("%q -> %q", b.String(), got)
			}
		}
	}
}

// TestMaskTOMLStrings: the precise layer for a varlatch.toml parse error.
func TestMaskTOMLStrings(t *testing.T) {
	for in, want := range map[string]string{
		`3:  server = "https://alice:fake pass@example.com" x`:      `3:  server = "https://[redacted]@example.com" x`,
		`3:  server = "https://alice:fake\"pass@example.com" x`:     `3:  server = "https://[redacted]@example.com" x`,
		`3:  server = "https://alice:fake\u0040pass@example.com" x`: `3:  server = "https://[redacted]@example.com" x`,
		"3:  server = 'https://alice:fake@h' x":                     `3:  server = "https://[redacted]@h" x`,
		"3:  server = \"\"\"https://alice:fake\\U00000040h\"\"\"":   `3:  server = "https://[redacted]@h"`,
		// Kept: no user name and password, an unclosed string (the fail-safe's).
		`3:  server = "https://example.com" "ops@example.net"`: `3:  server = "https://example.com" "ops@example.net"`,
		`3:  server = "https://example.com\\path@segment"`:     `3:  server = "https://example.com\\path@segment"`,
		`3:  server = "https://alice:fake@h`:                   `3:  server = "https://alice:fake@h`,
	} {
		if got := MaskTOMLStrings(in); got != want {
			t.Errorf("MaskTOMLStrings(%q) =\n %q, want\n %q", in, got, want)
		}
	}
}

// TestFailSafeAgreesWithWHATWG: URLs (with and without credentials, nested
// schemes, quotes, escapes, "@", spaces, tabs and newlines in their parts,
// hosts that do not parse) in the contexts failure text puts them. Zero
// leaks: where WHATWG reads a user name or password, or the URL does not
// parse and holds an "@", none of it shows. Exact bytes where there is no
// ":"...at-sign pair.
func TestFailSafeAgreesWithWHATWG(t *testing.T) {
	schemes := []string{"https", "HTTPS", "ht\ttps", "http", "ftp", "foo", "mailto", "foohttps"}
	separators := []string{"//", "/", "", `\`, "///", "/\n/"}
	userinfos := []string{"", "Us3r:Pa55word@", "Us3r:ftp:Pa55@", `Us3r:Pa55"q@`, "Us3r:Pa55 sp@", "Us3r:Pa\n55@", "Us3r:Pa\t55@", "Us3r@", ":Pa55@", "Us3r:Pa55@x@", "Us3r:ftp://Pa55:@", "Us3r:Pa55\tlabel:tail@", `Us3r\part:Pa55@`, "Us3r:Pa55%40"}
	hosts := []string{"example.com", "[bad", "h:8080"}
	tails := []string{"", "/p", `\path@seg`, "?q@r"}
	tomlQuote := func(v string) string {
		r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`)
		return `"` + r.Replace(v) + `"`
	}
	quote5 := func(v string) string {
		for range 5 {
			v = strconv.Quote(v)
		}
		return v
	}
	contexts := []func(string) string{
		func(v string) string { return v },
		func(v string) string { return "3:  server = " + tomlQuote(v) + " # note" },
		func(v string) string { return "3:  server = " + tomlQuote(v) + ` "ops@example.net"` },
		func(v string) string { return "--file needs <path>=<name>, got " + strconv.Quote(v) },
		func(v string) string { return "got " + quote5(v) },
		func(v string) string { return "reach " + v + " or mail ops@example.net" },
		func(v string) string { return `server = "` + v + `"x@y` },
		func(v string) string { return "varlatch server: unknown option --" + v },
		func(v string) string { return "x" + v + " (given)" },
		func(v string) string { return "servers: https://h0.example,\t" + v + "; done" },
		func(v string) string { return `''' "` + v + `"` },
	}
	letterColonThenAt := regexp.MustCompile(`(?s)[A-Za-z][\t\r\n]*:.*(@|%40|\\[uU]0{2,6}40|\\x40)`)
	checked := map[string]int{}
	for _, sc := range schemes {
		for _, sep := range separators {
			for _, ui := range userinfos {
				for _, h := range hosts {
					for _, tail := range tails {
						v := sc + ":" + sep + ui + h + tail
						u, parsed := whatwg.ParseURL(v)
						creds := parsed && (u.Username != "" || u.Password != "")
						for _, build := range contexts {
							text := build(v)
							masked := MaskUserinfoInText(text)
							if creds || !parsed && strings.Contains(ui, "@") {
								checked["masked"]++
								for _, secret := range []string{"Us3r", "Pa55", "label:tail"} {
									if strings.Contains(ui, secret) && strings.Contains(masked, secret) {
										t.Errorf("MaskUserinfoInText(%q) = %q shows %q", text, masked, secret)
									}
								}
							}
							if !letterColonThenAt.MatchString(text) {
								checked["no pair"]++
								if masked != text {
									t.Errorf("MaskUserinfoInText(%q) = %q, but it has no \":\"...at-sign pair", text, masked)
								}
							}
						}
					}
				}
			}
		}
	}
	t.Logf("%v", checked)
	if checked["masked"] < 10000 || checked["no pair"] < 500 {
		t.Fatalf("too few cases: %v", checked)
	}
}

// FuzzMaskUserinfoInText: no text makes the maskers panic, and the
// fail-safe changes nothing more on its own output.
func FuzzMaskUserinfoInText(f *testing.F) {
	for _, c := range failSafeReproducers {
		f.Add(c.text)
	}
	f.Fuzz(func(t *testing.T, text string) {
		once := MaskUserinfoInText(text)
		if twice := MaskUserinfoInText(once); twice != once {
			t.Fatalf("not stable: %q -> %q -> %q", text, once, twice)
		}
		_ = MaskTOMLStrings(text)
		_ = MaskUserinfo(text)
	})
}

// TestMaskingIsLinear: inputs that made the earlier scanners rescan (a tab
// after every letter, a URL every ten bytes, quotes, escapes, "@"s, and
// "http:u:p@h\" repeated) take time linear in their length: 200 KB in well
// under a second each (Sol, #265 rounds 2 and 3).
func TestMaskingIsLinear(t *testing.T) {
	const size = 200_000
	for _, unit := range []string{
		"a\t", "https://h/", "https://u:p@", "https:", "@", "ht\ttps:", "--", `"https://h" `, `"x" `, `"\u0040" `,
		`https:"x"`, `'''a`, `a\"`, ", https:", "a:", "https://[", "http:/u:p@h, ", `"https://a:b" @`, "x\n", `"https://a:b`,
		`http:u:p@h\`, "a:\n@b\n", "%40", `\U00000040`, "a:\n", "[redacted]@", "\n@", "x: [redacted]@h, ",
	} {
		in := strings.Repeat(unit, size/len(unit)+1)[:size]
		start := time.Now()
		MaskUserinfoInText(in)
		MaskTOMLStrings(in)
		MaskUserinfo(in)
		if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
			t.Errorf("%q repeated to %d bytes: %v", unit, size, elapsed)
		}
	}
}

// TestMaskingIsLinearOnLargeMessages: a 2 MB message of URLs, colons and
// at-signs is masked in well under a second.
func TestMaskingIsLinearOnLargeMessages(t *testing.T) {
	in := strings.Repeat("open https://u:p@h/x: denied\n", 2_000_000/29)
	start := time.Now()
	out := MaskUserinfoInText(in)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("2 MB: %v", elapsed)
	}
	if strings.Contains(out, "u:p") {
		t.Error("a password survived")
	}
}
