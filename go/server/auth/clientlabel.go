// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"regexp"
	"strings"
)

// ClientLabel is clientLabel (auth/client-label.ts): a short readable
// summary of a User-Agent ("Firefox on Linux", "varlatch CLI 0.14.0 on
// Linux"), or nil when it is missing or not recognized. Every word of a
// label comes from the fixed lists below, except a varlatch client's
// version, which must look like a release version: no other text from the
// header reaches it. What the client says about itself, never verified and
// never an authorization input.
func ClientLabel(userAgent *string) *string {
	if userAgent == nil {
		return nil
	}
	ua := *userAgent
	// Real User-Agents are short; a huge header is not worth matching
	// (length in UTF-16 units, as JavaScript counts it).
	if ua == "" || utf16Len(ua) > 1024 {
		return nil
	}
	if m := varlatchClient.FindStringSubmatch(ua); m != nil {
		os, rest := "", []string(nil)
		if m[3] != "" || strings.Contains(m[0], "(") {
			parts := strings.Split(m[3], ";")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			os, rest = parts[0], parts[1:]
		}
		kind := "CLI"
		if m[1] == "mcp" {
			kind = "MCP"
		}
		label := "varlatch " + kind + " " + m[2]
		if p, ok := platforms[os]; ok {
			label += " on " + p
		}
		for _, t := range rest {
			if t == "assisted" {
				label += ", assisted"
				break
			}
		}
		if utf16Len(label) > ClientLabelMax {
			return nil
		}
		return &label
	}
	browser := first(browsers, ua)
	if browser == "" {
		return nil
	}
	if system := first(systems, ua); system != "" {
		browser += " on " + system
	}
	return &browser
}

// ClientLabelMax is the longest label kept.
const ClientLabelMax = 60

// varlatchClient matches what varlatch's own clients send: the CLI's
// `varlatch-cli/<version> (<platform>; <arch>[; assisted])` and the MCP
// server's `varlatch-mcp/<version> (<platform>; <arch>)`. The version is
// followed by the end or white space (JavaScript's lookahead (?=$|\s)), which
// RE2 has no form of: the version group is checked separately.
var varlatchClient = regexp.MustCompile(`^varlatch-(cli|mcp)/(\d{1,4}\.\d{1,4}\.\d{1,4}(?:-[0-9A-Za-z.]{1,20})?)(?:$|[\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]+\(([^()]{1,100})\)|[\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}])`)

var platforms = map[string]string{
	"linux":   "Linux",
	"darwin":  "macOS",
	"win32":   "Windows",
	"freebsd": "FreeBSD",
	"openbsd": "OpenBSD",
}

type pattern struct {
	re    *regexp.Regexp
	label string
}

// Order matters: Edge, Opera, and others also claim Chrome and Safari.
var browsers = []pattern{
	{regexp.MustCompile(`\bEdg(?:e|A|iOS)?/`), "Edge"},
	{regexp.MustCompile(`\bOPR/|\bOpera\b`), "Opera"},
	{regexp.MustCompile(`\bSamsungBrowser/`), "Samsung Internet"},
	{regexp.MustCompile(`\bVivaldi/`), "Vivaldi"},
	{regexp.MustCompile(`\bFirefox/|\bFxiOS/`), "Firefox"},
	{regexp.MustCompile(`\bChromium/`), "Chromium"},
	{regexp.MustCompile(`\bChrome/|\bCriOS/`), "Chrome"},
	{regexp.MustCompile(`\bVersion/[\d.]+.*\bSafari/`), "Safari"},
}

// Order matters: Android and ChromeOS also claim Linux, iPadOS may claim Mac.
var systems = []pattern{
	{regexp.MustCompile(`\bWindows\b`), "Windows"},
	{regexp.MustCompile(`\b(?:iPhone|iPad|iPod)\b`), "iOS"},
	{regexp.MustCompile(`\bAndroid\b`), "Android"},
	{regexp.MustCompile(`\bCrOS\b`), "ChromeOS"},
	{regexp.MustCompile(`\bMac OS X\b|\bMacintosh\b`), "macOS"},
	{regexp.MustCompile(`\bLinux\b|\bX11\b`), "Linux"},
}

func first(list []pattern, ua string) string {
	for _, p := range list {
		if p.re.MatchString(ua) {
			return p.label
		}
	}
	return ""
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}
