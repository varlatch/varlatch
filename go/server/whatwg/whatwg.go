// SPDX-License-Identifier: AGPL-3.0-or-later

// Package whatwg is the part of the WHATWG URL Standard that the TypeScript
// server's code depends on through Node.js: the host parser (as
// url.domainToASCII exposes it), the parts of `new URL` that audit
// redaction reads (protocol, host, pathname, search, hash), net.isIP, and
// String.prototype.trim and toLowerCase. Vectors recorded from Node.js
// (go/server/authz/testdata, go/server/audit/testdata) hold it to Node's
// answers.
package whatwg

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// uts46 is domain to ASCII as the URL Standard calls it with beStrict
// false: UseSTD3ASCIIRules false, CheckHyphens false, CheckBidi and
// CheckJoiners true, nontransitional, VerifyDnsLength false.
var uts46 = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.Transitional(false),
	idna.CheckHyphens(false),
	idna.CheckJoiners(true),
	idna.StrictDomainName(false),
	idna.VerifyDNSLength(false),
)

// DomainToASCII is Node's url.domainToASCII, which sets the hostname of a
// special URL to s and answers with it, or "" when the setter fails: tabs
// and newlines are removed, the host ends at the first /, ?, # or \, and a
// colon outside brackets (a port) fails it.
func DomainToASCII(s string) string {
	s = removeTabNewline(s)
	inBrackets := false
	end := len(s)
scan:
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[':
			inBrackets = true
		case ']':
			inBrackets = false
		case ':':
			if !inBrackets {
				return ""
			}
		case '/', '?', '#', '\\':
			end = i
			break scan
		}
	}
	if end == 0 {
		return ""
	}
	h, ok := ParseHost(s[:end], true)
	if !ok {
		return ""
	}
	return h
}

func removeTabNewline(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// domainToASCII is the URL Standard's domain to ASCII as Node.js (ada)
// carries it out: an all-ASCII domain is only lowercased (its xn-- labels
// are not decoded or validated); any other goes through UTS #46.
func domainToASCII(domain string) (string, bool) {
	if isASCII(domain) {
		return strings.ToLower(domain), domain != ""
	}
	ascii, err := uts46.ToASCII(domain)
	return ascii, err == nil && ascii != ""
}

func isForbiddenHost(r rune) bool {
	switch r {
	case 0, '\t', '\n', '\r', ' ', '#', '/', ':', '<', '>', '?', '@', '[', '\\', ']', '^', '|':
		return true
	}
	return false
}

func isForbiddenDomain(r rune) bool {
	return isForbiddenHost(r) || r <= 0x1f || r == '%' || r == 0x7f
}

// ParseHost is the URL Standard's host parser, serialized: a domain, an
// IPv4 address in dotted form, or an IPv6 address in brackets. special
// says whether the URL's scheme is special; a host that is not is opaque.
func ParseHost(input string, special bool) (string, bool) {
	if strings.HasPrefix(input, "[") {
		if !strings.HasSuffix(input, "]") {
			return "", false
		}
		a, ok := parseIPv6(input[1 : len(input)-1])
		if !ok {
			return "", false
		}
		return "[" + serializeIPv6(a) + "]", true
	}
	if !special {
		return opaqueHost(input)
	}
	domain := percentDecode(input)
	if !utf8.ValidString(domain) {
		domain = strings.ToValidUTF8(domain, "\ufffd")
	}
	ascii, ok := domainToASCII(domain)
	if !ok {
		return "", false
	}
	for _, r := range ascii {
		if isForbiddenDomain(r) {
			return "", false
		}
	}
	if endsInNumber(ascii) {
		v, ok := parseIPv4(ascii)
		if !ok {
			return "", false
		}
		return fmt.Sprintf("%d.%d.%d.%d", v>>24, v>>16&0xff, v>>8&0xff, v&0xff), true
	}
	return ascii, true
}

func opaqueHost(input string) (string, bool) {
	for _, r := range input {
		if isForbiddenHost(r) {
			return "", false
		}
	}
	return percentEncode(input, func(b byte) bool { return b < 0x20 || b > 0x7e }), true
}

func percentEncode(s string, set func(byte) bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if set(s[i]) {
			fmt.Fprintf(&b, "%%%02X", s[i])
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func percentDecode(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				b = append(b, hi<<4|lo)
				i += 2
				continue
			}
		}
		b = append(b, s[i])
	}
	return string(b)
}

func endsInNumber(s string) bool {
	parts := strings.Split(s, ".")
	if parts[len(parts)-1] == "" {
		if len(parts) == 1 {
			return false
		}
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	if last != "" && strings.Trim(last, "0123456789") == "" {
		return true
	}
	_, ok := parseIPv4Number(last)
	return ok
}

func parseIPv4Number(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	base := 10
	switch {
	case len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X"):
		base, s = 16, s[2:]
	case len(s) >= 2 && s[0] == '0':
		base, s = 8, s[1:]
	}
	if s == "" {
		return 0, true
	}
	for i := 0; i < len(s); i++ {
		d, ok := unhex(s[i])
		if !ok || int(d) >= base {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		return 1 << 40, true // larger than any part may be: refused by the caller
	}
	return v, true
}

func parseIPv4(s string) (uint32, bool) {
	parts := strings.Split(s, ".")
	if parts[len(parts)-1] == "" && len(parts) > 1 {
		parts = parts[:len(parts)-1]
	}
	if len(parts) > 4 {
		return 0, false
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		n, ok := parseIPv4Number(p)
		if !ok {
			return 0, false
		}
		nums[i] = n
	}
	for _, n := range nums[:len(nums)-1] {
		if n > 255 {
			return 0, false
		}
	}
	last := nums[len(nums)-1]
	if last >= 1<<(8*(5-len(nums))) {
		return 0, false
	}
	v := last
	for i, n := range nums[:len(nums)-1] {
		v += n << (8 * (3 - i))
	}
	return uint32(v), true
}

// parseIPv6 is the URL Standard's IPv6 parser.
func parseIPv6(s string) ([8]uint16, bool) {
	var a [8]uint16
	in := []byte(s)
	piece, compress, p := 0, -1, 0
	at := func(i int) int {
		if i < len(in) {
			return int(in[i])
		}
		return -1
	}
	if at(p) == ':' {
		if at(p+1) != ':' {
			return a, false
		}
		p += 2
		piece++
		compress = piece
	}
	for at(p) != -1 {
		if piece == 8 {
			return a, false
		}
		if at(p) == ':' {
			if compress != -1 {
				return a, false
			}
			p++
			piece++
			compress = piece
			continue
		}
		value, length := 0, 0
		for length < 4 && at(p) != -1 {
			d, ok := unhex(byte(at(p)))
			if !ok {
				break
			}
			value = value*16 + int(d)
			p++
			length++
		}
		if at(p) == '.' {
			if length == 0 {
				return a, false
			}
			p -= length
			if piece > 6 {
				return a, false
			}
			seen := 0
			for at(p) != -1 {
				v := -1
				if seen > 0 {
					if at(p) == '.' && seen < 4 {
						p++
					} else {
						return a, false
					}
				}
				if c := at(p); c < '0' || c > '9' {
					return a, false
				}
				for c := at(p); c >= '0' && c <= '9'; c = at(p) {
					n := c - '0'
					switch {
					case v == -1:
						v = n
					case v == 0:
						return a, false
					default:
						v = v*10 + n
					}
					if v > 255 {
						return a, false
					}
					p++
				}
				a[piece] = a[piece]*0x100 + uint16(v)
				seen++
				if seen == 2 || seen == 4 {
					piece++
				}
			}
			if seen != 4 {
				return a, false
			}
			break
		} else if at(p) == ':' {
			p++
			if at(p) == -1 {
				return a, false
			}
		} else if at(p) != -1 {
			return a, false
		}
		a[piece] = uint16(value)
		piece++
	}
	if compress != -1 {
		swaps := piece - compress
		piece = 7
		for piece != 0 && swaps > 0 {
			a[piece], a[compress+swaps-1] = a[compress+swaps-1], a[piece]
			piece--
			swaps--
		}
	} else if piece != 8 {
		return a, false
	}
	return a, true
}

func serializeIPv6(a [8]uint16) string {
	// The first longest run of two or more zero pieces is compressed.
	best, bestLen := -1, 1
	for i := 0; i < 8; {
		if a[i] != 0 {
			i++
			continue
		}
		j := i
		for j < 8 && a[j] == 0 {
			j++
		}
		if j-i > bestLen {
			best, bestLen = i, j-i
		}
		i = j
	}
	var b strings.Builder
	ignore0 := false
	for i := 0; i < 8; i++ {
		if ignore0 && a[i] == 0 {
			continue
		}
		ignore0 = false
		if i == best {
			if i == 0 {
				b.WriteString("::")
			} else {
				b.WriteString(":")
			}
			ignore0 = true
			continue
		}
		b.WriteString(strconv.FormatUint(uint64(a[i]), 16))
		if i != 7 {
			b.WriteString(":")
		}
	}
	return b.String()
}

// URL is what audit redaction reads of a parsed URL, as `new URL` gives it.
type URL struct {
	Protocol string // "https:"
	Host     string // the host, with the port when it is not the scheme's default
	Pathname string
	Search   string // "" or "?..."
	Hash     string // "" or "#..."
}

var defaultPorts = map[string]string{"http": "80", "https": "443", "ws": "80", "wss": "443", "ftp": "21"}

// ParseURL parses an absolute URL as `new URL(input)` does: the special
// schemes, file without its Windows drive letter rules, and non-special
// schemes. It reports false where `new URL` throws.
func ParseURL(input string) (URL, bool) {
	input = strings.TrimFunc(input, func(r rune) bool { return r <= 0x20 })
	input = removeTabNewline(input)
	colon := strings.IndexByte(input, ':')
	if colon <= 0 || !isAlpha(input[0]) {
		return URL{}, false
	}
	for i := 1; i < colon; i++ {
		c := input[i]
		if !isAlpha(c) && !(c >= '0' && c <= '9') && c != '+' && c != '-' && c != '.' {
			return URL{}, false
		}
	}
	scheme := strings.ToLower(input[:colon])
	rest := input[colon+1:]
	if scheme == "file" {
		return parseFile(rest)
	}
	def, special := defaultPorts[scheme]
	u := URL{Protocol: scheme + ":"}

	isSlash := func(c byte) bool { return c == '/' || (special && c == '\\') }
	hasAuthority := special || strings.HasPrefix(rest, "//")
	if hasAuthority {
		if special {
			rest = strings.TrimLeft(rest, `/\`)
		} else {
			rest = rest[2:]
		}
		end := len(rest)
		for i := 0; i < len(rest); i++ {
			if isSlash(rest[i]) || rest[i] == '?' || rest[i] == '#' {
				end = i
				break
			}
		}
		authority := rest[:end]
		rest = rest[end:]
		if at := strings.LastIndexByte(authority, '@'); at >= 0 {
			authority = authority[at+1:]
			if authority == "" {
				return URL{}, false
			}
		}
		hostPart, port := authority, ""
		inBrackets := false
		for i := 0; i < len(authority); i++ {
			switch authority[i] {
			case '[':
				inBrackets = true
			case ']':
				inBrackets = false
			case ':':
				if !inBrackets {
					hostPart, port = authority[:i], authority[i+1:]
					if hostPart == "" {
						return URL{}, false
					}
					i = len(authority)
				}
			}
		}
		if special && hostPart == "" {
			return URL{}, false
		}
		if port != "" {
			if strings.Trim(port, "0123456789") != "" {
				return URL{}, false
			}
			n, err := strconv.Atoi(port)
			if err != nil || n > 65535 {
				// Atoi fails only past int's range here: above 65535 as well.
				return URL{}, false
			}
			port = strconv.Itoa(n)
			if port == def {
				port = ""
			}
		}
		host := ""
		if hostPart != "" {
			h, ok := ParseHost(hostPart, special)
			if !ok {
				return URL{}, false
			}
			host = h
		}
		u.Host = host
		if port != "" {
			u.Host += ":" + port
		}
	}

	path := rest
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path, rest = path[:i], path[i:]
	} else {
		rest = ""
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		if rest[i+1:] != "" {
			u.Hash = rest[i:]
		}
		rest = rest[:i]
	}
	if len(rest) > 1 {
		u.Search = rest
	}
	switch {
	case special:
		u.Pathname = normalizePath(path, true)
	case hasAuthority && path == "":
		u.Pathname = ""
	case strings.HasPrefix(path, "/"):
		u.Pathname = normalizePath(path, false)
	default:
		u.Pathname = path // an opaque path: compared with "/" only
	}
	return u, true
}

// parseFile is the file scheme: a host only after two slashes, localhost
// as no host, no port.
func parseFile(rest string) (URL, bool) {
	u := URL{Protocol: "file:"}
	if len(rest) >= 2 && (rest[0] == '/' || rest[0] == '\\') && (rest[1] == '/' || rest[1] == '\\') {
		rest = rest[2:]
		end := strings.IndexAny(rest, "/\\?#")
		if end < 0 {
			end = len(rest)
		}
		if host := rest[:end]; host != "" {
			h, ok := ParseHost(host, true)
			if !ok {
				return URL{}, false
			}
			if h != "localhost" {
				u.Host = h
			}
		}
		rest = rest[end:]
	}
	path := rest
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path, rest = path[:i], path[i:]
	} else {
		rest = ""
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		if rest[i+1:] != "" {
			u.Hash = rest[i:]
		}
		rest = rest[:i]
	}
	if len(rest) > 1 {
		u.Search = rest
	}
	u.Pathname = normalizePath(path, true)
	return u, true
}

func isAlpha(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

// normalizePath resolves a hierarchical path's dot segments, as the path
// state does. Only whether the result is "/" matters to callers, so
// segments are not percent-encoded.
func normalizePath(path string, special bool) string {
	split := func(r rune) bool { return r == '/' || (special && r == '\\') }
	if path != "" && split(rune(path[0])) {
		path = path[1:]
	}
	var segs, parts []string
	start := 0
	for i := 0; i < len(path); i++ {
		if split(rune(path[i])) {
			parts = append(parts, path[start:i])
			start = i + 1
		}
	}
	parts = append(parts, path[start:])
	for i, p := range parts {
		last := i == len(parts)-1
		switch lp := strings.ToLower(p); lp {
		case "..", ".%2e", "%2e.", "%2e%2e":
			if len(segs) > 0 {
				segs = segs[:len(segs)-1]
			}
			if last {
				segs = append(segs, "")
			}
		case ".", "%2e":
			if last {
				segs = append(segs, "")
			}
		default:
			segs = append(segs, p)
		}
	}
	return "/" + strings.Join(segs, "/")
}

var ipv4Reg, ipv6Reg = func() (*regexp.Regexp, *regexp.Regexp) {
	// Node.js's own expressions (lib/internal/net.js).
	v4Seg := `(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])`
	v4Str := `(?:` + v4Seg + `\.){3}` + v4Seg
	v6Seg := `(?:[0-9a-fA-F]{1,4})`
	v6 := `^(?:` +
		`(?:` + v6Seg + `:){7}(?:` + v6Seg + `|:)|` +
		`(?:` + v6Seg + `:){6}(?:` + v4Str + `|:` + v6Seg + `|:)|` +
		`(?:` + v6Seg + `:){5}(?::` + v4Str + `|(?::` + v6Seg + `){1,2}|:)|` +
		`(?:` + v6Seg + `:){4}(?:(?::` + v6Seg + `){0,1}:` + v4Str + `|(?::` + v6Seg + `){1,3}|:)|` +
		`(?:` + v6Seg + `:){3}(?:(?::` + v6Seg + `){0,2}:` + v4Str + `|(?::` + v6Seg + `){1,4}|:)|` +
		`(?:` + v6Seg + `:){2}(?:(?::` + v6Seg + `){0,3}:` + v4Str + `|(?::` + v6Seg + `){1,5}|:)|` +
		`(?:` + v6Seg + `:){1}(?:(?::` + v6Seg + `){0,4}:` + v4Str + `|(?::` + v6Seg + `){1,6}|:)|` +
		`(?::(?:(?::` + v6Seg + `){0,5}:` + v4Str + `|(?::` + v6Seg + `){1,7}|:))` +
		`)(?:%[0-9a-zA-Z-.:]{1,})?$`
	return regexp.MustCompile(`^` + v4Str + `$`), regexp.MustCompile(v6)
}()

// IsIP is Node's net.isIP: 4, 6 or 0.
func IsIP(s string) int {
	switch {
	case ipv4Reg.MatchString(s):
		return 4
	case ipv6Reg.MatchString(s):
		return 6
	}
	return 0
}

// isJSSpace is ECMAScript's WhiteSpace and LineTerminator: what trim and
// \s remove and match.
func IsJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// Trim is String.prototype.trim.
func Trim(s string) string { return strings.TrimFunc(s, IsJSSpace) }

// ToLower is String.prototype.toLowerCase: Unicode's default lowercasing,
// with its one unconditional special mapping (U+0130) and Final_Sigma.
func ToLower(s string) string {
	rs := []rune(s)
	var b strings.Builder
	for i, r := range rs {
		switch {
		case r < utf8.RuneSelf:
			if 'A' <= r && r <= 'Z' {
				r += 'a' - 'A'
			}
			b.WriteRune(r)
		case r == 0x130:
			b.WriteString("i\u0307")
		case r == 0x3a3 && finalSigma(rs, i):
			b.WriteRune(0x3c2)
		default:
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

func cased(r rune) bool {
	return unicode.IsUpper(r) || unicode.IsLower(r) || unicode.IsTitle(r) || unicode.Is(unicode.Other_Lowercase, r) || unicode.Is(unicode.Other_Uppercase, r)
}

func caseIgnorable(r rune) bool {
	return unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf, unicode.Lm, unicode.Sk) ||
		r == '\'' || r == '.' || r == ':' || r == '^' || r == '`' || r == 0xad || r == 0xb7 || r == 0x2019
}

// finalSigma: preceded by a cased letter and not followed by one, ignoring
// case-ignorable characters in between.
func finalSigma(rs []rune, i int) bool {
	before := false
	for j := i - 1; j >= 0; j-- {
		if caseIgnorable(rs[j]) {
			continue
		}
		before = cased(rs[j])
		break
	}
	if !before {
		return false
	}
	for j := i + 1; j < len(rs); j++ {
		if caseIgnorable(rs[j]) {
			continue
		}
		return !cased(rs[j])
	}
	return true
}
