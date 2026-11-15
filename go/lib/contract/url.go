// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// urlValid is whether `new URL(value)` succeeds: the failure conditions of
// the WHATWG URL Standard's basic URL parser (https://url.spec.whatwg.org/)
// run with no base URL, ported from packages/accessor-python's
// whatwg_url.py (the same project's port of the specification text). Paths,
// queries, fragments and opaque paths never fail, so only the scheme, the
// authority, the port and the host are examined. A special-scheme domain
// that is not plain ASCII (or has an "xn--" label) goes through UTS #46's
// ToASCII as the standard's "domain to ASCII" asks (CheckHyphens off,
// CheckBidi and CheckJoiners on, no STD3 rules, nontransitional, no DNS
// length check), with golang.org/x/net/idna.
func urlValid(value string) bool {
	text := []rune(strings.TrimFunc(value, func(r rune) bool { return r <= 0x20 }))
	text = removeRunes(text, '\t', '\n', '\r')
	colon := indexRune(text, ':')
	if colon < 1 || !isAlpha(text[0]) {
		return false
	}
	for _, r := range text[:colon] {
		if !isAlpha(r) && !isDigit(r) && r != '+' && r != '-' && r != '.' {
			return false
		}
	}
	scheme := strings.ToLower(string(text[:colon]))
	rest := text[colon+1:]
	slash := func(i int) bool { return i < len(rest) && (rest[i] == '/' || rest[i] == '\\') }
	switch {
	case scheme == "file":
		if !slash(0) || !slash(1) {
			return true
		}
		host := rest[2:]
		host = host[:firstOf(host, "/\\?#")]
		if len(host) == 0 || (len(host) == 2 && isAlpha(host[0]) && (host[1] == ':' || host[1] == '|')) {
			return true
		}
		return hostValid(host, true)
	case scheme == "ftp" || scheme == "http" || scheme == "https" || scheme == "ws" || scheme == "wss":
		i := 0
		for i < len(rest) && (rest[i] == '/' || rest[i] == '\\') {
			i++
		}
		return authorityValid(rest[i:], true)
	case len(rest) >= 2 && rest[0] == '/' && rest[1] == '/':
		return authorityValid(rest[2:], false)
	}
	return true // a path or an opaque path
}

func isAlpha(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }
func isDigit(r rune) bool { return r >= '0' && r <= '9' }
func isHex(r rune) bool   { return isDigit(r) || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' }

func removeRunes(s []rune, drop ...rune) []rune {
	out := s[:0:0]
	for _, r := range s {
		keep := true
		for _, d := range drop {
			if r == d {
				keep = false
			}
		}
		if keep {
			out = append(out, r)
		}
	}
	return out
}

func indexRune(s []rune, r rune) int {
	for i, c := range s {
		if c == r {
			return i
		}
	}
	return -1
}

// firstOf is the index of the first rune of s in stops, or len(s).
func firstOf(s []rune, stops string) int {
	for i, r := range s {
		if strings.ContainsRune(stops, r) {
			return i
		}
	}
	return len(s)
}

func authorityValid(rest []rune, special bool) bool {
	stops := "/?#"
	if special {
		stops = "/\\?#"
	}
	authority := rest[:firstOf(rest, stops)]
	for i := len(authority) - 1; i >= 0; i-- {
		if authority[i] == '@' {
			authority = authority[i+1:]
			if len(authority) == 0 {
				return false // host-missing after credentials
			}
			break
		}
	}
	colon := -1
	inside := false
	for i, r := range authority {
		if r == ':' && !inside {
			colon = i
			break
		}
		if r == '[' {
			inside = true
		} else if r == ']' {
			inside = false
		}
	}
	if colon < 0 {
		if special && len(authority) == 0 {
			return false // host-missing
		}
		return hostValid(authority, special)
	}
	if colon == 0 {
		return false // host-missing before the port
	}
	if !hostValid(authority[:colon], special) {
		return false
	}
	port := authority[colon+1:]
	for _, r := range port {
		if !isDigit(r) {
			return false
		}
	}
	digits := strings.TrimLeft(string(port), "0")
	if len(digits) > 5 {
		return false
	}
	if digits == "" {
		return true
	}
	n, _ := strconv.Atoi(digits)
	return n <= 65535
}

const forbiddenHost = "\x00\t\n\r #/:<>?@[\\]^|"

func forbiddenDomain(r rune) bool {
	return strings.ContainsRune(forbiddenHost, r) || r <= 0x1f || r == '%' || r == 0x7f
}

var domainToASCII = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.Transitional(false), idna.CheckHyphens(false),
	idna.CheckJoiners(true), idna.BidiRule(), idna.VerifyDNSLength(false))

func hostValid(host []rune, special bool) bool {
	if len(host) > 0 && host[0] == '[' {
		return host[len(host)-1] == ']' && len(host) >= 2 && ipv6Valid(host[1:len(host)-1])
	}
	if !special {
		// Opaque-host parser: only forbidden host code points fail.
		for _, r := range host {
			if strings.ContainsRune(forbiddenHost, r) {
				return false
			}
		}
		return true
	}
	// Percent-decode, then UTF-8 decode (an invalid sequence is U+FFFD).
	decoded := percentDecode(string(host))
	domain := strings.ToValidUTF8(decoded, "�")
	ascii := true
	for i := 0; i < len(domain); i++ {
		if domain[i] >= 0x80 {
			ascii = false
		}
	}
	lower := strings.ToLower(domain)
	idn := !ascii
	for _, label := range strings.Split(lower, ".") {
		if strings.HasPrefix(label, "xn--") {
			idn = true
		}
	}
	if idn {
		out, err := domainToASCII.ToASCII(domain)
		if err != nil || out == "" {
			return false
		}
		lower = out
	}
	if lower == "" {
		return false
	}
	for _, r := range lower {
		if forbiddenDomain(r) {
			return false
		}
	}
	if endsInANumber(lower) {
		return ipv4Valid(lower)
	}
	return true
}

func percentDecode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(rune(s[i+1])) && isHex(rune(s[i+2])) {
			n, _ := strconv.ParseUint(s[i+1:i+3], 16, 8)
			b.WriteByte(byte(n))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func endsInANumber(domain string) bool {
	parts := strings.Split(domain, ".")
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		return false
	}
	last := parts[len(parts)-1]
	if last != "" && strings.Trim(last, "0123456789") == "" {
		return true
	}
	_, ok := ipv4Number(last)
	return ok
}

// ipv4Number is the IPv4 number parser: the value, or false. Values above
// 2^32 all fail alike, so long inputs are capped.
func ipv4Number(part string) (uint64, bool) {
	if part == "" {
		return 0, false
	}
	radix := 10
	switch {
	case len(part) >= 2 && (part[:2] == "0x" || part[:2] == "0X"):
		part, radix = part[2:], 16
	case len(part) >= 2 && part[0] == '0':
		part, radix = part[1:], 8
	}
	if part == "" {
		return 0, true
	}
	for _, r := range part {
		ok := isDigit(r)
		switch radix {
		case 8:
			ok = r >= '0' && r <= '7'
		case 16:
			ok = isHex(r)
		}
		if !ok {
			return 0, false
		}
	}
	part = strings.TrimLeft(part, "0")
	if len(part) > 12 {
		return 1 << 48, true
	}
	if part == "" {
		return 0, true
	}
	n, err := strconv.ParseUint(part, radix, 64)
	return n, err == nil
}

func ipv4Valid(domain string) bool {
	parts := strings.Split(domain, ".")
	if parts[len(parts)-1] == "" && len(parts) > 1 {
		parts = parts[:len(parts)-1]
	}
	if len(parts) > 4 {
		return false
	}
	numbers := make([]uint64, 0, len(parts))
	for _, p := range parts {
		n, ok := ipv4Number(p)
		if !ok {
			return false
		}
		numbers = append(numbers, n)
	}
	for _, n := range numbers[:len(numbers)-1] {
		if n > 255 {
			return false
		}
	}
	limit := uint64(1)
	for range 5 - len(numbers) {
		limit *= 256
	}
	return numbers[len(numbers)-1] < limit
}

// ipv6Valid is the IPv6 parser's failure conditions (the piece values
// themselves never fail).
func ipv6Valid(text []rune) bool {
	size := len(text)
	pointer, piece := 0, 0
	compress := -1
	at := func(i int) rune {
		if i < size {
			return text[i]
		}
		return utf8.RuneError
	}
	if at(0) == ':' {
		if at(1) != ':' {
			return false
		}
		pointer, piece, compress = 2, 1, 1
	}
	for pointer < size {
		if piece == 8 {
			return false
		}
		if text[pointer] == ':' {
			if compress >= 0 {
				return false
			}
			pointer++
			piece++
			compress = piece
			continue
		}
		length := 0
		for length < 4 && pointer < size && isHex(text[pointer]) {
			pointer++
			length++
		}
		c := at(pointer)
		if pointer < size && c == '.' {
			if length == 0 || piece > 6 {
				return false
			}
			pointer -= length
			seen := 0
			for pointer < size {
				if seen > 0 {
					if text[pointer] == '.' && seen < 4 {
						pointer++
					} else {
						return false
					}
				}
				if pointer >= size || !isDigit(text[pointer]) {
					return false
				}
				piece4 := -1
				for pointer < size && isDigit(text[pointer]) {
					n := int(text[pointer] - '0')
					switch piece4 {
					case -1:
						piece4 = n
					case 0:
						return false
					default:
						piece4 = piece4*10 + n
					}
					if piece4 > 255 {
						return false
					}
					pointer++
				}
				seen++
				if seen == 2 || seen == 4 {
					piece++
				}
			}
			if seen != 4 {
				return false
			}
			break
		}
		if pointer < size && c == ':' {
			pointer++
			if pointer >= size {
				return false
			}
		} else if pointer < size {
			return false
		}
		piece++
	}
	return compress >= 0 || piece == 8
}
