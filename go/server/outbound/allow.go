// SPDX-License-Identifier: AGPL-3.0-or-later

package outbound

import (
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// Port is an entry's port: a number, Any ("*"), or None (the scheme's
// default only).
type Port struct {
	N   int
	Any bool
}

// None is an entry without a port.
var None = Port{}

// fits is portFits.
func (p Port) fits(d Destination) bool {
	return p.Any || p.N == d.Port || p == None && d.Port == DefaultPort(d.Scheme)
}

// Entry is one allow list entry (AllowEntry): a host name (or *.suffix),
// or a CIDR range (an address is its own /32 or /128).
type Entry struct {
	Kind string // "name" or "cidr"
	// Text is the entry as the operator wrote it, whitespace removed.
	Text string
	// Name and Wildcard, for a name entry.
	Name     string
	Wildcard bool
	// Range and HostOnly (the range lies inside a host-only range), for a
	// CIDR entry.
	rng      prefixRange
	HostOnly bool
	Port     Port
}

// RangeBase is a CIDR entry's base address as a hexadecimal number, its
// family and its prefix (the vectors' form).
func (e Entry) RangeBase() (string, int, int) {
	return e.rng.base.Text(16), e.rng.family, e.rng.prefix
}

// AllowError is OutboundAllowError: an allow list entry that is not one.
type AllowError struct{ msg string }

func (e *AllowError) Error() string { return e.msg }

func allowError(format string, args ...any) error {
	return &AllowError{fmt.Sprintf(format, args...)}
}

var (
	label      = `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`
	hostName   = regexp.MustCompile(`^` + label + `(?:\.` + label + `)*$`)
	digitsDots = regexp.MustCompile(`^[\d.]+$`)
	portDigits = regexp.MustCompile(`^\d{1,5}$`)
	prefixRe   = regexp.MustCompile(`^\d{1,3}$`)
	bracketed  = regexp.MustCompile(`^\[([^\]]+)\](?::([^:]+))?$`)
	cidrText   = regexp.MustCompile(`^([^/]+)/(\d+)(?::([^:/]+))?$`)
	withPort   = regexp.MustCompile(`^(.+?)(?::([^:]+))?$`)
	// normalizeAddress's (http/client-address.ts) patterns.
	addrBracketed = regexp.MustCompile(`^\[([^\]]+)\](?::\d+)?$`)
	addrV4Port    = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}:\d+$`)
	addrMapped    = regexp.MustCompile(`^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$`)
)

// normalizeAddress is http/client-address.ts's normalizeAddress, as the
// allow list parser uses it: the text as written, lowercased, without
// brackets, a port or a zone, an IPv4-mapped address in dotted form as
// its IPv4 address; "" when it is not an IP address. (go/server/clientaddr
// canonicalizes IPv6 text, which this parser must not.)
func normalizeAddress(raw string) string {
	v := whatwg.Trim(raw)
	if m := addrBracketed.FindStringSubmatch(v); m != nil {
		v = m[1]
	} else if addrV4Port.MatchString(v) {
		v = v[:strings.LastIndexByte(v, ':')]
	}
	if i := strings.IndexByte(v, '%'); i >= 0 {
		v = v[:i]
	}
	v = whatwg.ToLower(v)
	if m := addrMapped.FindStringSubmatch(v); m != nil {
		v = m[1]
	}
	if whatwg.IsIP(v) == 0 {
		return ""
	}
	return v
}

func parsePort(raw string, present bool, entry string) (Port, error) {
	if !present {
		return None, nil
	}
	if raw == "*" {
		return Port{Any: true}, nil
	}
	n, err := strconv.Atoi(raw)
	if !portDigits.MatchString(raw) || err != nil || n < 1 || n > 65535 {
		return Port{}, allowError("VARLATCH_OUTBOUND_ALLOW: %s has an invalid port", entry)
	}
	return Port{N: n}, nil
}

func cidrEntry(text, address, prefixText string, hasPrefix bool, portText string, hasPort bool) (Entry, error) {
	normalized := normalizeAddress(address)
	var a ip
	ok := normalized != "" && !strings.ContainsAny(address, "[]")
	if ok {
		a, ok = parseIP(normalized)
	}
	if !ok {
		return Entry{}, allowError("VARLATCH_OUTBOUND_ALLOW: %s is not a valid address or CIDR range", text)
	}
	// normalizeAddress turns ::ffff:a.b.c.d into a.b.c.d: an entry for a
	// mapped address is an entry for the IPv4 address it carries.
	prefix := bits(a.family)
	check := "0"
	if hasPrefix {
		prefix, _ = strconv.Atoi(prefixText)
		check = prefixText
	}
	if !prefixRe.MatchString(check) || prefix > bits(a.family) {
		return Entry{}, allowError("VARLATCH_OUTBOUND_ALLOW: %s is not a valid CIDR range", text)
	}
	shift := uint(bits(a.family) - prefix)
	base := new(big.Int).Lsh(new(big.Int).Rsh(a.value, shift), shift)
	r := prefixRange{a.family, base, prefix}
	port, err := parsePort(portText, hasPort, text)
	if err != nil {
		return Entry{}, err
	}
	hostOnly := false
	for _, outer := range hostOnlyRanges {
		if r.within(outer) {
			hostOnly = true
		}
	}
	return Entry{Kind: "cidr", Text: text, rng: r, Port: port, HostOnly: hostOnly}, nil
}

// group is a regexp submatch: its text, and whether it took part.
func group(m []string, idx []int, i int) (string, bool) {
	return m[i], idx[2*i] >= 0
}

func parseEntry(text string) (Entry, error) {
	// [v6], [v6/prefix], with an optional :port after the bracket.
	if idx := bracketed.FindStringSubmatchIndex(text); idx != nil {
		m := bracketed.FindStringSubmatch(text)
		address, prefix, hasPrefix := strings.Cut(m[1], "/")
		if hasPrefix {
			// TypeScript splits on every "/" and takes the first two parts.
			prefix, _, _ = strings.Cut(prefix, "/")
		}
		port, hasPort := group(m, idx, 2)
		return cidrEntry(text, address, prefix, hasPrefix, port, hasPort)
	}
	// address/prefix with an optional :port after the prefix (::1/128:*).
	if idx := cidrText.FindStringSubmatchIndex(text); idx != nil {
		m := cidrText.FindStringSubmatch(text)
		port, hasPort := group(m, idx, 3)
		return cidrEntry(text, m[1], m[2], true, port, hasPort)
	}
	// A bare IPv6 address takes no port without brackets.
	if whatwg.IsIP(text) == 6 {
		return cidrEntry(text, text, "", false, "", false)
	}
	idx := withPort.FindStringSubmatchIndex(text)
	m := withPort.FindStringSubmatch(text)
	host := m[1]
	portText, hasPort := group(m, idx, 2)
	if whatwg.IsIP(host) == 4 {
		return cidrEntry(text, host, "", false, portText, hasPort)
	}
	lower := strings.TrimSuffix(whatwg.ToLower(host), ".")
	wildcard := strings.HasPrefix(lower, "*.")
	name := lower
	if wildcard {
		name = lower[2:]
	}
	if n := len([]rune(name)); n < 1 || n > 253 || !hostName.MatchString(name) || digitsDots.MatchString(name) {
		return Entry{}, allowError("VARLATCH_OUTBOUND_ALLOW: %s is not a host name, a *.suffix, an address or a CIDR range", text)
	}
	port, err := parsePort(portText, hasPort, text)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Kind: "name", Text: text, Name: name, Wildcard: wildcard, Port: port}, nil
}

// ParseAllow is parseOutboundAllow: the allow list, or an *AllowError
// naming the first invalid entry.
func ParseAllow(spec string) ([]Entry, error) {
	var out []Entry
	for _, raw := range strings.Split(spec, ",") {
		text := strings.Map(func(r rune) rune {
			if whatwg.IsJSWhitespace(r) {
				return -1
			}
			return r
		}, raw)
		if text == "" {
			continue
		}
		e, err := parseEntry(text)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// Warnings is allowListWarnings (ADR-0057 Decision 8): entries that add
// nothing a narrower one would not, and entries that open host-only
// ranges.
func Warnings(entries []Entry) []string {
	out := []string{}
	for _, e := range entries {
		switch {
		case e.Kind == "cidr" && e.HostOnly:
			out = append(out, e.Text+" opens a host-only range (loopback, link-local or metadata) to every Organization")
		case e.Kind == "cidr" && e.rng.prefix == 0:
			out = append(out, e.Text+" adds only the private ranges, and opens all of them to every Organization: list the destinations instead")
		case e.Kind == "cidr" && withinNever(e.rng):
			out = append(out, e.Text+" adds nothing: unspecified, multicast and reserved addresses are never allowed")
		case e.Kind == "name" && e.Name == "localhost":
			out = append(out, e.Text+" adds nothing: a hostname entry never opens loopback; use 127.0.0.1/32 instead")
		}
	}
	return out
}

func withinNever(r prefixRange) bool {
	for _, row := range table {
		if row.Class == Never && r.within(row.r) {
			return true
		}
	}
	return false
}
