// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/server/whatwg"
)

// Destination Selectors (ADR-0022 §9), authz/destination.ts: canonical host
// and port. Selectors and exercised destinations pass through one
// canonicalization, so validation and matching cannot diverge. Wildcards
// match subdomains only, never the apex; IP literals match exactly; a
// selector without a port means 443.

// DestinationSelector is a parsed selector.
type DestinationSelector struct {
	// Host is the canonical lowercase ASCII host, without "*." for a
	// wildcard.
	Host     string
	Wildcard bool
	Port     int
}

// Destination is an exercised destination.
type Destination struct {
	Host string
	Port int
}

var hostRefused = regexp.MustCompile(`[/@\\?#[\]]`)

// CanonicalizeHost is canonicalizeHost: lowercase, one trailing dot
// stripped, punycode to ASCII; false for anything malformed or ambiguous
// (credentials, paths, schemes, ports, empty labels).
func CanonicalizeHost(raw string) (string, bool) {
	host := whatwg.ToLower(whatwg.Trim(raw))
	host = strings.TrimSuffix(host, ".")
	if host == "" || hostRefused.MatchString(host) || strings.IndexFunc(host, whatwg.IsJSSpace) >= 0 {
		return "", false
	}
	if whatwg.IsIP(host) != 0 {
		return host, true
	}
	ascii := whatwg.DomainToASCII(host)
	if ascii == "" || strings.Contains(ascii, "%") {
		return "", false
	}
	// Empty labels ("a..b") and lone dots, which domainToASCII tolerates.
	for _, label := range strings.Split(ascii, ".") {
		if label == "" {
			return "", false
		}
	}
	return ascii, true
}

func parsePort(raw string) (int, bool) {
	if len(raw) < 1 || len(raw) > 5 || strings.Trim(raw, "0123456789") != "" {
		return 0, false
	}
	n, _ := strconv.Atoi(raw)
	return n, n >= 1 && n <= 65535
}

// ParseDestinationSelector is parseDestinationSelector: host, host:port,
// *.suffix, *.suffix:port, an IPv4 literal, or [ipv6] and [ipv6]:port; no
// port is 443.
func ParseDestinationSelector(raw string) (DestinationSelector, bool) {
	input := whatwg.Trim(raw)
	if input == "" {
		return DestinationSelector{}, false
	}
	port := 443
	if strings.HasPrefix(input, "[") {
		end := strings.IndexByte(input, ']')
		if end < 0 {
			return DestinationSelector{}, false
		}
		ip, rest := input[1:end], input[end+1:]
		if whatwg.IsIP(ip) != 6 {
			return DestinationSelector{}, false
		}
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return DestinationSelector{}, false
			}
			p, ok := parsePort(rest[1:])
			if !ok {
				return DestinationSelector{}, false
			}
			port = p
		}
		return DestinationSelector{Host: whatwg.ToLower(ip), Port: port}, true
	}
	if colon := strings.LastIndexByte(input, ':'); colon >= 0 {
		// A bare IPv6 literal without brackets is ambiguous with host:port.
		if strings.IndexByte(input, ':') != colon {
			return DestinationSelector{}, false
		}
		p, ok := parsePort(input[colon+1:])
		if !ok {
			return DestinationSelector{}, false
		}
		port, input = p, input[:colon]
	}
	wildcard := false
	if strings.HasPrefix(input, "*.") {
		wildcard, input = true, input[2:]
		if whatwg.IsIP(input) != 0 {
			return DestinationSelector{}, false
		}
	} else if strings.Contains(input, "*") {
		return DestinationSelector{}, false
	}
	host, ok := CanonicalizeHost(input)
	if !ok || strings.Contains(host, "*") {
		return DestinationSelector{}, false
	}
	return DestinationSelector{Host: host, Wildcard: wildcard, Port: port}, true
}

// String is formatSelector.
func (s DestinationSelector) String() string {
	host := s.Host
	if whatwg.IsIP(host) == 6 {
		host = "[" + host + "]"
	}
	prefix := ""
	if s.Wildcard {
		prefix = "*."
	}
	return prefix + host + ":" + strconv.Itoa(s.Port)
}

// Matches is destinationMatches. Wildcards match subdomains at any depth,
// never the apex, never IP literals.
func (s DestinationSelector) Matches(d Destination) bool {
	if s.Port != d.Port {
		return false
	}
	host, ok := CanonicalizeHost(d.Host)
	if !ok {
		return false
	}
	if !s.Wildcard {
		return host == s.Host
	}
	if whatwg.IsIP(host) != 0 {
		return false
	}
	return strings.HasSuffix(host, "."+s.Host)
}
