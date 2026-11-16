// SPDX-License-Identifier: AGPL-3.0-or-later

// Package outbound is the outbound policy (ADR-0057; net/outbound.ts,
// ADR-0059 step 4.7, feature-parity decision 6). Every request whose
// destination an Organization can choose or influence (webhooks, the sync
// adapters, GitHub, OIDC discovery and JWKS, audit export) goes through
// this package, and only this package: the structural test
// (structure_test.go) fails the build on a request made anywhere else in
// go/server, apart from a reviewed list of destinations the host chose.
//
// What an Organization reaches is what the internet reaches, plus what the
// host operator allowed in outbound_allow (VARLATCH_OUTBOUND_ALLOW today):
//
//   - every address is in one class (the class table): never, host-only,
//     private or public. Public is always allowed over https. Private needs
//     an allow list entry, host-only a CIDR entry inside its own range, and
//     nothing opens never;
//   - plain http needs an entry, whatever the address;
//   - every DNS answer must be allowed: one refused answer refuses the name;
//   - redirects are never followed, and no environment proxy applies.
//
// The deciding check runs inside the connection: the dialer resolves the
// name once, classifies every answer, and connects only to the addresses
// it checked, so DNS rebinding cannot move a connection to an unchecked
// address. TLS and the Host header still use the URL's name. The
// configuration-time check (Policy.Check) gives friendly errors only.
package outbound

import (
	"math/big"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// Class is an address's class (ADR-0057 Decision 2).
type Class string

// The classes.
const (
	Never    Class = "never"
	HostOnly Class = "host-only"
	Private  Class = "private"
	Public   Class = "public"
)

// ip is an address as net/outbound.ts holds it: its family and its value.
type ip struct {
	family int // 4 or 6
	value  *big.Int
}

// prefixRange is a CIDR range: a family, a base and a prefix length.
type prefixRange struct {
	family int
	base   *big.Int
	prefix int
}

func bits(family int) int {
	if family == 4 {
		return 32
	}
	return 128
}

func v4Value(address string) *big.Int {
	v := new(big.Int)
	for _, octet := range strings.Split(address, ".") {
		n, _ := strconv.Atoi(octet)
		v.Lsh(v, 8)
		v.Or(v, big.NewInt(int64(n)))
	}
	return v
}

// v6Value is v6Value: groups, a trailing dotted quad as two groups, "::"
// expanded.
func v6Value(address string) *big.Int {
	text := whatwg.ToLower(address)
	if i := strings.IndexByte(text, '%'); i >= 0 {
		text = text[:i]
	}
	if dot := strings.LastIndexByte(text, '.'); dot >= 0 {
		colon := strings.LastIndexByte(text, ':')
		v4 := v4Value(text[colon+1:]).Uint64()
		text = text[:colon+1] + strconv.FormatUint(v4>>16&0xffff, 16) + ":" + strconv.FormatUint(v4&0xffff, 16)
	}
	var head, tail []string
	nonEmpty := func(s string) []string {
		var out []string
		for _, g := range strings.Split(s, ":") {
			if g != "" {
				out = append(out, g)
			}
		}
		return out
	}
	groups := nonEmpty(text)
	if double := strings.Index(text, "::"); double >= 0 {
		head, tail = nonEmpty(text[:double]), nonEmpty(text[double+2:])
		groups = append(append(append([]string{}, head...), make([]string, 8-len(head)-len(tail))...), tail...)
	}
	v := new(big.Int)
	for _, g := range groups {
		n, _ := strconv.ParseUint(g, 16, 16)
		v.Lsh(v, 16)
		v.Or(v, new(big.Int).SetUint64(n))
	}
	return v
}

// parseIP is parseIp: an IP address, or false when raw is not one.
// Brackets and a zone are dropped; what an address is, is Node's isIP.
func parseIP(raw string) (ip, bool) {
	text := raw
	if len(text) >= 2 && text[0] == '[' && text[len(text)-1] == ']' {
		text = text[1 : len(text)-1]
	}
	if i := strings.IndexByte(text, '%'); i >= 0 {
		text = text[:i]
	}
	switch whatwg.IsIP(text) {
	case 4:
		return ip{4, v4Value(text)}, true
	case 6:
		return ip{6, v6Value(text)}, true
	}
	return ip{}, false
}

func mustRange(cidr string) prefixRange {
	address, prefix, _ := strings.Cut(cidr, "/")
	a, ok := parseIP(address)
	if !ok {
		panic("outbound: " + cidr)
	}
	n, _ := strconv.Atoi(prefix)
	return prefixRange{a.family, a.value, n}
}

func (r prefixRange) contains(a ip) bool {
	if r.family != a.family {
		return false
	}
	shift := uint(bits(a.family) - r.prefix)
	return new(big.Int).Rsh(r.base, shift).Cmp(new(big.Int).Rsh(a.value, shift)) == 0
}

// within is whether inner lies entirely inside outer.
func (inner prefixRange) within(outer prefixRange) bool {
	return inner.family == outer.family && inner.prefix >= outer.prefix && outer.contains(ip{inner.family, inner.base})
}

// ClassRow is one row of the class table.
type ClassRow struct {
	CIDR  string
	Class Class
	Label string
}

// ClassTable is CLASS_TABLE (ADR-0057 Decision 2), from the IANA
// special-purpose address registries. The most specific matching range
// decides; an address no range matches is public.
var ClassTable = []ClassRow{
	// Never: no allow list entry opens these.
	{"0.0.0.0/8", Never, "unspecified"},
	{"::/128", Never, "unspecified"},
	{"224.0.0.0/4", Never, "multicast"},
	{"ff00::/8", Never, "multicast"},
	{"240.0.0.0/4", Never, "reserved and broadcast"},
	{"100::/64", Never, "discard"},
	// Host-only: opened only by a CIDR entry inside the range.
	{"127.0.0.0/8", HostOnly, "loopback"},
	{"::1/128", HostOnly, "loopback"},
	{"169.254.0.0/16", HostOnly, "link-local (cloud metadata)"},
	{"fe80::/10", HostOnly, "link-local"},
	{"100.100.100.200/32", HostOnly, "metadata service"},
	{"fd00:ec2::254/128", HostOnly, "metadata service"},
	{"168.63.129.16/32", HostOnly, "platform services"},
	{"fec0::/10", HostOnly, "deprecated site-local"},
	{"192.0.0.0/24", HostOnly, "protocol assignments"},
	{"2001::/23", HostOnly, "protocol assignments"},
	{"2002::/16", HostOnly, "6to4"},
	{"192.88.99.0/24", HostOnly, "6to4 relay"},
	{"64:ff9b:1::/48", HostOnly, "NAT64 local-use"},
	{"192.0.2.0/24", HostOnly, "documentation"},
	{"198.51.100.0/24", HostOnly, "documentation"},
	{"203.0.113.0/24", HostOnly, "documentation"},
	{"2001:db8::/32", HostOnly, "documentation"},
	{"3fff::/20", HostOnly, "documentation"},
	{"198.18.0.0/15", HostOnly, "benchmarking"},
	{"5f00::/16", HostOnly, "SRv6 segment identifiers"},
	// Private: opened by a matching hostname or CIDR entry.
	{"10.0.0.0/8", Private, "private network"},
	{"172.16.0.0/12", Private, "private network"},
	{"192.168.0.0/16", Private, "private network"},
	{"100.64.0.0/10", Private, "carrier-grade NAT (Tailscale)"},
	{"fc00::/7", Private, "unique-local (Tailscale)"},
}

type tableRow struct {
	ClassRow
	r prefixRange
}

var (
	table          []tableRow
	hostOnlyRanges []prefixRange
	mapped         = mustRange("::ffff:0:0/96")
	compatible     = mustRange("::/96")
	nat64          = mustRange("64:ff9b::/96")
	unspecifiedV6  = mustRange("::/128")
	loopbackV6     = mustRange("::1/128")
)

func init() {
	for _, row := range ClassTable {
		t := tableRow{row, mustRange(row.CIDR)}
		table = append(table, t)
		if row.Class == HostOnly {
			hostOnlyRanges = append(hostOnlyRanges, t.r)
		}
	}
}

// effective is the address a connection to a really reaches, as far as
// classes go: IPv4-mapped, IPv4-compatible and NAT64 well-known addresses
// carry an IPv4 address and are classified by it.
func effective(a ip) ip {
	if a.family != 6 {
		return a
	}
	if mapped.contains(a) || nat64.contains(a) || compatible.contains(a) && !unspecifiedV6.contains(a) && !loopbackV6.contains(a) {
		return ip{4, new(big.Int).And(a.value, big.NewInt(0xffffffff))}
	}
	return a
}

func classifyIP(a ip) (Class, string) {
	target := effective(a)
	var best *tableRow
	for i := range table {
		row := &table[i]
		if row.r.contains(target) && (best == nil || row.r.prefix > best.r.prefix) {
			best = row
		}
	}
	if best == nil {
		return Public, "public"
	}
	return best.Class, best.Label
}

// ClassOf is classifyAddress: the class of an IP address, false for a
// string that is not one.
func ClassOf(address string) (Class, bool) {
	a, ok := parseIP(address)
	if !ok {
		return "", false
	}
	c, _ := classifyIP(a)
	return c, true
}
