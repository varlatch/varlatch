// SPDX-License-Identifier: AGPL-3.0-or-later

package outbound

import (
	"slices"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// Reason is a refusal's reason (OutboundRefusalReason).
type Reason string

// The reasons, in the API's order (OUTBOUND_REFUSAL_REASONS).
const (
	PrivateAddress  Reason = "private_address"
	HostOnlyAddress Reason = "host_only_address"
	NeverAddress    Reason = "never_address"
	MixedAnswers    Reason = "mixed_answers"
	Scheme          Reason = "scheme"
	PortReason      Reason = "port"
)

// Reasons are the reasons in the API's order.
var Reasons = []Reason{PrivateAddress, HostOnlyAddress, NeverAddress, MixedAnswers, Scheme, PortReason}

// severity is SEVERITY: with no answer allowed, the most severe reason
// among the answers' is the name's.
var severity = []Reason{NeverAddress, HostOnlyAddress, MixedAnswers, PrivateAddress, PortReason, Scheme}

// Destination is a request's destination: its scheme ("https:" or
// "http:"), its host (lowercase, without brackets or a trailing dot) and
// its port.
type Destination struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
}

// DefaultPort is the scheme's port.
func DefaultPort(scheme string) int {
	if scheme == "http:" {
		return 80
	}
	return 443
}

// NormalizeHost is normalizeHost: lowercase, no brackets, one trailing dot
// removed.
func NormalizeHost(hostname string) string {
	h := hostname
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	return strings.TrimSuffix(whatwg.ToLower(h), ".")
}

// DestinationOf is destinationOf for a URL as `new URL` parses it (lib/whatwg
// ParseURL): false when it is neither https nor http.
func DestinationOf(u whatwg.URL) (Destination, bool) {
	if u.Protocol != "https:" && u.Protocol != "http:" {
		return Destination{}, false
	}
	host, port := u.Host, ""
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.HasSuffix(host, "]") {
		host, port = host[:i], host[i+1:]
	}
	d := Destination{Scheme: u.Protocol, Host: NormalizeHost(host), Port: DefaultPort(u.Protocol)}
	if port != "" {
		d.Port, _ = strconv.Atoi(port)
	}
	return d, true
}

// Verdict is a decision: allowed (by the address being public, or by
// allow list entries), or refused with a reason.
type Verdict struct {
	Allowed bool
	// Via is "public" or "entry" for an allowed destination; Entries are
	// the entries that opened it.
	Via     string
	Entries []string
	Reason  Reason
}

func (e Entry) nameMatches(host string) bool {
	if e.Wildcard {
		return strings.HasSuffix(host, "."+e.Name)
	}
	return host == e.Name
}

// Decide is decide: a destination whose name resolved to addresses (a
// literal address resolves to itself), against the allow list and the
// class table. Pure.
func Decide(entries []Entry, d Destination, addresses []string) Verdict {
	literal := whatwg.IsIP(d.Host) != 0
	var names, cidrs []Entry
	for _, e := range entries {
		switch {
		case e.Kind == "name" && !literal && e.nameMatches(d.Host):
			names = append(names, e)
		case e.Kind == "cidr":
			cidrs = append(cidrs, e)
		}
	}
	var nameEntry *Entry
	for i := range names {
		if names[i].Port.fits(d) {
			nameEntry = &names[i]
			break
		}
	}
	if len(addresses) == 0 {
		return Verdict{Reason: NeverAddress}
	}
	var used []string
	var refusals []Reason
	allowed := 0
	for _, address := range addresses {
		a, ok := parseIP(address)
		if !ok {
			refusals = append(refusals, NeverAddress)
			continue
		}
		target := effective(a)
		cls, _ := classifyIP(a)
		var inRange []Entry
		for _, e := range cidrs {
			if e.rng.contains(target) || e.rng.contains(a) {
				inRange = append(inRange, e)
			}
		}
		var cidrEntry *Entry
		for i := range inRange {
			if inRange[i].Port.fits(d) && (cls != HostOnly || inRange[i].HostOnly) {
				cidrEntry = &inRange[i]
				break
			}
		}
		portOnly := len(inRange) > 0 || len(names) > 0
		if cls == HostOnly {
			portOnly = slices.ContainsFunc(inRange, func(e Entry) bool { return e.HostOnly })
		}
		var reason Reason
		switch {
		case cls == Never:
			reason = NeverAddress
		case cls == HostOnly && cidrEntry == nil:
			reason = pick(portOnly, PortReason, HostOnlyAddress)
		case cls == Private && cidrEntry == nil && nameEntry == nil:
			reason = pick(portOnly, PortReason, PrivateAddress)
		case cls == Public && d.Scheme == "http:" && cidrEntry == nil && nameEntry == nil:
			reason = pick(portOnly, PortReason, Scheme)
		}
		if reason != "" {
			refusals = append(refusals, reason)
			continue
		}
		allowed++
		if cls != Public || d.Scheme == "http:" {
			text := ""
			if cidrEntry != nil {
				text = cidrEntry.Text
			} else if nameEntry != nil {
				text = nameEntry.Text
			}
			if text != "" && !slices.Contains(used, text) {
				used = append(used, text)
			}
		}
	}
	if len(refusals) == 0 {
		if len(used) > 0 {
			return Verdict{Allowed: true, Via: "entry", Entries: used}
		}
		return Verdict{Allowed: true, Via: "public", Entries: []string{}}
	}
	if allowed > 0 {
		return Verdict{Reason: MixedAnswers}
	}
	for _, r := range severity {
		if slices.Contains(refusals, r) {
			return Verdict{Reason: r}
		}
	}
	return Verdict{Reason: refusals[0]}
}

func pick(cond bool, a, b Reason) Reason {
	if cond {
		return a
	}
	return b
}
