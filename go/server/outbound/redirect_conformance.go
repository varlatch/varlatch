// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build conformance

package outbound

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// The conformance harness's host override (scripts/conformance, the sync
// suite): fake platform services stand in for api.github.com and the
// Coolify and Convex hosts. Built only with the conformance build tag, so a
// release has none of this (server/stages/check-release.sh checks the
// release binary for it); off unless VARLATCH_CONFORMANCE_OUTBOUND_HOSTS
// names the hosts, and loud when on (ConformanceRedirects, logged at
// startup).
//
// VARLATCH_CONFORMANCE_OUTBOUND_HOSTS is "name=address:port,...". A
// destination with that host name resolves to that address and port
// instead of through DNS, and is then decided as any other: the policy
// sees the original host name with the override's address and port, so
// only an allow list entry for that address and port lets it through.
// Both the configuration-time check and the connection's own dial use it.

type conformanceHost struct {
	address string
	port    int
}

var conformanceHosts = parseConformanceHosts(os.Getenv("VARLATCH_CONFORMANCE_OUTBOUND_HOSTS"))

func parseConformanceHosts(spec string) map[string]conformanceHost {
	out := map[string]conformanceHost{}
	for _, entry := range strings.Split(spec, ",") {
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		name, target, ok := strings.Cut(entry, "=")
		host, portText, err := net.SplitHostPort(target)
		port, perr := strconv.Atoi(portText)
		if !ok || err != nil || perr != nil || port < 1 || port > 65535 || whatwg.IsIP(host) == 0 || NormalizeHost(name) == "" {
			panic(fmt.Sprintf("VARLATCH_CONFORMANCE_OUTBOUND_HOSTS: %q is not name=address:port", entry))
		}
		out[NormalizeHost(name)] = conformanceHost{address: host, port: port}
	}
	return out
}

func (p *Policy) redirect(d Destination) (Destination, string, bool) {
	h, ok := conformanceHosts[d.Host]
	if !ok {
		return d, "", false
	}
	d.Port = h.port
	return d, h.address, true
}

// ConformanceRedirects describes the override when it is on ("" when it
// is off), for varlatchd's startup warning.
func ConformanceRedirects() string {
	if len(conformanceHosts) == 0 {
		return ""
	}
	var parts []string
	for name, h := range conformanceHosts {
		parts = append(parts, name+" -> "+net.JoinHostPort(h.address, strconv.Itoa(h.port)))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}
