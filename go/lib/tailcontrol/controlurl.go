// SPDX-License-Identifier: Apache-2.0

package tailcontrol

import (
	"net/netip"
	"net/url"
	"strconv"
)

// CanonicalControlURL is a self-hosted control server's URL (Headscale),
// as the node is given it and the pin records it: https, and an IP
// address for its host (ADR-0059 Decision 5, as amended for step 7.5c).
// tsnet resolves a control server's host name through Tailscale's DERP
// servers whenever the ordinary lookup fails (its bootstrap DNS fallback,
// which no tailscale.com release can turn off), so a self-hosted server's
// name would go to Tailscale while that server or its DNS is down; an IP
// address is never looked up. msg says why v is refused, "" when it is
// not. varlatchd's configuration (tailnet_control_url) and varlatch
// migrate (the sidecar's --login-server, --headscale-url) both judge a URL
// by it, so one server has one spelling.
func CanonicalControlURL(v string) (string, string) {
	const why = "a self-hosted control server (Headscale) is given as https://<its IP address>[:port], such as https://192.0.2.10 or https://[2001:db8::10]:8443: " +
		"tsnet looks a control server's host name up through Tailscale's DERP servers when the ordinary lookup fails, so a name would go to Tailscale; " +
		"an IP address is never looked up. Leave tailnet_control_url unset for Tailscale's"
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", why
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		return "", why
	}
	// Judged as it is written back: an IPv4-mapped address is its IPv4
	// one, so ::ffff:0.0.0.0 is the unspecified address it unmaps to.
	if addr.Zone() != "" {
		return "", "a zoned address is not a control server's; " + why
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return "", "not an address a control server listens on (an unspecified, multicast, link-local or broadcast address); " + why
	}
	host := addr.String()
	if addr.Is6() {
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", "its port is not 1 to 65535; " + why
		}
		if n != 443 {
			host += ":" + strconv.Itoa(n)
		}
	}
	return "https://" + host, ""
}
