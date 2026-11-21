// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// The tailnet handoff on a self-hosted control server (Headscale; slice
// 7.5c c2, ADR-0059 Decision 5 as amended): the same handoff, its
// authority Headscale's (lib/tailcontrol's HeadscaleAPI, with a key that
// expires within the hour and is expired when the run ends, or
// HeadscaleCLI on the control server itself), and no certificates:
// Headscale issues none, so the HTTPS overlay is refused, and with it the
// certificate steps and the issuance count.
//
// Both nodes must be on the same control server: the source's sidecar
// logs in to it (--login-server in its TS_EXTRA_ARGS, an operator's
// Compose override), the target's varlatchd.conf names it
// (tailnet_control_url), given the same way.

// tailscaleControlURLs are Tailscale's own control server, as a sidecar's
// --login-server may name it: the same as none.
var tailscaleControlURLs = []string{"https://controlplane.tailscale.com", "https://login.tailscale.com"}

// canonicalControlURL is a control server's URL in the form compared: the
// scheme and host lower-cased, the default port and a lone "/" path
// dropped; "" for Tailscale's own.
func canonicalControlURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("%q is not a control server's URL", raw)
	}
	scheme, host := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname())
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("%q is not a control server's URL", raw)
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" && !(scheme == "https" && p == "443") && !(scheme == "http" && p == "80") {
		host += ":" + p
	}
	c := scheme + "://" + host
	for _, ts := range tailscaleControlURLs {
		if c == ts {
			return "", nil
		}
	}
	return c, nil
}

// loginServer is the control server a sidecar's TS_EXTRA_ARGS names
// (--login-server <url> or --login-server=<url>), canonical; "" when it
// names none (Tailscale's).
func loginServer(extraArgs string) (string, error) {
	f := strings.Fields(extraArgs)
	for i := 0; i < len(f); i++ {
		a := f[i]
		if v, ok := strings.CutPrefix(a, "--login-server="); ok {
			return canonicalControlURL(v)
		}
		if a == "--login-server" {
			if i+1 >= len(f) {
				return "", errors.New("the sidecar's TS_EXTRA_ARGS ends with --login-server and no URL")
			}
			return canonicalControlURL(f[i+1])
		}
	}
	return "", nil
}

// controlShown names a control server in a message.
func controlShown(u string) string {
	if u == "" {
		return "Tailscale's"
	}
	return u
}

// checkControlPlane is the handoff's control-plane preflight: both nodes
// on one control server, the authority given for it, and no HTTPS on a
// self-hosted one.
func checkControlPlane(kind string, info TailnetInfo, tn *TargetTailnet) error {
	switch {
	case info.ControlURL != tn.ControlURL:
		return fmt.Errorf("preflight: the source's sidecar logs in to %s control server (its --login-server), the target's tailnet_control_url names %s: the name moves within one tailnet, so both name the same server, given the same way (https://<its IP address>[:port] for a self-hosted one); nothing was done",
			controlShown(info.ControlURL), controlShown(tn.ControlURL))
	case kind == "headscale" && tn.ControlURL == "":
		return errors.New("preflight: the tailnet's authority given is Headscale's (--headscale-url or --headscale-cli), and both nodes are on Tailscale's control server: give --tailscale-oauth-client-file instead; nothing was done")
	case kind != "headscale" && tn.ControlURL != "":
		return fmt.Errorf("preflight: both nodes are on the self-hosted control server %s, and the tailnet's authority given is Tailscale's: give Headscale's (--headscale-url with --headscale-api-key-file, or --headscale-cli on the control server); nothing was done", tn.ControlURL)
	case kind == "headscale" && info.HTTPS:
		return errors.New("preflight: the source serves the tailnet browser endpoint over HTTPS (its sidecar's TS_SERVE_CONFIG), and a self-hosted control server issues no certificates, so the target cannot serve it: remove the HTTPS overlay from the source first; nothing was done")
	case kind == "headscale" && tn.HTTPSPort != 0:
		return errors.New("preflight: the target's configuration sets tailnet_https_port, and a self-hosted control server issues no certificates: leave it unset; nothing was done")
	}
	return nil
}
