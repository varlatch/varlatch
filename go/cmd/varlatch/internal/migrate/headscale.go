// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/lib/tailcontrol"
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

// tailscaleControlHosts are Tailscale's own control server, as a
// sidecar's --login-server may name it: the same as none.
var tailscaleControlHosts = []string{"controlplane.tailscale.com", "login.tailscale.com"}

// canonicalControlURL is a control server's URL as compared: ""
// for Tailscale's own; a self-hosted one by lib/tailcontrol's rule, the
// one varlatchd's tailnet_control_url is judged by (https on an IP
// address, one spelling per server), refused with its reason otherwise.
func canonicalControlURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if u, err := url.Parse(raw); err == nil && strings.EqualFold(u.Scheme, "https") && slices.Contains(tailscaleControlHosts, strings.ToLower(u.Hostname())) &&
		(u.Port() == "" || u.Port() == "443") && (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.User == nil {
		return "", nil
	}
	c, why := tailcontrol.CanonicalControlURL(raw)
	if why != "" {
		return "", fmt.Errorf("%q: %s", raw, why)
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

// sameAuthority refuses a run whose authority names another server, or
// takes another form, than the one the handoff was planned with: the
// journal's node ids are that server's, and only its authority may rename
// them. A Tailscale authority has no server of its own ("").
func sameAuthority(rec *TailnetRecord, o *TailnetOptions) error {
	if rec == nil || rec.Operation == "" || o == nil || o.Control == nil {
		return nil
	}
	if k := o.Control.Kind(); rec.Control != "" && k != rec.Control {
		return fmt.Errorf("the tailnet handoff was planned on %s's control plane, and the authority given is %s's: give %s's; nothing was done", rec.Control, k, rec.Control)
	}
	if rec.Control == "headscale" && rec.ControlServer != o.Server {
		return fmt.Errorf("the tailnet handoff was planned with the authority of %s, and this run's is %s: its node ids are that server's, so give the same authority (%s); nothing was done",
			authorityShown(rec.ControlServer), authorityShown(o.Server), authorityHint(rec.ControlServer))
	}
	return nil
}

// CLIAuthority is how the journal records a --headscale-cli authority: the
// CLI reports no server URL, so the command itself stands for it.
func CLIAuthority(path string) string { return "cli@" + path }

func authorityShown(s string) string {
	if p, ok := strings.CutPrefix(s, "cli@"); ok {
		return "the headscale command " + p
	}
	if s == "" {
		return "no server named"
	}
	return "the Headscale API at " + s
}

func authorityHint(s string) string {
	if p, ok := strings.CutPrefix(s, "cli@"); ok {
		return "--headscale-cli " + p
	}
	return "--headscale-url " + s + " with a new --headscale-api-key-file"
}

// controlShown names a control server in a message.
func controlShown(u string) string {
	if u == "" {
		return "Tailscale's"
	}
	return u
}

// checkControlPlane is the handoff's control-plane preflight: both nodes
// on one control server, the authority given for it (Headscale's API at
// that very server: server is the authority's, TailnetOptions.Server),
// and no HTTPS on a self-hosted one.
func checkControlPlane(kind, server string, info TailnetInfo, tn *TargetTailnet) error {
	switch {
	case info.ControlURL != tn.ControlURL:
		return fmt.Errorf("preflight: the source's sidecar logs in to %s control server (its --login-server), the target's tailnet_control_url names %s: the name moves within one tailnet, so both name the same server, given the same way (https://<its IP address>[:port] for a self-hosted one); nothing was done",
			controlShown(info.ControlURL), controlShown(tn.ControlURL))
	case kind == "headscale" && tn.ControlURL == "":
		return errors.New("preflight: the tailnet's authority given is Headscale's (--headscale-url or --headscale-cli), and both nodes are on Tailscale's control server: give --tailscale-oauth-client-file instead; nothing was done")
	case kind != "headscale" && tn.ControlURL != "":
		return fmt.Errorf("preflight: both nodes are on the self-hosted control server %s, and the tailnet's authority given is Tailscale's: give Headscale's (--headscale-url with --headscale-api-key-file, or --headscale-cli on the control server); nothing was done", tn.ControlURL)
	case kind == "headscale" && strings.HasPrefix(server, "https://") && server != tn.ControlURL:
		return fmt.Errorf("preflight: the Headscale API given (--headscale-url %s) is not the control server both nodes are on (%s): give that server's API; nothing was done", server, tn.ControlURL)
	case kind == "headscale" && info.HTTPS:
		return errors.New("preflight: the source serves the tailnet browser endpoint over HTTPS (its sidecar's TS_SERVE_CONFIG), and a self-hosted control server issues no certificates, so the target cannot serve it: remove the HTTPS overlay from the source first; nothing was done")
	case kind == "headscale" && tn.HTTPSPort != 0:
		return errors.New("preflight: the target's configuration sets tailnet_https_port, and a self-hosted control server issues no certificates: leave it unset; nothing was done")
	}
	return nil
}
