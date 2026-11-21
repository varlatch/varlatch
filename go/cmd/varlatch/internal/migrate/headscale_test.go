// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/tailhandoff"
)

func TestLoginServer(t *testing.T) {
	for _, c := range []struct{ args, want, err string }{
		{"", "", ""},
		{"--advertise-tags=tag:varlatch", "", ""},
		{"--login-server=https://192.0.2.10", "https://192.0.2.10", ""},
		{"--accept-dns=false --login-server https://192.0.2.10:443/ --advertise-tags=tag:x", "https://192.0.2.10", ""},
		{"--login-server=HTTPS://[2001:DB8::10]:8443", "https://[2001:db8::10]:8443", ""},
		{"--login-server=https://controlplane.tailscale.com", "", ""},
		{"--login-server=https://login.tailscale.com/", "", ""},
		{"--login-server", "", "ends with --login-server"},
		{"--login-server=https://192.0.2.10/headscale", "", "not a control server's URL"},
		{"--login-server=ftp://192.0.2.10", "", "not a control server's URL"},
	} {
		got, err := loginServer(c.args)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%q: %q %v, want an error with %q", c.args, got, err, c.err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%q: %q %v, want %q", c.args, got, err, c.want)
		}
	}
}

// The control-plane preflight: both nodes on one control server, the
// authority given for it, no HTTPS on a self-hosted one.
func TestCheckControlPlane(t *testing.T) {
	const hs = "https://192.0.2.10"
	for _, c := range []struct {
		name string
		kind string
		info TailnetInfo
		tn   TargetTailnet
		want string
	}{
		{"Tailscale's", "tailscale", TailnetInfo{}, TargetTailnet{}, ""},
		{"Headscale's", "headscale", TailnetInfo{ControlURL: hs}, TargetTailnet{ControlURL: hs}, ""},
		{"another server", "headscale", TailnetInfo{ControlURL: "https://192.0.2.11"}, TargetTailnet{ControlURL: hs}, "logs in to https://192.0.2.11 control server"},
		{"the sidecar on Tailscale", "headscale", TailnetInfo{}, TargetTailnet{ControlURL: hs}, "logs in to Tailscale's control server"},
		{"a Headscale authority on Tailscale", "headscale", TailnetInfo{}, TargetTailnet{}, "give --tailscale-oauth-client-file instead"},
		{"a Tailscale authority on Headscale", "tailscale", TailnetInfo{ControlURL: hs}, TargetTailnet{ControlURL: hs}, "give Headscale's"},
		{"HTTPS on Headscale", "headscale", TailnetInfo{ControlURL: hs, HTTPS: true}, TargetTailnet{ControlURL: hs}, "issues no certificates"},
		{"tailnet_https_port on Headscale", "headscale", TailnetInfo{ControlURL: hs}, TargetTailnet{ControlURL: hs, HTTPSPort: 8443}, "leave it unset"},
	} {
		err := checkControlPlane(c.kind, c.info, &c.tn)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "nothing was done") {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

// The preflight refuses a migration whose nodes are on another control
// server than the authority's, before anything is enrolled; the journal
// records the control plane a handoff was planned on, and a run resumed
// with another's authority is refused.
func TestTheControlPlaneIsChecked(t *testing.T) {
	w := newTailnetWorld(t)
	w.src.info.ControlURL = "https://192.0.2.10"
	w.tgt.info.Tailnet.ControlURL = "https://192.0.2.10"
	if _, err := w.eng.Run(context.Background(), true); err == nil || !strings.Contains(err.Error(), "the tailnet's authority given is Tailscale's") {
		t.Fatalf("a Tailscale authority over Headscale's nodes: %v", err)
	}
	if w.tgt.enrolled != "" {
		t.Fatalf("the target's node enrolled as %s", w.tgt.enrolled)
	}

	w = newTailnetWorld(t)
	j, err := w.eng.Run(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if j.Tailnet == nil || j.Tailnet.Control != "tailscale" {
		t.Fatalf("the record's control plane: %+v", j.Tailnet)
	}
	j.Tailnet.Control = "headscale"
	j.Tailnet.Handoff.Phase = tailhandoff.Prepared
	if err := w.eng.switchTailnet(context.Background(), j); err == nil || !strings.Contains(err.Error(), "planned on headscale's control plane, and the authority given is tailscale's") {
		t.Fatalf("another authority: %v", err)
	}
}
