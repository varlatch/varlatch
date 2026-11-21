// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/tailcontrol"
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
		{"--login-server=https://192.0.2.10/headscale", "", "is given as https://<its IP address>[:port]"},
		{"--login-server=ftp://192.0.2.10", "", "is given as https://<its IP address>[:port]"},
		{"--login-server=http://192.0.2.10", "", "is given as https://<its IP address>[:port]"},
		{"--login-server=https://headscale.example.com", "", "is given as https://<its IP address>[:port]"},
		// One server, one spelling (lib/tailcontrol's rule, as
		// tailnet_control_url): IPv6 forms and a mapped IPv4 address.
		{"--login-server=https://[2001:0db8:0:0::10]:443", "https://[2001:db8::10]", ""},
		{"--login-server=https://[::ffff:192.0.2.10]", "https://192.0.2.10", ""},
		{"--login-server=https://[fe80::1%25eth0]", "", "zoned address"},
		{"--login-server=https://0.0.0.0", "", "not an address a control server listens on"},
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
		name   string
		kind   string
		server string
		info   TailnetInfo
		tn     TargetTailnet
		want   string
	}{
		{"Tailscale's", "tailscale", "", TailnetInfo{}, TargetTailnet{}, ""},
		{"Headscale's API", "headscale", hs, TailnetInfo{ControlURL: hs}, TargetTailnet{ControlURL: hs}, ""},
		{"Headscale's CLI", "headscale", CLIAuthority("/usr/bin/headscale"), TailnetInfo{ControlURL: hs}, TargetTailnet{ControlURL: hs}, ""},
		{"another server's API", "headscale", "https://192.0.2.11", TailnetInfo{ControlURL: hs}, TargetTailnet{ControlURL: hs}, "the Headscale API given (--headscale-url https://192.0.2.11) is not the control server both nodes are on (https://192.0.2.10)"},
		{"another server", "headscale", hs, TailnetInfo{ControlURL: "https://192.0.2.11"}, TargetTailnet{ControlURL: hs}, "logs in to https://192.0.2.11 control server"},
		{"the sidecar on Tailscale", "headscale", hs, TailnetInfo{}, TargetTailnet{ControlURL: hs}, "logs in to Tailscale's control server"},
		{"a Headscale authority on Tailscale", "headscale", hs, TailnetInfo{}, TargetTailnet{}, "give --tailscale-oauth-client-file instead"},
		{"a Tailscale authority on Headscale", "tailscale", "", TailnetInfo{ControlURL: hs}, TargetTailnet{ControlURL: hs}, "give Headscale's"},
		{"HTTPS on Headscale", "headscale", hs, TailnetInfo{ControlURL: hs, HTTPS: true}, TargetTailnet{ControlURL: hs}, "issues no certificates"},
		{"tailnet_https_port on Headscale", "headscale", hs, TailnetInfo{ControlURL: hs}, TargetTailnet{ControlURL: hs, HTTPSPort: 8443}, "leave it unset"},
	} {
		err := checkControlPlane(c.kind, c.server, c.info, &c.tn)
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

// asKind is a control plane answering another kind: the Tailscale fake as
// a Headscale for the authority checks, which judge the kind and the
// server only.
type asKind struct {
	tailcontrol.ControlPlane
	kind string
}

func (a asKind) Kind() string { return a.kind }

// Headscale's authority must be the nodes' control server's: another
// server's API is refused before the target's node enrols; and a run
// resumed mid-switch with another server's authority (or the other form)
// is refused before anything is renamed, since the journal's node ids are
// the planning server's.
func TestTheAuthoritysServerIsChecked(t *testing.T) {
	ctx := context.Background()
	const hs = "https://192.0.2.10"
	headscale := func(w *tnWorld, server string) {
		w.src.info.ControlURL, w.tgt.info.Tailnet.ControlURL = hs, hs
		w.eng.Tailnet.Control = asKind{ControlPlane: w.eng.Tailnet.Control, kind: "headscale"}
		w.eng.Tailnet.Server = server
	}
	w := newTailnetWorld(t)
	headscale(w, "https://192.0.2.11")
	if _, err := w.eng.Run(ctx, true); err == nil || !strings.Contains(err.Error(), "is not the control server both nodes are on") {
		t.Fatalf("another server's API: %v", err)
	}
	if w.tgt.enrolled != "" {
		t.Fatalf("the target's node enrolled as %s", w.tgt.enrolled)
	}

	w = newTailnetWorld(t)
	headscale(w, hs)
	j, err := w.eng.Run(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if j.Tailnet.Control != "headscale" || j.Tailnet.ControlServer != hs {
		t.Fatalf("the record: %+v", j.Tailnet)
	}
	names := w.names()
	j.Tailnet.Handoff.Phase, j.Tailnet.Handoff.ServingRenamed = tailhandoff.Switching, true
	for _, other := range []string{"https://192.0.2.11", CLIAuthority("/usr/bin/headscale")} {
		w.eng.Tailnet.Server = other
		err := w.eng.switchTailnet(ctx, j)
		if err == nil || !strings.Contains(err.Error(), "the tailnet handoff was planned with the authority of the Headscale API at https://192.0.2.10") ||
			!strings.Contains(err.Error(), "--headscale-url https://192.0.2.10 with a new --headscale-api-key-file") {
			t.Fatalf("resumed with %s: %v", other, err)
		}
		if err := w.eng.unwindTailnet(ctx, j); err == nil || !strings.Contains(err.Error(), "planned with the authority of") {
			t.Fatalf("aborted with %s: %v", other, err)
		}
	}
	if n := w.names(); n["old"] != names["old"] || n["new"] != names["new"] {
		t.Fatalf("renamed with another authority: %v, was %v", n, names)
	}
}
