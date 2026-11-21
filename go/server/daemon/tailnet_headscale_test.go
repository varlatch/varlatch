// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build headscale && linux

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/tailnet"
	"github.com/varlatch/varlatch/go/server/tailnet/headscaletest"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

// varlatchd on Headscale 0.29.7 (build tag headscale; go.yml's own step):
// the node commands of a handoff (enroll, hold, reach, open) and the
// tailnet listener's identity cases, against Headscale in a container
// (ADR-0059 Decision 5 and amendment 11; step 7.5c c3).

var headscaleCA *headscaletest.CA

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "headscaletest-ca-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Before anything in the process uses TLS: Go reads the roots once.
	if headscaleCA, err = headscaletest.Trust(dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// hsPeer is a client node on Headscale, tagged (or not) by its key.
func hsPeer(t *testing.T, ctx context.Context, hs *headscaletest.Server, name, key string) *tsnet.Server {
	t.Helper()
	peer := &tsnet.Server{Dir: t.TempDir(), Hostname: name, ControlURL: hs.URL, AuthKey: key, Logf: logger.Discard}
	t.Cleanup(func() { _ = peer.Close() })
	if _, err := peer.Up(ctx); err != nil {
		t.Fatalf("%s did not join Headscale: %v", name, err)
	}
	return peer
}

// sameJSON is whether two JSON documents hold the same values (the audit
// stores its members in its own order).
func sameJSON(a, b string) bool {
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// writeKey writes a pre-auth key to the auth key file (never logged).
func writeKey(t *testing.T, file, key string) {
	t.Helper()
	if err := os.WriteFile(file, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A handoff's node on Headscale. Enrolled with an untagged key, the node
// joins untagged and enroll refuses it, naming both sets and the remedy;
// the node stays held. Given tailnet_tags in Headscale, enroll takes it:
// pinned to the control URL and base_domain, its StableID Headscale's node
// id. Started held, varlatchd serves nothing on the tailnet; the reach
// check (a probe joined with the node's tagged key) sees the name reach
// that node; `tailnet open` opens the listener. Over it, a tagged peer is
// known by its tags and a user's device by its login, each by Headscale's
// node id. The node retagged in Headscale closes tailnet access
// (TAGS_DIFFER, doctor naming both sets) and nothing is written; tagged
// again, it opens.
func TestHeadscaleHandoffNode(t *testing.T) {
	headscaletest.Skip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	hs := headscaletest.Start(t, headscaleCA)
	in := newInstall(t, "")
	keyFile := filepath.Join(in.dir, "tailnet-auth-key")
	writeKey(t, keyFile, hs.PreauthKey(t))
	in.write(t, fmt.Sprintf("tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_auth_key_file = %s\ntailnet_control_url = %s\n", keyFile, hs.URL))
	const temp = "vault-vl-0a1b2c3d4e5f-n"

	code, out, errOut := runAdmin(t, "tailnet", "enroll", "--hostname", temp, "--json", "--config", in.conf)
	if code != ExitFailure || !strings.Contains(errOut, "The node's tags (none) are not tailnet_tags (tag:varlatch)") || !strings.Contains(errOut, "headscale nodes tag") {
		t.Fatalf("enroll with an untagged key: %d %q %q", code, out, errOut)
	}
	if hold, err := tailnet.LoadHold(in.data); err != nil || hold == nil || hold.Hostname != temp {
		t.Fatalf("the hold after a refused enrolment: %+v %v", hold, err)
	}
	nodeID := hs.NodeID(t, temp)
	hs.Tag(t, nodeID, "tag:varlatch")
	// Headscale's change reaches the node with its next map.
	var en enrollResult
	for i := 0; i < 30; i++ {
		if code, out, errOut = runAdmin(t, "tailnet", "enroll", "--hostname", temp, "--json", "--config", in.conf); code == ExitOK {
			break
		}
		time.Sleep(time.Second)
	}
	if code != ExitOK || json.Unmarshal([]byte(out), &en) != nil {
		t.Fatalf("enroll once tagged: %d %q %q", code, out, errOut)
	}
	if en.DNSName != temp+"."+headscaletest.BaseDomain || en.StableID != nodeID || en.Pinned != headscaletest.BaseDomain || en.TailnetID != "" || !en.Open || !en.Held || en.ControlURL != hs.URL {
		t.Fatalf("enroll: %+v (Headscale's node id %s)", en, nodeID)
	}
	pin, err := tailnet.LoadPin(filepath.Join(in.data, tailnet.PinFile))
	if err != nil || pin == nil || pin.ControlURL != hs.URL || pin.TailnetID != "" || pin.Suffix != headscaletest.BaseDomain || pin.Closed != nil {
		t.Fatalf("the pin: %+v %v", pin, err)
	}

	// The probe joins with the node's key: a tagged, reusable one.
	writeKey(t, keyFile, hs.PreauthKey(t, "tag:varlatch"))
	r := startWith(t, in, &hooks{})
	code, out, errOut = runAdmin(t, "bootstrap", "--cli-credential", "--config", in.conf)
	m := bootstrapCLI.FindStringSubmatch(out)
	if code != ExitOK || m == nil {
		t.Fatalf("bootstrap: %d %q %q", code, out, errOut)
	}
	bearer := m[2]
	waitReport(t, r, bearer, `"controlUrl":"`+hs.URL+`"`)
	ci := hsPeer(t, ctx, hs, "ci-1", hs.PreauthKey(t, "tag:ci"))
	addr := hostOfLabel(t, ctx, ci, temp)
	base := "http://" + addr + ":8687"
	client := ci.HTTPClient()
	client.Timeout = 5 * time.Second
	if res, err := client.Get(base + "/v1/meta"); err == nil {
		res.Body.Close()
		t.Fatalf("a held node answered on the tailnet: %d", res.StatusCode)
	}
	code, out, errOut = runAdmin(t, "tailnet", "reaches", "--name", temp, "--stable-id", en.StableID, "--wait", "90s", "--json", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, `"reaches":true`) {
		t.Fatalf("reaches: %d %q %q", code, out, errOut)
	}
	if code, out, _ := runAdmin(t, "tailnet", "reaches", "--name", temp, "--stable-id", "999999", "--config", in.conf); code != ExitFailure || !strings.Contains(out, "does not reach") {
		t.Fatalf("reaches another node: %d %q", code, out)
	}
	code, out, errOut = runAdmin(t, "tailnet", "open", "--json", "--config", in.conf)
	if code != ExitOK || out != `{"opened":true,"wasHeld":true,"running":true}`+"\n" {
		t.Fatalf("open: %d %q %q", code, out, errOut)
	}
	res, err := client.Get(base + "/v1/meta")
	if err != nil {
		t.Fatalf("the opened listener: %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the opened listener: %d", res.StatusCode)
	}

	// The identity cases, through the tailnet listener.
	if code := do(t, client, "POST", base+"/v1/organizations", bearer, `{"name":"Tagged","slug":"hs-tagged"}`, nil); code != 201 {
		t.Fatalf("a write from a tagged peer: %d", code)
	}
	listener, ctxJSON := tailnetAuditOf(t, r, bearer, "hs-tagged")
	if want := `{"tailnet":"` + headscaletest.BaseDomain + `","nodeId":"` + hs.NodeID(t, "ci-1") + `","nodeName":"ci-1","tags":["tag:ci"]}`; listener != "tailnet" || !sameJSON(ctxJSON, want) {
		t.Fatalf("a tagged peer's Tailnet Context: %s %s, want %s", listener, ctxJSON, want)
	}
	laptop := hsPeer(t, ctx, hs, "laptop", hs.PreauthKey(t))
	lc := laptop.HTTPClient()
	lc.Timeout = 5 * time.Second
	if code := do(t, lc, "POST", "http://"+hostOfLabel(t, ctx, laptop, temp)+":8687/v1/organizations", bearer, `{"name":"User","slug":"hs-user"}`, nil); code != 201 {
		t.Fatalf("a write from a user's device: %d", code)
	}
	if _, ctxJSON := tailnetAuditOf(t, r, bearer, "hs-user"); !sameJSON(ctxJSON, `{"tailnet":"`+headscaletest.BaseDomain+`","nodeId":"`+hs.NodeID(t, "laptop")+`","nodeName":"laptop","tags":[],"userLogin":"`+headscaletest.User+`"}`) {
		t.Fatalf("a user's device's Tailnet Context: %s", ctxJSON)
	}

	// The node retagged in Headscale: access closed, both sets named.
	hs.Tag(t, nodeID, "tag:prod")
	waitReport(t, r, bearer, `"node":{"status":"fail","reason":"TAGS_DIFFER"}`)
	waitReport(t, r, bearer, `"warnings":["The node's tags (tag:prod) are not tailnet_tags (tag:varlatch)`)
	refusedWhileClosed(t, r, ci, base, bearer, "hs-closed")
	code, out, _ = runAdmin(t, "doctor", "--json", "--config", in.conf)
	var rep struct {
		Checks []struct {
			ID, Status, Detail, Remedy string
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("doctor --json: %d %v %q", code, err, out)
	}
	var seen int
	for _, c := range rep.Checks {
		switch c.ID {
		case "tailnet.pin":
			seen++
			if c.Status != "fail" || !strings.Contains(c.Detail, "The node's tags (tag:prod) are not tailnet_tags (tag:varlatch)") || !strings.Contains(c.Remedy, "headscale nodes tag") {
				t.Errorf("doctor's tailnet.pin: %+v", c)
			}
		case "tailnet.control":
			seen++
			if c.Status != "pass" || !strings.Contains(c.Detail, hs.URL) {
				t.Errorf("doctor's tailnet.control (the embedded DERP server only): %+v", c)
			}
		}
	}
	if seen != 2 {
		t.Errorf("doctor: %q", out)
	}
	hs.Tag(t, nodeID, "tag:varlatch")
	waitReport(t, r, bearer, `"node":{"status":"pass"}`)
	if code := do(t, client, "POST", base+"/v1/organizations", bearer, `{"name":"Tagged again","slug":"hs-again"}`, nil); code != 201 {
		t.Fatalf("a write once the node is tagged again: %d", code)
	}
	r.stop(t)
}
