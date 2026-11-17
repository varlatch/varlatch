// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"

	"github.com/varlatch/varlatch/go/server/tailnet"
)

// The tailnet listener end to end, with no real tailnet: Tailscale's own
// control server (testcontrol) and a DERP relay run in process, on
// loopback, and varlatchd's node joins them through the tailnetControl
// hook (the configuration accepts Tailscale's control server only).

func startTestControl(t *testing.T) *testcontrol.Server {
	t.Helper()
	derp := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	c := &testcontrol.Server{
		DERPMap: derp, DNSConfig: &tailcfg.DNSConfig{Proxied: true}, MagicDNSDomain: "corp.ts.net", Logf: logger.Discard,
		TagOwners: map[string][]string{"tag:varlatch": nil, "tag:ci": nil},
	}
	c.HTTPTestServer = httptest.NewUnstartedServer(c)
	c.HTTPTestServer.Start()
	t.Cleanup(c.HTTPTestServer.Close)
	return c
}

// do sends a request with the bearer, through client, and decodes the
// answer into into (when set).
func do(t *testing.T, client *http.Client, method, url, bearer, body string, into any) int {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if into != nil {
		if err := json.Unmarshal(b, into); err != nil {
			t.Fatalf("%s %s: %q: %v", method, url, b, err)
		}
	}
	return res.StatusCode
}

// waitReport waits for the listeners report to contain want.
func waitReport(t *testing.T, r *running, bearer, want string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var got json.RawMessage
	for time.Now().Before(deadline) {
		if do(t, http.DefaultClient, "GET", "http://"+r.addr+"/v1/installation/listeners", bearer, "", &got) == 200 && strings.Contains(string(got), want) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("the listeners report never showed %s: %s\n%s", want, got, r.stderr.String())
}

// tailnetAuditOf is the listener and Tailnet Context the audit recorded for
// the Organization slug's creation.
func tailnetAuditOf(t *testing.T, r *running, bearer, slug string) (string, string) {
	t.Helper()
	var page struct {
		Items []struct {
			EventType string          `json:"eventType"`
			Listener  string          `json:"listener"`
			Tailnet   json.RawMessage `json:"tailnetContext"`
		} `json:"items"`
	}
	if code := do(t, http.DefaultClient, "GET", "http://"+r.addr+"/v1/organizations/"+slug+"/audit-events", bearer, "", &page); code != 200 {
		t.Fatalf("the audit events of %s: %d", slug, code)
	}
	for _, e := range page.Items {
		if e.EventType == "organization.created" {
			return e.Listener, string(e.Tailnet)
		}
	}
	t.Fatalf("no organization.created event for %s: %+v", slug, page.Items)
	return "", ""
}

// varlatchd with tailnet = on: its node enrols with the auth key, records
// the pin, and serves the API on its tailnet address, where a tagged
// peer's request carries the peer's Tailnet Context, resolved by the node,
// into the audit. Restarted without the auth key, it rejoins; with a pin
// whose suffix is no longer the tailnet's, the same peer has no Tailnet
// Context (other-tailnet) until `admin tailnet repin --yes` takes the
// observed suffix.
func TestTailnetListener(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	control := startTestControl(t)
	in := newInstall(t, "")
	keyFile := filepath.Join(in.dir, "tailnet-auth-key")
	if err := os.WriteFile(keyFile, []byte("tskey-auth-hermetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in.write(t, fmt.Sprintf("tailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_auth_key_file = %s\n", keyFile))
	h := &hooks{tailnetControl: control.BaseURL()}
	r := startWith(t, in, h)
	code, out, errOut := runAdmin(t, "bootstrap", "--cli-credential", "--config", in.conf)
	m := bootstrapCLI.FindStringSubmatch(out)
	if code != ExitOK || m == nil {
		t.Fatalf("bootstrap: %d %q %q", code, out, errOut)
	}
	bearer := m[2]
	waitReport(t, r, bearer, `"checks":{"listener":{"status":"pass"},"localApi":{"status":"pass"},"node":{"status":"pass"}}`)
	waitReport(t, r, bearer, `"configured":{"tailnet":"corp.ts.net","listenerPort":8687,"browserEndpoint":null}`)
	if st, err := os.Stat(filepath.Join(in.data, tailnet.StateDir)); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("the node's state directory: %v %v", st, err)
	}
	pin, err := tailnet.LoadPin(filepath.Join(in.data, tailnet.PinFile))
	if err != nil || pin == nil || pin.Suffix != "corp.ts.net" || pin.ControlURL != control.BaseURL() {
		t.Fatalf("the pin: %+v %v", pin, err)
	}

	peer := &tsnet.Server{Dir: t.TempDir(), Hostname: "ci-1", ControlURL: control.BaseURL(), Ephemeral: true, AdvertiseTags: []string{"tag:ci"}, Logf: logger.Discard}
	t.Cleanup(func() { _ = peer.Close() })
	if _, err := peer.Up(ctx); err != nil {
		t.Fatal(err)
	}
	base := "http://" + varlatchdAddr(t, ctx, peer) + ":8687"
	if code := do(t, peer.HTTPClient(), "POST", base+"/v1/organizations", bearer, `{"name":"Over the tailnet","slug":"over-tailnet"}`, nil); code != 201 {
		t.Fatalf("creating an Organization over the tailnet: %d", code)
	}
	listener, ctxJSON := tailnetAuditOf(t, r, bearer, "over-tailnet")
	if listener != "tailnet" || !strings.Contains(ctxJSON, `"tailnet":"corp.ts.net"`) || !strings.Contains(ctxJSON, `"nodeName":"ci-1"`) || !strings.Contains(ctxJSON, `"tags":["tag:ci"]`) {
		t.Fatalf("the audit's listener and Tailnet Context: %s %s", listener, ctxJSON)
	}
	// The ordinary listener never resolves a peer.
	if code := do(t, http.DefaultClient, "POST", "http://"+r.addr+"/v1/organizations", bearer, `{"name":"Ordinary","slug":"ordinary"}`, nil); code != 201 {
		t.Fatalf("creating an Organization on the ordinary listener: %d", code)
	}
	if listener, ctxJSON := tailnetAuditOf(t, r, bearer, "ordinary"); listener != "ordinary" || ctxJSON != "null" {
		t.Fatalf("the ordinary listener's audit: %s %s", listener, ctxJSON)
	}
	if code, out, errOut := runAdmin(t, "tailnet", "repin", "--config", in.conf); code != ExitOK || !strings.Contains(out, "The pin holds: nothing to re-pin.") {
		t.Fatalf("repin with the pin holding: %d %q %q", code, out, errOut)
	}
	r.stop(t)

	// Offline there is no node to compare with.
	if code, _, errOut := runAdmin(t, "tailnet", "repin", "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "it runs in a running varlatchd with tailnet = on") {
		t.Fatalf("repin offline: %d %q", code, errOut)
	}
	if code, _, errOut := runAdmin(t, "tailnet", "--config", in.conf); code != 64 || !strings.Contains(errOut, "Usage: varlatchd admin tailnet repin") {
		t.Fatalf("usage: %d %q", code, errOut)
	}

	// The node is enrolled: the auth key is no longer needed. The pin now
	// names a suffix the tailnet no longer has.
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	pin.Suffix = "old.ts.net"
	if err := tailnet.SavePin(filepath.Join(in.data, tailnet.PinFile), pin); err != nil {
		t.Fatal(err)
	}
	r = startWith(t, in, h)
	waitReport(t, r, bearer, `"node":{"status":"fail","reason":"OTHER_TAILNET"}`)
	// #220 review P1: the whole tailnet listener refuses, and nothing the
	// request asked for is written.
	refusedWhileClosed(t, r, peer, base, bearer, "pin-changed")
	code, out, errOut = runAdmin(t, "tailnet", "repin", "--json", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, `"reason":"suffix-changed","closed":"suffix-changed","missing":false,"offered":true`) {
		t.Fatalf("repin --json: %d %q %q", code, out, errOut)
	}
	code, out, errOut = runAdmin(t, "tailnet", "repin", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, "pinned:   suffix old.ts.net") || !strings.Contains(out, "observed: suffix corp.ts.net") || !strings.Contains(out, "Run again with --yes") {
		t.Fatalf("repin without --yes: %d %q %q", code, out, errOut)
	}
	code, out, errOut = runAdmin(t, "tailnet", "repin", "--yes", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, "Re-pinned the tailnet from old.ts.net to corp.ts.net; tailnet access is open.") {
		t.Fatalf("repin --yes: %d %q %q", code, out, errOut)
	}
	waitReport(t, r, bearer, `"node":{"status":"pass"}`)
	if code := do(t, peer.HTTPClient(), "POST", base+"/v1/organizations", bearer, `{"name":"Re-pinned","slug":"re-pinned"}`, nil); code != 201 {
		t.Fatalf("creating an Organization over the tailnet after the re-pin: %d", code)
	}
	if _, ctxJSON := tailnetAuditOf(t, r, bearer, "re-pinned"); !strings.Contains(ctxJSON, `"nodeName":"ci-1"`) {
		t.Fatalf("the audit after the re-pin: %s", ctxJSON)
	}
	if pin, err := tailnet.LoadPin(filepath.Join(in.data, tailnet.PinFile)); err != nil || pin.Suffix != "corp.ts.net" || len(pin.History) != 1 || pin.History[0].Suffix != "old.ts.net" {
		t.Fatalf("the pin after the re-pin: %+v %v", pin, err)
	}
	r.stop(t)

	// #220 review P6: the pin file is gone, but the node was enrolled: it
	// is never pinned again silently; the host adopts what it is on.
	if err := os.Remove(filepath.Join(in.data, tailnet.PinFile)); err != nil {
		t.Fatal(err)
	}
	r = startWith(t, in, h)
	waitReport(t, r, bearer, `"node":{"status":"fail","reason":"OTHER_TAILNET"}`)
	refusedWhileClosed(t, r, peer, base, bearer, "pin-missing")
	if _, err := os.Stat(filepath.Join(in.data, tailnet.PinFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a pin was taken silently: %v", err)
	}
	if code, _, errOut := runAdmin(t, "tailnet", "repin", "--yes", "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "run again with --yes --adopt") {
		t.Fatalf("repin --yes of a missing pin: %d %q", code, errOut)
	}
	if code, out, errOut := runAdmin(t, "tailnet", "repin", "--yes", "--adopt", "--config", in.conf); code != ExitOK || !strings.Contains(out, "Adopted corp.ts.net as the pinned tailnet; tailnet access is open.") {
		t.Fatalf("repin --yes --adopt: %d %q %q", code, out, errOut)
	}
	if code := do(t, peer.HTTPClient(), "POST", base+"/v1/organizations", bearer, `{"name":"Adopted","slug":"adopted"}`, nil); code != 201 {
		t.Fatalf("creating an Organization over the tailnet after adopting: %d", code)
	}
	r.stop(t)
}

// refusedWhileClosed: with tailnet access closed, the tailnet listener
// refuses a write (403 TAILNET_CONTEXT_UNAVAILABLE), which never commits.
func refusedWhileClosed(t *testing.T, r *running, peer *tsnet.Server, base, bearer, slug string) {
	t.Helper()
	var refusal struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if code := do(t, peer.HTTPClient(), "POST", base+"/v1/organizations", bearer, `{"name":"Closed","slug":"`+slug+`"}`, &refusal); code != 403 || refusal.Error.Code != "TAILNET_CONTEXT_UNAVAILABLE" {
		t.Fatalf("a write over the tailnet with access closed: %d %+v", code, refusal)
	}
	if code := do(t, http.DefaultClient, "GET", "http://"+r.addr+"/v1/organizations/"+slug, bearer, "", nil); code != 404 {
		t.Fatalf("the refused write committed: GET %s answers %d", slug, code)
	}
}

// varlatchdAddr is varlatchd's tailnet address, as the peer sees it.
func varlatchdAddr(t *testing.T, ctx context.Context, peer *tsnet.Server) string {
	t.Helper()
	lc, err := peer.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	for ctx.Err() == nil {
		st, err := lc.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range st.Peer {
			if p.HostName == "varlatch" && len(p.TailscaleIPs) > 0 {
				return p.TailscaleIPs[0].String()
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the peer never saw varlatchd")
	return ""
}
