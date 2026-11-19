// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"

	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/tailnet"
	"github.com/varlatch/varlatch/go/server/tailnet/tailnettest"
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
	if code != ExitOK || !strings.Contains(out, `"reason":"suffix-changed","closed":"suffix-changed","missing":false,"offered":true`) || !strings.Contains(out, `"outcome":"suffix-changed"`) || !strings.Contains(out, `"pin":null`) {
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
	// --json with --yes: the outcome and the pin after it (step 6.2b).
	code, out, errOut = runAdmin(t, "tailnet", "repin", "--yes", "--adopt", "--json", "--config", in.conf)
	var adopted struct {
		Outcome string       `json:"outcome"`
		Message string       `json:"message"`
		Pin     *tailnet.Pin `json:"pin"`
	}
	if err := json.Unmarshal([]byte(out), &adopted); code != ExitOK || err != nil || adopted.Outcome != "adopted" || adopted.Message != "Adopted corp.ts.net as the pinned tailnet; tailnet access is open." || adopted.Pin == nil || adopted.Pin.Suffix != "corp.ts.net" {
		t.Fatalf("repin --yes --adopt --json: %d %q %q", code, out, errOut)
	}
	if code := do(t, peer.HTTPClient(), "POST", base+"/v1/organizations", bearer, `{"name":"Adopted","slug":"adopted"}`, nil); code != 201 {
		t.Fatalf("creating an Organization over the tailnet after adopting: %d", code)
	}
	r.stop(t)

	// Each re-pin is the audit event tailnet.repinned, by the host
	// operator (no identity, no Organization), value-free.
	conn, err := sql.Open("sqlite", "file:"+filepath.Join(in.data, config.DatabaseFile)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rows, err := conn.Query("SELECT metadata, organization_id IS NULL, actor_identity_id IS NULL FROM audit_events WHERE event_type = 'tailnet.repinned' ORDER BY event_order")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var events []string
	for rows.Next() {
		var metadata string
		var noOrg, noActor bool
		if err := rows.Scan(&metadata, &noOrg, &noActor); err != nil {
			t.Fatal(err)
		}
		if !noOrg || !noActor {
			t.Errorf("tailnet.repinned with an Organization or an actor identity: %s", metadata)
		}
		events = append(events, metadata)
	}
	if want := []string{
		`{"action":"repinned","fromSuffix":"old.ts.net","toSuffix":"corp.ts.net","tailnetId":"","reason":"suffix-changed","operator":true}`,
		`{"action":"adopted","fromSuffix":null,"toSuffix":"corp.ts.net","tailnetId":"","reason":null,"operator":true}`,
	}; !slices.Equal(events, want) {
		t.Fatalf("tailnet.repinned events %q, want %q", events, want)
	}
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

// The browser endpoint end to end: varlatchd's node serves HTTPS on the
// tailnet with its certificate (a test CA stands in for Let's Encrypt).
// A tagged peer's browser-style request, from an allowlisted origin,
// reads its own device; another origin, another name in the handshake or
// another Host are refused; the ordinary listener names the endpoint.
func TestBrowserEndpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	control := startTestControl(t)
	ca, err := tailnettest.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	in := newInstall(t, "tailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\n"+
		"tailnet_https_port = 8443\ntailnet_browser_origins = https://dash.example.com\n")
	r := startWith(t, in, &hooks{tailnetControl: control.BaseURL(), tailnetCerts: ca})
	defer func() { r.stop(t) }()
	code, out, errOut := runAdmin(t, "bootstrap", "--cli-credential", "--config", in.conf)
	m := bootstrapCLI.FindStringSubmatch(out)
	if code != ExitOK || m == nil {
		t.Fatalf("bootstrap: %d %q %q", code, out, errOut)
	}
	bearer := m[2]
	const endpoint = "https://varlatch.corp.ts.net:8443"
	waitReport(t, r, bearer, `"configured":{"tailnet":"corp.ts.net","listenerPort":8687,"browserEndpoint":"`+endpoint+`"}`)
	waitReport(t, r, bearer, `"checks":{"listener":{"status":"pass"},"browserTls":{"status":"pass","certificateNotAfter":"`)
	if len(ca.Requested()) == 0 || ca.Requested()[0].Domain != "varlatch.corp.ts.net" {
		t.Fatalf("the certificate requests: %+v", ca.Requested())
	}
	var ep map[string]any
	if code := do(t, http.DefaultClient, "GET", "http://"+r.addr+"/v1/tailnet/endpoint", bearer, "", &ep); code != 200 || ep["browserEndpoint"] != endpoint {
		t.Fatalf("the endpoint on the ordinary listener: %d %v", code, ep)
	}
	var meta struct {
		Capabilities []string `json:"capabilities"`
	}
	if code := do(t, http.DefaultClient, "GET", "http://"+r.addr+"/v1/meta", bearer, "", &meta); code != 200 || !slices.Contains(meta.Capabilities, "tailnet.browser-reads") {
		t.Fatalf("/v1/meta: %d %v", code, meta.Capabilities)
	}

	peer := &tsnet.Server{Dir: t.TempDir(), Hostname: "ci-1", ControlURL: control.BaseURL(), Ephemeral: true, AdvertiseTags: []string{"tag:ci"}, Logf: logger.Discard}
	t.Cleanup(func() { _ = peer.Close() })
	if _, err := peer.Up(ctx); err != nil {
		t.Fatal(err)
	}
	addr := varlatchdAddr(t, ctx, peer) + ":8443"
	client := func(serverName string) *http.Client {
		return &http.Client{Transport: &http.Transport{
			DialContext:     func(ctx context.Context, _, _ string) (net.Conn, error) { return peer.Dial(ctx, "tcp", addr) },
			TLSClientConfig: &tls.Config{RootCAs: ca.Pool, ServerName: serverName},
		}}
	}
	browserGet := func(c *http.Client, url, origin string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		res, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", url, err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res, string(b)
	}
	res, body := browserGet(client("varlatch.corp.ts.net"), endpoint+"/v1/tailnet/context", "https://dash.example.com")
	if res.StatusCode != 200 || res.Header.Get("Access-Control-Allow-Origin") != "https://dash.example.com" ||
		!strings.Contains(body, `"recognized":true`) || !strings.Contains(body, `"nodeName":"ci-1"`) || !strings.Contains(body, `"tags":["tag:ci"]`) {
		t.Fatalf("the peer's device through the browser endpoint: %d %v %s", res.StatusCode, res.Header, body)
	}
	if res, _ := browserGet(client("varlatch.corp.ts.net"), endpoint+"/v1/tailnet/context", "https://elsewhere.example.com"); res.StatusCode != 403 || res.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("another origin: %d %v", res.StatusCode, res.Header)
	}
	if res, _ := browserGet(client("varlatch.corp.ts.net"), "https://"+addr+"/v1/tailnet/context", ""); res.StatusCode != 403 {
		t.Errorf("another Host: %d", res.StatusCode)
	}
	other := client("other.corp.ts.net")
	other.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://other.corp.ts.net:8443/v1/tailnet/context", nil)
	if res, err := other.Do(req); err == nil {
		res.Body.Close()
		t.Error("a handshake for another name was served")
	}
	// The plain tailnet listener has no browser route.
	plain := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return peer.Dial(ctx, "tcp", strings.TrimSuffix(addr, ":8443")+":8687")
	}}}
	if res, _ := browserGet(plain, "http://varlatch.corp.ts.net:8687/v1/tailnet/context", ""); res.StatusCode != 404 {
		t.Errorf("the device route on the plain tailnet listener: %d", res.StatusCode)
	}

	// Tailnet access closed (a latched closure): the browser endpoint
	// refuses as the plain listener does.
	r.stop(t)
	pinPath := filepath.Join(in.data, tailnet.PinFile)
	pin, err := tailnet.LoadPin(pinPath)
	if err != nil || pin == nil {
		t.Fatalf("the pin: %+v %v", pin, err)
	}
	pin.Closed = &tailnet.Closure{Reason: tailnet.PinSuffix, Since: "2026-11-17T00:00:00Z", Observed: tailnet.Observed{Suffix: "other.ts.net"}}
	if err := tailnet.SavePin(pinPath, pin); err != nil {
		t.Fatal(err)
	}
	r = startWith(t, in, &hooks{tailnetControl: control.BaseURL(), tailnetCerts: ca})
	waitReport(t, r, bearer, `"browserTls":{"status":"pass"`)
	res, body = browserGet(client("varlatch.corp.ts.net"), endpoint+"/v1/tailnet/context", "https://dash.example.com")
	if res.StatusCode != 403 || !strings.Contains(body, `"code":"TAILNET_CONTEXT_UNAVAILABLE"`) {
		t.Fatalf("the browser endpoint with tailnet access closed: %d %s", res.StatusCode, body)
	}
}
