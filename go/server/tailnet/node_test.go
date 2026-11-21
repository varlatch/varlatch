// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"

	"github.com/varlatch/varlatch/go/server/jsvalue"
)

var jsvalueStringify = jsvalue.Stringify

// The automated tests never reach a real tailnet: Tailscale's own control
// server (testcontrol) and a DERP relay run in process, on loopback.

const testSuffix = "corp.ts.net"

// startControl runs a control server whose tailnet is testSuffix, where
// tag:varlatch, tag:prod and tag:ci may be advertised.
func startControl(t *testing.T) *testcontrol.Server {
	t.Helper()
	derp := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	c := &testcontrol.Server{
		DERPMap: derp, DNSConfig: &tailcfg.DNSConfig{Proxied: true}, MagicDNSDomain: testSuffix, Logf: logger.Discard,
		TagOwners: map[string][]string{"tag:varlatch": nil, "tag:prod": nil, "tag:ci": nil},
	}
	c.HTTPTestServer = httptest.NewUnstartedServer(c)
	c.HTTPTestServer.Start()
	t.Cleanup(c.HTTPTestServer.Close)
	return c
}

// startVarlatchd starts varlatchd's node on control.
func startVarlatchd(t *testing.T, control *testcontrol.Server, ctx context.Context) *TSNode {
	t.Helper()
	n, err := StartNode(NodeConfig{Dir: t.TempDir(), Hostname: "varlatch", ControlURL: control.BaseURL(), Tags: []string{"tag:varlatch"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.Close() })
	if err := n.Up(ctx); err != nil {
		t.Fatal(err)
	}
	return n
}

// startPeer starts another device on control.
func startPeer(t *testing.T, control *testcontrol.Server, ctx context.Context, hostname string, tags ...string) *tsnet.Server {
	t.Helper()
	s := &tsnet.Server{Dir: t.TempDir(), Hostname: hostname, ControlURL: control.BaseURL(), Ephemeral: true, AdvertiseTags: tags, Logf: logger.Discard}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.Up(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

// A tagged peer that connects to varlatchd's tailnet listener resolves,
// through the node's own WhoIs on the connection's peer address, to its
// tags; a request's headers play no part.
func TestTaggedPeerThroughTheNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	control := startControl(t)
	node := startVarlatchd(t, control, ctx)
	ln, err := node.Listen(8687)
	if err != nil {
		t.Fatal(err)
	}
	resolver := NewResolver(node, testSuffix, nil)
	got := make(chan Resolution, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- resolver.Resolve(r.Context(), r.RemoteAddr)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	peer := startPeer(t, control, ctx, "build-1", "tag:prod")
	st, err := node.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+st.Addresses[0]+":8687/", nil)
	req.Header.Set("X-Forwarded-For", "100.64.0.99")
	res, err := peer.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	r := <-got
	if r.Context == nil {
		t.Fatalf("the tagged peer was refused: %s", r.Refused)
	}
	if r.Context.Tailnet != testSuffix || len(r.Context.Tags) != 1 || r.Context.Tags[0] != "tag:prod" || *r.Context.NodeName != "build-1" || r.Context.UserLogin != nil {
		t.Fatalf("the tagged peer: %+v", *r.Context)
	}
}

// peerAddr is a peer's tailnet address, as a connection from it shows.
func peerAddr(t *testing.T, s *tsnet.Server) string {
	t.Helper()
	ip4, _ := s.TailscaleIPs()
	return ip4.String() + ":40000"
}

// eventually waits for the resolution of remote to be want, as the node's
// netmap catches up with a change at the control server.
func eventually(t *testing.T, ctx context.Context, r *Resolver, remote, want string) {
	t.Helper()
	var got string
	for ctx.Err() == nil {
		got = string(jsvalueStringify(r.Resolve(ctx, remote).JSValue()))
		if got == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s: %s, want %s", remote, got, want)
}

// Every case of the device check against a real node and its control
// server: the pin recorded at enrolment, a tagged device by its tags, a
// person's device with its login, a device shared in, a device of another
// tailnet, the node itself, an address no device has; and the listeners
// report once the node runs.
func TestPeersThroughThePinnedNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	control := startControl(t)
	node := startVarlatchd(t, control, ctx)
	dir := t.TempDir()
	if err := BeginEnrolment(dir); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(node, control.BaseURL(), dir, 8687, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := NewPinnedResolver(node, m, nil)
	if got := r.Resolve(ctx, "100.64.0.1:1"); got.Refused != ResolverUnavailable {
		t.Fatalf("before enrolment: %+v", got)
	}
	m.Check(ctx)
	pin, err := LoadPin(filepath.Join(dir, PinFile))
	if err != nil || pin == nil || pin.Suffix != testSuffix || pin.ControlURL != control.BaseURL() || pin.TailnetID != "" {
		t.Fatalf("the pin recorded at enrolment: %+v, %v", pin, err)
	}

	tagged := startPeer(t, control, ctx, "build-1", "tag:prod")
	person := startPeer(t, control, ctx, "laptop")
	guest := startPeer(t, control, ctx, "guest")
	foreign := startPeer(t, control, ctx, "box")
	eventually(t, ctx, r, peerAddr(t, tagged), `{"tailnet":"corp.ts.net","nodeId":"`+stableIDOf(t, ctx, tagged)+`","nodeName":"build-1","tags":["tag:prod"]}`)
	if got := r.Resolve(ctx, peerAddr(t, person)); got.Context == nil || got.Context.UserLogin == nil || *got.Context.UserLogin == "" || len(got.Context.Tags) != 0 {
		t.Fatalf("a person's device: %+v", got)
	}

	// The control server shares guest in, and moves box to another tailnet.
	shared := control.Node(publicKeyOf(t, ctx, guest))
	shared.Sharer = 4242
	control.UpdateNode(shared)
	other := control.Node(publicKeyOf(t, ctx, foreign))
	other.Name = "box.other.ts.net."
	control.UpdateNode(other)
	eventually(t, ctx, r, peerAddr(t, guest), `{"refused":"shared"}`)
	eventually(t, ctx, r, peerAddr(t, foreign), `{"refused":"other-tailnet"}`)

	st, err := node.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Resolve(ctx, st.Addresses[0]+":40000"); got.Refused != Self {
		t.Fatalf("the node itself: %+v", got)
	}
	if got := r.Resolve(ctx, "100.127.0.9:1"); got.Refused != Unrecognized {
		t.Fatalf("no device: %+v", got)
	}

	m.Listening(true)
	m.Check(ctx)
	report := string(jsvalueStringify(m.Report()))
	for _, want := range []string{`"configured":{"tailnet":"corp.ts.net","listenerPort":8687,"browserEndpoint":null,"controlUrl":"` + control.BaseURL() + `"}`,
		`"checks":{"listener":{"status":"pass"},"localApi":{"status":"pass"},"node":{"status":"pass"}}`,
		`"name":"varlatch","dnsName":"varlatch.corp.ts.net","tailnet":"corp.ts.net","tags":["tag:varlatch"]`} {
		if !strings.Contains(report, want) {
			t.Errorf("the report lacks %s: %s", want, report)
		}
	}
}

func stableIDOf(t *testing.T, ctx context.Context, s *tsnet.Server) string {
	t.Helper()
	lc, err := s.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	st, err := lc.StatusWithoutPeers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return string(st.Self.ID)
}

func publicKeyOf(t *testing.T, ctx context.Context, s *tsnet.Server) key.NodePublic {
	t.Helper()
	lc, err := s.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	st, err := lc.StatusWithoutPeers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return st.Self.PublicKey
}
