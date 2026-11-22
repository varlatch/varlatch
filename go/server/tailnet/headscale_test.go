// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build headscale && linux

package tailnet

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/tailnet/headscaletest"
)

// The Headscale tests (build tag headscale; go.yml's own step): varlatchd's
// node on a self-hosted control server, given as https on an IP address
// (ADR-0059 Decision 5 as amended for step 7.5c), against Headscale 0.29.7
// in a container.

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

// tsnetLog is the node's log, kept for what it must never say.
type tsnetLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *tsnetLog) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *tsnetLog) contains(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.lines {
		if strings.Contains(line, s) {
			return true
		}
	}
	return false
}

// The node joins Headscale and is pinned to it: the pin is its control URL
// and base_domain, with no tailnet StableID (Headscale has none); the
// listeners report names the control server. With Headscale unreachable,
// the node never asks Tailscale's DERP servers for its address (no
// bootstrap DNS query: the control URL is an IP address, never looked up),
// and once Headscale answers again the pin still holds. The same node
// under another configured control URL is closed (control-url-changed).
func TestHeadscaleJoinAndPin(t *testing.T) {
	headscaletest.Skip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	hs := headscaletest.Start(t, headscaleCA)
	// A tagged key, as varlatchd's node is always tagged.
	key := hs.PreauthKey(t, "tag:varlatch")

	dir := t.TempDir()
	if err := BeginEnrolment(dir); err != nil {
		t.Fatal(err)
	}
	log := &tsnetLog{}
	node, err := StartNode(NodeConfig{Dir: filepath.Join(dir, StateDir), Hostname: "varlatch", ControlURL: hs.URL, AuthKey: key, Tags: []string{"tag:varlatch"}, KeyTags: true, Logf: log.logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	if err := node.Up(ctx); err != nil {
		t.Fatalf("the node did not join Headscale: %v\nHeadscale's log:\n%s", err, hs.Logs())
	}
	m, err := NewManager(node, hs.URL, dir, 8687, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Check(ctx)
	pin, err := LoadPin(filepath.Join(dir, PinFile))
	if err != nil || pin == nil || pin.ControlURL != hs.URL || pin.TailnetID != "" || pin.Suffix != headscaletest.BaseDomain {
		t.Fatalf("the pin recorded at enrolment: %+v, %v", pin, err)
	}
	if m.Closed() != "" {
		t.Fatalf("access closed on its own tailnet: %q", m.Closed())
	}
	st, err := node.Status(ctx)
	if err != nil || st.SelfID == "" || st.DNSName != "varlatch."+headscaletest.BaseDomain || !slices.Equal(st.Tags, []string{"tag:varlatch"}) {
		t.Fatalf("the node's status (tagged by its key): %+v, %v", st, err)
	}
	m.Listening(true)
	m.Check(ctx)
	report := string(jsvalueStringify(m.Report()))
	for _, want := range []string{`"configured":{"tailnet":"` + headscaletest.BaseDomain + `","listenerPort":8687,"browserEndpoint":null,"controlUrl":"` + hs.URL + `"}`,
		`"checks":{"listener":{"status":"pass"},"localApi":{"status":"pass"},"node":{"status":"pass"}}`} {
		if !strings.Contains(report, want) {
			t.Errorf("the listeners report lacks %s:\n%s", want, report)
		}
	}

	// Headscale unreachable: the node keeps trying its IP address, and
	// never falls back to looking a name up through Tailscale's DERP.
	hs.Stop(t)
	time.Sleep(20 * time.Second)
	if log.contains("bootstrapDNS") {
		t.Error("the node asked Tailscale's DERP servers to resolve its control server")
	}
	hs.Resume(t)
	m.Check(ctx)
	if m.Closed() != "" {
		t.Errorf("access closed once Headscale answered again: %q", m.Closed())
	}

	// The same node, configured for another control server: closed.
	other, err := NewManager(node, "https://127.0.0.2:8443", dir, 8687, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	other.Check(ctx)
	if other.Closed() != PinControlURL {
		t.Errorf("another configured control server: %q", other.Closed())
	}
}

// hsNode is a node of the test's on Headscale, joined with key: tagged by
// it, advertising nothing (KeyTags), as varlatchd's node on a self-hosted
// control server.
func hsNode(t *testing.T, ctx context.Context, hs *headscaletest.Server, name, key string) *TSNode {
	t.Helper()
	node, err := StartNode(NodeConfig{Dir: t.TempDir(), Hostname: name, ControlURL: hs.URL, AuthKey: key, Tags: []string{"tag:varlatch"}, KeyTags: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	if err := node.Up(ctx); err != nil {
		t.Fatalf("%s did not join Headscale: %v\nHeadscale's log:\n%s", name, err, hs.Logs())
	}
	return node
}

// checkUntil checks m until cond holds (Headscale's change reaches the
// node with its next map), or fails.
func checkUntil(t *testing.T, ctx context.Context, m *Manager, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for {
		m.Check(ctx)
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: never (closed %q)", what, m.Closed())
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// An untagged pre-auth key (a user's) joins the node untagged: its tags
// are not tailnet_tags, so tailnet access is closed (tags-differ), the
// listeners report naming both sets (step 7.5c c3; ADR-0059 amendment
// 11). Once the operator gives the node tailnet_tags in Headscale
// (headscale nodes tag, the remedy said), access opens at the next check.
// The embedded DERP server's map names none of Tailscale's: no warning.
func TestHeadscaleUntaggedKey(t *testing.T) {
	headscaletest.Skip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	hs := headscaletest.Start(t, headscaleCA)
	dir := t.TempDir()
	if err := BeginEnrolment(dir); err != nil {
		t.Fatal(err)
	}
	node, err := StartNode(NodeConfig{Dir: filepath.Join(dir, StateDir), Hostname: "varlatch", ControlURL: hs.URL, AuthKey: hs.PreauthKey(t), Tags: []string{"tag:varlatch"}, KeyTags: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	if err := node.Up(ctx); err != nil {
		t.Fatalf("the node did not join Headscale: %v\nHeadscale's log:\n%s", err, hs.Logs())
	}
	m, err := NewManager(node, hs.URL, dir, 8687, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.RequireTags([]string{"tag:varlatch"})
	m.Listening(true)
	m.Check(ctx)
	if st, err := node.Status(ctx); err != nil || len(st.Tags) != 0 {
		t.Fatalf("the node's tags with an untagged key: %+v, %v", st.Tags, err)
	}
	if m.Closed() != TagsDiffer || open(m) {
		t.Fatalf("an untagged node: closed %q", m.Closed())
	}
	report := string(jsvalueStringify(m.Report()))
	for _, want := range []string{`"node":{"status":"fail","reason":"TAGS_DIFFER"}`, `"warnings":["The node's tags (none) are not tailnet_tags (tag:varlatch)`} {
		if !strings.Contains(report, want) {
			t.Errorf("the listeners report lacks %s:\n%s", want, report)
		}
	}
	hosts, err := node.DERPHosts(ctx)
	if err != nil || len(hosts) == 0 {
		t.Errorf("the node's DERP map: %v %v", hosts, err)
	}
	if _, warnings := m.Explain(); warnings != nil {
		t.Errorf("a DERP warning for the embedded DERP server (%v): %q", hosts, warnings)
	}
	// The remedy: the node given tailnet_tags in Headscale.
	hs.Tag(t, hs.NodeID(t, "varlatch"), "tag:varlatch")
	checkUntil(t, ctx, m, "access open once tagged", func() bool { return m.Closed() == "" && open(m) })
	if report := string(jsvalueStringify(m.Report())); strings.Contains(report, "warnings") || !strings.Contains(report, `"node":{"status":"pass"}`) {
		t.Errorf("once tagged:\n%s", report)
	}
}

// resolveFrom is the resolution of a connection from to the listener of
// varlatchd's node at addr: the accepted socket's own peer address, as the
// tailnet listener resolves it.
func resolveFrom(t *testing.T, ctx context.Context, from *TSNode, ln net.Listener, addr string, r *Resolver) Resolution {
	t.Helper()
	accepted := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- ""
			return
		}
		accepted <- c.RemoteAddr().String()
		_ = c.Close()
	}()
	deadline := time.Now().Add(45 * time.Second)
	for {
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		c, err := from.srv.Dial(dctx, "tcp", addr)
		cancel()
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dialing %s: %v", addr, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	remote := <-accepted
	if remote == "" {
		t.Fatal("the listener accepted nothing")
	}
	return r.Resolve(ctx, remote)
}

// The identity cases on Headscale 0.29.7 (ADR-0059 Decision 5: the same
// positive and negative WhoIs cases as on Tailscale, shared and foreign
// peers not existing on Headscale): a tagged peer is known by its tags,
// never a login; a user's device by its user's login; the node itself is
// refused (self), and an address no device has (unrecognized). Every
// StableID is Headscale's node id (a number, per database: never a pin).
// With the node's tags no longer tailnet_tags, every peer is refused
// before WhoIs, until they are again.
func TestHeadscaleIdentity(t *testing.T) {
	headscaletest.Skip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	hs := headscaletest.Start(t, headscaleCA)
	dir := t.TempDir()
	if err := BeginEnrolment(dir); err != nil {
		t.Fatal(err)
	}
	node, err := StartNode(NodeConfig{Dir: filepath.Join(dir, StateDir), Hostname: "varlatch", ControlURL: hs.URL, AuthKey: hs.PreauthKey(t, "tag:varlatch"), Tags: []string{"tag:varlatch"}, KeyTags: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	if err := node.Up(ctx); err != nil {
		t.Fatalf("the node did not join Headscale: %v\nHeadscale's log:\n%s", err, hs.Logs())
	}
	m, err := NewManager(node, hs.URL, dir, 8687, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.RequireTags([]string{"tag:varlatch"})
	m.Check(ctx)
	if m.Closed() != "" {
		t.Fatalf("closed: %q", m.Closed())
	}
	st, err := node.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	selfID := hs.NodeID(t, "varlatch")
	if st.SelfID != selfID {
		t.Fatalf("the node's StableID %q is not Headscale's node id %q", st.SelfID, selfID)
	}
	if _, err := strconv.ParseUint(selfID, 10, 64); err != nil {
		t.Errorf("Headscale's node id is not a number: %q", selfID)
	}
	ln, err := node.Listen(8687)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	addr := net.JoinHostPort(st.Addresses[0], "8687")
	r := NewPinnedResolver(node, m, nil)

	ci := hsNode(t, ctx, hs, "ci-1", hs.PreauthKey(t, "tag:ci"))
	res := resolveFrom(t, ctx, ci, ln, addr, r)
	if c := res.Context; c == nil || c.Tailnet != headscaletest.BaseDomain || c.NodeID != hs.NodeID(t, "ci-1") || c.NodeName == nil || *c.NodeName != "ci-1" ||
		!slices.Equal(c.Tags, []string{"tag:ci"}) || c.UserLogin != nil {
		t.Errorf("a tagged peer: %s", jsvalueStringify(res.JSValue()))
	}
	laptop := hsNode(t, ctx, hs, "laptop", hs.PreauthKey(t))
	res = resolveFrom(t, ctx, laptop, ln, addr, r)
	if c := res.Context; c == nil || c.NodeID != hs.NodeID(t, "laptop") || len(c.Tags) != 0 || c.UserLogin == nil || !strings.HasPrefix(*c.UserLogin, headscaletest.User) {
		t.Errorf("a user's device: %s", jsvalueStringify(res.JSValue()))
	} else {
		t.Logf("a user's device on Headscale: userLogin %q, nodeId %q", *c.UserLogin, c.NodeID)
	}
	if res := r.Resolve(ctx, net.JoinHostPort(st.Addresses[0], "40000")); res.Refused != Self {
		t.Errorf("the node itself: %s", jsvalueStringify(res.JSValue()))
	}
	if res := r.Resolve(ctx, "100.64.255.254:40000"); res.Refused != Unrecognized {
		t.Errorf("an address no device has: %s", jsvalueStringify(res.JSValue()))
	}

	// The node's tags changed in Headscale: every peer refused before
	// WhoIs, a resolution made before no longer counts; tagged again, the
	// peer resolves as before.
	held := resolveFrom(t, ctx, ci, ln, addr, r)
	hs.Tag(t, selfID, "tag:prod")
	checkUntil(t, ctx, m, "access closed once retagged", func() bool { return m.Closed() == TagsDiffer })
	if d, _ := m.Explain(); !strings.Contains(d, "The node's tags (tag:prod) are not tailnet_tags (tag:varlatch)") {
		t.Errorf("the detail: %q", d)
	}
	if held.Valid() {
		t.Error("a resolution made before access closed still counts")
	}
	if res := resolveFrom(t, ctx, ci, ln, addr, r); res.Refused != ResolverUnavailable {
		t.Errorf("a peer with the node's tags not tailnet_tags: %s", jsvalueStringify(res.JSValue()))
	}
	hs.Tag(t, selfID, "tag:varlatch")
	checkUntil(t, ctx, m, "access open once tagged again", func() bool { return m.Closed() == "" })
	if res := resolveFrom(t, ctx, ci, ln, addr, r); res.Context == nil || res.Context.NodeID != hs.NodeID(t, "ci-1") {
		t.Errorf("a tagged peer once the node is tagged again: %s", jsvalueStringify(res.JSValue()))
	}
	// The StableIDs hold across the retagging.
	if st, err := node.Status(ctx); err != nil || st.SelfID != selfID {
		t.Errorf("the node's StableID after retagging: %q %v", st.SelfID, err)
	}
}
