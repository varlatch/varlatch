// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build headscale && linux

package tailnet

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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

// An untagged pre-auth key (a user's) joins the node untagged: access
// stays open, and the listeners report says it (step 7.5c c1; c3 closes
// access when the tags are not tailnet_tags).
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
	m.Check(ctx)
	if st, err := node.Status(ctx); err != nil || len(st.Tags) != 0 {
		t.Fatalf("the node's tags with an untagged key: %+v, %v", st.Tags, err)
	}
	if m.Closed() != "" {
		t.Errorf("access closed: %q", m.Closed())
	}
	if report := string(jsvalueStringify(m.Report())); !strings.Contains(report, `"warnings":["`+UntaggedWarning+`"]`) {
		t.Errorf("the listeners report does not say the node is untagged:\n%s", report)
	}
}
