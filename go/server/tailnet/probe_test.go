// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// keyedControl is a control server that takes one auth key (made at run
// time), behind a gate: once spent, it answers nothing, as a control plane
// refuses a single-use key used before.
func keyedControl(t *testing.T) (*testcontrol.Server, string, *atomic.Bool) {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	key := hex.EncodeToString(b)
	derp := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	c := &testcontrol.Server{
		DERPMap: derp, DNSConfig: &tailcfg.DNSConfig{Proxied: true}, MagicDNSDomain: testSuffix, Logf: logger.Discard,
		TagOwners: map[string][]string{"tag:varlatch": nil}, RequireAuthKey: key,
	}
	spent := &atomic.Bool{}
	c.HTTPTestServer = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if spent.Load() {
			http.Error(w, "the key is spent", http.StatusUnauthorized)
			return
		}
		c.ServeHTTP(w, r)
	}))
	c.HTTPTestServer.Start()
	t.Cleanup(c.HTTPTestServer.Close)
	return c, key, spent
}

type events struct {
	mu   sync.Mutex
	list []string
}

func (e *events) add(s string) { e.mu.Lock(); e.list = append(e.list, s); e.mu.Unlock() }

func (e *events) count(prefix string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(slices.DeleteFunc(slices.Clone(e.list), func(s string) bool { return !strings.HasPrefix(s, prefix) }))
}

// The probe (decision 16): ephemeral probe nodes join with the key, see a
// peer that holds the configured name (case-insensitively), log out, and
// leave no state; a key that joins once only is reported single-use.
func TestTheProbeSeesAHeldName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	control, key, _ := keyedControl(t)
	old := &tsNetPeer{}
	old.start(t, control, ctx, key, "VarLatch")
	dir := t.TempDir()
	ev := &events{}
	res, err := ProbeName(ctx, ProbeConfig{Dir: dir, Hostname: "varlatch", ControlURL: control.BaseURL(), AuthKey: key, Tags: []string{"tag:varlatch"}, observe: ev.add})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Seen) != 1 || !strings.HasPrefix(res.Seen[0], "varlatch.") || !res.Reusable {
		t.Fatalf("%+v", res)
	}
	if ev.count("join ") != 2 || ev.count("logout ") != 2 || ev.count("removed ") != 2 || ev.count("join varlatch-restore-probe-") != 2 {
		t.Fatalf("the probe nodes: %q", ev.list)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("the probe left state: %v", left)
	}
}

func TestTheProbeFindsASingleUseKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	control, key, spent := keyedControl(t)
	dir := t.TempDir()
	ev := &events{}
	res, err := ProbeName(ctx, ProbeConfig{Dir: dir, Hostname: "varlatch", ControlURL: control.BaseURL(), AuthKey: key, Tags: []string{"tag:varlatch"},
		Timeout: 15 * time.Second, betweenJoins: func() { spent.Store(true) }, observe: ev.add})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Seen) != 0 || res.Reusable || res.SecondJoin == "" {
		t.Fatalf("%+v", res)
	}
	if ev.count("logout ") != 1 || ev.count("removed ") != 2 {
		t.Fatalf("the probe nodes: %q", ev.list)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("the probe left state: %v", left)
	}
	// A key the control plane refuses: nothing could be checked.
	if _, err := ProbeName(ctx, ProbeConfig{Dir: dir, Hostname: "varlatch", ControlURL: control.BaseURL(), AuthKey: key, Tags: []string{"tag:varlatch"}, Timeout: 10 * time.Second}); err == nil {
		t.Error("a refused key probed")
	}
}

// tsNetPeer is the old installation's node, still on the tailnet.
type tsNetPeer struct{}

func (tsNetPeer) start(t *testing.T, control *testcontrol.Server, ctx context.Context, key, hostname string) {
	t.Helper()
	n, err := StartNode(NodeConfig{Dir: t.TempDir(), Hostname: hostname, ControlURL: control.BaseURL(), AuthKey: key, Tags: []string{"tag:varlatch"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.Close() })
	if err := n.Up(ctx); err != nil {
		t.Fatal(err)
	}
}
