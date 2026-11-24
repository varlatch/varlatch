// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"

	"github.com/varlatch/varlatch/go/server/tailnet"
	"github.com/varlatch/varlatch/go/server/tailnet/tailnettest"
)

// shortNodeWait is nodeWait for the test.
func shortNodeWait(t *testing.T, d time.Duration) {
	t.Helper()
	prev := nodeWait
	nodeWait = d
	t.Cleanup(func() { nodeWait = prev })
}

// netmapWorld is an installation whose node has enrolled under temp on an
// in-process control server, and opened: no handoff holds it.
type netmapWorld struct {
	in       install
	control  *testcontrol.Server
	temp     string
	stableID string
}

// netmapTemp is the handoff's temporary name.
const netmapTemp = "vault-vl-0123456789ab-n"

func newNetmapWorld(t *testing.T) *netmapWorld {
	t.Helper()
	w := &netmapWorld{control: startTestControl(t), temp: netmapTemp}
	prev := nodeControlURL
	nodeControlURL = w.control.BaseURL()
	t.Cleanup(func() { nodeControlURL = prev })
	w.in = newInstall(t, "")
	keyFile := filepath.Join(w.in.dir, "tailnet-auth-key")
	if err := os.WriteFile(keyFile, []byte("hermetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.in.write(t, fmt.Sprintf("tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_auth_key_file = %s\n", keyFile))
	if err := os.MkdirAll(w.in.data, 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := w.enroll(t)
	var en enrollResult
	if code != ExitOK || json.Unmarshal([]byte(out), &en) != nil {
		t.Fatalf("enroll: %d %q %q", code, out, errOut)
	}
	w.stableID = en.StableID
	if code, _, errOut := runAdmin(t, "tailnet", "open", "--config", w.in.conf); code != ExitOK {
		t.Fatalf("open: %d %q", code, errOut)
	}
	return w
}

func (w *netmapWorld) enroll(t *testing.T) (int, string, string) {
	t.Helper()
	return runAdmin(t, "tailnet", "enroll", "--hostname", w.temp, "--json", "--config", w.in.conf)
}

// change is the control plane's change of the node, pushed to it.
func (w *netmapWorld) change(t *testing.T, f func(n *tailcfg.Node)) {
	t.Helper()
	for _, n := range w.control.AllNodes() {
		if string(n.StableID) == w.stableID {
			f(n)
			w.control.UpdateNode(n)
			return
		}
	}
	t.Fatal("the node is not in the control server")
}

func (w *netmapWorld) rename(t *testing.T, label string) {
	t.Helper()
	w.change(t, func(n *tailcfg.Node) { n.Name = label + ".corp.ts.net." })
}

// renameLate renames the node after d, while something waits for it: what
// the control plane records first and its map says later. The test waits
// for it.
func (w *netmapWorld) renameLate(t *testing.T, label string, d time.Duration) {
	t.Helper()
	var done sync.WaitGroup
	t.Cleanup(done.Wait)
	done.Add(1)
	go func() {
		defer done.Done()
		time.Sleep(d)
		for _, n := range w.control.AllNodes() {
			if string(n.StableID) == w.stableID {
				n.Name = label + ".corp.ts.net."
				w.control.UpdateNode(n)
			}
		}
	}()
}

func (w *netmapWorld) stateDir() string { return filepath.Join(w.in.data, tailnet.StateDir) }

// cacheMap starts and stops the node as a varlatchd before this one did,
// tsnet's network map cache on, until the node's map is on disk.
func (w *netmapWorld) cacheMap(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { envknob.Setenv("TS_USE_CACHED_NETMAP", "false") })
	envknob.Setenv("TS_NO_LOGS_NO_SUPPORT", "true")
	cached := func() bool {
		files, _ := filepath.Glob(filepath.Join(w.stateDir(), "profile-data", "*", "netmap-cache", "*"))
		return len(files) > 0
	}
	for range 40 {
		envknob.Setenv("TS_USE_CACHED_NETMAP", "true")
		srv := &tsnet.Server{Dir: w.stateDir(), Hostname: w.temp, ControlURL: w.control.BaseURL(), AdvertiseTags: []string{"tag:varlatch"}, Logf: logger.Discard, UserLogf: logger.Discard}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		if _, err := srv.Up(ctx); err != nil {
			t.Fatal(err)
		}
		// Written about when the node is up, and discarded by the next whole
		// map: it stays when the node closes in between.
		for end := time.Now().Add(time.Second); time.Now().Before(end) && !cached(); {
			time.Sleep(time.Millisecond)
		}
		_ = srv.Close()
		cancel()
		if cached() {
			return
		}
	}
	t.Fatal("tsnet cached no network map: this test shows nothing")
}

func (w *netmapWorld) held(t *testing.T) bool {
	t.Helper()
	h, err := tailnet.LoadHold(w.in.data)
	if err != nil {
		t.Fatal(err)
	}
	return h != nil
}

// A handoff undone gives the node its temporary name back while it is
// stopped; enroll then holds it again, at the first call, though the map
// cached on its disk names it vault (the G5 gate's undone rollback).
func TestEnrollHoldsAgainWhateverIsCached(t *testing.T) {
	shortNodeWait(t, 10*time.Second)
	w := newNetmapWorld(t)
	for range 3 {
		w.rename(t, "vault")
		w.cacheMap(t)
		w.rename(t, w.temp)
		if code, _, errOut := w.enroll(t); code != ExitOK || !w.held(t) {
			t.Fatalf("enroll after the undo: %d %q", code, errOut)
		}
		if code, _, errOut := runAdmin(t, "tailnet", "open", "--config", w.in.conf); code != ExitOK {
			t.Fatalf("open: %d %q", code, errOut)
		}
	}
}

// The other way: the map cached on its disk gives it the temporary name and
// the control plane does not. It is refused, and nothing is changed.
func TestEnrollNeverAcceptsACachedName(t *testing.T) {
	shortNodeWait(t, 2*time.Second)
	w := newNetmapWorld(t)
	w.cacheMap(t)
	w.rename(t, "vault")
	code, _, errOut := w.enroll(t)
	if code != ExitFailure || !strings.Contains(errOut, "enrolled as vault.corp.ts.net and not held") || !strings.Contains(errOut, "only a node named "+w.temp) {
		t.Fatalf("enroll under a name only the cache gives it: %d %q", code, errOut)
	}
	if w.held(t) {
		t.Fatal("a refused enrolment held the node")
	}
}

// The control plane's map lags its own record of the name: enroll waits for
// it, within a bound, and refuses a name that does not come, naming both.
func TestEnrollWaitsForTheControlPlanesName(t *testing.T) {
	w := newNetmapWorld(t)
	shortNodeWait(t, 20*time.Second)
	w.rename(t, "vault")
	w.renameLate(t, w.temp, 3*time.Second)
	if code, _, errOut := w.enroll(t); code != ExitOK || !w.held(t) {
		t.Fatalf("enroll with a rename that comes late: %d %q", code, errOut)
	}
	// Held: the same wait, the other refusal.
	shortNodeWait(t, 2*time.Second)
	w.rename(t, "vault")
	begun := time.Now()
	code, _, errOut := w.enroll(t)
	if took := time.Since(begun); code != ExitFailure || took < 2*time.Second || took > 30*time.Second ||
		!strings.Contains(errOut, "joined as vault.corp.ts.net, not "+w.temp) || !regexp.MustCompile(`did not name it so in \d+s: `).MatchString(errOut) {
		t.Fatalf("enroll with a rename that never comes: %d in %v %q", code, took, errOut)
	}
	if pin, err := tailnet.LoadPin(filepath.Join(w.in.data, tailnet.PinFile)); err != nil || pin == nil || pin.Closed != nil {
		t.Fatalf("another name latched the pin: %+v %v", pin, err)
	}
	// Not held: refused too, and not held by it.
	if code, _, errOut := runAdmin(t, "tailnet", "open", "--config", w.in.conf); code != ExitOK {
		t.Fatalf("open: %d %q", code, errOut)
	}
	if code, _, errOut := w.enroll(t); code != ExitFailure || !regexp.MustCompile(`did not name it in \d+s; nothing was changed`).MatchString(errOut) || w.held(t) {
		t.Fatalf("enroll again with a rename that never comes: %d %q", code, errOut)
	}
}

// The name's certificate, right after the rename: asked for once the node's
// own map names it so (tsnet refuses it at once before), and never under
// another name.
func TestACertificateWaitsForTheNodesName(t *testing.T) {
	w := newNetmapWorld(t)
	ca, err := tailnettest.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	prev := obtainNodeCert
	var asked []string
	obtainNodeCert = func(ctx context.Context, n *tailnet.TSNode, dataDir, domain string) ([]byte, error) {
		st, err := n.Status(ctx)
		if err != nil {
			return nil, err
		}
		asked = append(asked, st.DNSName)
		certPEM, keyPEM, err := ca.CertPair(ctx, domain, 0)
		clear(keyPEM)
		return certPEM, err
	}
	t.Cleanup(func() { obtainNodeCert = prev })
	obtain := func() (int, string, string) {
		return runAdmin(t, "tailnet", "certificate", "obtain", "--name", "vault", "--json", "--config", w.in.conf)
	}
	shortNodeWait(t, 20*time.Second)
	w.renameLate(t, "vault", 3*time.Second)
	if code, out, errOut := obtain(); code != ExitOK || len(asked) != 1 || asked[0] != "vault.corp.ts.net" {
		t.Fatalf("obtain with a rename that comes late: %d %q %q, asked as %v", code, out, errOut, asked)
	}
	shortNodeWait(t, 2*time.Second)
	w.rename(t, w.temp)
	code, out, errOut := obtain()
	if code != ExitFailure || len(asked) != 1 || !strings.Contains(out, `"refusal":"failed"`) ||
		!regexp.MustCompile(`the node's name is `+w.temp+`\.corp\.ts\.net, not vault\.corp\.ts\.net, for \d+s: `).MatchString(errOut) || !strings.Contains(errOut, "no certificate was asked for") {
		t.Fatalf("obtain with a rename that never comes: %d %q %q, asked as %v", code, out, errOut, asked)
	}
}

// On a self-hosted control server the node's tags are checked at the
// enrolment: tags the operator has just given it are waited for, and other
// ones refused as before.
func TestEnrollWaitsForTheNodesTags(t *testing.T) {
	control := startTestControl(t)
	prev := nodeControlURL
	nodeControlURL = control.BaseURL()
	t.Cleanup(func() { nodeControlURL = prev })
	in := newInstall(t, "")
	keyFile := filepath.Join(in.dir, "tailnet-auth-key")
	if err := os.WriteFile(keyFile, []byte("hermetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in.write(t, fmt.Sprintf("tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_auth_key_file = %s\ntailnet_control_url = https://192.0.2.10\n", keyFile))
	if err := os.MkdirAll(in.data, 0o700); err != nil {
		t.Fatal(err)
	}
	enroll := func() (int, string, string) {
		return runAdmin(t, "tailnet", "enroll", "--hostname", netmapTemp, "--json", "--config", in.conf)
	}
	shortNodeWait(t, 2*time.Second)
	if code, _, errOut := enroll(); code != ExitFailure || !strings.Contains(errOut, "run enroll again (the node stays held)") {
		t.Fatalf("enroll without its tags: %d %q", code, errOut)
	}
	shortNodeWait(t, 20*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(2 * time.Second)
		for _, n := range control.AllNodes() {
			n.Tags = []string{"tag:varlatch"}
			control.UpdateNode(n)
		}
	}()
	code, _, errOut := enroll()
	<-done
	if code != ExitOK {
		t.Fatalf("enroll with tags given while it looks: %d %q", code, errOut)
	}
}
