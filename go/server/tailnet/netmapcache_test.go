// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// cachedMap starts and stops tsnet on the node's state directory as a
// varlatchd before this one did, with tsnet's network map cache on, until
// the node's map is cached there.
func cachedMap(t *testing.T, control *testcontrol.Server, dir, hostname string) {
	t.Helper()
	// Off again for whatever starts after it.
	t.Cleanup(func() { envknob.Setenv(netmapCacheEnv, "false") })
	prepareTsnet()
	for range 40 {
		envknob.Setenv(netmapCacheEnv, "true")
		srv := &tsnet.Server{Dir: dir, Hostname: hostname, ControlURL: control.BaseURL(), AdvertiseTags: []string{"tag:varlatch"}, Logf: logger.Discard, UserLogf: logger.Discard}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		if _, err := srv.Up(ctx); err != nil {
			t.Fatal(err)
		}
		// The home DERP region's choice writes it, about when the node is
		// up, and the next whole map discards it: it stays when the node
		// closes in between, as a handoff's short-lived node does.
		for end := time.Now().Add(time.Second); time.Now().Before(end) && !hasCachedMap(dir); {
			time.Sleep(time.Millisecond)
		}
		_ = srv.Close()
		cancel()
		if hasCachedMap(dir) {
			return
		}
	}
	t.Fatal("tsnet cached no network map: this test shows nothing")
}

func hasCachedMap(dir string) bool {
	files, _ := filepath.Glob(filepath.Join(dir, ipnlocal.ProfileDataDir, "*", netmapCacheDir, "*"))
	return len(files) > 0
}

// rename is the control plane's rename of its one node named from.
func rename(t *testing.T, control *testcontrol.Server, from, to string) {
	t.Helper()
	for _, n := range control.AllNodes() {
		if n.Name == from+"."+testSuffix+"." {
			n.Name = to + "." + testSuffix + "."
			control.UpdateNode(n)
			return
		}
	}
	t.Fatalf("the control server has no node named %s", from)
}

// A node restarted after the control plane renamed it is what the control
// plane says it is now, from its first status: never the map cached on disk
// before, which tsnet would be Running on before it spoke to the control
// plane. The cache an earlier varlatchd left is removed.
func TestARestartedNodeNeverReadsACachedMap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	control := startControl(t)
	dir := t.TempDir()
	start := func() *TSNode {
		t.Helper()
		// Whatever varlatchd's environment says.
		t.Setenv(netmapCacheEnv, "true")
		n, err := StartNode(NodeConfig{Dir: dir, Hostname: "vault-1", ControlURL: control.BaseURL(), Tags: []string{"tag:varlatch"}})
		if err != nil {
			t.Fatal(err)
		}
		if envknob.BoolDefaultTrue(netmapCacheEnv) {
			t.Error("the node started with tsnet's network map cache on")
		}
		return n
	}
	n := start()
	if err := n.Up(ctx); err != nil {
		t.Fatal(err)
	}
	_ = n.Close()
	name := "vault-1"
	for _, to := range []string{"vault-2", "vault-3", "vault-4"} {
		cachedMap(t, control, dir, name)
		rename(t, control, name, to)
		n := start()
		if hasCachedMap(dir) {
			t.Error("the cached map an earlier start left was not removed")
		}
		if err := n.Up(ctx); err != nil {
			t.Fatal(err)
		}
		st, err := n.Status(ctx)
		_ = n.Close()
		if err != nil || st.Label() != to {
			t.Fatalf("renamed %s to %s while it was stopped, the node reads %q: %v", name, to, st.DNSName, err)
		}
		name = to
	}
}

// A node whose control plane does not answer is not on its tailnet, whatever
// was cached: nothing (the pin, its tags, its name, its peers) is judged by a
// map of an earlier start.
func TestANodeIsNotUpWithoutItsControlPlane(t *testing.T) {
	control := startControl(t)
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	n, err := StartNode(NodeConfig{Dir: dir, Hostname: "varlatch", ControlURL: control.BaseURL(), Tags: []string{"tag:varlatch"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Up(ctx); err != nil {
		t.Fatal(err)
	}
	_ = n.Close()
	cachedMap(t, control, dir, "varlatch")
	url := control.BaseURL()
	control.HTTPTestServer.Close()
	n, err = StartNode(NodeConfig{Dir: dir, Hostname: "varlatch", ControlURL: url, Tags: []string{"tag:varlatch"}})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	uctx, ucancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer ucancel()
	if err := n.Up(uctx); err == nil {
		st, _ := n.Status(context.Background())
		t.Fatalf("up without its control plane, as %s (%s)", st.DNSName, st.BackendState)
	}
	if st, err := n.Status(context.Background()); err != nil || st.BackendState == "Running" || st.DNSName != "" {
		t.Fatalf("the status without its control plane: %+v %v", st, err)
	}
}

// The cache is removed below the node's state directory only, never through
// a link that leaves it.
func TestTheCachedMapIsRemovedInTheStateDirectoryOnly(t *testing.T) {
	outside := t.TempDir()
	kept := filepath.Join(outside, "p", netmapCacheDir, "self")
	if err := os.MkdirAll(filepath.Dir(kept), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kept, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, ipnlocal.ProfileDataDir)); err != nil {
		t.Skip(err)
	}
	dropNetmapCache(dir)
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("removed through a link: %v", err)
	}
	// Other data of a profile stays; a directory without any is nothing.
	dir = t.TempDir()
	profile := filepath.Join(dir, ipnlocal.ProfileDataDir, "ab12")
	for _, f := range []string{filepath.Join(profile, netmapCacheDir, "self"), filepath.Join(profile, "other", "x")} {
		if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dropNetmapCache(dir)
	if _, err := os.Stat(filepath.Join(profile, netmapCacheDir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the cache stays: %v", err)
	}
	if _, err := os.Stat(filepath.Join(profile, "other", "x")); err != nil {
		t.Errorf("other data of the profile: %v", err)
	}
	dropNetmapCache(filepath.Join(dir, "none"))
}

func TestAwaitStatus(t *testing.T) {
	named := func(label string) Status { return Status{BackendState: "Running", DNSName: label + "." + testSuffix} }
	want := func(s Status) bool { return s.Label() == "vault" }
	// reads answers each in turn, the last one for good.
	reads := func(n *int, answers ...Status) func(context.Context) (Status, error) {
		return func(context.Context) (Status, error) {
			i := min(*n, len(answers)-1)
			*n++
			if answers[i].BackendState == "" {
				return Status{}, errors.New("not yet")
			}
			return answers[i], nil
		}
	}
	ctx := context.Background()
	var n int
	if st, ok, err := awaitStatus(ctx, 10*time.Second, reads(&n, named("old"), Status{}, named("old"), named("vault")), want); err != nil || !ok || st.Label() != "vault" || n != 4 {
		t.Errorf("a name that arrives late: %+v %v %v after %d", st, ok, err, n)
	}
	// As expected at once: no wait.
	n = 0
	begun := time.Now()
	if _, ok, err := awaitStatus(ctx, 10*time.Second, reads(&n, named("vault")), want); err != nil || !ok || n != 1 || time.Since(begun) > time.Second {
		t.Errorf("already named: %v %v after %d", ok, err, n)
	}
	// Never: the last status, not as expected, in the wait and no longer.
	n, begun = 0, time.Now()
	st, ok, err := awaitStatus(ctx, 700*time.Millisecond, reads(&n, named("old"), named("other")), want)
	if took := time.Since(begun); err != nil || ok || st.Label() != "other" || took < 600*time.Millisecond || took > 5*time.Second {
		t.Errorf("a name that never arrives: %+v %v %v in %v", st, ok, err, took)
	}
	// A name of another case, a longer label or a part of it is another.
	for _, other := range []string{"vault-1", "vaul", "Vault"} {
		n = 0
		if _, ok, _ := awaitStatus(ctx, 10*time.Millisecond, reads(&n, named(other)), want); ok {
			t.Errorf("%s passed for vault", other)
		}
	}
	// Never readable, and the caller's end.
	n = 0
	if _, ok, err := awaitStatus(ctx, 300*time.Millisecond, reads(&n, Status{}), want); err == nil || ok {
		t.Errorf("never readable: %v %v", ok, err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	n, begun = 0, time.Now()
	if _, ok, _ := awaitStatus(cctx, time.Minute, reads(&n, named("old")), want); ok || time.Since(begun) > 5*time.Second {
		t.Errorf("the caller's end did not end the wait: %v", time.Since(begun))
	}
}
