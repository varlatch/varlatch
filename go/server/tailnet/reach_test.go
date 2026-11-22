// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The reach check (go-step7 decision 11): a probe node sees the name held
// by exactly the expected node, by StableID, case-insensitively; another
// StableID, or a name nobody holds, does not reach. The probe leaves no
// state.
func TestReaches(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	control, key, _ := keyedControl(t)
	n, err := StartNode(NodeConfig{Dir: t.TempDir(), Hostname: "Vault-vl-1-n", ControlURL: control.BaseURL(), AuthKey: key, Tags: []string{"tag:varlatch"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.Close() })
	if err := n.Up(ctx); err != nil {
		t.Fatal(err)
	}
	id, err := n.SelfID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ev := &events{}
	c := ProbeConfig{Dir: dir, ControlURL: control.BaseURL(), AuthKey: key, Tags: []string{"tag:varlatch"}, observe: ev.add}
	res, err := Reaches(ctx, c, "vault-vl-1-n", id, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reaches || len(res.Holders) != 1 || res.Holders[0].StableID != id || !strings.HasPrefix(res.Holders[0].DNSName, "vault-vl-1-n.") {
		t.Fatalf("%+v", res)
	}
	if ev.count("join varlatch-reach-probe-") != 1 || ev.count("logout ") != 1 {
		t.Fatalf("the probe node: %q", ev.list)
	}
	if res, err := Reaches(ctx, c, "vault-vl-1-n", "nSomeoneElse", 0); err != nil || res.Reaches || len(res.Holders) != 1 {
		t.Fatalf("another StableID: %+v %v", res, err)
	}
	if res, err := Reaches(ctx, c, "vault", id, 0); err != nil || res.Reaches || len(res.Holders) != 0 {
		t.Fatalf("a name nobody holds: %+v %v", res, err)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("the probe left state: %v", left)
	}
}

func TestTheHold(t *testing.T) {
	dir := t.TempDir()
	if h, err := LoadHold(dir); err != nil || h != nil {
		t.Fatalf("no hold: %+v %v", h, err)
	}
	if err := ClearHold(dir); err != nil {
		t.Fatalf("clearing no hold: %v", err)
	}
	if err := SaveHold(dir, &Hold{Hostname: "vault-vl-1-n", Since: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(dir, HoldFile)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the hold's mode: %v %v", st, err)
	}
	if h, err := LoadHold(dir); err != nil || h == nil || h.Hostname != "vault-vl-1-n" {
		t.Fatalf("the hold: %+v %v", h, err)
	}
	if err := ClearHold(dir); err != nil {
		t.Fatal(err)
	}
	if h, err := LoadHold(dir); err != nil || h != nil {
		t.Fatalf("after clearing: %+v %v", h, err)
	}
	// An unreadable hold fails closed: never taken for none.
	if err := os.WriteFile(filepath.Join(dir, HoldFile), []byte(`{"hostname":"../x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHold(dir); err == nil {
		t.Fatal("an invalid hold was read")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".hold-*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

func TestCachedNotAfter(t *testing.T) {
	dir := t.TempDir()
	if _, ok, err := CachedNotAfter(dir, "vault.corp.ts.net"); ok || err != nil {
		t.Fatalf("no certificate: %v %v", ok, err)
	}
	if err := os.MkdirAll(filepath.Dir(CertFile(dir, "vault.corp.ts.net")), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(CertFile(dir, "Vault.corp.ts.net"), []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CachedNotAfter(dir, "vault.corp.ts.net"); err == nil {
		t.Fatal("a broken certificate was read")
	}
}
