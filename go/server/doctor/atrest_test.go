// SPDX-License-Identifier: AGPL-3.0-or-later

package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/tailnet"
)

const tailnetOn = "tailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\n"

// The tailnet's auth key: kept while the node enrols, said once it has
// joined (advisory: a migration or a takeover may still need it), never
// open to others; gone or never configured passes.
func TestTailnetAuthKeyOnDisk(t *testing.T) {
	key := filepath.Join(t.TempDir(), "tailnet-auth-key")
	f := newFixture(t, tailnetOn+"tailnet_auth_key_file = "+key+"\n")
	f.in.Live.Tailnet = true
	pin := filepath.Join(f.cfg.DataDir, pinFile)
	check := func(want, detail, remedy string) {
		t.Helper()
		r := f.run(t)
		c := checkOf(t, r, "tailnet.auth-key")
		if c.Status != want || c.Class != Advisory || !strings.Contains(c.Detail, detail) || !strings.Contains(c.Remedy, remedy) {
			t.Errorf("%+v\nwant %s, detail containing %q, remedy containing %q", c, want, detail, remedy)
		}
		if r.Failed() {
			t.Error("an advisory check failed doctor")
		}
	}
	check(Pass, "is not on disk", "")
	if err := os.WriteFile(key, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0o640); err != nil {
		t.Fatal(err)
	}
	check(Pass, "stays until the node has joined", "") // no pin: never enrolled
	if err := os.WriteFile(pin, []byte(`{"controlUrl":"","tailnetId":"","suffix":"","pinnedAt":"","enrolling":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	check(Pass, "stays until the node has joined", "") // enrolling
	if err := os.WriteFile(pin, []byte(`{"controlUrl":"","tailnetId":"T1","suffix":"example.ts.net","pinnedAt":"2026-11-20T12:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	check(Fail, "the node has joined its tailnet, and its auth key is still on disk at "+key, "sudo rm "+key)
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	check(Fail, "readable by others (mode 0644)", "chmod 0640 "+key)
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	check(Pass, "is not on disk", "")

	// A node with state of its own and no pin never enrols again.
	if err := os.Remove(pin); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.cfg.DataDir, "tailnet"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.cfg.DataDir, "tailnet", "tailscaled.state"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	check(Fail, "the node has joined its tailnet", "sudo rm "+key)
}

// The bucket key file: the service's group may read it, nobody else; a
// group-writable one, one open to others or another group's fails doctor.
func TestBucketKeyFile(t *testing.T) {
	f := newFixture(t, "")
	key := filepath.Join(f.dir, "bucket-write.json")
	for _, c := range []struct {
		mode           os.FileMode
		status, detail string
	}{
		{0o640, Pass, "(mode 0640)"},
		{0o600, Pass, "(mode 0600)"},
		{0o400, Pass, "(mode 0400)"},
		{0o644, Fail, "is open to others (mode 0644)"},
		{0o660, Fail, "may be written by its group (mode 0660)"},
	} {
		if err := os.Chmod(key, c.mode); err != nil {
			t.Fatal(err)
		}
		r := f.run(t)
		got := checkOf(t, r, "files.bucket-key")
		if got.Status != c.status || got.Class != Mandatory || !strings.Contains(got.Detail, c.detail) || r.Failed() != (c.status == Fail) {
			t.Errorf("mode %04o: %+v (failed %v)", c.mode, got, r.Failed())
		}
		if c.status == Fail && !strings.Contains(got.Remedy, "chmod 0640 "+key) {
			t.Errorf("mode %04o: remedy %q", c.mode, got.Remedy)
		}
	}
	if err := os.Chmod(key, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if c := checkOf(t, f.run(t), "files.bucket-key"); c.Status != Fail || !strings.Contains(c.Detail, "is missing") {
		t.Errorf("missing: %+v", c)
	}
}

// Whether the bucket key may read: what the running varlatchd found,
// advisory, never failing doctor.
func TestBucketKeyRead(t *testing.T) {
	f := newFixture(t, "")
	if c := checkOf(t, f.run(t), "backups.bucket-key-read"); c.Status != Pass || c.Class != Advisory || !strings.Contains(c.Detail, "may not read") {
		t.Errorf("write-only: %+v", c)
	}
	reads := true
	f.in.Live.BucketKeyReads, f.in.Live.BucketKeyDetail = &reads, "the key read the metadata of varlatch/x.vltbak"
	r := f.run(t)
	if c := checkOf(t, r, "backups.bucket-key-read"); c.Status != Fail || !strings.Contains(c.Detail, "may read archives") || !strings.Contains(c.Remedy, "may only write") || r.Failed() {
		t.Errorf("reads: %+v (failed %v)", c, r.Failed())
	}
	f.in.Live.BucketKeyReads, f.in.Live.BucketKeyDetail = nil, "asking the destination failed"
	if c := checkOf(t, f.run(t), "backups.bucket-key-read"); c.Status != Unknown || c.Detail != "asking the destination failed" {
		t.Errorf("unknown: %+v", c)
	}
	f.in.Live = nil
	if c := checkOf(t, f.run(t), "backups.bucket-key-read"); c.Status != Unknown {
		t.Errorf("no varlatchd: %+v", c)
	}
}

// doctor reads the tailnet's files by their names, without importing tsnet.
func TestTheTailnetsFileNames(t *testing.T) {
	if pinFile != tailnet.PinFile || tailnet.StateDir != "tailnet" {
		t.Fatalf("doctor reads %s and tailnet/, the tailnet writes %s and %s/", pinFile, tailnet.PinFile, tailnet.StateDir)
	}
}
