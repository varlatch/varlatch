// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/varlatch/varlatch/go/lib/envelope"
)

// A backup seals an archive and opens it again for its check: with one
// KeyCache the archive key (scrypt) is derived once, not twice; without
// one each derives. A different salt derives again. Clear zeroes the key.
// The archive is the same either way: Open without a cache opens it.
func TestKeyCacheDerivesOnce(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	bek, _ := KeyBEK(key)
	dir := t.TempDir()
	files, paths := components(t, dir, 300_000, 10)
	manifest := goManifest(t, envelope.GenerateKey(), files)

	seal := func(name string, keys *KeyCache) string {
		out := filepath.Join(dir, name)
		if err := Seal(out, manifest, paths, bek, SealOptions{Keys: keys}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	open := func(path string, keys *KeyCache) {
		o, err := OpenWith(path, bek, dir, OpenOptions{Keys: keys})
		if err != nil {
			t.Fatal(err)
		}
		o.Close()
	}

	keys := &KeyCache{}
	before := Derivations()
	a := seal("a.vlt", keys)
	open(a, keys)
	if n := Derivations() - before; n != 1 {
		t.Fatalf("seal and check with one cache derived %d keys, want 1", n)
	}
	// Another archive: another salt, derived again, and then cached.
	before = Derivations()
	b := seal("b.vlt", keys)
	open(b, keys)
	if n := Derivations() - before; n != 1 {
		t.Fatalf("a second archive derived %d keys, want 1", n)
	}
	cached := keys.key
	keys.Clear()
	if keys.key != nil || keys.salt != nil || !bytes.Equal(cached, make([]byte, len(cached))) {
		t.Fatalf("Clear left the key: %x", cached)
	}
	// Without a cache: one derivation each, and the archives open alike.
	before = Derivations()
	open(a, nil)
	open(b, nil)
	c := seal("c.vlt", nil)
	open(c, nil)
	if n := Derivations() - before; n != 4 {
		t.Fatalf("without a cache %d derivations, want 4", n)
	}
	// A cache holding another archive's key still opens this one.
	other := &KeyCache{}
	open(a, other)
	before = Derivations()
	open(b, other)
	if n := Derivations() - before; n != 1 {
		t.Fatalf("a cache holding another salt derived %d, want 1", n)
	}
	other.Clear()
}

// The check's two passes (decryption, the components' SHA-256) and the
// manifest's hashing go through their pacers chunk by chunk, with the bytes
// so far; every check is still made, and a pacer's error ends them.
func TestOpenAndDescribePaced(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	bek, _ := KeyBEK(key)
	dir := t.TempDir()
	sizes := []int{3<<20 + 5, 1000}
	files, paths := components(t, dir, sizes...)
	manifest := goManifest(t, envelope.GenerateKey(), files)
	out := filepath.Join(dir, "a.vlt")
	if err := Seal(out, manifest, paths, bek, SealOptions{}); err != nil {
		t.Fatal(err)
	}

	var calls []int64
	o, err := OpenWith(out, bek, dir, OpenOptions{Pace: func(done int64) error { calls = append(calls, done); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	o.Close()
	plain := int64(len(manifest) + 4 + sizes[0] + sizes[1])
	want := plain + int64(sizes[0]+sizes[1]) // decrypted, then hashed
	if len(calls) < 6 || calls[len(calls)-1] != want {
		t.Fatalf("paced %d times, to %v; want at least 6, to %d", len(calls), calls[len(calls)-1:], want)
	}
	for i := 1; i < len(calls); i++ {
		if calls[i] <= calls[i-1] || calls[i]-calls[i-1] > chunk {
			t.Fatalf("pace steps %v", calls)
		}
	}
	// A pacer's error ends the check, with nothing left behind.
	stop := errors.New("stopped")
	n := 0
	if _, err := OpenWith(out, bek, dir, OpenOptions{Pace: func(int64) error {
		if n++; n == 3 {
			return stop
		}
		return nil
	}}); !errors.Is(err, stop) {
		t.Fatalf("open with a failing pacer: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "varlatch-backup-*")); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
	// A changed byte is still refused with a pacer.
	raw, _ := os.ReadFile(out)
	bad := filepath.Join(dir, "bad.vlt")
	os.WriteFile(bad, flip(raw, len(raw)/2), 0o600)
	if _, err := OpenWith(bad, bek, dir, OpenOptions{Pace: func(int64) error { return nil }}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("a changed byte, paced: %v", err)
	}

	// The manifest's hashing.
	calls = nil
	d, err := DescribeWith("snapshot.sqlite", paths[0], func(h int64) error { calls = append(calls, h); return nil })
	plainD, _ := Describe("snapshot.sqlite", paths[0])
	if err != nil || d != plainD || len(calls) != 4 || calls[3] != int64(sizes[0]) {
		t.Fatalf("describe paced: %v %+v %+v %v", err, d, plainD, calls)
	}
	if _, err := DescribeWith("snapshot.sqlite", paths[0], func(int64) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("describe with a failing pacer: %v", err)
	}
}
