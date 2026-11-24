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
	st, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	// Decrypted (the archive but its header and tag), then hashed.
	want := st.Size() - header2Bytes - gcmTagSize + int64(sizes[0]+sizes[1])
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

// A cache hit needs the BEK too, not only the salt: on a warm cache, with
// the archive's own salt, another key, an empty BEK or a cleared one takes
// the full derivation and fails as it would without the cache. The cache
// keeps no copy of the BEK, only an HMAC under a key of its own.
func TestKeyCacheBindsTheBEK(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	bek, _ := KeyBEK(key)
	dir := t.TempDir()
	files, paths := components(t, dir, 200_000, 10)
	manifest := goManifest(t, envelope.GenerateKey(), files)
	out := filepath.Join(dir, "a.vlt")
	keys := &KeyCache{}
	if err := Seal(out, manifest, paths, bek, SealOptions{Keys: keys}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(keys.bek, key) || bytes.Equal(keys.bek, key) {
		t.Fatal("the cache holds the BEK's material")
	}
	warm := func(t *testing.T) {
		t.Helper()
		o, err := OpenWith(out, bek, dir, OpenOptions{Keys: keys})
		if err != nil {
			t.Fatalf("the right BEK on a warm cache: %v", err)
		}
		o.Close()
	}
	other := make([]byte, 32)
	rand.Read(other)
	wrong, _ := KeyBEK(other)
	cleared, _ := KeyBEK(key)
	cleared.Clear()
	for _, c := range []struct {
		name string
		bek  BEK
		want error
	}{
		{"another key", wrong, ErrIntegrity},
		{"a cleared key", cleared, ErrIntegrity},
		{"an empty BEK", BEK{}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			warm(t)
			before := Derivations()
			o, err := OpenWith(out, c.bek, dir, OpenOptions{Keys: keys})
			if err == nil {
				o.Close()
				t.Fatal("opened with the wrong BEK from a warm cache")
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("error %v, want %v", err, c.want)
			}
			if c.want != nil && Derivations()-before != 1 {
				t.Fatalf("%d derivations, want the full derivation (1)", Derivations()-before)
			}
			// The right BEK still opens it afterwards.
			warm(t)
		})
	}
	keys.Clear()
	if keys.bek != nil || keys.mac != nil {
		t.Fatal("Clear left the BEK's tag or the cache's HMAC key")
	}
}

// OpenWith removes its decrypted files on a panic too (a pacer's, here,
// after the first chunk was written), until the caller owns them.
func TestOpenCleansUpOnPanic(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	bek, _ := KeyBEK(key)
	dir := t.TempDir()
	files, paths := components(t, dir, 3<<20, 10)
	manifest := goManifest(t, envelope.GenerateKey(), files)
	out := filepath.Join(dir, "a.vlt")
	if err := Seal(out, manifest, paths, bek, SealOptions{}); err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("no panic")
			}
		}()
		_, _ = OpenWith(out, bek, scratch, OpenOptions{Pace: func(int64) error { panic("pacer") }})
	}()
	if left, _ := os.ReadDir(scratch); len(left) != 0 {
		t.Fatalf("a panicking open left %d entries in its scratch directory", len(left))
	}
}
