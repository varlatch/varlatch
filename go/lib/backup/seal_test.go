// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/envelope"
)

// goManifest is a format-3 manifest for the files, with a canary of rootKEK.
func goManifest(t *testing.T, rootKEK []byte, files map[string]string) []byte {
	t.Helper()
	canary, err := envelope.NewCanary(rootKEK, "inst_test")
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{
		FormatVersion: FormatGo, ArchiveID: "0b1c2d3e-0000-4000-8000-000000000000", InstallationID: "inst_test",
		CreatedAt: "2026-11-15T12:00:00.000Z", Release: json.RawMessage(`{"version":"0.50.0","apiMajor":1,"databaseSchema":1}`),
		RequiredKeyVersions: []int{1}, Canaries: []Canary{CanaryOf(1, canary)},
	}
	for _, name := range FormatComponents[FormatGo] {
		c, err := Describe(name, files[name])
		if err != nil {
			t.Fatal(err)
		}
		m.Components = append(m.Components, c)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func components(t *testing.T, dir string, sizes ...int) (map[string]string, []string) {
	t.Helper()
	files := map[string]string{}
	var paths []string
	for i, name := range FormatComponents[FormatGo] {
		p := filepath.Join(dir, name)
		data := make([]byte, sizes[i])
		rand.Read(data)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		files[name] = p
		paths = append(paths, p)
	}
	return files, paths
}

func TestSealOpen(t *testing.T) {
	rootKEK := envelope.GenerateKey()
	key := make([]byte, 32)
	rand.Read(key)
	keyBEK, _ := KeyBEK(key)
	passBEK, _ := PassphraseBEK([]byte("correct horse battery"))
	for _, tc := range []struct {
		name  string
		bek   BEK
		sizes []int
	}{{"key", keyBEK, []int{70_000, 3}}, {"passphrase", passBEK, []int{2 << 20, 0}}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			files, paths := components(t, dir, tc.sizes...)
			manifest := goManifest(t, rootKEK, files)
			out := filepath.Join(dir, "archive.vlt")
			paced := int64(0)
			if err := Seal(out, manifest, paths, tc.bek, SealOptions{Pace: func(n int64) error { paced = n; return nil }}); err != nil {
				t.Fatal(err)
			}
			if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
				t.Errorf("mode %v", st.Mode())
			}
			if leftovers, _ := filepath.Glob(out + ".*.partial"); len(leftovers) != 0 {
				t.Errorf("partial files left: %v", leftovers)
			}
			if want := int64(len(manifest)+4+tc.sizes[0]) + int64(tc.sizes[1]); paced != want {
				t.Errorf("paced to %d, want %d", paced, want)
			}
			o, err := Open(out, tc.bek, dir)
			if err != nil {
				t.Fatal(err)
			}
			defer o.Close()
			if !bytes.Equal(o.ManifestJSON, manifest) || o.Manifest.FormatVersion != FormatGo {
				t.Errorf("manifest %s", o.ManifestJSON)
			}
			for name, p := range files {
				want, _ := os.ReadFile(p)
				got, err := os.ReadFile(o.Path(name))
				if err != nil || !bytes.Equal(got, want) {
					t.Errorf("%s differs", name)
				}
			}
			if !CheckKeys(o.Manifest, map[int][]byte{1: rootKEK}) || CheckKeys(o.Manifest, map[int][]byte{1: envelope.GenerateKey()}) || CheckKeys(o.Manifest, nil) {
				t.Error("CheckKeys")
			}
			// Sealing again to the same name never replaces the archive.
			if err := Seal(out, manifest, paths, tc.bek, SealOptions{}); err == nil {
				t.Error("an existing archive was replaced")
			}
		})
	}
}

// Every byte matters: a change in the header, the body or the tag, a
// truncation, another BEK or another magic is refused before anything is
// unpacked.
func TestOpenRefuses(t *testing.T) {
	dir := t.TempDir()
	files, paths := components(t, dir, 5000, 10)
	bek, _ := PassphraseBEK([]byte("correct horse battery"))
	out := filepath.Join(dir, "a.vlt")
	if err := Seal(out, goManifest(t, envelope.GenerateKey(), files), paths, bek, SealOptions{}); err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(out)
	other, _ := PassphraseBEK([]byte("another passphrase"))
	cases := map[string]struct {
		data []byte
		bek  BEK
		want error
	}{
		"the magic":     {flip(good, 0), bek, ErrFormat},
		"the salt":      {flip(good, 10), bek, ErrIntegrity},
		"the nonce":     {flip(good, 30), bek, ErrIntegrity},
		"the body":      {flip(good, 100), bek, ErrIntegrity},
		"the tag":       {flip(good, len(good)-1), bek, ErrIntegrity},
		"a truncation":  {good[:len(good)-1], bek, ErrIntegrity},
		"too short":     {good[:40], bek, ErrSize},
		"another BEK":   {good, other, ErrIntegrity},
		"a longer file": {append(bytes.Clone(good), 0), bek, ErrIntegrity},
	}
	for name, tc := range cases {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(p, tc.data, 0o600); err != nil {
			t.Fatal(err)
		}
		scratch := t.TempDir()
		_, err := Open(p, tc.bek, scratch)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
		if left, _ := os.ReadDir(scratch); len(left) != 0 {
			t.Errorf("%s: left %d entries in scratch", name, len(left))
		}
	}
}

func flip(b []byte, i int) []byte {
	c := bytes.Clone(b)
	c[i] ^= 1
	return c
}

func TestKeys(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	for _, text := range []string{"  " + strings.ToUpper(hexOf(key)) + "\n", b64(key)} {
		got, err := ParseKey(text)
		if err != nil || !bytes.Equal(got, key) {
			t.Errorf("%q: %v", text, err)
		}
	}
	for _, bad := range []string{"", "abc", hexOf(key)[:62], b64(key)[:43]} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	if _, err := KeyBEK(key[:31]); err == nil {
		t.Error("a 31-byte key")
	}
	if _, err := PassphraseBEK([]byte("eleven char")); err == nil {
		t.Error("an 11-byte passphrase")
	}
	same, _ := KeyBEK(key)
	asHex, _ := PassphraseBEK([]byte(hexOf(key) + "\n"))
	asB64, _ := PassphraseBEK([]byte(b64(key)))
	for name, b := range map[string]BEK{"raw": same, "hex": asHex, "base64": asB64} {
		if err := DistinctKeys(b, envelope.GenerateKey(), key); err == nil {
			t.Errorf("%s: the Root KEK as the BEK was accepted", name)
		}
	}
	other, _ := PassphraseBEK([]byte("a different passphrase"))
	if err := DistinctKeys(other, key); err != nil {
		t.Error(err)
	}
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Format 3 is Go's: its components and a strict release record.
func TestGoManifest(t *testing.T) {
	dir := t.TempDir()
	files, _ := components(t, dir, 10, 2)
	good := goManifest(t, envelope.GenerateKey(), files)
	m, err := ParseManifest(good)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := m.GoRelease(); err != nil || r.Version != "0.50.0" || r.APIMajor != 1 || r.DatabaseSchema != 1 {
		t.Errorf("release %+v %v", r, err)
	}
	change := func(f func(map[string]any)) []byte {
		var o map[string]any
		_ = json.Unmarshal(good, &o)
		f(o)
		b, _ := json.Marshal(o)
		return b
	}
	for name, raw := range map[string][]byte{
		"the TypeScript components": change(func(o map[string]any) {
			o["components"] = []any{map[string]any{"name": "secret-plane.dump", "bytes": 1, "sha256": strings.Repeat("a", 64)}}
		}),
		"its components reversed": change(func(o map[string]any) {
			c := o["components"].([]any)
			o["components"] = []any{c[1], c[0]}
		}),
		"a release member it does not know": change(func(o map[string]any) { o["release"].(map[string]any)["extra"] = 1 }),
		"no database schema":                change(func(o map[string]any) { delete(o["release"].(map[string]any), "databaseSchema") }),
		"database schema 0":                 change(func(o map[string]any) { o["release"].(map[string]any)["databaseSchema"] = 0 }),
		"an empty version":                  change(func(o map[string]any) { o["release"].(map[string]any)["version"] = "" }),
		"a TypeScript release record": change(func(o map[string]any) {
			o["release"] = map[string]any{"schemaVersion": 1, "version": "0.22.0", "apiMajor": 1, "migrationVersion": 52, "supportedPostgresMajor": 17}
		}),
	} {
		if _, err := ParseManifest(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Seal checks its manifest and the component files against it before it
// writes anything; an empty BEK derives nothing.
func TestSealRefuses(t *testing.T) {
	dir := t.TempDir()
	files, paths := components(t, dir, 100, 3)
	manifest := goManifest(t, envelope.GenerateKey(), files)
	bek, _ := PassphraseBEK([]byte("correct horse battery"))
	other := filepath.Join(dir, "other.json")
	_ = os.WriteFile(other, make([]byte, 3), 0o600)
	short := filepath.Join(t.TempDir(), ComponentDatabase)
	_ = os.WriteFile(short, make([]byte, 99), 0o600)
	for name, tc := range map[string]struct {
		manifest []byte
		paths    []string
		bek      BEK
	}{
		"an invalid manifest":     {[]byte(`{"formatVersion":3}`), paths, bek},
		"a component missing":     {manifest, paths[:1], bek},
		"another file's name":     {manifest, []string{paths[0], other}, bek},
		"another size":            {manifest, []string{short, paths[1]}, bek},
		"the components reversed": {manifest, []string{paths[1], paths[0]}, bek},
		"the zero BEK":            {manifest, paths, BEK{}},
	} {
		out := filepath.Join(t.TempDir(), "a.vlt")
		if err := Seal(out, tc.manifest, tc.paths, tc.bek, SealOptions{}); err == nil {
			t.Errorf("%s: sealed", name)
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("%s: an archive was written", name)
		}
	}
}

// A Pace error ends the sealing: Seal returns it, and leaves neither an
// archive nor a partial file.
func TestSealPaceStops(t *testing.T) {
	dir := t.TempDir()
	files, paths := components(t, dir, 3<<20, 10)
	manifest := goManifest(t, envelope.GenerateKey(), files)
	key := make([]byte, 32)
	rand.Read(key)
	bek, _ := KeyBEK(key)
	out := filepath.Join(dir, "archive.vlt")
	stop := errors.New("stopped")
	calls := 0
	err := Seal(out, manifest, paths, bek, SealOptions{Pace: func(n int64) error {
		if calls++; n > 1<<20 {
			return stop
		}
		return nil
	}})
	if !errors.Is(err, stop) || calls != 2 {
		t.Fatalf("err %v after %d calls", err, calls)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("an archive was written: %v", err)
	}
	if leftovers, _ := filepath.Glob(out + ".*.partial"); len(leftovers) != 0 {
		t.Errorf("partial files left: %v", leftovers)
	}
}
