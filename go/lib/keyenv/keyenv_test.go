// SPDX-License-Identifier: Apache-2.0

package keyenv

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func random(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRefusal(t *testing.T) {
	kek, bek := random(t), random(t)
	keys := []Key{{RootKEK, kek}, {BEK, bek}}
	if why := Refusal([]string{"PATH=/usr/bin", "HOME=/var/lib/varlatch", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"}, keys...); why != "" {
		t.Fatalf("an environment without a key: %s", why)
	}
	for _, c := range []struct {
		name, value, want string
	}{
		{"ROOT_KEY", hex.EncodeToString(kek), RootKEK},
		{"KEY_UPPER", strings.ToUpper(hex.EncodeToString(kek)), RootKEK},
		{"EMBEDDED", "prefix-" + hex.EncodeToString(bek) + "-suffix", BEK},
		{"B64", base64.StdEncoding.EncodeToString(bek), BEK},
		{"B64RAW", base64.RawStdEncoding.EncodeToString(kek), RootKEK},
		{"B64URL", base64.RawURLEncoding.EncodeToString(kek), RootKEK},
		{"B64URLPAD", base64.URLEncoding.EncodeToString(bek), BEK},
	} {
		why := Refusal([]string{"PATH=/usr/bin", c.name + "=" + c.value}, keys...)
		if !strings.Contains(why, "the environment variable "+c.name+" holds "+c.want) {
			t.Errorf("%s: %q", c.name, why)
		}
		// Never the value, in any of its forms.
		for _, k := range [][]byte{kek, bek} {
			for _, f := range []string{hex.EncodeToString(k), strings.ToUpper(hex.EncodeToString(k)), base64.StdEncoding.EncodeToString(k), base64.RawURLEncoding.EncodeToString(k)} {
				if strings.Contains(why, f) || strings.Contains(why, c.value) {
					t.Errorf("%s: the refusal shows a key", c.name)
				}
			}
		}
	}
	for _, name := range Variables {
		for _, n := range []string{name, strings.ToLower(name)} {
			why := Refusal([]string{n + "=a-value-of-its-own"}, keys...)
			if !strings.Contains(why, "the environment variable "+n+" is where the TypeScript line kept a key") || strings.Contains(why, "a-value-of-its-own") {
				t.Errorf("%s: %q", n, why)
			}
		}
	}
	// A path to a key file is no key; nor is an empty key.
	if why := Refusal([]string{"VARLATCH_KEK_FILE=/keys/root-kek", "EMPTY="}, Key{RootKEK, nil}); why != "" {
		t.Fatalf("a key file's path: %s", why)
	}
}

func TestConfigured(t *testing.T) {
	dir := t.TempDir()
	kek, bek := random(t), random(t)
	if err := os.WriteFile(filepath.Join(dir, "root-kek"), []byte(hex.EncodeToString(kek)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "backup-key"), []byte(base64.StdEncoding.EncodeToString(bek)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "varlatchd.conf")
	write := func(text string) {
		if err := os.WriteFile(conf, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("# keys\nlisten = 127.0.0.1:8686\nroot_kek_file = " + filepath.Join(dir, "root-kek") + "\n  backup_key_file=" + filepath.Join(dir, "backup-key") + "  \n")
	got := Configured(conf)
	if len(got) != 2 || got[0].What != RootKEK || hex.EncodeToString(got[0].Bytes) != hex.EncodeToString(kek) || got[1].What != BEK || hex.EncodeToString(got[1].Bytes) != hex.EncodeToString(bek) {
		t.Fatalf("both keys: %d", len(got))
	}
	// A key file it cannot read, or that holds no key, is left out.
	write("root_kek_file = " + filepath.Join(dir, "missing") + "\nbackup_key_file = " + conf + "\n")
	if got := Configured(conf); len(got) != 0 {
		t.Fatalf("unreadable keys: %d", len(got))
	}
	if got := Configured(filepath.Join(dir, "no-such.conf")); got != nil {
		t.Fatal("a missing configuration")
	}
}
