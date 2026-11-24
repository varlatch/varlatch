// SPDX-License-Identifier: Apache-2.0

package keyenv

import (
	"bytes"
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
	// A key whose base64 has several of the two alphabets' own characters.
	slashes := bytes.Repeat([]byte{0xfb, 0xff, 0xbf, 0xef}, 8)
	keys = append(keys, Key{BEK, slashes})
	mixed := func(h string) string {
		b := []byte(h)
		for i := range b {
			if i%2 == 0 {
				b[i] = strings.ToUpper(string(b[i]))[0]
			}
		}
		return string(b)
	}
	if why := Refusal([]string{"PATH=/usr/bin", "HOME=/var/lib/varlatch", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"}, keys...); why != "" {
		t.Fatalf("an environment without a key: %s", why)
	}
	for _, c := range []struct {
		name, value, want string
	}{
		{"ROOT_KEY", hex.EncodeToString(kek), RootKEK},
		{"KEY_UPPER", strings.ToUpper(hex.EncodeToString(kek)), RootKEK},
		{"KEY_MIXED", mixed(hex.EncodeToString(kek)), RootKEK},
		{"B64_MIXED", strings.Replace(strings.Replace(base64.StdEncoding.EncodeToString(slashes), "/", "_", 1), "+", "-", 1), BEK},
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
			if !strings.Contains(why, "the environment variable "+n+" is a key or passphrase variable name") || strings.Contains(why, "a-value-of-its-own") {
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
	got := Configured(conf, "")
	if len(got) != 2 || got[0].What != RootKEK || hex.EncodeToString(got[0].Bytes) != hex.EncodeToString(kek) || got[1].What != BEK || hex.EncodeToString(got[1].Bytes) != hex.EncodeToString(bek) {
		t.Fatalf("both keys: %d", len(got))
	}
	// A byte order mark before the first line, as config.Parse allows.
	write("\uFEFFroot_kek_file = " + filepath.Join(dir, "root-kek") + "\n")
	if got := Configured(conf, ""); len(got) != 1 || got[0].What != RootKEK || hex.EncodeToString(got[0].Bytes) != hex.EncodeToString(kek) {
		t.Fatalf("after a byte order mark: %d", len(got))
	}
	// A key file it cannot read, or that holds no key, is left out.
	write("root_kek_file = " + filepath.Join(dir, "missing") + "\nbackup_key_file = " + conf + "\n")
	if got := Configured(conf, ""); len(got) != 0 {
		t.Fatalf("unreadable keys: %d", len(got))
	}
	if got := Configured(filepath.Join(dir, "no-such.conf"), dir); got != nil {
		t.Fatal("a missing configuration")
	}
	// A configuration that names no key file loads the credentials
	// directory's (as varlatchd admin finds them beside the configuration);
	// one it names wins.
	write("listen = 127.0.0.1:8686\n")
	if got := Configured(conf, ""); len(got) != 0 {
		t.Fatalf("no key named, no credentials directory: %d", len(got))
	}
	got = Configured(conf, dir)
	if len(got) != 2 || got[0].What != RootKEK || hex.EncodeToString(got[0].Bytes) != hex.EncodeToString(kek) || got[1].What != BEK || hex.EncodeToString(got[1].Bytes) != hex.EncodeToString(bek) {
		t.Fatalf("the credentials directory's keys: %d", len(got))
	}
	write("root_kek_file = " + filepath.Join(dir, "missing") + "\n")
	if got := Configured(conf, dir); len(got) != 1 || got[0].What != BEK {
		t.Fatalf("root_kek_file named wins over the credential: %d", len(got))
	}
}

// CredentialsDir: the run's own CREDENTIALS_DIRECTORY (an empty one is
// none); else, as root only, the configuration's directory, made
// absolute, when root-kek is there.
func TestCredentialsDir(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "varlatchd.conf")
	env := func(vars map[string]string) func(string) string { return func(k string) string { return vars[k] } }
	none := env(nil)
	if got := CredentialsDir(none, conf, true); got != "" {
		t.Errorf("no root-kek there: %q", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "root-kek"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := CredentialsDir(none, conf, true); got != dir {
		t.Errorf("as root, root-kek beside the configuration: %q", got)
	}
	if got := CredentialsDir(none, conf, false); got != "" {
		t.Errorf("not as root: %q", got)
	}
	if got := CredentialsDir(env(map[string]string{"CREDENTIALS_DIRECTORY": ""}), conf, true); got != dir {
		t.Errorf("an empty CREDENTIALS_DIRECTORY is none: %q", got)
	}
	if got := CredentialsDir(env(map[string]string{"CREDENTIALS_DIRECTORY": "/run/credentials/x"}), conf, false); got != "/run/credentials/x" {
		t.Errorf("the run's own: %q", got)
	}
	t.Chdir(dir)
	if got := CredentialsDir(none, "varlatchd.conf", true); got != dir {
		t.Errorf("a relative path: %q", got)
	}
}
