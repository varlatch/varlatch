// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/keyenv"
)

// In the image, the CLI refuses a key in its environment (78), naming the
// variable and never the value; outside it, it does not look.
func TestImageRefusesAKeyInTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	text := hex.EncodeToString(key)
	if err := os.WriteFile(filepath.Join(dir, "root-kek"), []byte(text+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "varlatchd.conf")
	if err := os.WriteFile(conf, []byte("root_kek_file = "+filepath.Join(dir, "root-kek")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	was := imageConfig
	imageConfig = conf
	t.Cleanup(func() { imageConfig = was })

	runVersion := func() (int, string) {
		var out, errOut bytes.Buffer
		code := run([]string{"--version"}, strings.NewReader(""), &out, &errOut)
		return code, out.String() + errOut.String()
	}
	t.Setenv("APP_SETTING", text)
	if code, _ := runVersion(); code != 0 {
		t.Fatalf("outside the image: %d", code)
	}
	t.Setenv(keyenv.ImageMarker, "varlatchd")
	code, out := runVersion()
	if code != exitConfig || !strings.Contains(out, "the environment variable APP_SETTING holds the Root KEK") || strings.Contains(out, text) || strings.Contains(out, strings.ToUpper(text)) {
		t.Fatalf("the Root KEK: %d %q", code, strings.ReplaceAll(out, text, "[KEY]"))
	}
	t.Setenv("APP_SETTING", "")
	t.Setenv("VARLATCH_BEK_PASSPHRASE", "a-passphrase-of-its-own")
	if code, out := runVersion(); code != exitConfig || !strings.Contains(out, "VARLATCH_BEK_PASSPHRASE is a key or passphrase variable name") || strings.Contains(out, "a-passphrase-of-its-own") {
		t.Fatalf("a key variable name: %d %q", code, out)
	}
	os.Unsetenv("VARLATCH_BEK_PASSPHRASE")
	if code, out := runVersion(); code != 0 {
		t.Fatalf("no key left: %d %q", code, out)
	}
}

// The keys the configuration loads without naming them are refused too:
// those in the run's CREDENTIALS_DIRECTORY, and, run as root, those beside
// the configuration (where varlatchd admin finds them); not for another
// user, who cannot read them.
func TestImageRefusesAKeyTheConfigurationLoads(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	text := hex.EncodeToString(key)
	if err := os.WriteFile(filepath.Join(dir, "root-kek"), []byte(text+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(t.TempDir(), "varlatchd.conf")
	if err := os.WriteFile(conf, []byte("listen = 127.0.0.1:8686\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wasConf, wasRoot := imageConfig, imageAsRoot
	t.Cleanup(func() { imageConfig, imageAsRoot = wasConf, wasRoot })
	imageConfig = conf
	imageAsRoot = func() bool { return false }
	runVersion := func() (int, string) {
		var out, errOut bytes.Buffer
		code := run([]string{"--version"}, strings.NewReader(""), &out, &errOut)
		return code, out.String() + errOut.String()
	}
	refused := func(why string) {
		t.Helper()
		code, out := runVersion()
		if code != exitConfig || !strings.Contains(out, "the environment variable DEPLOYMENT_SETTING holds the Root KEK") || strings.Contains(out, text) {
			t.Fatalf("%s: %d %q", why, code, strings.ReplaceAll(out, text, "[KEY]"))
		}
	}
	t.Setenv(keyenv.ImageMarker, "varlatchd")
	t.Setenv("DEPLOYMENT_SETTING", text)
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	refused("the credentials directory's key")

	// Beside the configuration, as root.
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	beside := filepath.Join(dir, "varlatchd.conf")
	if err := os.WriteFile(beside, []byte("listen = 127.0.0.1:8686\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	imageConfig = beside
	if code, out := runVersion(); code != 0 {
		t.Fatalf("not as root, the key beside the configuration is not loaded: %d %q", code, strings.ReplaceAll(out, text, "[KEY]"))
	}
	imageAsRoot = func() bool { return true }
	refused("as root, the key beside the configuration")
	t.Setenv("DEPLOYMENT_SETTING", "")
	if code, out := runVersion(); code != 0 {
		t.Fatalf("no key left: %d %q", code, out)
	}
}
