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
	t.Setenv(imageMarker, "varlatchd")
	code, out := runVersion()
	if code != exitConfig || !strings.Contains(out, "the environment variable APP_SETTING holds the Root KEK") || strings.Contains(out, text) || strings.Contains(out, strings.ToUpper(text)) {
		t.Fatalf("the Root KEK: %d %q", code, strings.ReplaceAll(out, text, "[KEY]"))
	}
	t.Setenv("APP_SETTING", "")
	t.Setenv("VARLATCH_BEK_PASSPHRASE", "a-passphrase-of-its-own")
	if code, out := runVersion(); code != exitConfig || !strings.Contains(out, "VARLATCH_BEK_PASSPHRASE is where the TypeScript line kept a key") || strings.Contains(out, "a-passphrase-of-its-own") {
		t.Fatalf("a TypeScript key variable: %d %q", code, out)
	}
	os.Unsetenv("VARLATCH_BEK_PASSPHRASE")
	if code, out := runVersion(); code != 0 {
		t.Fatalf("no key left: %d %q", code, out)
	}
}
