// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/keyenv"
)

// serve refuses (78) with the Root KEK in its environment, naming the
// variable, never the value, and before it opens anything.
func TestServeRefusesAKeyInItsEnvironment(t *testing.T) {
	in := newInstall(t, "")
	raw, err := os.ReadFile(in.kekFile)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.TrimSpace(string(raw))
	t.Setenv("DEPLOYMENT_SETTING", key)
	stderr := &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- Serve(Options{ConfigPath: in.conf, Stderr: stderr}) }()
	select {
	case code := <-done:
		if code != ExitConfig || !strings.Contains(stderr.String(), "the environment variable DEPLOYMENT_SETTING holds the Root KEK") || strings.Contains(stderr.String(), key) {
			t.Fatalf("%d %q", code, stderr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve started with the Root KEK in its environment")
	}
	if _, err := os.Stat(in.data + "/varlatch.db"); !os.IsNotExist(err) {
		t.Fatalf("the database was opened: %v", err)
	}
}

// In the image (keyenv.ImageMarker), varlatchd admin refuses a key in its
// environment as serve does (78), naming the variable, never the value;
// outside it, admin does not look.
func TestAdminRefusesAKeyInTheImage(t *testing.T) {
	in := newInstall(t, "")
	raw, err := os.ReadFile(in.kekFile)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.TrimSpace(string(raw))
	t.Setenv("DEPLOYMENT_SETTING", key)
	if code, out, errOut := runAdmin(t, "kek", "verify", "--config", in.conf); code == ExitConfig || strings.Contains(out+errOut, key) {
		t.Fatalf("outside the image: %d", code)
	}
	t.Setenv(keyenv.ImageMarker, "varlatchd")
	code, out, errOut := runAdmin(t, "kek", "verify", "--config", in.conf)
	if code != ExitConfig || !strings.Contains(errOut, "the environment variable DEPLOYMENT_SETTING holds the Root KEK") || strings.Contains(out+errOut, key) {
		t.Fatalf("the Root KEK: %d %q", code, strings.ReplaceAll(out+errOut, key, "[KEY]"))
	}
	t.Setenv("DEPLOYMENT_SETTING", "")
	t.Setenv("VARLATCH_KEK_PASSPHRASE", "a-passphrase-of-its-own")
	if code, out, errOut := runAdmin(t, "kek", "verify", "--config", in.conf); code != ExitConfig || !strings.Contains(errOut, "VARLATCH_KEK_PASSPHRASE is a key or passphrase variable name") || strings.Contains(out+errOut, "a-passphrase-of-its-own") {
		t.Fatalf("a key variable name: %d %q", code, out+errOut)
	}
	os.Unsetenv("VARLATCH_KEK_PASSPHRASE")
	if code, out, errOut := runAdmin(t, "kek", "verify", "--config", in.conf); code == ExitConfig {
		t.Fatalf("no key left: %d %q %q", code, out, errOut)
	}
}
