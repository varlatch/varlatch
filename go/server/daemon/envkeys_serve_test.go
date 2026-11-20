// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"os"
	"strings"
	"testing"
	"time"
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
