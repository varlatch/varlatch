// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build crashpoint && linux

package daemon

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The restore's takeover killed (SIGKILL) at every step it journals, in a
// process of its own (this test binary, built with the crashpoint tag:
// tailnethook_crashpoint.go's VARLATCH_TEST_HANDOFF_PAUSE), then run again:
// it resumes from its journal (an unfinished switch undone, then done
// again) and the restored node holds the name.
func TestKillTheTakeoverAtEveryStep(t *testing.T) {
	for _, step := range []string{"prepared", "switching", "serving renamed", "incoming renamed", "opening", "done"} {
		t.Run(step, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()
			w := newRestoreWorld(t, ctx)
			ours := w.restored(t)
			log := filepath.Join(t.TempDir(), "handoff.log")
			cmd := exec.Command(os.Args[0], "-test.run=^TestTakeNameChild$")
			cmd.Env = append(os.Environ(), "VARLATCH_TAKENAME_CHILD_CONF="+w.in.conf, "VARLATCH_TAKENAME_CHILD_OAUTH="+w.oauth,
				"VARLATCH_TEST_TAILNET_CONTROL="+w.control.BaseURL(), "VARLATCH_TEST_TAILSCALE_API="+w.apiURL, "VARLATCH_TEST_TAILSCALE_CA="+w.caFile,
				"VARLATCH_TEST_HANDOFF_LOG="+log, "VARLATCH_TEST_HANDOFF_PAUSE=take-name "+step)
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(20 * time.Millisecond) {
				b, _ := os.ReadFile(log)
				if bytes.Contains(b, []byte("paused take-name "+step+"\n")) {
					_ = cmd.Process.Signal(syscall.SIGKILL)
					<-done
					break
				}
				select {
				case err := <-done:
					t.Fatalf("take-name ended (%v) before pausing at %q:\n%s\n%s", err, step, out.String(), b)
				default:
				}
				if time.Now().After(deadline) {
					_ = cmd.Process.Kill()
					t.Fatalf("take-name did not reach %q:\n%s", step, out.String())
				}
			}
			code, stdout, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--json", "--config", w.in.conf)
			if code != ExitOK || !strings.Contains(stdout, `"phase":"done"`) {
				t.Fatalf("take-name after the kill at %s: %d %q %q", step, code, stdout, errOut)
			}
			if n := w.api.names(); n[ours] != "vault" || n[w.dead] == "vault" {
				t.Fatalf("names after the kill at %s: %v", step, n)
			}
			// Again: nothing changes.
			if code, stdout, _ := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--json", "--config", w.in.conf); code != ExitOK || !strings.Contains(stdout, `"phase":"done"`) {
				t.Fatalf("take-name again: %d %q", code, stdout)
			}
		})
	}
}

// TestTakeNameChild is the killed process: take-name, as varlatchd's admin
// runs it, when the parent names its configuration.
func TestTakeNameChild(t *testing.T) {
	conf := os.Getenv("VARLATCH_TAKENAME_CHILD_CONF")
	if conf == "" {
		t.Skip("the child of TestKillTheTakeoverAtEveryStep")
	}
	os.Exit(Admin([]string{"tailnet", "take-name", "--oauth-client-file", os.Getenv("VARLATCH_TAKENAME_CHILD_OAUTH"), "--json", "--config", conf}, os.Stdout, os.Stderr))
}
