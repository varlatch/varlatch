// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build headscale && crashpoint && linux

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

	"github.com/varlatch/varlatch/go/lib/tailhandoff"
	"github.com/varlatch/varlatch/go/server/tailnet"
)

// The Headscale restore takeover killed (SIGKILL) at every journalled step
// against a real Headscale 0.29.7 container, then run again: it resumes
// from its journal, finishes the takeover, leaves no issuance file, and
// expires the resumed run's API key (only the killed run's key stays live
// until its 1h expiration).
func TestKillTheHeadscaleTakeoverAtEveryStep(t *testing.T) {
	for _, step := range []string{"prepared", "switching", "serving renamed", "incoming renamed", "opening", "hold cleared", "done"} {
		t.Run(step, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()
			setShortDeadGrace(t, 2*time.Second)

			w := newHeadscaleRestoreWorld(t, ctx, false, true)
			ours := w.restoredID(t)
			time.Sleep(3 * time.Second)
			_ = w.freshKey(t)

			log := filepath.Join(t.TempDir(), "handoff.log")
			cmd := exec.Command(os.Args[0], "-test.run=^TestHeadscaleTakeNameChild$")
			cmd.Env = append(os.Environ(),
				takeNameChild+"="+w.in.conf,
				"VARLATCH_HS_TAKENAME_CHILD_URL="+w.hs.URL,
				"VARLATCH_HS_TAKENAME_CHILD_KEY="+w.apiKeyFile,
				"VARLATCH_TEST_HANDOFF_LOG="+log,
				"VARLATCH_TEST_HANDOFF_PAUSE=take-name "+step,
			)
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
			if step == "hold cleared" {
				j := &takeoverJournal{path: filepath.Join(w.in.data, TakeoverFile)}
				s, err := j.read()
				if hold, _ := tailnet.LoadHold(w.in.data); hold != nil || err != nil || s == nil || s.Phase != tailhandoff.Switching || !s.IncomingOpened {
					t.Fatalf("after kill at %s: hold=%+v journal=%+v err=%v", step, hold, s, err)
				}
			}

			// Fresh API key for the resumed run; the killed run's key stays live (1).
			_ = w.freshKey(t)
			code, stdout, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", w.hs.URL, "--headscale-api-key-file", w.apiKeyFile, "--json", "--config", w.in.conf)
			if code != ExitOK || !strings.Contains(stdout, `"phase":"done"`) {
				t.Fatalf("take-name after kill at %s: %d %q %q", step, code, stdout, errOut)
			}
			if n := w.names(t); n[ours] != "vault" || n[w.deadID] == "vault" {
				t.Fatalf("names after kill at %s: %v", step, n)
			}
			if _, err := os.Stat(filepath.Join(w.in.data, IssuanceFile)); !os.IsNotExist(err) {
				t.Fatalf("issuance file written on Headscale after kill at %s: %v", step, err)
			}
			if live := w.hs.LiveAPIKeys(t); live != 1 {
				t.Fatalf("live API keys after kill at %s: %d, want 1 (the killed run's)", step, live)
			}
			// Idempotent rerun with another fresh key: still done, new key expired too.
			_ = w.freshKey(t)
			if code, stdout, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", w.hs.URL, "--headscale-api-key-file", w.apiKeyFile, "--json", "--config", w.in.conf); code != ExitOK || !strings.Contains(stdout, `"phase":"done"`) {
				t.Fatalf("take-name again after %s: %d %q %q", step, code, stdout, errOut)
			}
			if live := w.hs.LiveAPIKeys(t); live != 1 {
				t.Fatalf("live API keys after rerun at %s: %d, want 1", step, live)
			}
		})
	}
}

// TestHeadscaleTakeNameChild is the killed process of
// TestKillTheHeadscaleTakeoverAtEveryStep.
func TestHeadscaleTakeNameChild(t *testing.T) {
	conf := os.Getenv(takeNameChild)
	if conf == "" {
		t.Skip("the child of TestKillTheHeadscaleTakeoverAtEveryStep")
	}
	deadGrace = 2 * time.Second
	tuneTakeName = func(e *tailhandoff.Engine) {
		e.Deadline, e.UndoWait, e.RetryEvery = 60*time.Second, 30*time.Second, 200*time.Millisecond
	}
	os.Exit(Admin([]string{
		"tailnet", "take-name",
		"--headscale-url", os.Getenv("VARLATCH_HS_TAKENAME_CHILD_URL"),
		"--headscale-api-key-file", os.Getenv("VARLATCH_HS_TAKENAME_CHILD_KEY"),
		"--json", "--config", conf,
	}, os.Stdout, os.Stderr))
}
