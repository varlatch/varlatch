// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/tailnet"
)

// joinInstall is an installation with tailnet = on, its node's auth key, and
// what its control server answers a machine request (0: as it would).
func joinInstall(t *testing.T) (in install, h *hooks, answer *atomic.Pointer[func(*http.Request) (int, string, string)], login func(auth bool, key string)) {
	t.Helper()
	prev := joinNotice
	joinNotice = time.Second
	t.Cleanup(func() { joinNotice = prev })
	control := startTestControl(t)
	answer = &atomic.Pointer[func(*http.Request) (int, string, string)]{}
	control.MaybeRejectRequest = func(r *http.Request) (int, string, string) {
		if f := answer.Load(); f != nil {
			return (*f)(r)
		}
		return 0, "", ""
	}
	in = newInstall(t, "")
	keyFile := filepath.Join(in.dir, "tailnet-auth-key")
	if err := os.WriteFile(keyFile, []byte("hermetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in.write(t, fmt.Sprintf("tailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_auth_key_file = %s\n", keyFile))
	return in, &hooks{tailnetControl: control.BaseURL()}, answer, func(auth bool, key string) { control.RequireAuth, control.RequireAuthKey = auth, key }
}

// joinBootstrap is an owner's bearer.
func joinBootstrap(t *testing.T, in install) string {
	t.Helper()
	code, out, errOut := runAdmin(t, "bootstrap", "--cli-credential", "--config", in.conf)
	m := bootstrapCLI.FindStringSubmatch(out)
	if code != ExitOK || m == nil {
		t.Fatalf("bootstrap: %d %q", code, errOut)
	}
	return m[2]
}

const joined = `"checks":{"listener":{"status":"pass"},"localApi":{"status":"pass"},"node":{"status":"pass"}}`

// doctorSays waits until doctor's tailnet pin check says it.
func doctorSays(t *testing.T, in install, want ...string) {
	t.Helper()
	var out string
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		_, out, _ = runAdmin(t, "doctor", "--config", in.conf)
		missing := false
		for _, w := range want {
			missing = missing || !strings.Contains(out, w)
		}
		if !missing {
			return
		}
	}
	t.Fatalf("doctor never said %q:\n%s", want, out)
}

// A control server that limits the node's registrations, or does not answer,
// is waited for: said meanwhile (the log, the report, doctor), and the
// tailnet listener opens when it recovers, with no restart. First at the
// node's enrolment, then at a restart.
func TestTheTailnetListenerOpensWhenItsControlServerRecovers(t *testing.T) {
	in, h, answer, _ := joinInstall(t)
	reject := func(status int, retryAfter string) {
		f := func(r *http.Request) (int, string, string) { return status, retryAfter, "not now" }
		answer.Store(&f)
	}
	bearer := ""
	for i, c := range []struct {
		status     int
		retryAfter string
		says       string
	}{
		{http.StatusTooManyRequests, "1", "rate limited"},
		{http.StatusTooManyRequests, "1", "rate limited"},
		{http.StatusInternalServerError, "", "has not answered since varlatchd started"},
	} {
		reject(c.status, c.retryAfter)
		r := startWith(t, in, h)
		if i == 0 {
			bearer = joinBootstrap(t, in)
		}
		waitReport(t, r, bearer, `"warnings":["The node is waiting for control: `)
		waitReport(t, r, bearer, c.says)
		waitReport(t, r, bearer, `"node":{"status":"fail","reason":"NOT_RUNNING"}`)
		doctorSays(t, in, "FAIL    tailnet.pin", "waiting for control", c.says, "nothing needs restarting here")
		if log := r.stderr.String(); !strings.Contains(log, "has not joined its tailnet") || !strings.Contains(log, "waiting-for-control") || strings.Contains(log, "is not serving") {
			t.Fatalf("the log: %s", log)
		}
		answer.Store(nil)
		waitReport(t, r, bearer, joined)
		doctorSays(t, in, "PASS    tailnet.pin")
		r.stop(t)
	}
}

// A node its control server refuses stays closed, and says why, until
// varlatchd is restarted; the control server's own words are the log's only.
func TestARefusedNodeStaysClosed(t *testing.T) {
	in, h, _, login := joinInstall(t)
	login(false, "another")
	r := startWith(t, in, h)
	bearer := joinBootstrap(t, in)
	waitReport(t, r, bearer, `"listener":{"status":"fail","reason":"NOT_LISTENING"}`)
	waitReport(t, r, bearer, "The node's control server refused it")
	doctorSays(t, in, "FAIL    tailnet.pin", "control server refused it", "restart varlatchd")
	if log := r.stderr.String(); !strings.Contains(log, "is not serving") || !strings.Contains(log, "invalid authkey") {
		t.Fatalf("the log: %s", log)
	}
	if b, err := os.ReadFile(filepath.Join(in.data, tailnet.ListenersFile)); err != nil || strings.Contains(string(b), "invalid authkey") {
		t.Fatalf("the report: %s %v", b, err)
	}
}

// A handoff's open of a node its control server refused fails at once,
// rather than when it is out of time.
func TestOpenOfARefusedNodeFails(t *testing.T) {
	in, h, _, login := joinInstall(t)
	if err := os.MkdirAll(in.data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := tailnet.SaveHold(in.data, &tailnet.Hold{Hostname: "varlatch-vl-0123456789ab-n", Since: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	login(false, "another")
	r := startWith(t, in, h)
	bearer := joinBootstrap(t, in)
	waitReport(t, r, bearer, "The node's control server refused it")
	begun := time.Now()
	if code, _, errOut := runAdmin(t, "tailnet", "open", "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "invalid authkey") || time.Since(begun) > 10*time.Second {
		t.Fatalf("open: %d in %v %q", code, time.Since(begun), errOut)
	}
}

// A node that must be logged in at its control server is said to be, and
// waits for it.
func TestANodeThatNeedsALoginSaysSo(t *testing.T) {
	in, h, _, login := joinInstall(t)
	login(true, "")
	r := startWith(t, in, h)
	bearer := joinBootstrap(t, in)
	waitReport(t, r, bearer, "must be logged in or approved at its control server")
	doctorSays(t, in, "FAIL    tailnet.pin", "must be logged in or approved", "admin console")
	if log := r.stderr.String(); !strings.Contains(log, "login-needed") || strings.Contains(log, "/auth/") {
		t.Fatalf("the log: %s", log)
	}
}
