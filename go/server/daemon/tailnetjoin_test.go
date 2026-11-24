// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"crypto/rand"
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
		doctorSays(t, in, "FAIL    tailnet.pin", "waiting for control", c.says, "the listener then opens with no restart", "may also be refusing the node")
		if log := r.stderr.String(); !strings.Contains(log, "has not joined its tailnet") || !strings.Contains(log, "waiting-for-control") || strings.Contains(log, "is not serving") {
			t.Fatalf("the log: %s", log)
		}
		answer.Store(nil)
		waitReport(t, r, bearer, joined)
		doctorSays(t, in, "PASS    tailnet.pin")
		r.stop(t)
	}
}

// A node its control server refuses stays closed, and says so, until
// varlatchd is restarted; the control server's own words are shown nowhere.
func TestARefusedNodeStaysClosed(t *testing.T) {
	in, h, _, login := joinInstall(t)
	login(false, "another")
	r := startWith(t, in, h)
	bearer := joinBootstrap(t, in)
	waitReport(t, r, bearer, `"listener":{"status":"fail","reason":"NOT_LISTENING"}`)
	waitReport(t, r, bearer, "The node's control server refused it")
	doctorSays(t, in, "FAIL    tailnet.pin", "control server refused it", "restart varlatchd")
	if log := r.stderr.String(); !strings.Contains(log, "is not serving") || !strings.Contains(log, "control server refused it") || strings.Contains(log, "invalid authkey") {
		t.Fatalf("the log: %s", log)
	}
	if b, err := os.ReadFile(filepath.Join(in.data, tailnet.ListenersFile)); err != nil || strings.Contains(string(b), "invalid authkey") {
		t.Fatalf("the report: %s %v", b, err)
	}
	// Doctor's way out: the state moved away, and the new key.
	doctorSays(t, in, "move <data_dir>/tailnet away")
	r.stop(t)
	if err := os.WriteFile(filepath.Join(in.dir, "tailnet-auth-key"), []byte("another\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(in.data, tailnet.StateDir), filepath.Join(in.dir, "moved")); err != nil {
		t.Fatal(err)
	}
	r = startWith(t, in, h)
	waitReport(t, r, bearer, joined)
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
	if code, _, errOut := runAdmin(t, "tailnet", "open", "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "control server refused it") || time.Since(begun) > 10*time.Second {
		t.Fatalf("open: %d in %v %q", code, time.Since(begun), errOut)
	}
}

// echoed is a control server that answers a registration with the auth key
// it was given (key, of the test's own making).
func echoed(key string) *func(*http.Request) (int, string, string) {
	f := func(r *http.Request) (int, string, string) {
		if r.URL.Path == "/machine/register" {
			return http.StatusOK, "", `{"Error":"the key ` + key + ` is not valid"}`
		}
		return 0, "", ""
	}
	return &f
}

// A refusal that repeats the auth key: it is in none of varlatchd's log, the
// open that waits for the node, the report, doctor and enroll's refusal.
func TestARefusalThatRepeatsTheAuthKeyIsNotShown(t *testing.T) {
	in, h, answer, _ := joinInstall(t)
	secret := strings.ToLower(rand.Text())
	if err := os.WriteFile(filepath.Join(in.dir, "tailnet-auth-key"), []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(in.data, 0o700); err != nil {
		t.Fatal(err)
	}
	const temp = "varlatch-vl-0123456789ab-n"
	prev := nodeControlURL
	nodeControlURL = h.tailnetControl
	t.Cleanup(func() { nodeControlURL = prev })
	answer.Store(echoed(secret))
	shown := map[string]string{}
	code, out, errOut := runAdmin(t, "tailnet", "enroll", "--hostname", temp, "--json", "--config", in.conf)
	if shown["enroll"] = out + errOut; code != ExitFailure || !strings.Contains(errOut, "the key [auth key] is not valid") {
		t.Errorf("enroll: %d", code)
	}
	// Held by that enroll; the open waits for the node, refused after it.
	answer.Store(func() *func(*http.Request) (int, string, string) {
		f := func(*http.Request) (int, string, string) { return http.StatusInternalServerError, "", "down" }
		return &f
	}())
	r := startWith(t, in, h)
	bearer := joinBootstrap(t, in)
	waitReport(t, r, bearer, "waiting for control")
	opened := make(chan string, 1)
	go func() {
		code, out, errOut := runAdmin(t, "tailnet", "open", "--config", in.conf)
		opened <- fmt.Sprintf("%d %s%s", code, out, errOut)
	}()
	time.Sleep(500 * time.Millisecond)
	answer.Store(echoed(secret))
	select {
	case shown["open"] = <-opened:
	case <-time.After(90 * time.Second):
		t.Fatal("open did not end")
	}
	if !strings.HasPrefix(shown["open"], fmt.Sprint(ExitFailure)) || !strings.Contains(shown["open"], "control server refused it") {
		t.Errorf("open did not say the refusal")
	}
	waitReport(t, r, bearer, "The node's control server refused it")
	_, shown["doctor"], _ = runAdmin(t, "doctor", "--config", in.conf)
	b, err := os.ReadFile(filepath.Join(in.data, tailnet.ListenersFile))
	if err != nil {
		t.Fatal(err)
	}
	shown["report"], shown["log"] = string(b), r.stderr.String()
	for what, text := range shown {
		if text == "" || strings.Contains(text, secret) {
			t.Errorf("%s has the auth key in it, or nothing", what)
		}
	}
}

// After a refusal nothing listens until a restart, though tsnet goes on and
// the node comes to run: said until then, whatever a repin's check finds.
func TestARefusedNodeNeedsARestartThoughItRuns(t *testing.T) {
	in, h, answer, _ := joinInstall(t)
	answer.Store(echoed("k"))
	r := startWith(t, in, h)
	bearer := joinBootstrap(t, in)
	waitReport(t, r, bearer, "The node's control server refused it")
	answer.Store(nil)
	for end := time.Now().Add(90 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		if _, out, _ := runAdmin(t, "tailnet", "repin", "--config", in.conf); strings.Contains(out, "observed: suffix corp.ts.net") {
			break
		} else if time.Now().After(end) {
			t.Fatalf("the node never ran: %s", out)
		}
	}
	doctorSays(t, in, "FAIL    tailnet.pin", "control server refused it", "restart varlatchd")
	waitReport(t, r, bearer, `"listener":{"status":"fail","reason":"NOT_LISTENING"}`)
	waitReport(t, r, bearer, "The node's control server refused it")
	r.stop(t)
	r = startWith(t, in, h)
	waitReport(t, r, bearer, joined)
	doctorSays(t, in, "PASS    tailnet.pin")
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
