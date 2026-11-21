// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build headscale && linux

package daemon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailcontrol"
	"github.com/varlatch/varlatch/go/lib/tailhandoff"
	"github.com/varlatch/varlatch/go/server/tailnet"
	"github.com/varlatch/varlatch/go/server/tailnet/headscaletest"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

// Real Headscale 0.29.7 container tests for `varlatchd admin tailnet
// take-name` (slice 7.5c c4, build tag headscale).

var headscaleCA *headscaletest.CA

func TestMain(m *testing.M) {
	// A crashpoint child inherits SSL_CERT_FILE from its parent test process.
	var dir string
	if _, set := os.LookupEnv("SSL_CERT_FILE"); !set {
		var err error
		dir, err = os.MkdirTemp("", "daemon-headscale-ca-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if headscaleCA, err = headscaletest.Trust(dir); err != nil {
			_ = os.RemoveAll(dir)
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	code := m.Run()
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
	os.Exit(code)
}

type hsRestoreWorld struct {
	hs          *headscaletest.Server
	in          install
	preauth     string
	authKeyFile string
	apiKeyFile  string
	deadDir     string
	deadID      string
	deadNode    *tsnet.Server
	op          string
	temp        string
}

func newHeadscaleRestoreWorld(t *testing.T, ctx context.Context, keepDeadOnline bool, withOutboundAllow bool) *hsRestoreWorld {
	t.Helper()
	headscaletest.Skip(t)
	if headscaleCA == nil {
		t.Fatal("SSL_CERT_FILE was set before the run: Headscale CA is not trusted")
	}
	hs := headscaletest.Start(t, headscaleCA)
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(hs.Logs())
		}
	})
	preauth := hs.PreauthKey(t, "tag:varlatch")
	deadDir := t.TempDir()
	dead := &tsnet.Server{Dir: deadDir, Hostname: "vault", ControlURL: hs.URL, AuthKey: preauth, Logf: logger.Discard}
	st, err := dead.Up(ctx)
	if err != nil {
		t.Fatalf("old node did not join Headscale: %v", err)
	}
	deadID := string(st.Self.ID)
	if !keepDeadOnline {
		_ = dead.Close()
		waitHeadscaleOnline(t, hs, deadID, false)
	} else {
		t.Cleanup(func() { _ = dead.Close() })
	}

	in := newInstall(t, "")
	authKeyFile := filepath.Join(in.dir, "tailnet-auth-key")
	if err := os.WriteFile(authKeyFile, []byte(preauth+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	apiKeyFile := filepath.Join(in.dir, "headscale-api-key")
	w := &hsRestoreWorld{
		hs:          hs,
		in:          in,
		preauth:     preauth,
		authKeyFile: authKeyFile,
		apiKeyFile:  apiKeyFile,
		deadDir:     deadDir,
		deadID:      deadID,
		op:          "",
	}
	if keepDeadOnline {
		w.deadNode = dead
	}
	w.writeConf(t, withOutboundAllow)
	if w.op, err = tailcontrol.NewOperationID(); err != nil {
		t.Fatal(err)
	}
	if w.temp, err = tailcontrol.TempName("vault", w.op, tailcontrol.RoleNew); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := runAdmin(t, "tailnet", "enroll", "--hostname", w.temp, "--json", "--config", in.conf); code != ExitOK {
		t.Fatalf("enroll: %d %q %q", code, out, errOut)
	}
	prevTune := tuneTakeName
	tuneTakeName = func(e *tailhandoff.Engine) {
		e.Deadline, e.UndoWait, e.RetryEvery = 60*time.Second, 30*time.Second, 200*time.Millisecond
	}
	t.Cleanup(func() { tuneTakeName = prevTune })
	return w
}

func (w *hsRestoreWorld) writeConf(t *testing.T, withOutboundAllow bool) {
	t.Helper()
	extra := ""
	if withOutboundAllow {
		extra = "outbound_allow = " + headscaleOutboundAllowEntry(w.hs.URL) + "\n"
	}
	w.in.write(t, fmt.Sprintf("tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_control_url = %s\ntailnet_auth_key_file = %s\n%s",
		w.hs.URL, w.authKeyFile, extra))
}

func (w *hsRestoreWorld) freshKey(t *testing.T) string {
	t.Helper()
	key := w.hs.APIKey(t)
	if err := os.WriteFile(w.apiKeyFile, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return key
}

func (w *hsRestoreWorld) names(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, n := range w.hs.Nodes(t) {
		out[n.ID] = n.GivenName
	}
	return out
}

func (w *hsRestoreWorld) restoredID(t *testing.T) string {
	t.Helper()
	for id, name := range w.names(t) {
		if id != w.deadID && (name == w.temp || name == "vault") {
			return id
		}
	}
	t.Fatalf("restored node not listed: %v", w.names(t))
	return ""
}

func waitHeadscaleOnline(t *testing.T, hs *headscaletest.Server, id string, want bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range hs.Nodes(t) {
			if n.ID == id && n.Online == want {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("Headscale node %s did not reach online=%v: %+v", id, want, hs.Nodes(t))
}

func setShortDeadGrace(t *testing.T, d time.Duration) {
	t.Helper()
	prev := deadGrace
	deadGrace = d
	t.Cleanup(func() { deadGrace = prev })
}

// Dead holder taken over on real Headscale 0.29.7: first refused without
// outbound_allow (naming the exact line to add), then succeeds once
// outbound_allow is added, skips certificates/issuances, expires the API
// key on exit (including on an idempotent rerun with a fresh key), and
// reaches confirms the restored node serves vault.
func TestHeadscaleTakeNameDeadHolder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	setShortDeadGrace(t, 2*time.Second)

	w := newHeadscaleRestoreWorld(t, ctx, false, false)
	ours := w.restoredID(t)
	time.Sleep(3 * time.Second)

	// Without outbound_allow: refused before contacting Headscale, naming the exact line.
	key0 := w.freshKey(t)
	wantLine := "outbound_allow = " + headscaleOutboundAllowEntry(w.hs.URL)
	code, _, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", w.hs.URL, "--headscale-api-key-file", w.apiKeyFile, "--config", w.in.conf)
	if code != ExitFailure || !strings.Contains(errOut, wantLine) || strings.Contains(errOut, key0) {
		t.Fatalf("without outbound_allow: %d %q (want %q)", code, errOut, wantLine)
	}
	if n := w.names(t); n[w.deadID] != "vault" || n[ours] != w.temp {
		t.Fatalf("renamed despite outbound refusal: %v", n)
	}
	// The key could not be expired through the policy that refused
	// Headscale: the refusal names the command that does it on the control
	// server, and that command expires it.
	prefix := headscaleKeyPrefix(key0)
	manual := "headscale apikeys expire --prefix " + prefix
	if prefix == "" || !strings.Contains(errOut, manual) {
		t.Fatalf("the refusal does not say how to expire the key (%q): %q", manual, errOut)
	}
	if out, err := exec.Command(w.hs.CLI(t), "apikeys", "expire", "--prefix", prefix).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v (%d bytes of output)", manual, err, len(out))
	}
	if live := w.hs.LiveAPIKeys(t); live != 0 {
		t.Fatalf("%d Headscale API keys live after %s, want 0", live, manual)
	}

	// Add the exact suggested outbound_allow entry and run take-name.
	w.writeConf(t, true)
	key0 = w.freshKey(t)
	code, out, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", w.hs.URL, "--headscale-api-key-file", w.apiKeyFile, "--json", "--config", w.in.conf)
	if code != ExitOK || !strings.Contains(out, `"phase":"done"`) {
		t.Fatalf("take-name on Headscale: %d %q %q", code, out, errOut)
	}
	if strings.Contains(out+errOut, key0) {
		t.Fatal("the Headscale API key was printed")
	}
	oldTemp, _ := tailcontrol.TempName("vault", w.op, tailcontrol.RoleOld)
	if n := w.names(t); n[ours] != "vault" || n[w.deadID] != oldTemp {
		t.Fatalf("names after takeover: %v (ours=%s dead=%s)", n, ours, w.deadID)
	}
	if hold, err := tailnet.LoadHold(w.in.data); err != nil || hold != nil {
		t.Fatalf("hold after takeover: %+v %v", hold, err)
	}
	if _, err := os.Stat(filepath.Join(w.in.data, IssuanceFile)); !os.IsNotExist(err) {
		t.Fatalf("issuance file written on Headscale: %v", err)
	}
	if live := w.hs.LiveAPIKeys(t); live != 0 {
		t.Fatalf("%d Headscale API keys still live after takeover, want 0", live)
	}
	if code, out, errOut := runAdmin(t, "tailnet", "reaches", "--name", "vault", "--stable-id", ours, "--wait", "30s", "--json", "--config", w.in.conf); code != ExitOK || !strings.Contains(out, `"reaches":true`) {
		t.Fatalf("reaches: %d %q %q", code, out, errOut)
	}
	// Idempotent rerun with a fresh key: still done, and expires the fresh key too.
	key1 := w.freshKey(t)
	if code, out, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", w.hs.URL, "--headscale-api-key-file", w.apiKeyFile, "--json", "--config", w.in.conf); code != ExitOK || !strings.Contains(out, `"phase":"done"`) || strings.Contains(out+errOut, key1) {
		t.Fatalf("rerun: %d %q %q", code, out, errOut)
	}
	if live := w.hs.LiveAPIKeys(t); live != 0 {
		t.Fatalf("%d Headscale API keys live after rerun, want 0", live)
	}
}

// Live holder (online, or disconnected within default 5m deadGrace) is
// refused on real Headscale 0.29.7; nothing is renamed and the API key is
// still expired.
func TestHeadscaleTakeNameLiveHolderRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	w := newHeadscaleRestoreWorld(t, ctx, true, true)
	ours := w.restoredID(t)

	// A take-name that ends before its handoff (the node not held for one)
	// expires the key all the same.
	hold, err := tailnet.LoadHold(w.in.data)
	if err != nil || hold == nil {
		t.Fatalf("the hold: %+v %v", hold, err)
	}
	if err := tailnet.ClearHold(w.in.data); err != nil {
		t.Fatal(err)
	}
	key0 := w.freshKey(t)
	if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", w.hs.URL, "--headscale-api-key-file", w.apiKeyFile, "--config", w.in.conf); code != ExitFailure || !strings.Contains(errOut, "not held") || strings.Contains(errOut, key0) {
		t.Fatalf("a node not held: %d %q", code, errOut)
	}
	if live := w.hs.LiveAPIKeys(t); live != 0 {
		t.Fatalf("%d Headscale API keys live after a refusal before the handoff, want 0", live)
	}
	if err := tailnet.SaveHold(w.in.data, hold); err != nil {
		t.Fatal(err)
	}

	// Online holder: refused, nothing renamed, API key expired.
	key1 := w.freshKey(t)
	code, _, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", w.hs.URL, "--headscale-api-key-file", w.apiKeyFile, "--config", w.in.conf)
	if code != ExitFailure || !strings.Contains(errOut, "is connected to the tailnet now") || !strings.Contains(errOut, "nothing was renamed") || strings.Contains(errOut, key1) {
		t.Fatalf("online holder: %d %q", code, errOut)
	}
	if n := w.names(t); n[w.deadID] != "vault" || n[ours] != w.temp {
		t.Fatalf("names after online refusal: %v", n)
	}
	if live := w.hs.LiveAPIKeys(t); live != 0 {
		t.Fatalf("%d Headscale API keys live after online refusal, want 0", live)
	}

	// Disconnected moments ago (within default 5m deadGrace): refused, nothing renamed, API key expired.
	_ = w.deadNode.Close()
	waitHeadscaleOnline(t, w.hs, w.deadID, false)
	key2 := w.freshKey(t)
	code, _, errOut = runAdmin(t, "tailnet", "take-name", "--headscale-url", w.hs.URL, "--headscale-api-key-file", w.apiKeyFile, "--config", w.in.conf)
	if code != ExitFailure || !strings.Contains(errOut, "within 5m0s") || !strings.Contains(errOut, "nothing was renamed") || strings.Contains(errOut, key2) {
		t.Fatalf("recently seen holder: %d %q", code, errOut)
	}
	if n := w.names(t); n[w.deadID] != "vault" || n[ours] != w.temp {
		t.Fatalf("names after deadGrace refusal: %v", n)
	}
	if hold, _ := tailnet.LoadHold(w.in.data); hold == nil {
		t.Fatal("hold removed after refusal")
	}
	if live := w.hs.LiveAPIKeys(t); live != 0 {
		t.Fatalf("%d Headscale API keys live after deadGrace refusal, want 0", live)
	}
}

// Holder that comes back online between Prepare and the first rename is
// refused on real Headscale 0.29.7; nothing is renamed, journal stays
// prepared, API key is expired; once dead again, take-name finishes.
func TestHeadscaleTakeNameHolderReturnsBeforeRename(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	setShortDeadGrace(t, 2*time.Second)

	w := newHeadscaleRestoreWorld(t, ctx, false, true)
	ours := w.restoredID(t)
	time.Sleep(3 * time.Second)

	var back *tsnet.Server
	prev := handoffPoint
	t.Cleanup(func() {
		handoffPoint = prev
		if back != nil {
			_ = back.Close()
		}
	})
	handoffPoint = func(step string) {
		if step != "take-name prepared" {
			return
		}
		// Bring the old node back online before stillDead checks it.
		back = &tsnet.Server{Dir: w.deadDir, Hostname: "vault", ControlURL: w.hs.URL, Logf: logger.Discard}
		if _, err := back.Up(ctx); err != nil {
			t.Errorf("bringing old node back online: %v", err)
			return
		}
		waitHeadscaleOnline(t, w.hs, w.deadID, true)
	}

	key1 := w.freshKey(t)
	code, _, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", w.hs.URL, "--headscale-api-key-file", w.apiKeyFile, "--config", w.in.conf)
	if code != ExitFailure || !strings.Contains(errOut, "is connected to the tailnet now") || !strings.Contains(errOut, "nothing was renamed") || strings.Contains(errOut, key1) {
		t.Fatalf("holder returned before rename: %d %q", code, errOut)
	}
	if n := w.names(t); n[w.deadID] != "vault" || n[ours] != w.temp {
		t.Fatalf("names after returning holder: %v", n)
	}
	j := &takeoverJournal{path: filepath.Join(w.in.data, TakeoverFile)}
	if s, err := j.read(); err != nil || s == nil || s.Phase != tailhandoff.Prepared {
		t.Fatalf("journal after returning holder: %+v %v", s, err)
	}
	if live := w.hs.LiveAPIKeys(t); live != 0 {
		t.Fatalf("%d Headscale API keys live after returning-holder refusal, want 0", live)
	}

	// Shut the old node down again, wait past deadGrace, and finish.
	handoffPoint = prev
	_ = back.Close()
	back = nil
	waitHeadscaleOnline(t, w.hs, w.deadID, false)
	time.Sleep(3 * time.Second)
	_ = w.freshKey(t)
	code, out, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", w.hs.URL, "--headscale-api-key-file", w.apiKeyFile, "--json", "--config", w.in.conf)
	if code != ExitOK || !strings.Contains(out, `"phase":"done"`) {
		t.Fatalf("take-name after old node died again: %d %q %q", code, out, errOut)
	}
	if n := w.names(t); n[ours] != "vault" || n[w.deadID] == "vault" {
		t.Fatalf("names after completion: %v", n)
	}
	if live := w.hs.LiveAPIKeys(t); live != 0 {
		t.Fatalf("%d Headscale API keys live after completion, want 0", live)
	}
}
