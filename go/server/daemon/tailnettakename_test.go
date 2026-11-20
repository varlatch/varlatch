// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailcontrol"
	"github.com/varlatch/varlatch/go/lib/tailhandoff"
	"github.com/varlatch/varlatch/go/server/tailnet"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// apiOver is a fake of Tailscale's API over a testcontrol server, as G5's
// tailnet half has it: the OAuth exchange with the devices:core scope, the
// devices from the control server, and a rename that is the control
// server's (its node's name, pushed to every peer's netmap); a taken name
// is refused. down makes it answer 503, as a control plane out of reach.
type apiOver struct {
	control  *testcontrol.Server
	suffix   string
	id, sec  string
	mu       sync.Mutex
	tokens   map[string]bool
	renames  int
	downFrom int // the rename after which it is down (0: never)
	down     bool
}

func (a *apiOver) serve(rw http.ResponseWriter, r *http.Request) {
	fail := func(code int, msg string) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(code)
		_ = json.NewEncoder(rw).Encode(map[string]string{"message": msg})
	}
	a.mu.Lock()
	down := a.down
	a.mu.Unlock()
	if down {
		fail(http.StatusServiceUnavailable, "unavailable")
		return
	}
	if r.URL.Path == "/api/v2/oauth/token" {
		if r.ParseForm() != nil || r.PostForm.Get("client_id") != a.id || r.PostForm.Get("client_secret") != a.sec {
			fail(http.StatusUnauthorized, "invalid client")
			return
		}
		tok := hex.EncodeToString(randomTestBytes(16))
		a.mu.Lock()
		a.tokens[tok] = true
		a.mu.Unlock()
		_ = json.NewEncoder(rw).Encode(map[string]string{"access_token": tok, "scope": "devices:core"})
		return
	}
	a.mu.Lock()
	ok := a.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	a.mu.Unlock()
	if !ok {
		fail(http.StatusUnauthorized, "invalid token")
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/tailnet/-/devices":
		var out []map[string]any
		for _, n := range a.control.AllNodes() {
			out = append(out, map[string]any{"id": strconv.FormatInt(int64(n.ID), 10), "nodeId": string(n.StableID), "name": strings.TrimSuffix(n.Name, "."), "keyExpiryDisabled": true})
		}
		_ = json.NewEncoder(rw).Encode(map[string]any{"devices": out})
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/name"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v2/device/"), "/name")
		var body struct {
			Name string `json:"name"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || !regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`).MatchString(body.Name) {
			fail(http.StatusBadRequest, "invalid name")
			return
		}
		var target *tailcfg.Node
		for _, n := range a.control.AllNodes() {
			label, _, _ := strings.Cut(n.Name, ".")
			if strconv.FormatInt(int64(n.ID), 10) == id {
				target = n
			} else if strings.EqualFold(label, body.Name) {
				fail(http.StatusConflict, "name already in use")
				return
			}
		}
		if target == nil {
			fail(http.StatusNotFound, "no such device")
			return
		}
		target.Name = body.Name + "." + a.suffix + "."
		a.control.UpdateNode(target)
		a.mu.Lock()
		a.renames++
		if a.downFrom > 0 && a.renames >= a.downFrom {
			a.down = true
		}
		a.mu.Unlock()
		rw.WriteHeader(http.StatusOK)
	default:
		fail(http.StatusNotFound, "not found")
	}
}

func (a *apiOver) names() map[string]string {
	out := map[string]string{}
	for _, n := range a.control.AllNodes() {
		label, _, _ := strings.Cut(n.Name, ".")
		out[string(n.StableID)] = label
	}
	return out
}

func randomTestBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// restoreWorld is a restored installation's host: the dead installation's
// node under the name (offline), the operator's OAuth client, the API over
// the same control server, and the restored node enrolled, held.
type restoreWorld struct {
	in      install
	control *testcontrol.Server
	api     *apiOver
	oauth   string
	dead    string // the dead node's StableID
	temp    string
	op      string
	apiURL  string
	caFile  string
}

func newRestoreWorld(t *testing.T, ctx context.Context) *restoreWorld {
	t.Helper()
	control := startTestControl(t)
	w := &restoreWorld{control: control}
	w.api = &apiOver{control: control, suffix: "corp.ts.net", id: "k" + hex.EncodeToString(randomTestBytes(6)), sec: hex.EncodeToString(randomTestBytes(16)), tokens: map[string]bool{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(w.api.serve))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	w.apiURL = srv.URL
	w.caFile = filepath.Join(t.TempDir(), "api-ca.pem")
	if err := os.WriteFile(w.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	prevAPI, prevTLS, prevControl, prevTune := takeNameAPI, takeNameTLS, nodeControlURL, tuneTakeName
	takeNameAPI, takeNameTLS, nodeControlURL = srv.URL, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, control.BaseURL()
	tuneTakeName = func(e *tailhandoff.Engine) {
		e.Deadline, e.UndoWait, e.RetryEvery = 20*time.Second, 2*time.Second, 50*time.Millisecond
	}
	t.Cleanup(func() {
		takeNameAPI, takeNameTLS, nodeControlURL, tuneTakeName = prevAPI, prevTLS, prevControl, prevTune
	})
	// The dead installation's node: joined under the name, then gone.
	dead := &tsnet.Server{Dir: t.TempDir(), Hostname: "vault", ControlURL: control.BaseURL(), AdvertiseTags: []string{"tag:varlatch"}, Logf: logger.Discard}
	st, err := dead.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w.dead = string(st.Self.ID)
	_ = dead.Close()
	w.in = newInstall(t, "")
	keyFile := filepath.Join(w.in.dir, "tailnet-auth-key")
	w.oauth = filepath.Join(w.in.dir, "oauth-client.json")
	b, _ := json.Marshal(map[string]string{"clientId": w.api.id, "clientSecret": w.api.sec})
	for path, body := range map[string][]byte{keyFile: []byte("hermetic\n"), w.oauth: b} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w.in.write(t, fmt.Sprintf("tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_auth_key_file = %s\noutbound_allow = 127.0.0.1/32:*\n", keyFile))
	if w.op, err = tailcontrol.NewOperationID(); err != nil {
		t.Fatal(err)
	}
	if w.temp, err = tailcontrol.TempName("vault", w.op, tailcontrol.RoleNew); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := runAdmin(t, "tailnet", "enroll", "--hostname", w.temp, "--json", "--config", w.in.conf); code != ExitOK {
		t.Fatalf("enroll: %d %q %q", code, out, errOut)
	}
	return w
}

func (w *restoreWorld) restored(t *testing.T) string {
	t.Helper()
	for id, name := range w.api.names() {
		if id != w.dead && (name == w.temp || name == "vault") && !strings.HasPrefix(name, "varlatch-") {
			return id
		}
	}
	t.Fatalf("the restored node is not listed: %v", w.api.names())
	return ""
}

// The restore's handoff (go-step7 decision 11): the restored node, held
// under its temporary name, takes the dead node's name over, by rename,
// through the outbound policy's client; the hold removed, varlatchd
// starts and serves on the tailnet under the name, and a client node's map
// says the name reaches it. Run again, take-name changes nothing.
func TestTheRestoreTakesTheName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	w := newRestoreWorld(t, ctx)
	ours := w.restored(t)
	code, out, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--json", "--config", w.in.conf)
	if code != ExitOK || !strings.Contains(out, `"phase":"done"`) {
		t.Fatalf("take-name: %d %q %q", code, out, errOut)
	}
	if strings.Contains(out+errOut, w.api.sec) {
		t.Fatal("the OAuth client's secret was printed")
	}
	old, _ := tailcontrol.TempName("vault", w.op, tailcontrol.RoleOld)
	if n := w.api.names(); n[ours] != "vault" || n[w.dead] != old {
		t.Fatalf("names %v", n)
	}
	if hold, err := tailnet.LoadHold(w.in.data); err != nil || hold != nil {
		t.Fatalf("the hold after the takeover: %+v %v", hold, err)
	}
	if st, err := os.Stat(filepath.Join(w.in.data, TakeoverFile)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the journal: %v %v", st, err)
	}
	if code, out, _ := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--json", "--config", w.in.conf); code != ExitOK || !strings.Contains(out, `"phase":"done"`) {
		t.Fatalf("take-name again: %d %q", code, out)
	}
	r := startWith(t, w.in, &hooks{tailnetControl: w.control.BaseURL()})
	peer := &tsnet.Server{Dir: t.TempDir(), Hostname: "ci-1", ControlURL: w.control.BaseURL(), Ephemeral: true, AdvertiseTags: []string{"tag:ci"}, Logf: logger.Discard}
	t.Cleanup(func() { _ = peer.Close() })
	if _, err := peer.Up(ctx); err != nil {
		t.Fatal(err)
	}
	addr := hostOfLabel(t, ctx, peer, "vault")
	client := peer.HTTPClient()
	client.Timeout = 10 * time.Second
	var res *http.Response
	var err error
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if res, err = client.Get("http://" + addr + ":8687/v1/meta"); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("the restored node's listener: %v\n%s", err, r.stderr.String())
	}
	res.Body.Close()
	if code, out, _ := runAdmin(t, "tailnet", "reaches", "--name", "vault", "--stable-id", ours, "--wait", "30s", "--json", "--config", w.in.conf); code != ExitOK || !strings.Contains(out, `"reaches":true`) {
		t.Fatalf("reaches: %d %q", code, out)
	}
	r.stop(t)
	if pin, err := tailnet.LoadPin(filepath.Join(w.in.data, tailnet.PinFile)); err != nil || pin == nil || pin.Closed != nil {
		t.Fatalf("the pin: %+v %v", pin, err)
	}
}

// The control plane lost in the middle of the takeover: the switch cannot
// finish, nor its undo; the journal holds where it stands. Run again once
// the control plane answers, take-name resumes it (tailhandoff undoes the
// unfinished switch) and takes the name over.
func TestATakeoverCutShortIsResumed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	w := newRestoreWorld(t, ctx)
	ours := w.restored(t)
	w.api.mu.Lock()
	w.api.downFrom = 1 // down once the dead node is renamed
	w.api.mu.Unlock()
	if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--config", w.in.conf); code != ExitFailure {
		t.Fatalf("take-name with the control plane lost: %d %q", code, errOut)
	}
	j := &takeoverJournal{path: filepath.Join(w.in.data, TakeoverFile)}
	s, err := j.read()
	if err != nil || s == nil || s.Phase == tailhandoff.Done {
		t.Fatalf("the journal after the cut: %+v %v", s, err)
	}
	if hold, _ := tailnet.LoadHold(w.in.data); hold == nil {
		t.Fatal("the hold went though the takeover did not finish")
	}
	w.api.mu.Lock()
	w.api.down, w.api.downFrom = false, 0
	w.api.mu.Unlock()
	code, out, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--json", "--config", w.in.conf)
	if code != ExitOK || !strings.Contains(out, `"phase":"done"`) {
		t.Fatalf("take-name resumed: %d %q %q", code, out, errOut)
	}
	if n := w.api.names(); n[ours] != "vault" {
		t.Fatalf("names %v", n)
	}
}

// What take-name refuses: a node no handoff holds, a hold that is not a
// temporary name of the configured name, a missing OAuth client.
func TestTakeNameRefusals(t *testing.T) {
	in := newInstall(t, "")
	in.write(t, "tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\n")
	oauth := filepath.Join(in.dir, "oauth.json")
	if err := os.WriteFile(oauth, []byte(`{"clientId":"k","clientSecret":"s"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", oauth, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "not held") {
		t.Fatalf("no hold: %d %q", code, errOut)
	}
	if err := tailnet.SaveHold(in.data, &tailnet.Hold{Hostname: "other-vl-abcdefghij-n", Since: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", oauth, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "not a temporary name of vault") {
		t.Fatalf("another hold: %d %q", code, errOut)
	}
	if code, _, _ := runAdmin(t, "tailnet", "take-name", "--config", in.conf); code != 64 {
		t.Fatalf("no --oauth-client-file: %d", code)
	}
	if code, _, _ := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", "relative.json", "--config", in.conf); code != 64 {
		t.Fatalf("a relative path: %d", code)
	}
}
