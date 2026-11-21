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
// Each device's presence (connectedToControl, lastSeen) is seen's, by
// StableID, else connected and seen now; a deleted one is no longer listed
// (and no longer holds its name).
type apiOver struct {
	control  *testcontrol.Server
	suffix   string
	id, sec  string
	mu       sync.Mutex
	tokens   map[string]bool
	renames  int
	downFrom int // the rename after which it is down (0: never)
	down     bool
	seen     map[string]presence
	deleted  map[string]bool
}

type presence struct {
	online   bool
	lastSeen time.Time // zero: not said
}

func (a *apiOver) setSeen(stableID string, p presence) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seen[stableID] = p
}

// remove deletes a device, as the tailnet's admin console would: gone from
// the listing, and its name freed in every netmap.
func (a *apiOver) remove(stableID string) {
	for _, n := range a.control.AllNodes() {
		if string(n.StableID) == stableID {
			n.Name = "deleted-" + strconv.FormatInt(int64(n.ID), 10) + "." + a.suffix + "."
			a.control.UpdateNode(n)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.deleted[stableID] = true
}

func (a *apiOver) renameCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.renames
}

// listed is the control server's nodes less the deleted ones.
func (a *apiOver) listed() []*tailcfg.Node {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []*tailcfg.Node
	for _, n := range a.control.AllNodes() {
		if !a.deleted[string(n.StableID)] {
			out = append(out, n)
		}
	}
	return out
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
		for _, n := range a.listed() {
			a.mu.Lock()
			p, ok := a.seen[string(n.StableID)]
			a.mu.Unlock()
			if !ok {
				p = presence{online: true, lastSeen: time.Now()}
			}
			d := map[string]any{"id": strconv.FormatInt(int64(n.ID), 10), "nodeId": string(n.StableID), "name": strings.TrimSuffix(n.Name, "."), "keyExpiryDisabled": true, "connectedToControl": p.online}
			if !p.lastSeen.IsZero() {
				d["lastSeen"] = p.lastSeen.UTC().Format(time.RFC3339)
			}
			out = append(out, d)
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
		for _, n := range a.listed() {
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
	for _, n := range a.listed() {
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
	keyFile string
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
	w.api = &apiOver{control: control, suffix: "corp.ts.net", id: "k" + hex.EncodeToString(randomTestBytes(6)), sec: hex.EncodeToString(randomTestBytes(16)), tokens: map[string]bool{},
		seen: map[string]presence{}, deleted: map[string]bool{}}
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
	// Gone for two hours, as the control plane sees it.
	w.api.setSeen(w.dead, presence{lastSeen: time.Now().Add(-2 * time.Hour)})
	w.in = newInstall(t, "")
	keyFile := filepath.Join(w.in.dir, "tailnet-auth-key")
	w.keyFile = keyFile
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

// The dead node must be dead: a device under the name that is connected
// now, was seen within deadGrace, or has no last-seen time may be the old
// installation still running, and take-name renames nothing. Once the
// control plane has not seen it for long, the name is taken over. An
// unreadable auth key file is refused with its read error.
func TestTakeNameRefusesALiveHolder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	w := newRestoreWorld(t, ctx)
	ours := w.restored(t)
	recent := time.Now().Add(-time.Minute).UTC()
	for _, c := range []struct {
		name string
		p    presence
		want string
	}{
		{"online", presence{online: true, lastSeen: time.Now()}, "is connected to the tailnet now"},
		{"seen a minute ago", presence{lastSeen: recent}, "was last seen at " + recent.Format(time.RFC3339) + ", within 5m0s"},
		{"last seen unknown", presence{}, "has no last-seen time"},
	} {
		w.api.setSeen(w.dead, c.p)
		code, _, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--config", w.in.conf)
		if code != ExitFailure || !strings.Contains(errOut, c.want) || !strings.Contains(errOut, "the device vault (") ||
			!strings.Contains(errOut, "Stop the old installation (or remove its device from the tailnet), then run take-name again; nothing was renamed") {
			t.Fatalf("%s: %d %q", c.name, code, errOut)
		}
		if n := w.api.names(); n[w.dead] != "vault" || n[ours] != w.temp || w.api.renameCount() != 0 {
			t.Fatalf("%s: names %v after %d renames", c.name, n, w.api.renameCount())
		}
		if hold, _ := tailnet.LoadHold(w.in.data); hold == nil {
			t.Fatalf("%s: the hold went", c.name)
		}
	}
	w.api.setSeen(w.dead, presence{lastSeen: time.Now().Add(-time.Hour)})
	if err := os.Chmod(w.keyFile, 0); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--config", w.in.conf); code != ExitFailure || !strings.Contains(errOut, "cannot read the auth key file: ") || !strings.Contains(errOut, "permission denied") {
		t.Fatalf("an unreadable auth key file: %d %q", code, errOut)
	}
	if err := os.Chmod(w.keyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--json", "--config", w.in.conf)
	if code != ExitOK || !strings.Contains(out, `"phase":"done"`) {
		t.Fatalf("take-name over a long-dead holder: %d %q %q", code, out, errOut)
	}
	if n := w.api.names(); n[ours] != "vault" {
		t.Fatalf("names %v", n)
	}
}

// The dead node checked again right before the first rename: one that
// comes back online after the plan is refused, nothing renamed, the
// handoff left prepared; run again once it is gone for long, it is done.
func TestAHolderBackOnlineBeforeTheRename(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	w := newRestoreWorld(t, ctx)
	ours := w.restored(t)
	prev := handoffPoint
	t.Cleanup(func() { handoffPoint = prev })
	handoffPoint = func(step string) {
		if step == "take-name prepared" {
			w.api.setSeen(w.dead, presence{online: true, lastSeen: time.Now()})
		}
	}
	code, _, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--config", w.in.conf)
	if code != ExitFailure || !strings.Contains(errOut, "is connected to the tailnet now") || !strings.Contains(errOut, "nothing was renamed") {
		t.Fatalf("a holder back online: %d %q", code, errOut)
	}
	if n := w.api.names(); n[w.dead] != "vault" || n[ours] != w.temp || w.api.renameCount() != 0 {
		t.Fatalf("names %v after %d renames", n, w.api.renameCount())
	}
	j := &takeoverJournal{path: filepath.Join(w.in.data, TakeoverFile)}
	if s, err := j.read(); err != nil || s == nil || s.Phase != tailhandoff.Prepared {
		t.Fatalf("the journal: %+v %v", s, err)
	}
	// Still online: the prepared handoff is refused the same way.
	handoffPoint = prev
	if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--config", w.in.conf); code != ExitFailure || !strings.Contains(errOut, "is connected to the tailnet now") {
		t.Fatalf("again while online: %d %q", code, errOut)
	}
	w.api.setSeen(w.dead, presence{lastSeen: time.Now().Add(-time.Hour)})
	code, out, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--json", "--config", w.in.conf)
	if code != ExitOK || !strings.Contains(out, `"phase":"done"`) {
		t.Fatalf("take-name once it is gone: %d %q %q", code, out, errOut)
	}
	if n := w.api.names(); n[ours] != "vault" {
		t.Fatalf("names %v", n)
	}
}

// The dead node's device deleted by the operator during the takeover,
// before its rename: its name is free, and the restored node takes it
// (tailhandoff's takeFreedName) instead of an undo that would wait on a
// device that is gone.
func TestADeadNodeDeletedDuringTheTakeover(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	w := newRestoreWorld(t, ctx)
	ours := w.restored(t)
	prev := handoffPoint
	t.Cleanup(func() { handoffPoint = prev })
	handoffPoint = func(step string) {
		if step == "take-name serving renamed" {
			w.api.remove(w.dead)
		}
	}
	code, out, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--config", w.in.conf)
	if code != ExitOK || !strings.Contains(out, "the old node's device was deleted from the tailnet") {
		t.Fatalf("take-name: %d %q %q", code, out, errOut)
	}
	if n := w.api.names(); n[ours] != "vault" || n[w.dead] != "" {
		t.Fatalf("names %v", n)
	}
	if hold, _ := tailnet.LoadHold(w.in.data); hold != nil {
		t.Fatal("the hold is still there")
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
	// On a self-hosted control server: not yet (slice 7.5c c4).
	hs := newInstall(t, "")
	hs.write(t, "tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_control_url = https://192.0.2.10\n")
	if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", oauth, "--config", hs.conf); code != ExitFailure || !strings.Contains(errOut, "names a self-hosted control server (https://192.0.2.10)") || !strings.Contains(errOut, "nothing was done") {
		t.Fatalf("on Headscale: %d %q", code, errOut)
	}
	if code, _, _ := runAdmin(t, "tailnet", "take-name", "--config", in.conf); code != 64 {
		t.Fatalf("no --oauth-client-file: %d", code)
	}
	if code, _, _ := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", "relative.json", "--config", in.conf); code != 64 {
		t.Fatalf("a relative path: %d", code)
	}
}
