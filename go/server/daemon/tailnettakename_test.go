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
	"github.com/varlatch/varlatch/go/lib/tailcontrol/tailcontroltest"
	"github.com/varlatch/varlatch/go/lib/tailhandoff"
	"github.com/varlatch/varlatch/go/server/outbound"
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
	// skew moves the listing's Date header off this host's clock, as a
	// host whose clock is off sees it; noDate sends none.
	skew   time.Duration
	noDate bool
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
		a.mu.Lock()
		skew, noDate := a.skew, a.noDate
		a.mu.Unlock()
		if noDate {
			rw.Header()["Date"] = nil // net/http adds none then
		} else {
			rw.Header().Set("Date", time.Now().Add(skew).UTC().Format(http.TimeFormat))
		}
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
	// Root reads it all the same.
	if os.Geteuid() != 0 {
		if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--config", w.in.conf); code != ExitFailure || !strings.Contains(errOut, "cannot read the auth key file: ") || !strings.Contains(errOut, "permission denied") {
			t.Fatalf("an unreadable auth key file: %d %q", code, errOut)
		}
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

// The dead node is judged by the control plane's clock (its listing's
// Date header), never this host's: a node the control plane saw a minute
// ago is too recent, though this host's fast clock makes it eleven; one it
// saw eleven minutes ago is dead, though this host's slow clock makes it
// one; a listing without a Date is refused.
func TestTakeNameJudgesByTheControlPlanesClock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	w := newRestoreWorld(t, ctx)
	ours := w.restored(t)
	set := func(skew time.Duration, noDate bool, seen time.Time) {
		w.api.mu.Lock()
		w.api.skew, w.api.noDate = skew, noDate
		w.api.mu.Unlock()
		w.api.setSeen(w.dead, presence{lastSeen: seen})
	}
	// This host's clock ten minutes fast: by it, the old node was seen
	// eleven minutes ago; by the control plane's, one.
	set(-10*time.Minute, false, time.Now().Add(-11*time.Minute))
	if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--config", w.in.conf); code != ExitFailure || !strings.Contains(errOut, "within 5m0s") || !strings.Contains(errOut, "nothing was renamed") {
		t.Fatalf("seen a minute ago by the control plane's clock: %d %q", code, errOut)
	}
	// A Date over an hour off this host's clock: neither is trusted.
	set(2*time.Hour, false, time.Now().Add(-3*time.Hour))
	if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--config", w.in.conf); code != ExitFailure || !strings.Contains(errOut, "more than 1h0m0s apart") || !strings.Contains(errOut, "nothing was renamed") {
		t.Fatalf("a Date two hours ahead: %d %q", code, errOut)
	}
	set(0, true, time.Now().Add(-time.Hour))
	if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--config", w.in.conf); code != ExitFailure || !strings.Contains(errOut, "no Date header") || !strings.Contains(errOut, "nothing was renamed") {
		t.Fatalf("a listing without a Date: %d %q", code, errOut)
	}
	if n := w.api.names(); n[w.dead] != "vault" || w.api.renameCount() != 0 {
		t.Fatalf("names %v after %d renames", n, w.api.renameCount())
	}
	// This host's clock ten minutes slow: by it, a minute ago; by the
	// control plane's, eleven: dead.
	set(10*time.Minute, false, time.Now().Add(-time.Minute))
	code, out, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--json", "--config", w.in.conf)
	if code != ExitOK || !strings.Contains(out, `"phase":"done"`) {
		t.Fatalf("seen eleven minutes ago by the control plane's clock: %d %q %q", code, out, errOut)
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
	// The journal planned for another node: refused before anything is
	// renamed (a handoff under way goes on for its own node only).
	rec, err := j.readRecord()
	if err != nil || rec == nil || rec.IncomingStableID != ours {
		t.Fatalf("the journal's incoming node: %+v %v (this node %s)", rec, err, ours)
	}
	rec.IncomingStableID = "nOTHER"
	other, _ := json.Marshal(rec)
	if err := os.WriteFile(j.path, other, 0o600); err != nil {
		t.Fatal(err)
	}
	handoffPoint = prev
	if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--config", w.in.conf); code != ExitFailure ||
		!strings.Contains(errOut, "planned for the node nOTHER, not this node ("+ours+")") || w.api.renameCount() != 0 {
		t.Fatalf("a journal planned for another node: %d %q, %d renames", code, errOut, w.api.renameCount())
	}
	// A journal that records no node (from before take-name recorded it):
	// on Tailscale the plan's id is the device's, not the node's StableID,
	// so it cannot be told to be this node's, and is refused.
	rec.IncomingStableID = ""
	none, _ := json.Marshal(rec)
	if err := os.WriteFile(j.path, none, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", w.oauth, "--config", w.in.conf); code != ExitFailure ||
		!strings.Contains(errOut, "records no node (a journal from before take-name recorded it), so it is not known to be planned for this node ("+ours+")") || w.api.renameCount() != 0 {
		t.Fatalf("a journal that records no node: %d %q, %d renames", code, errOut, w.api.renameCount())
	}
	rec.IncomingStableID = ours
	back, _ := json.Marshal(rec)
	if err := os.WriteFile(j.path, back, 0o600); err != nil {
		t.Fatal(err)
	}
	// Still online: the prepared handoff is refused the same way.
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
	// On a self-hosted control server: --oauth-client-file is refused.
	hs := newInstall(t, "")
	hs.write(t, "tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_control_url = https://192.0.2.10\n")
	if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", oauth, "--config", hs.conf); code != ExitFailure || !strings.Contains(errOut, "names a self-hosted control server (https://192.0.2.10)") || !strings.Contains(errOut, "nothing was done") {
		t.Fatalf("on Headscale with OAuth: %d %q", code, errOut)
	}
	hsKey := filepath.Join(hs.dir, "hs-api-key")
	if err := os.WriteFile(hsKey, []byte("test-key-"+hex.EncodeToString(randomTestBytes(16))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// On Tailscale (tailnet_control_url unset): --headscale-url is refused.
	if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", "https://192.0.2.10", "--headscale-api-key-file", hsKey, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "tailnet_control_url is unset") || !strings.Contains(errOut, "nothing was done") {
		t.Fatalf("on Tailscale with Headscale authority: %d %q", code, errOut)
	}
	// Mismatched --headscale-url vs tailnet_control_url: refused.
	if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", "https://192.0.2.11", "--headscale-api-key-file", hsKey, "--config", hs.conf); code != ExitFailure || !strings.Contains(errOut, "does not match tailnet_control_url") || !strings.Contains(errOut, "nothing was done") {
		t.Fatalf("mismatched headscale URL: %d %q", code, errOut)
	}
	// --headscale-cli is refused with an explanation of why (no HTTP Date header).
	if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-cli", "/usr/bin/headscale", "--config", hs.conf); code != 64 || !strings.Contains(errOut, "Date header") || !strings.Contains(errOut, "--headscale-api-key-file") {
		t.Fatalf("--headscale-cli: %d %q", code, errOut)
	}
	if code, _, _ := runAdmin(t, "tailnet", "take-name", "--config", in.conf); code != 64 {
		t.Fatalf("no authority: %d", code)
	}
	if code, _, _ := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", "relative.json", "--config", in.conf); code != 64 {
		t.Fatalf("a relative OAuth path: %d", code)
	}
	if code, _, _ := runAdmin(t, "tailnet", "take-name", "--headscale-url", "https://192.0.2.10", "--config", hs.conf); code != 64 {
		t.Fatalf("missing --headscale-api-key-file: %d", code)
	}
	if code, _, _ := runAdmin(t, "tailnet", "take-name", "--headscale-api-key-file", hsKey, "--config", hs.conf); code != 64 {
		t.Fatalf("missing --headscale-url: %d", code)
	}
	if code, _, _ := runAdmin(t, "tailnet", "take-name", "--headscale-url", "https://headscale.example", "--headscale-api-key-file", hsKey, "--config", hs.conf); code != 64 {
		t.Fatalf("hostname in --headscale-url: %d", code)
	}
	if code, _, _ := runAdmin(t, "tailnet", "take-name", "--headscale-url", "https://192.0.2.10", "--headscale-api-key-file", "relative-key", "--config", hs.conf); code != 64 {
		t.Fatalf("relative --headscale-api-key-file: %d", code)
	}
	if code, _, _ := runAdmin(t, "tailnet", "take-name", "--oauth-client-file", oauth, "--headscale-url", "https://192.0.2.10", "--headscale-api-key-file", hsKey, "--config", hs.conf); code != 64 {
		t.Fatalf("both authorities: %d", code)
	}
}

// headscaleOutboundAllowEntry formats IPv4 and IPv6 addresses with default
// and non-default ports so every generated entry parses with
// outbound.ParseAllow and allows the Headscale destination.
func TestHeadscaleOutboundAllowEntry(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want string
		host string
		port int
	}{
		{"https://192.168.1.10:443/", "192.168.1.10/32", "192.168.1.10", 443},
		{"https://192.168.1.10:8443", "192.168.1.10/32:8443", "192.168.1.10", 8443},
		{"https://127.0.0.1:41234", "127.0.0.1/32:41234", "127.0.0.1", 41234},
		{"https://[fd00::10]:443", "fd00::10/128", "fd00::10", 443},
		{"https://[fd00::10]:8443", "[fd00::10/128]:8443", "fd00::10", 8443},
	} {
		canon, why := tailcontrol.CanonicalControlURL(c.raw)
		if why != "" {
			t.Fatalf("%s: %s", c.raw, why)
		}
		got := headscaleOutboundAllowEntry(canon)
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.raw, got, c.want)
		}
		entries, err := outbound.ParseAllow(got)
		if err != nil {
			t.Fatalf("ParseAllow(%q): %v", got, err)
		}
		v := outbound.Decide(entries, outbound.Destination{Scheme: "https:", Host: c.host, Port: c.port}, []string{c.host})
		if !v.Allowed {
			t.Errorf("%q did not allow %s:%d: %+v", got, c.host, c.port, v)
		}
	}
}

type fakeTakeNameResolver struct{ ok bool }

func (r fakeTakeNameResolver) Reaches(context.Context, string, string) (bool, error) {
	return r.ok, nil
}

// Unit tests for Headscale take-name with fakes: secret-file checks,
// outbound_allow refusal naming the exact line to add, ClockedLister /
// deadGrace / Date skew checks, HeadscaleCLI refusal, key expiry on both
// success and failure, holder returning before rename, and no certificates.
func TestHeadscaleTakeNameFakes(t *testing.T) {
	ctx := context.Background()

	// 1. Secret-file checks on --headscale-api-key-file.
	t.Run("secret file checks", func(t *testing.T) {
		f := tailcontroltest.NewHeadscale(50*time.Minute, tailcontroltest.Node{ID: "1", Name: "vault"})
		defer f.Close()
		in := newInstall(t, "")
		in.write(t, fmt.Sprintf("tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_control_url = %s\noutbound_allow = %s\n",
			f.URL, headscaleOutboundAllowEntry(f.URL)))
		op, _ := tailcontrol.NewOperationID()
		temp, _ := tailcontrol.TempName("vault", op, tailcontrol.RoleNew)
		if err := tailnet.SaveHold(in.data, &tailnet.Hold{Hostname: temp, Since: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(in.data, tailnet.StateDir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(in.data, tailnet.StateDir, "tailscaled.state"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Mode 0644 (group/world readable): refused.
		loose := filepath.Join(in.dir, "loose-key")
		if err := os.WriteFile(loose, []byte(f.Key+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", f.URL, "--headscale-api-key-file", loose, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "tighten it to 0600") || strings.Contains(errOut, f.Key) {
			t.Fatalf("mode 0644: %d %q", code, errOut)
		}
		// Symlink: refused.
		realKey := filepath.Join(in.dir, "real-key")
		if err := os.WriteFile(realKey, []byte(f.Key+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(in.dir, "link-key")
		if err := os.Symlink(realKey, link); err != nil {
			t.Fatal(err)
		}
		if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", f.URL, "--headscale-api-key-file", link, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "symbolic link") {
			t.Fatalf("symlink: %d %q", code, errOut)
		}
		// Directory: refused.
		if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", f.URL, "--headscale-api-key-file", in.dir, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "not a regular file") {
			t.Fatalf("directory: %d %q", code, errOut)
		}
		// Empty / multi-line / NUL byte: refused.
		for name, content := range map[string][]byte{
			"empty":     []byte("\n"),
			"multiline": []byte("line1\nline2\n"),
			"nul":       []byte("abc\x00def"),
		} {
			p := filepath.Join(in.dir, name+"-key")
			if err := os.WriteFile(p, content, 0o600); err != nil {
				t.Fatal(err)
			}
			if code, _, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", f.URL, "--headscale-api-key-file", p, "--config", in.conf); code != ExitFailure {
				t.Fatalf("%s: %d %q", name, code, errOut)
			}
		}
	})

	// 1b. A take-name that ends before its handoff opens the key (a node
	// not held, a rerun with nothing left to do) still expires it: the
	// authority given ends with the command, however it ends.
	t.Run("early exits expire the key", func(t *testing.T) {
		f := tailcontroltest.NewHeadscale(50*time.Minute, tailcontroltest.Node{ID: "1", Name: "vault"})
		defer f.Close()
		// The outbound policy's client trusts the fake's certificate.
		prevTLS := takeNameTLS
		takeNameTLS = f.Client().Transport.(*http.Transport).TLSClientConfig
		t.Cleanup(func() { takeNameTLS = prevTLS })
		in := newInstall(t, "")
		in.write(t, fmt.Sprintf("tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_control_url = %s\noutbound_allow = %s\n",
			f.URL, headscaleOutboundAllowEntry(f.URL)))
		keyFile := filepath.Join(in.dir, "hs-key")
		if err := os.WriteFile(keyFile, []byte(f.Key+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, _, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", f.URL, "--headscale-api-key-file", keyFile, "--config", in.conf)
		if code != ExitFailure || !strings.Contains(errOut, "not held") || strings.Contains(errOut, f.Key) {
			t.Fatalf("a node not held: %d %q", code, errOut)
		}
		if !f.KeyExpired() {
			t.Fatal("the key is still live after a refusal before the handoff")
		}
		if f.Renames != 0 {
			t.Fatalf("%d renames on a refusal", f.Renames)
		}
	})

	// 1d. A handoff under way began against another control server (or
	// Tailscale's): refused before anything is renamed, the key expired.
	// Headscale's node ids are small integers another server reuses.
	t.Run("a handoff under way against another control server", func(t *testing.T) {
		for _, recorded := range []string{"https://192.0.2.99", ""} {
			f := tailcontroltest.NewHeadscale(50*time.Minute, tailcontroltest.Node{ID: "1", Name: "vault"})
			defer f.Close()
			prevTLS := takeNameTLS
			takeNameTLS = f.Client().Transport.(*http.Transport).TLSClientConfig
			in := newInstall(t, "")
			in.write(t, fmt.Sprintf("tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_control_url = %s\noutbound_allow = %s\n",
				f.URL, headscaleOutboundAllowEntry(f.URL)))
			op, _ := tailcontrol.NewOperationID()
			temp, _ := tailcontrol.TempName("vault", op, tailcontrol.RoleNew)
			if err := tailnet.SaveHold(in.data, &tailnet.Hold{Hostname: temp, Since: time.Now()}); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(in.data, tailnet.StateDir), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(in.data, tailnet.StateDir, "tailscaled.state"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			rec, _ := json.Marshal(takeoverRecord{State: tailhandoff.State{Plan: tailhandoff.Plan{Operation: op, Name: "vault", ServingID: "1", IncomingID: "2"},
				Phase: tailhandoff.Prepared}, ControlURL: recorded})
			if err := os.WriteFile(filepath.Join(in.data, TakeoverFile), rec, 0o600); err != nil {
				t.Fatal(err)
			}
			keyFile := filepath.Join(in.dir, "hs-key")
			if err := os.WriteFile(keyFile, []byte(f.Key+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			want := "began against " + controlName(recorded) + ", not this tailnet_control_url (" + f.URL + ")"
			if recorded == "" {
				want = "records no control server (Tailscale's, or a journal from before take-name recorded it), so it is not known to have begun against this tailnet_control_url (" + f.URL + ")"
			}
			code, _, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", f.URL, "--headscale-api-key-file", keyFile, "--config", in.conf)
			takeNameTLS = prevTLS
			if code != ExitFailure || !strings.Contains(errOut, want) || strings.Contains(errOut, f.Key) {
				t.Fatalf("recorded %q: %d %q", recorded, code, errOut)
			}
			if f.Renames != 0 || !f.KeyExpired() {
				t.Errorf("recorded %q: %d renames, key expired %v", recorded, f.Renames, f.KeyExpired())
			}
		}
	})

	// 1e. A key the handoff's open refuses (it expires more than an hour
	// from now): the warning names that refusal, and says how to expire
	// the key.
	t.Run("a key the open refuses is named as refused", func(t *testing.T) {
		f := tailcontroltest.NewHeadscale(3*time.Hour, tailcontroltest.Node{ID: "1", Name: "vault"})
		defer f.Close()
		prevTLS := takeNameTLS
		takeNameTLS = f.Client().Transport.(*http.Transport).TLSClientConfig
		t.Cleanup(func() { takeNameTLS = prevTLS })
		in := newInstall(t, "")
		in.write(t, fmt.Sprintf("tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_control_url = %s\noutbound_allow = %s\n",
			f.URL, headscaleOutboundAllowEntry(f.URL)))
		op, _ := tailcontrol.NewOperationID()
		temp, _ := tailcontrol.TempName("vault", op, tailcontrol.RoleNew)
		if err := tailnet.SaveHold(in.data, &tailnet.Hold{Hostname: temp, Since: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(in.data, tailnet.StateDir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(in.data, tailnet.StateDir, "tailscaled.state"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		keyFile := filepath.Join(in.dir, "hs-key")
		if err := os.WriteFile(keyFile, []byte(f.Key+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, _, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", f.URL, "--headscale-api-key-file", keyFile, "--config", in.conf)
		if code != ExitFailure || !strings.Contains(errOut, "was not expired (") || !strings.Contains(errOut, "more than an hour from now") ||
			strings.Contains(errOut, "could not be reached") || !strings.Contains(errOut, "headscale apikeys expire --prefix") || strings.Contains(errOut, f.Key) {
			t.Fatalf("a key expiring in 3 h: %d %q", code, errOut)
		}
	})

	// 1c. The prefix the manual instruction names: Headscale's listing of
	// the key, never the key.
	t.Run("the key's prefix", func(t *testing.T) {
		mid := hex.EncodeToString(randomTestBytes(6))
		secret := hex.EncodeToString(randomTestBytes(16))
		for key, want := range map[string]string{
			"hskey-api-" + mid + "-" + secret:      "hskey-api-" + mid,
			"hskey-api-" + mid:                     "",
			"hskey-api-" + mid[:11] + "-" + secret: "",
			mid[:10] + "." + secret:                mid[:10],
			secret:                                 "",
		} {
			got := headscaleKeyPrefix(key)
			if got != want || (got != "" && strings.Contains(got, secret)) {
				t.Errorf("headscaleKeyPrefix(<%d bytes>) = %q, want %q", len(key), got, want)
			}
		}
	})

	// 2. Outbound policy refusal names the exact outbound_allow line to add.
	t.Run("outbound policy refusal names exact outbound_allow line", func(t *testing.T) {
		for _, tc := range []struct {
			name, url, existing, wantLine string
		}{
			{"private IPv4", "https://192.168.10.20:8443", "", "outbound_allow = 192.168.10.20/32:8443"},
			{"private IPv4 with existing", "https://10.20.30.40", "172.16.0.1/32", "outbound_allow = 172.16.0.1/32, 10.20.30.40/32"},
			{"private IPv6", "https://[fd00::42]:8443", "", "outbound_allow = [fd00::42/128]:8443"},
		} {
			in := newInstall(t, "")
			extra := ""
			if tc.existing != "" {
				extra = "outbound_allow = " + tc.existing + "\n"
			}
			in.write(t, fmt.Sprintf("tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_control_url = %s\n%s", tc.url, extra))
			op, _ := tailcontrol.NewOperationID()
			temp, _ := tailcontrol.TempName("vault", op, tailcontrol.RoleNew)
			if err := tailnet.SaveHold(in.data, &tailnet.Hold{Hostname: temp, Since: time.Now()}); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(in.data, tailnet.StateDir), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(in.data, tailnet.StateDir, "tailscaled.state"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			keyFile := filepath.Join(in.dir, "hs-key")
			secret := "test-key-" + hex.EncodeToString(randomTestBytes(16))
			if err := os.WriteFile(keyFile, []byte(secret+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			code, _, errOut := runAdmin(t, "tailnet", "take-name", "--headscale-url", tc.url, "--headscale-api-key-file", keyFile, "--config", in.conf)
			if code != ExitFailure || !strings.Contains(errOut, tc.wantLine) || strings.Contains(errOut, secret) {
				t.Fatalf("%s: %d %q (want %q)", tc.name, code, errOut, tc.wantLine)
			}
		}
	})

	// 3. HeadscaleCLI has no Date header: listedAt refuses it directly.
	t.Run("HeadscaleCLI refused by listedAt", func(t *testing.T) {
		f := tailcontroltest.NewHeadscale(50*time.Minute, tailcontroltest.Node{ID: "1", Name: "vault"})
		defer f.Close()
		cli := &tailcontrol.HeadscaleCLI{Run: f.Run}
		if _, _, err := listedAt(ctx, cli); err == nil || !strings.Contains(err.Error(), "listing says no time") {
			t.Fatalf("HeadscaleCLI listedAt: %v", err)
		}
	})

	// 4. End-to-end takeOver on fake HeadscaleAPI: dead holder taken over,
	// live / recent / unknown / no-Date / skewed-Date refused, returning
	// holder refused before rename, no certificates / issuance file, key
	// expired on every exit path.
	t.Run("liveness, clock skew, returning holder, takeover and key expiry", func(t *testing.T) {
		op, _ := tailcontrol.NewOperationID()
		temp, _ := tailcontrol.TempName("vault", op, tailcontrol.RoleNew)

		runWithFake := func(t *testing.T, deadNode tailcontroltest.Node, skew time.Duration, noDate bool, onPoint func(string, *tailcontroltest.Headscale)) (*tailcontroltest.Headscale, *tailhandoff.State, error, string) {
			t.Helper()
			f := tailcontroltest.NewHeadscale(50*time.Minute, deadNode, tailcontroltest.Node{ID: "2", Name: temp, Online: true, LastSeen: time.Now()})
			t.Cleanup(f.Close)
			f.DateSkew, f.NoDate = skew, noDate
			hs, err := tailcontrol.NewHeadscaleAPI(tailcontrol.HeadscaleAPIConfig{BaseURL: f.URL, APIKey: f.Key, HTTP: f.Client()})
			if err != nil {
				t.Fatal(err)
			}
			if err := hs.Open(ctx); err != nil {
				t.Fatal(err)
			}
			var errBuf strings.Builder
			defer closeControlPlane(hs, &errBuf)
			dataDir := t.TempDir()
			if err := tailnet.SaveHold(dataDir, &tailnet.Hold{Hostname: temp, Since: time.Now()}); err != nil {
				t.Fatal(err)
			}
			j := &takeoverJournal{path: filepath.Join(dataDir, TakeoverFile)}
			he := &tailhandoff.Engine{
				Control:   hs,
				Endpoints: restoreEndpoints{dataDir: dataDir},
				Resolver:  fakeTakeNameResolver{ok: true},
				Journal:   j,
			}
			if onPoint != nil {
				prev := handoffPoint
				handoffPoint = func(step string) { onPoint(step, f) }
				defer func() { handoffPoint = prev }()
			}
			st, runErr := takeOver(ctx, he, j, hs, op, "vault", "2", false)
			return f, st, runErr, dataDir
		}

		// Live holder (online: true): refused, nothing renamed, key expired.
		f, _, err, _ := runWithFake(t, tailcontroltest.Node{ID: "1", Name: "vault", Online: true, LastSeen: time.Now()}, 0, false, nil)
		if err == nil || !strings.Contains(err.Error(), "is connected to the tailnet now") || f.Renames != 0 || !f.KeyExpired() {
			t.Fatalf("online holder: err=%v renames=%d expired=%v", err, f.Renames, f.KeyExpired())
		}
		// Seen within deadGrace: refused, nothing renamed, key expired.
		f, _, err, _ = runWithFake(t, tailcontroltest.Node{ID: "1", Name: "vault", Online: false, LastSeen: time.Now().Add(-time.Minute)}, 0, false, nil)
		if err == nil || !strings.Contains(err.Error(), "within 5m0s") || f.Renames != 0 || !f.KeyExpired() {
			t.Fatalf("recent holder: err=%v renames=%d expired=%v", err, f.Renames, f.KeyExpired())
		}
		// Unknown lastSeen: refused, nothing renamed, key expired.
		f, _, err, _ = runWithFake(t, tailcontroltest.Node{ID: "1", Name: "vault", Online: false}, 0, false, nil)
		if err == nil || !strings.Contains(err.Error(), "has no last-seen time") || f.Renames != 0 || !f.KeyExpired() {
			t.Fatalf("unknown lastSeen: err=%v renames=%d expired=%v", err, f.Renames, f.KeyExpired())
		}
		// Missing Date header: refused, nothing renamed, key expired.
		f, _, err, _ = runWithFake(t, tailcontroltest.Node{ID: "1", Name: "vault", Online: false, LastSeen: time.Now().Add(-time.Hour)}, 0, true, nil)
		if err == nil || !strings.Contains(err.Error(), "no Date header") || f.Renames != 0 || !f.KeyExpired() {
			t.Fatalf("missing Date: err=%v renames=%d expired=%v", err, f.Renames, f.KeyExpired())
		}
		// Date more than 1h off host clock: refused, nothing renamed, key expired.
		f, _, err, _ = runWithFake(t, tailcontroltest.Node{ID: "1", Name: "vault", Online: false, LastSeen: time.Now().Add(-3 * time.Hour)}, 2*time.Hour, false, nil)
		if err == nil || !strings.Contains(err.Error(), "more than 1h0m0s apart") || f.Renames != 0 || !f.KeyExpired() {
			t.Fatalf("skewed Date: err=%v renames=%d expired=%v", err, f.Renames, f.KeyExpired())
		}
		// Holder returns online between Prepare and Switch: refused, nothing renamed, key expired.
		f, _, err, _ = runWithFake(t, tailcontroltest.Node{ID: "1", Name: "vault", Online: false, LastSeen: time.Now().Add(-time.Hour)}, 0, false, func(step string, hs *tailcontroltest.Headscale) {
			if step == "take-name prepared" {
				hs.SetPresence("1", true, time.Now())
			}
		})
		if err == nil || !strings.Contains(err.Error(), "is connected to the tailnet now") || f.Renames != 0 || !f.KeyExpired() {
			t.Fatalf("returning holder: err=%v renames=%d expired=%v", err, f.Renames, f.KeyExpired())
		}
		// Dead holder taken over cleanly, no certificates/issuances, key expired.
		f, st, err, dataDir := runWithFake(t, tailcontroltest.Node{ID: "1", Name: "vault", Online: false, LastSeen: time.Now().Add(-time.Hour)}, 0, false, nil)
		if err != nil || st == nil || st.Phase != tailhandoff.Done || !f.KeyExpired() {
			t.Fatalf("dead holder takeover: st=%+v err=%v expired=%v", st, err, f.KeyExpired())
		}
		if _, err := os.Stat(filepath.Join(dataDir, IssuanceFile)); !os.IsNotExist(err) {
			t.Fatalf("issuance file written on Headscale: %v", err)
		}
		if hold, _ := tailnet.LoadHold(dataDir); hold != nil {
			t.Fatalf("hold still present: %+v", hold)
		}
		nodes := f.Nodes()
		oldTemp, _ := tailcontrol.TempName("vault", op, tailcontrol.RoleOld)
		if nodes[0].Name != oldTemp || nodes[1].Name != "vault" {
			t.Fatalf("names after takeover: %+v", nodes)
		}
	})
}
