// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g5 && linux

package g5_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/logtail"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// G5's tailnet half (internal docs/design/go-step7.md decisions 11 and 12,
// slice 7.5b): the migration of a source serving a tailnet address, and
// its reverse, the real `varlatch migrate` killed at every step the tailnet
// handoff journals, then resumed or aborted to its stated end.
//
// What is real, beside what interrupt_test.go says: the target varlatchd's
// tailnet node (tsnet, built with the crashpoint tag so that it joins the
// gate's control server: tailnethook_crashpoint.go), its handoff commands
// (enroll, certificate, open, the reach probe), and Tailscale's own control
// server and DERP relay (testcontrol), in this process, on loopback.
//
// What stands in:
//   - the Tailscale API, for the handoff's control-plane calls: a fake on
//     top of the same testcontrol, so that a rename is the control
//     server's (its node's name, pushed to every peer's netmap: the old
//     name is gone from every client's map, as on Tailscale), with the
//     OAuth exchange and the devices:core scope;
//   - the TypeScript installation's Tailscale sidecar: a real tsnet node
//     in a process of this binary (g5-sidecar), started and stopped by the
//     `docker` stand-in; stopped, it closes without logging out, so it
//     keeps its node key and its StableID when it starts again.

// tailnetEnv is one world's tailnet: the control server, the API over it,
// and the operator's files.
type tailnetEnv struct {
	control   *testcontrol.Server
	api       *httptest.Server
	suffix    string
	clientID  string
	secret    string
	oauthFile string
	mu        sync.Mutex
	tokens    map[string]bool
	renames   int
	// refuse is a name a rename to is refused (409, as a name another
	// device holds): for refuseNode only when set, else for every node but
	// refuseExcept. downAfterRefusal takes the API down after the first
	// refusal, as a control plane lost in the middle of an undo.
	refuse           string
	refuseNode       string
	refuseExcept     string
	downAfterRefusal bool
	down             bool
}

func (tn *tailnetEnv) set(f func(tn *tailnetEnv)) {
	tn.mu.Lock()
	defer tn.mu.Unlock()
	f(tn)
}

const tailnetSuffix = "g5.ts.net"

// newTailnetWorld is a world whose source serves the tailnet address
// vault.g5.ts.net through its sidecar, and whose target varlatchd has
// tailnet = on under the same name.
func newTailnetWorld(t *testing.T) (*world, *tailnetEnv) {
	t.Helper()
	w := newWorld(t, false)
	derp := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	tn := &tailnetEnv{suffix: tailnetSuffix, tokens: map[string]bool{}, clientID: "k" + hex.EncodeToString(randomBytes(6)), secret: hex.EncodeToString(randomBytes(16))}
	tn.control = &testcontrol.Server{DERPMap: derp, DNSConfig: &tailcfg.DNSConfig{Proxied: true}, MagicDNSDomain: tailnetSuffix, Logf: logger.Discard,
		TagOwners: map[string][]string{"tag:varlatch": nil}}
	tn.control.HTTPTestServer = httptest.NewUnstartedServer(tn.control)
	tn.control.HTTPTestServer.Start()
	t.Cleanup(tn.control.HTTPTestServer.Close)
	tn.api = httptest.NewTLSServer(http.HandlerFunc(tn.serveAPI))
	t.Cleanup(tn.api.Close)
	ca := filepath.Join(w.stateDir, "api-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tn.api.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tn.oauthFile = filepath.Join(w.compose, "oauth-client.json")
	b, _ := json.Marshal(map[string]string{"clientId": tn.clientID, "clientSecret": tn.secret})
	keyFile := filepath.Join(w.compose, "tailnet-auth-key")
	for name, body := range map[string][]byte{tn.oauthFile: b, keyFile: []byte("g5-reusable-key\n")} {
		if err := os.WriteFile(name, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w.env = []string{"G5_TAILNET=1", "VARLATCH_TEST_HANDOFF_UNDO_WAIT=3s", "G5_TAILNET_CONTROL=" + tn.control.BaseURL(), "VARLATCH_TEST_TAILNET_CONTROL=" + tn.control.BaseURL(),
		"VARLATCH_TEST_TAILSCALE_API=" + tn.api.URL, "VARLATCH_TEST_TAILSCALE_CA=" + ca}
	w.extraArgs = []string{"--tailscale-oauth-client-file", tn.oauthFile, "--tailnet-auth-key-file", keyFile}
	w.secrets = [][]byte{[]byte(tn.secret), []byte("g5-reusable-key")}
	// The source's .env names its node and tailnet; the target's
	// configuration takes the same name.
	env, _ := os.ReadFile(filepath.Join(w.compose, ".env"))
	env = append(env, []byte("VARLATCH_TAILNET_MACHINE=vault\nVARLATCH_TAILNET_NAME="+tailnetSuffix+"\n")...)
	if err := os.WriteFile(filepath.Join(w.compose, ".env"), env, 0o600); err != nil {
		t.Fatal(err)
	}
	extra := fmt.Sprintf("tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_auth_key_file = %s\n", filepath.Join(w.keys, "tailnet-auth-key"))
	for _, conf := range []string{w.conf, filepath.Join(w.stateDir, "service.conf")} {
		b, _ := os.ReadFile(conf)
		if err := os.WriteFile(conf, append(b, []byte(extra)...), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The sidecar runs, holding the name.
	w.useState()
	for _, kv := range w.env {
		k, v, _ := strings.Cut(kv, "=")
		t.Setenv(k, v)
	}
	if err := startSidecar(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Setenv("G5_STATE", w.stateDir)
		_ = stopSidecar()
	})
	return w, tn
}

// --- the Tailscale API over testcontrol ---

func (tn *tailnetEnv) serveAPI(rw http.ResponseWriter, r *http.Request) {
	fail := func(code int, msg string) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(code)
		_ = json.NewEncoder(rw).Encode(map[string]string{"message": msg})
	}
	tn.mu.Lock()
	down := tn.down
	tn.mu.Unlock()
	if down {
		fail(http.StatusServiceUnavailable, "unavailable")
		return
	}
	if r.URL.Path == "/api/v2/oauth/token" {
		if r.ParseForm() != nil || r.PostForm.Get("client_id") != tn.clientID || r.PostForm.Get("client_secret") != tn.secret {
			fail(http.StatusUnauthorized, "invalid client")
			return
		}
		tok := hex.EncodeToString(randomBytes(16))
		tn.mu.Lock()
		tn.tokens[tok] = true
		tn.mu.Unlock()
		_ = json.NewEncoder(rw).Encode(map[string]string{"access_token": tok, "scope": "devices:core"})
		return
	}
	tn.mu.Lock()
	ok := tn.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	tn.mu.Unlock()
	if !ok {
		fail(http.StatusUnauthorized, "invalid token")
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/tailnet/-/devices":
		var out []map[string]any
		for _, n := range tn.control.AllNodes() {
			online := n.Online != nil && *n.Online
			out = append(out, map[string]any{"id": strconv.FormatInt(int64(n.ID), 10), "nodeId": string(n.StableID), "name": strings.TrimSuffix(n.Name, "."),
				"connectedToControl": online, "keyExpiryDisabled": true})
		}
		_ = json.NewEncoder(rw).Encode(map[string]any{"devices": out})
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v2/device/") && strings.HasSuffix(r.URL.Path, "/name"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v2/device/"), "/name")
		var body struct {
			Name string `json:"name"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || !regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`).MatchString(body.Name) {
			fail(http.StatusBadRequest, "invalid name")
			return
		}
		var stable string
		for _, n := range tn.control.AllNodes() {
			if strconv.FormatInt(int64(n.ID), 10) == id {
				stable = string(n.StableID)
			}
		}
		tn.mu.Lock()
		refused := tn.refuse != "" && body.Name == tn.refuse &&
			(tn.refuseNode == "" || tn.refuseNode == stable) && (tn.refuseExcept == "" || tn.refuseExcept != stable)
		if refused && tn.downAfterRefusal {
			tn.down = true
		}
		tn.mu.Unlock()
		if refused {
			fail(http.StatusConflict, "name already in use")
			return
		}
		var target *tailcfg.Node
		for _, n := range tn.control.AllNodes() {
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
		// The control server's rename: the node's name, pushed to every
		// peer's map.
		target.Name = body.Name + "." + tn.suffix + "."
		tn.control.UpdateNode(target)
		tn.mu.Lock()
		tn.renames++
		tn.mu.Unlock()
		rw.WriteHeader(http.StatusOK)
	default:
		fail(http.StatusNotFound, "not found")
	}
}

// names are the control server's: each node's StableID to its name's
// first label.
func (tn *tailnetEnv) names() map[string]string {
	out := map[string]string{}
	for _, n := range tn.control.AllNodes() {
		label, _, _ := strings.Cut(n.Name, ".")
		out[string(n.StableID)] = label
	}
	return out
}

// --- the sidecar stand-in ---

// runSidecar is the TypeScript installation's Tailscale sidecar: a tsnet
// node named vault, its state in the stand-ins' directory, until SIGTERM,
// when it closes without logging out (its node key and StableID kept).
func runSidecar() int {
	netns.SetEnabled(false)
	envknob.Setenv("TS_NO_LOGS_NO_SUPPORT", "true")
	logtail.Disable()
	srv := &tsnet.Server{Dir: state("sidecar"), Hostname: "vault", ControlURL: os.Getenv("G5_TAILNET_CONTROL"), AuthKey: "g5-sidecar",
		AdvertiseTags: []string{"tag:varlatch"}, Logf: logger.Discard, UserLogf: logger.Discard}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st, err := srv.Up(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "the sidecar did not join:", err)
		return 1
	}
	if err := os.WriteFile(state("sidecar.up"), []byte(st.Self.ID), 0o600); err != nil {
		return 1
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	_ = os.Remove(state("sidecar.up"))
	_ = srv.Close()
	return 0
}

func sidecarPID() int {
	b, err := os.ReadFile(state("sidecar.pid"))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func sidecarRunning() bool { pid := sidecarPID(); return pid > 0 && alive(pid) }

// startSidecar starts the sidecar's process (detached: the stand-in that
// starts it exits) and waits until it is on the tailnet.
func startSidecar() error {
	if sidecarRunning() {
		return nil
	}
	// From a stand-in (docker), beside it; from the test, the shared one.
	self := filepath.Join(shared.fakebin, "g5-sidecar")
	if filepath.Base(os.Args[0]) == "docker" {
		self = filepath.Join(filepath.Dir(os.Args[0]), "g5-sidecar")
	}
	log, err := os.OpenFile(state("sidecar.log"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer log.Close()
	_ = os.Remove(state("sidecar.up"))
	cmd := exec.Command(self)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	if err := os.WriteFile(state("sidecar.pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		return err
	}
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if _, err := os.Stat(state("sidecar.up")); err == nil {
			return setStopped("tailscale", false)
		}
		if !alive(cmd.Process.Pid) {
			return fmt.Errorf("the sidecar exited (%s)", state("sidecar.log"))
		}
	}
	return fmt.Errorf("the sidecar did not join within 60 s")
}

// stopSidecar stops it: SIGTERM, it closes without logging out.
func stopSidecar() error {
	pid := sidecarPID()
	if pid > 0 && alive(pid) {
		_ = syscall.Kill(pid, syscall.SIGTERM)
		for deadline := time.Now().Add(20 * time.Second); alive(pid); time.Sleep(50 * time.Millisecond) {
			if time.Now().After(deadline) {
				return fmt.Errorf("the sidecar did not stop")
			}
		}
	}
	_ = os.Remove(state("sidecar.pid"))
	return setStopped("tailscale", true)
}

// fakeDockerTailnet answers Docker's part of the sidecar: the Compose
// project names it (and the server sharing its network), stop and start
// stop and start its process, and its certificate cache is empty (the
// gate's tailnet has no HTTPS: testcontrol issues no certificates).
func fakeDockerTailnet(args []string) (int, bool) {
	fail := func(f string, a ...any) (int, bool) { fmt.Fprintf(os.Stderr, f+"\n", a...); return 1, true }
	j := strings.Join(args, " ")
	switch {
	case j == "compose config --no-interpolate --format json":
		logCall(j)
		out, _ := json.Marshal(map[string]any{"name": composeProject(), "services": map[string]any{
			"varlatchd": map[string]any{"network_mode": "service:tailscale"},
			"tailscale": map[string]any{"environment": map[string]any{"TS_STATE_DIR": "/var/lib/tailscale"}},
		}})
		fmt.Println(string(out))
		return 0, true
	case j == "compose stop tailscale":
		logCall(j)
		if err := stopSidecar(); err != nil {
			return fail("%v", err)
		}
		return 0, true
	case j == "compose start tailscale":
		logCall(j)
		if err := startSidecar(); err != nil {
			return fail("%v", err)
		}
		return 0, true
	case j == "compose restart varlatchd":
		logCall(j)
		return 0, true
	case strings.HasPrefix(j, "compose run --rm --no-deps -T --entrypoint cat tailscale /var/lib/tailscale/certs/"):
		logCall(j)
		fmt.Fprintf(os.Stderr, "cat: %s: No such file or directory\n", args[len(args)-1])
		return 1, true
	case len(args) >= 4 && args[0] == "compose" && args[1] == "up" && args[2] == "-d" && strings.Contains(j, " varlatchd"):
		// varlatchd shares the sidecar's network: Compose starts the
		// sidecar first. The rest is the reverse's stand-in's.
		if err := startSidecar(); err != nil {
			return fail("%v", err)
		}
		return 0, false
	}
	return 0, false
}

// sidecarID is the sidecar node's StableID (it keeps it across stops).
func sidecarID(t *testing.T) string {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if b, err := os.ReadFile(state("sidecar.up")); err == nil && len(b) > 0 {
			return string(b)
		}
	}
	t.Fatal("the sidecar is not up")
	return ""
}

// targetID is the target node's StableID, from the migration's journal.
func (w *world) tailnetRecord(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(w.compose, "migration.json"))
	if err != nil {
		t.Fatal(err)
	}
	var j struct {
		Tailnet map[string]any `json:"tailnet"`
	}
	if err := json.Unmarshal(b, &j); err != nil || j.Tailnet == nil {
		t.Fatalf("the journal's tailnet: %s", b)
	}
	return j.Tailnet
}

// reaches asks the real varlatchd's reach probe (a client node of the
// tailnet) whether name reaches the node: what a client's netmap says.
func (w *world) reaches(t *testing.T, name, stableID string) bool {
	t.Helper()
	cmd := exec.Command(filepath.Join(filepath.Dir(shared.varlatch), "varlatchd"), "admin", "tailnet", "reaches", "--name", name, "--stable-id", stableID, "--wait", "20s", "--json", "--config", w.conf)
	cmd.Env = append(os.Environ(), w.env...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("reaches: %v %s", err, out)
	}
	return strings.Contains(string(out), `"reaches":true`)
}

// tailnetAt is where the name is: "source" (the sidecar's node holds it,
// the target's under its temporary name), "target" (the reverse), each
// read from the control server and from a client node's map.
func (w *world) tailnetAt(t *testing.T, tn *tailnetEnv, sidecar string, want string) {
	t.Helper()
	rec := w.tailnetRecord(t)
	target, _ := rec["stableId"].(string)
	names := tn.names()
	holder := sidecar
	if want == "target" {
		holder = target
	}
	if names[holder] != "vault" {
		t.Fatalf("the name is not with the %s's node: %v (sidecar %s, target %s)", want, names, sidecar, target)
	}
	if !w.reaches(t, "vault", holder) {
		t.Fatalf("vault does not reach the %s's node from a client node", want)
	}
	other := target
	if want == "target" {
		other = sidecar
	}
	if strings.EqualFold(names[other], "vault") {
		t.Fatalf("both nodes are named vault: %v", names)
	}
}

// The tailnet name moves with the migration and back with its reverse:
// after the public address, the name is the target's node's, a client
// node's map says so, the sidecar is stopped without logging out (its
// node and StableID kept); the reverse gives it back to the sidecar.
func TestG5TailnetWhole(t *testing.T) {
	w, tn := newTailnetWorld(t)
	sidecar := sidecarID(t)
	if code := w.run(""); code != 0 {
		t.Fatalf("the migration: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	w.expect("migrated", "open", "open", "target-open", "migrated-out")
	w.tailnetAt(t, tn, sidecar, "target")
	if sidecarRunning() {
		t.Error("the sidecar still runs after the switch")
	}
	if code := w.rollback("", "--rollback"); code != 0 {
		t.Fatalf("the reverse: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	if got := sidecarID(t); got != sidecar {
		t.Fatalf("the sidecar came back as another node: %s, was %s", got, sidecar)
	}
	w.tailnetAt(t, tn, sidecar, "source")
	w.noSecrets()
	for _, out := range w.outputs {
		if strings.Contains(string(out), tn.secret) {
			t.Fatal("the OAuth client's secret in an output")
		}
	}
}

// The forward handoff's journal steps, in the transfer.
var forwardSteps = []string{"prepared", "switching", "serving closed", "serving renamed", "incoming renamed", "opening", "done"}

// G5, the tailnet handoff interrupted: varlatch migrate killed at every
// step the forward handoff journals, then --resume to open (the name the
// target's), or --abort to released (the name the sidecar's again, its
// node unchanged), a second --resume changing nothing.
func TestG5TailnetInterruptions(t *testing.T) {
	for _, step := range forwardSteps {
		for _, abort := range []bool{false, true} {
			point := "tailnet forward " + step
			name := step + map[bool]string{false: ", resumed", true: ", aborted"}[abort]
			t.Run(name, func(t *testing.T) {
				w, tn := newTailnetWorld(t)
				sidecar := sidecarID(t)
				if code := w.run(point); code != -1 {
					t.Fatalf("not killed at %s: %d", point, code)
				}
				before := step == "prepared"
				if before {
					// Prepared before the barrier: the source serves, nothing
					// was renamed.
					w.expect("killed at "+point, "preflight", "preflight", "source", "")
					if tn.names()[sidecar] != "vault" {
						t.Fatalf("renamed before the barrier: %v", tn.names())
					}
				}
				final := "open"
				var code int
				if abort {
					final = "released"
					code = w.run("", "--abort")
				} else {
					code = w.run("", "--resume")
				}
				if code != 0 && !(abort && code == 1 && before) {
					t.Fatalf("%v: %d\n%s", map[bool]string{false: "--resume", true: "--abort"}[abort], code, w.outputs[len(w.outputs)-1])
				}
				w.useState()
				switch {
				case final == "open":
					w.expect("resumed", "open", "open", "target-open", "migrated-out")
					w.tailnetAt(t, tn, sidecar, "target")
				case before:
					// An abort before the barrier: the migration was never
					// switched, the source serves.
					if a := w.answers(); a != "source" {
						t.Fatalf("after --abort before the barrier: %s", a)
					}
					if tn.names()[sidecar] != "vault" {
						t.Fatalf("names %v", tn.names())
					}
				default:
					w.expect("aborted", "released", "released", "source", "")
					w.tailnetAt(t, tn, sidecar, "source")
					if !sidecarRunning() {
						t.Fatal("the sidecar was not started again")
					}
				}
				if final == "released" {
					if got := sidecarID(t); got != sidecar {
						t.Fatalf("the sidecar came back as another node: %s", got)
					}
				} else if sidecarRunning() {
					t.Error("the sidecar runs after the open")
				}
				if code := w.run("", "--resume"); code != 0 {
					t.Errorf("a second --resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
				}
				w.noSecrets()
			})
		}
	}
}

// G5, the reverse's tailnet handoff interrupted: --rollback killed at
// every step that hands the name back to the sidecar, then --resume to
// rolled back (the name the sidecar's), or, before the name moved,
// --abort back to open (the name the target's).
func TestG5TailnetRollbackInterruptions(t *testing.T) {
	for _, step := range forwardSteps {
		for _, abort := range []bool{false, true} {
			// From the open the name is effectively back with the sidecar:
			// the reverse goes forward only, an abort is refused.
			late := step == "opening" || step == "done"
			point := "tailnet rollback " + step
			name := step + map[bool]string{false: ", resumed", true: ", aborted"}[abort]
			t.Run(name, func(t *testing.T) {
				w, tn := newTailnetWorld(t)
				sidecar := sidecarID(t)
				if code := w.run(""); code != 0 {
					t.Fatalf("the migration: %d\n%s", code, w.outputs[len(w.outputs)-1])
				}
				if code := w.rollback(point, "--rollback"); code != -1 {
					t.Fatalf("not killed at %s: %d\n%s", point, code, w.outputs[len(w.outputs)-1])
				}
				if abort && late {
					if code := w.rollback("", "--abort"); code != 1 {
						t.Fatalf("--abort once the name is back: %d\n%s", code, w.outputs[len(w.outputs)-1])
					}
				}
				if abort && !late {
					if code := w.rollback("", "--abort"); code != 0 {
						t.Fatalf("--abort: %d\n%s", code, w.outputs[len(w.outputs)-1])
					}
					w.useState()
					w.tailnetAt(t, tn, sidecar, "target")
					if sidecarRunning() {
						calls, _ := os.ReadFile(state("docker-calls"))
						t.Errorf("the sidecar runs after the reverse was undone; Docker was asked:\n%s", calls)
					}
				} else {
					if code := w.rollback("", "--resume"); code != 0 {
						t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
					}
					w.useState()
					w.tailnetAt(t, tn, sidecar, "source")
					if got := sidecarID(t); got != sidecar {
						t.Fatalf("the sidecar came back as another node: %s", got)
					}
				}
				if code := w.rollback("", "--resume"); code != 0 {
					t.Errorf("a second --resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
				}
				w.noSecrets()
			})
		}
	}
}

// heldAs is the target's hold's temporary name ("" for none).
func (w *world) heldAs() string {
	b, err := os.ReadFile(filepath.Join(w.data, "tailnet-handoff.json"))
	if err != nil {
		return ""
	}
	var h struct {
		Hostname string `json:"hostname"`
	}
	_ = json.Unmarshal(b, &h)
	return h.Hostname
}

// A migration killed in its transfer before the name moved, resumed
// without the tailnet's authority: refused (exit 1), naming what it needs,
// nothing changed; resumed with it, it opens.
func TestG5TailnetResumeWithoutTheAuthority(t *testing.T) {
	w, tn := newTailnetWorld(t)
	sidecar := sidecarID(t)
	if code := w.run("tailnet switch"); code != -1 {
		t.Fatalf("not killed: %d", code)
	}
	given := w.extraArgs
	w.extraArgs = nil
	if code := w.run("", "--resume"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "--tailscale-oauth-client-file") {
		t.Fatalf("--resume without the authority: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	if s, d := w.phases(); s != "transfer" || d != "transfer" {
		t.Fatalf("the journals after the refusal: %s / %s", s, d)
	}
	if tn.names()[sidecar] != "vault" {
		t.Fatalf("renamed without the authority: %v", tn.names())
	}
	w.extraArgs = given
	if code := w.run("", "--resume"); code != 0 {
		t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	w.useState()
	w.expect("resumed", "open", "open", "target-open", "migrated-out")
	w.tailnetAt(t, tn, sidecar, "target")
	w.noSecrets()
}

// The forward handoff's own undo, killed at each step it journals: the
// rename to the name refused (another device's), the handoff undoes; then
// --resume moves the name again to open, or --abort undoes the migration.
// undo-pending is the control plane lost in the middle of that undo.
func TestG5TailnetForwardUndoSteps(t *testing.T) {
	for _, c := range []struct {
		step string
		down bool
	}{{"undoing", false}, {"undone", false}, {"undo-pending", true}} {
		for _, abort := range []bool{false, true} {
			name := c.step + map[bool]string{false: ", resumed", true: ", aborted"}[abort]
			t.Run(name, func(t *testing.T) {
				w, tn := newTailnetWorld(t)
				sidecar := sidecarID(t)
				// The target's rename to the name refused; the sidecar may
				// take it back.
				tn.set(func(tn *tailnetEnv) { tn.refuse, tn.refuseExcept, tn.downAfterRefusal = "vault", sidecar, c.down })
				if code := w.run("tailnet forward " + c.step); code != -1 {
					t.Fatalf("not killed at %s: %d\n%s", c.step, code, w.outputs[len(w.outputs)-1])
				}
				tn.set(func(tn *tailnetEnv) { tn.refuse, tn.refuseExcept, tn.downAfterRefusal, tn.down = "", "", false, false })
				if abort {
					if code := w.run("", "--abort"); code != 0 {
						t.Fatalf("--abort: %d\n%s", code, w.outputs[len(w.outputs)-1])
					}
					w.useState()
					w.expect("aborted", "released", "released", "source", "")
					w.tailnetAt(t, tn, sidecar, "source")
					if !sidecarRunning() {
						t.Fatal("the sidecar was not started again")
					}
				} else {
					if code := w.run("", "--resume"); code != 0 {
						t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
					}
					w.useState()
					w.expect("resumed", "open", "open", "target-open", "migrated-out")
					w.tailnetAt(t, tn, sidecar, "target")
				}
				if code := w.run("", "--resume"); code != 0 {
					t.Errorf("a second --resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
				}
				w.noSecrets()
			})
		}
	}
}

// The undo after the name moved (the reverse handoff, the "undo" slot),
// killed at each step it journals during --abort, then --abort again: the
// name is the sidecar's, the migration released, and the target's node
// held again under its temporary name, so a new migration goes on.
func TestG5TailnetUndoSlotSteps(t *testing.T) {
	for _, step := range forwardSteps {
		t.Run(step, func(t *testing.T) {
			w, tn := newTailnetWorld(t)
			sidecar := sidecarID(t)
			if code := w.run("tailnet forward done"); code != -1 {
				t.Fatalf("not killed at the forward's done: %d", code)
			}
			if code := w.run("tailnet undo "+step, "--abort"); code != -1 {
				t.Fatalf("--abort not killed at %s: %d\n%s", step, code, w.outputs[len(w.outputs)-1])
			}
			if code := w.run("", "--abort"); code != 0 {
				t.Fatalf("--abort again: %d\n%s", code, w.outputs[len(w.outputs)-1])
			}
			w.useState()
			w.expect("aborted", "released", "released", "source", "")
			w.tailnetAt(t, tn, sidecar, "source")
			rec := w.tailnetRecord(t)
			op, _ := rec["operation"].(string)
			if h := w.heldAs(); !strings.HasPrefix(h, "vault-vl-"+op) {
				t.Fatalf("the target's node is not held again: %q", h)
			}
			if !sidecarRunning() {
				t.Fatal("the sidecar was not started again")
			}
			// A new migration to the same target goes on with its node.
			if code := w.run(""); code != 0 {
				t.Fatalf("the next migration: %d\n%s", code, w.outputs[len(w.outputs)-1])
			}
			w.useState()
			w.expect("migrated again", "open", "open", "target-open", "migrated-out")
			w.tailnetAt(t, tn, sidecar, "target")
			w.noSecrets()
		})
	}
}

// The rollback's return of the name, its own undo killed at each step it
// journals (the sidecar's rename to the name refused): --resume hands the
// name back again and rolls back; --abort leaves it with Go.
func TestG5TailnetRollbackUndoSteps(t *testing.T) {
	for _, step := range []string{"undoing", "undone"} {
		for _, abort := range []bool{false, true} {
			name := step + map[bool]string{false: ", resumed", true: ", aborted"}[abort]
			t.Run(name, func(t *testing.T) {
				w, tn := newTailnetWorld(t)
				sidecar := sidecarID(t)
				if code := w.run(""); code != 0 {
					t.Fatalf("the migration: %d\n%s", code, w.outputs[len(w.outputs)-1])
				}
				// The sidecar's rename to the name refused; Go's node may take
				// it back.
				tn.set(func(tn *tailnetEnv) { tn.refuse, tn.refuseNode = "vault", sidecar })
				if code := w.rollback("tailnet rollback "+step, "--rollback"); code != -1 {
					t.Fatalf("not killed at %s: %d\n%s", step, code, w.outputs[len(w.outputs)-1])
				}
				tn.set(func(tn *tailnetEnv) { tn.refuse, tn.refuseNode = "", "" })
				if abort {
					if code := w.rollback("", "--abort"); code != 0 {
						t.Fatalf("--abort: %d\n%s", code, w.outputs[len(w.outputs)-1])
					}
					w.useState()
					w.tailnetAt(t, tn, sidecar, "target")
				} else {
					if code := w.rollback("", "--resume"); code != 0 {
						t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
					}
					w.useState()
					w.tailnetAt(t, tn, sidecar, "source")
				}
				if code := w.rollback("", "--resume"); code != 0 {
					t.Errorf("a second --resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
				}
				w.noSecrets()
			})
		}
	}
}
