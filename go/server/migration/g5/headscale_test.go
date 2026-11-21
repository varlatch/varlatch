// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g5 && linux && headscale

package g5_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/tailnet/headscaletest"
)

// G5's tailnet half on a self-hosted control server (slice 7.5c c2): the
// same migration, its tailnet name moved on a real Headscale (0.29.7, in a
// container: headscaletest), the authority Headscale's API with a key that
// expires within the hour, which each run of varlatch migrate expires when
// it ends. No certificates: Headscale issues none.
//
// What changes from tailnet_test.go's world: no testcontrol and no fake
// API; the sidecar stand-in and the target's varlatchd join Headscale with
// a tagged pre-auth key (they advertise no tags); the sidecar's Compose
// service logs in to it (--login-server in TS_EXTRA_ARGS), and the
// target's varlatchd.conf names it (tailnet_control_url).

// hsCA is the run's certificate authority, which the test process and
// every process it starts (they inherit SSL_CERT_FILE) trust for
// Headscale's https on its IP address.
var hsCA *headscaletest.CA

func init() {
	// The test binary only: the stand-ins it runs as inherit the CA.
	if !strings.HasSuffix(filepath.Base(os.Args[0]), ".test") {
		return
	}
	if _, set := os.LookupEnv("SSL_CERT_FILE"); set {
		return
	}
	dir, err := os.MkdirTemp("", "g5-headscale-ca-")
	if err != nil {
		panic(err)
	}
	if hsCA, err = headscaletest.Trust(dir); err != nil {
		panic(err)
	}
}

// hsEnv is a world's Headscale.
type hsEnv struct {
	hs      *headscaletest.Server
	keyFile string // the API key's file, written anew before every run
}

func newHeadscaleWorld(t *testing.T) (*world, *hsEnv) {
	t.Helper()
	headscaletest.Skip(t)
	if hsCA == nil {
		t.Fatal("SSL_CERT_FILE was set before the run: the Headscale CA is not the one trusted")
	}
	w := newWorld(t, false)
	h := &hsEnv{hs: headscaletest.Start(t, hsCA), keyFile: filepath.Join(w.compose, "headscale-api-key")}
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(h.hs.Logs())
		}
	})
	preauth := h.hs.PreauthKey(t, "tag:varlatch")
	authKeyFile := filepath.Join(w.compose, "tailnet-auth-key")
	if err := os.WriteFile(authKeyFile, []byte(preauth+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The undo's wait as tailnet_test.go's world has it (3 s) is too
	// short for a node to log in to a real Headscale again: the default's
	// minute.
	w.env = []string{"G5_TAILNET=1", "VARLATCH_TEST_HANDOFF_UNDO_WAIT=60s", "G5_TAILNET_CONTROL=" + h.hs.URL, "G5_HEADSCALE=" + h.hs.URL, "G5_SIDECAR_AUTHKEY=" + preauth}
	w.extraArgs = []string{"--headscale-url", h.hs.URL, "--headscale-api-key-file", h.keyFile, "--tailnet-auth-key-file", authKeyFile}
	w.secrets = [][]byte{[]byte(preauth)}
	w.beforeRun = func() {
		key := h.hs.APIKey(t)
		if err := os.WriteFile(h.keyFile, []byte(key+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		w.secrets = append(w.secrets, []byte(key))
	}
	env, _ := os.ReadFile(filepath.Join(w.compose, ".env"))
	env = append(env, []byte("VARLATCH_TAILNET_MACHINE=vault\nVARLATCH_TAILNET_NAME="+headscaletest.BaseDomain+"\n")...)
	if err := os.WriteFile(filepath.Join(w.compose, ".env"), env, 0o600); err != nil {
		t.Fatal(err)
	}
	extra := fmt.Sprintf("tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_control_url = %s\ntailnet_auth_key_file = %s\n",
		h.hs.URL, filepath.Join(w.keys, "tailnet-auth-key"))
	for _, conf := range []string{w.conf, filepath.Join(w.stateDir, "service.conf")} {
		b, _ := os.ReadFile(conf)
		if err := os.WriteFile(conf, append(b, []byte(extra)...), 0o600); err != nil {
			t.Fatal(err)
		}
	}
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
	return w, h
}

// names are the nodes' names by Headscale's node id.
func (h *hsEnv) names(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, n := range h.hs.Nodes(t) {
		out[n.ID] = n.GivenName
	}
	return out
}

// at is where the name is ("source" or "target"), from Headscale's node
// listing and from a client node's map (the target's reach probe).
func (h *hsEnv) at(t *testing.T, w *world, sidecar, want string) {
	t.Helper()
	target, _ := w.tailnetRecord(t)["stableId"].(string)
	holder, other := sidecar, target
	if want == "target" {
		holder, other = target, sidecar
	}
	names := h.names(t)
	if names[holder] != "vault" {
		t.Fatalf("the name is not with the %s's node: %v (sidecar %s, target %s)", want, names, sidecar, target)
	}
	if strings.EqualFold(names[other], "vault") {
		t.Fatalf("both nodes are named vault: %v", names)
	}
	if !w.reaches(t, "vault", holder) {
		t.Fatalf("vault does not reach the %s's node from a client node", want)
	}
}

// expired checks that no run that ended left its API key alive: each
// expired its own. A run killed (SIGKILL) cannot: its key lives until its
// hour ends, killed of them.
func (h *hsEnv) expired(t *testing.T, killed int) {
	t.Helper()
	if n := h.hs.LiveAPIKeys(t); n != killed {
		t.Fatalf("%d Headscale API keys are live after the runs, want %d (the killed runs')", n, killed)
	}
}

// On Headscale, a node's StableID (what a client's netmap carries, and the
// target's enroll reports) is its node id: the handoff finds the target's
// device by it. The migration moves the name, then its rollback gives it
// back; every run's API key expired when it ended; no certificate was
// asked for.
func TestG5HeadscaleForwardAndRollback(t *testing.T) {
	w, h := newHeadscaleWorld(t)
	sidecar := sidecarID(t)
	if _, err := strconv.ParseUint(sidecar, 10, 64); err != nil {
		t.Fatalf("the sidecar's StableID on Headscale is %q, not its node id", sidecar)
	}
	if n := h.names(t); n[sidecar] != "vault" {
		t.Fatalf("the sidecar's StableID %s is not the node id Headscale lists under vault: %v", sidecar, n)
	}
	if code := w.run(""); code != 0 {
		t.Fatalf("the migration: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	w.expect("migrated", "open", "open", "target-open", "migrated-out")
	rec := w.tailnetRecord(t)
	if rec["control"] != "headscale" || rec["certificates"] != false {
		t.Fatalf("the handoff's record: %v", rec)
	}
	if target, _ := rec["stableId"].(string); h.names(t)[target] != "vault" {
		t.Fatalf("the target's StableID %s is not the node id Headscale lists under vault: %v", target, h.names(t))
	}
	h.at(t, w, sidecar, "target")
	if sidecarRunning() {
		t.Error("the sidecar still runs after the switch")
	}
	h.expired(t, 0)
	if code := w.rollback("", "--rollback"); code != 0 {
		t.Fatalf("the rollback: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	if got := sidecarID(t); got != sidecar {
		t.Fatalf("the sidecar came back as another node: %s, was %s", got, sidecar)
	}
	h.at(t, w, sidecar, "source")
	h.expired(t, 0)
	for _, out := range w.outputs {
		if strings.Contains(strings.ToLower(string(out)), "certificate") && strings.Contains(string(out), "tailscale cert") {
			t.Fatalf("a certificate was asked for on Headscale:\n%s", out)
		}
	}
	w.noSecrets()
}

// The authority as Headscale's CLI on the control server (--headscale-cli:
// here the container's own headscale command, through a wrapper): the
// name moves and comes back the same way, with no API key at all.
func TestG5HeadscaleCLIAuthority(t *testing.T) {
	w, h := newHeadscaleWorld(t)
	sidecar := sidecarID(t)
	w.beforeRun = nil
	w.extraArgs = []string{"--headscale-cli", h.hs.CLI(t), "--tailnet-auth-key-file", w.extraArgs[len(w.extraArgs)-1]}
	if code := w.run(""); code != 0 {
		t.Fatalf("the migration: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	w.expect("migrated", "open", "open", "target-open", "migrated-out")
	h.at(t, w, sidecar, "target")
	if code := w.rollback("", "--rollback"); code != 0 {
		t.Fatalf("the rollback: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	h.at(t, w, sidecar, "source")
	h.expired(t, 0)
	w.noSecrets()
}

// The forward handoff on Headscale, killed after the sidecar's node was
// renamed away, then aborted: the undo gives the name back to the
// sidecar's node, which serves again, and the migration is released.
func TestG5HeadscaleUndo(t *testing.T) {
	w, h := newHeadscaleWorld(t)
	sidecar := sidecarID(t)
	const point = "tailnet forward serving renamed"
	if code := w.run(point); code != -1 {
		t.Fatalf("not killed at %s: %d", point, code)
	}
	if code := w.run("", "--abort"); code != 0 {
		t.Fatalf("--abort: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	w.useState()
	w.expect("aborted", "released", "released", "source", "")
	h.at(t, w, sidecar, "source")
	if !sidecarRunning() {
		t.Fatal("the sidecar was not started again")
	}
	if got := sidecarID(t); got != sidecar {
		t.Fatalf("the sidecar came back as another node: %s", got)
	}
	h.expired(t, 1)
	w.noSecrets()
}

// The handoff resumed after a kill mid-switch goes on to open on Headscale
// too, with a new run's key.
func TestG5HeadscaleResume(t *testing.T) {
	w, h := newHeadscaleWorld(t)
	sidecar := sidecarID(t)
	const point = "tailnet forward incoming renamed"
	if code := w.run(point); code != -1 {
		t.Fatalf("not killed at %s: %d", point, code)
	}
	if code := w.run("", "--resume"); code != 0 {
		t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	w.useState()
	w.expect("resumed", "open", "open", "target-open", "migrated-out")
	h.at(t, w, sidecar, "target")
	h.expired(t, 1)
	w.noSecrets()
}
