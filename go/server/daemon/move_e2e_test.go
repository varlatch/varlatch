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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/auth/authtest"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/publictls"
	"github.com/varlatch/varlatch/go/server/tailnet"
)

// The `move` external suite's replacement (ADR-0059 step 6, slice 6.9):
// `varlatch move` run as the operator runs it, the CLI and varlatchd built
// from this tree as processes, against varlatchd here. Its restart of
// varlatchd.service goes to a systemctl of the test's own, which asks the
// test to restart the daemon and waits until it has.

const fakeSystemctl = `#!/bin/sh
# The test's systemctl: it asks the test to restart varlatchd, and waits.
here=$(dirname "$0")
echo "$*" >> "$here/systemctl.calls"
: > "$here/restart"
i=0
while [ -e "$here/restart" ] && [ $i -lt 1200 ]; do sleep 0.1; i=$((i+1)); done
[ ! -e "$here/restart" ]
`

// moveBinaries builds varlatch and varlatchd into a directory with the
// test's systemctl, or skips without the go tool.
func moveBinaries(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds varlatch and varlatchd")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("needs the go tool")
	}
	bin := t.TempDir()
	for _, cmd := range []string{"varlatch", "varlatchd"} {
		build := exec.Command(goTool, "build", "-o", filepath.Join(bin, cmd), "github.com/varlatch/varlatch/go/cmd/"+cmd)
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("go build %s: %v\n%s", cmd, err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(fakeSystemctl), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// runMoveCLI runs `varlatch move args...` and restarts the daemon each
// time the CLI's systemctl asks: its exit status and output.
func runMoveCLI(t *testing.T, bin string, restart func(), args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(filepath.Join(bin, "varlatch"), append([]string{"move"}, args...)...)
	cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "HOME=" + t.TempDir(), "VARLATCH_ASSISTED=0"}
	out := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	flag := filepath.Join(bin, "restart")
	deadline := time.After(8 * time.Minute)
	for {
		select {
		case err := <-done:
			var exit *exec.ExitError
			switch {
			case err == nil:
				return 0, out.String()
			case errors.As(err, &exit):
				return exit.ExitCode(), out.String()
			}
			t.Fatalf("varlatch move: %v", err)
		case <-deadline:
			_ = cmd.Process.Kill()
			t.Fatalf("varlatch move did not end:\n%s", out.String())
		case <-time.After(100 * time.Millisecond):
			if _, err := os.Stat(flag); err == nil {
				restart()
				_ = os.Remove(flag)
			}
		}
	}
}

// moveInstall is an installation with a fixed plain listener (the CLI
// waits for /readyz there), a Backup Encryption Key (a move takes an
// archive first) and extra settings.
func moveInstall(t *testing.T, extra string) (install, string) {
	t.Helper()
	in := newInstall(t, "")
	bek := make([]byte, 32)
	_, _ = rand.Read(bek)
	bekFile := filepath.Join(in.dir, "backup-key")
	if err := os.WriteFile(bekFile, []byte(hex.EncodeToString(bek)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := ln.Addr().String()
	ln.Close()
	conf := fmt.Sprintf("listen = %s\ndata_dir = %s\nroot_kek_file = %s\naccess_log = %s\nbackup_key_file = %s\nbackup_interval = off\n%s",
		listen, in.data, in.kekFile, in.accessLog, bekFile, extra)
	if err := os.WriteFile(in.conf, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	return in, listen
}

// browser is a browser at origin, over HTTPS to 127.0.0.1:5001 as host.
type browser struct {
	c      *http.Client
	origin string
}

func newHTTPSBrowser(roots *x509.CertPool, host string) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{origin: "https://" + host + ":5001", c: &http.Client{Jar: jar, Timeout: 15 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: host, RootCAs: roots},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:5001")
		}}}}
}

func (b *browser) post(t *testing.T, path string, body any) (int, []byte) {
	t.Helper()
	res, err := b.c.Get(b.origin + "/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	var s struct{ CsrfToken string }
	_ = json.NewDecoder(res.Body).Decode(&s)
	res.Body.Close()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", b.origin+path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", b.origin)
	req.Header.Set(httpserver.CSRFHeader, s.CsrfToken)
	res, err = b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

// enroll runs a passkey registration with token: the identity it enrolled.
func (b *browser) enroll(t *testing.T, token string, key *authtest.Key) string {
	t.Helper()
	code, raw := b.post(t, "/auth/passkey/registration/options", map[string]any{"token": token})
	var opts struct{ PublicKey auth.CreationOptions }
	if code != 200 || json.Unmarshal(raw, &opts) != nil {
		t.Fatalf("registration options at %s: %d %s", b.origin, code, raw)
	}
	code, raw = b.post(t, "/auth/passkey/registration", map[string]any{"response": json.RawMessage(key.Register(t, opts.PublicKey, b.origin)), "name": "Test"})
	var reg struct{ IdentityID string }
	if code != 200 || json.Unmarshal(raw, &reg) != nil || reg.IdentityID == "" {
		t.Fatalf("registration at %s: %d %s", b.origin, code, raw)
	}
	return reg.IdentityID
}

var enrollToken = regexp.MustCompile(`/enroll#(vlt_[A-Za-z0-9_]+_[A-Za-z0-9_-]+)`)

// TestPublicHTTPSMoveAgainstPebble: `varlatch move` takes an installation
// on the public ingress from one name to another against Pebble. It takes
// and verifies an archive first; the new name gets its certificate; the
// old address's passkey is removed once, and the old name is not served;
// one re-enrollment link per person is printed, and never written to the
// move's journal or a log; with --no-wait it stops until an Installation
// Admin enrolls, at the new origin through that link, on the same
// identity; a rerun finishes and closes the move.
func TestPublicHTTPSMoveAgainstPebble(t *testing.T) {
	ca, rootFile := os.Getenv("VARLATCH_TEST_PEBBLE"), os.Getenv("VARLATCH_TEST_PEBBLE_ROOT")
	if ca == "" || rootFile == "" {
		if os.Getenv("VARLATCH_REQUIRE_PEBBLE") != "" {
			t.Fatal("VARLATCH_REQUIRE_PEBBLE is set, but Pebble is not")
		}
		t.Skip("no Pebble: go/server/publictls/testdata/pebble.sh start <dir>, then set the variables it prints")
	}
	const oldHost, newHost = "vault.varlatch.test", "vault2.varlatch.test"
	bin := moveBinaries(t)
	in, _ := moveInstall(t, "public_url = https://"+oldHost+":5001\nlisten_https = 127.0.0.1:5001\nlisten_http_redirect = 127.0.0.1:5002\n"+
		"acme_ca = "+ca+"\nacme_ca_root = "+rootFile+"\nacme_email = ops@varlatch.test\n")
	h := &hooks{publicTLS: func(o *publictls.Options) {
		o.CheckInterval, o.Backoff = 500*time.Millisecond, []time.Duration{time.Second}
	}}
	r := startWith(t, in, h)
	defer func() { r.stop(t) }()
	roots := pebbleRoots(t, rootFile)
	old := newHTTPSBrowser(roots, oldHost)
	deadline := time.Now().Add(60 * time.Second)
	for {
		res, err := old.c.Get(old.origin + "/readyz")
		if err == nil {
			res.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no HTTPS at the old name: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	code, out, errOut := runAdmin(t, "bootstrap", "--config", in.conf)
	m := enrollToken.FindStringSubmatch(out)
	if code != ExitOK || m == nil {
		t.Fatalf("bootstrap: %d %q %q", code, out, errOut)
	}
	admin := old.enroll(t, m[1], authtest.New(t))
	restart := func() { r.stop(t); r = startWith(t, in, h) }

	code, out = runMoveCLI(t, bin, restart, "--public-url", "https://"+newHost+":5001", "--yes", "--no-wait", "--config", in.conf)
	for _, want := range []string{
		"Move https://" + oldHost + ":5001 (public ingress) to https://" + newHost + ":5001 (public ingress).",
		"  ✓ archive ", "made and verified",
		"  ✓ varlatchd answers",
		"  ✓ HTTPS certificate for " + newHost + " (issued by ",
		"  ✓ 1 passkey(s) for https://" + oldHost + ":5001 removed",
		"    https://" + newHost + ":5001/enroll#vlt_reenroll_",
		"Rerun `varlatch move` once an Installation Admin has enrolled, to finish.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the move's output lacks %q:\n%s", want, out)
		}
	}
	if code != 75 {
		t.Fatalf("exit %d, not 75 (pending):\n%s", code, out)
	}
	links := enrollToken.FindAllStringSubmatch(out, -1)
	if len(links) != 1 {
		t.Fatalf("%d links, not one per person", len(links))
	}
	journal, err := os.ReadFile(filepath.Join(in.dir, "move.json"))
	if err != nil || strings.Contains(string(journal), "vlt_reenroll_") || strings.Contains(string(journal), "/enroll#") ||
		!strings.Contains(string(journal), `"passkeysRetiredAt"`) || !strings.Contains(string(journal), `"linksIssuedAt"`) {
		t.Fatalf("the journal: %v %s", err, journal)
	}
	if raw, _ := os.ReadFile(in.conf); !strings.Contains(string(raw), "public_url = https://"+newHost+":5001\n") {
		t.Fatalf("the configuration: %s", raw)
	}
	// The old name is not served any more.
	if conn, err := tls.Dial("tcp", "127.0.0.1:5001", &tls.Config{ServerName: oldHost, InsecureSkipVerify: true}); err == nil {
		conn.Close()
		t.Fatal("the old name is still served")
	}
	// The Installation Admin enrolls at the new origin, on the same identity.
	if id := newHTTPSBrowser(roots, newHost).enroll(t, links[0][1], authtest.New(t)); id != admin {
		t.Fatalf("re-enrolled as %s, not %s", id, admin)
	}
	code, out = runMoveCLI(t, bin, restart, "--config", in.conf)
	if code != 0 || !strings.Contains(out, "Moved: https://"+oldHost+":5001 → https://"+newHost+":5001.") || strings.Contains(out, "vlt_reenroll_") {
		t.Fatalf("the rerun: %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(in.dir, "move.json")); !os.IsNotExist(err) {
		t.Fatal("the move is still open")
	}
	if logs := r.stderr.String(); strings.Contains(logs, "vlt_reenroll_") || strings.Contains(logs, "/enroll#") {
		t.Fatal("a link reached varlatchd's log")
	}
	if raw, _ := os.ReadFile(filepath.Join(bin, "systemctl.calls")); string(raw) != "restart varlatchd.service\n" {
		t.Fatalf("systemctl: %q", raw)
	}
}

// TestMoveKeepsTheTailnetNode: a move to another address behind the
// operator's proxy (the external ingress) leaves the tailnet node as it
// was: its settings, its pin and its state; it rejoins as the same node
// after the restart. A move to the tailnet ingress is refused before
// anything changes.
func TestMoveKeepsTheTailnetNode(t *testing.T) {
	bin := moveBinaries(t)
	control := startTestControl(t)
	keyDir := t.TempDir()
	keyFile := filepath.Join(keyDir, "tailnet-auth-key")
	// The test control server takes any auth key; this one is built here,
	// so no key-shaped text is in the file.
	if err := os.WriteFile(keyFile, []byte(strings.Join([]string{"tskey", "auth", "hermetic"}, "-")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tailnetLines := fmt.Sprintf("tailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_auth_key_file = %s\n", keyFile)
	in, _ := moveInstall(t, "public_url = https://vault.example.com\n"+tailnetLines)
	h := &hooks{tailnetControl: control.BaseURL()}
	r := startWith(t, in, h)
	defer func() { r.stop(t) }()
	code, out, errOut := runAdmin(t, "bootstrap", "--cli-credential", "--config", in.conf)
	m := bootstrapCLI.FindStringSubmatch(out)
	if code != ExitOK || m == nil {
		t.Fatalf("bootstrap: %d %q %q", code, out, errOut)
	}
	bearer := m[2]
	waitReport(t, r, bearer, `"node":{"status":"pass"}`)
	pinBefore, err := os.ReadFile(filepath.Join(in.data, tailnet.PinFile))
	if err != nil {
		t.Fatal(err)
	}
	stateFiles := func() []string {
		entries, err := os.ReadDir(filepath.Join(in.data, tailnet.StateDir))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		return names
	}
	before := stateFiles()
	restart := func() { r.stop(t); r = startWith(t, in, h) }

	if code, out := runMoveCLI(t, bin, restart, "--public-url", "https://vault.example.com", "--ingress", "tailnet", "--yes", "--config", in.conf); code != 64 || !strings.Contains(out, "the tailnet node keeps its own name and state") {
		t.Fatalf("a move to the tailnet ingress: %d\n%s", code, out)
	}
	code, out = runMoveCLI(t, bin, restart, "--public-url", "https://vault2.example.com", "--yes", "--no-wait", "--config", in.conf)
	if code != 75 || !strings.Contains(out, "Move https://vault.example.com (external ingress) to https://vault2.example.com (external ingress).") ||
		!strings.Contains(out, "The tailnet node, if any, is not touched") {
		t.Fatalf("the move: %d\n%s", code, out)
	}
	conf, _ := os.ReadFile(in.conf)
	if !strings.Contains(string(conf), tailnetLines) || !strings.Contains(string(conf), "public_url = https://vault2.example.com\n") {
		t.Fatalf("the configuration: %s", conf)
	}
	pinAfter, err := os.ReadFile(filepath.Join(in.data, tailnet.PinFile))
	if err != nil || string(pinAfter) != string(pinBefore) {
		t.Fatalf("the pin changed: %v", err)
	}
	if after := stateFiles(); strings.Join(after, " ") != strings.Join(before, " ") {
		t.Fatalf("the node's state: %v, before %v", after, before)
	}
	waitReport(t, r, bearer, `"node":{"status":"pass"}`)

	// The move stopped after varlatchd removed the passkeys and before its
	// journal recorded it: a rerun takes the removal as done and goes on.
	journalPath := filepath.Join(in.dir, "move.json")
	raw, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	var journal map[string]any
	if err := json.Unmarshal(raw, &journal); err != nil || journal["passkeysRetiredAt"] == nil {
		t.Fatalf("the journal: %v %s", err, raw)
	}
	delete(journal, "passkeysRetiredAt")
	raw, _ = json.Marshal(journal)
	if err := os.WriteFile(journalPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out = runMoveCLI(t, bin, restart, "--no-wait", "--config", in.conf)
	if code != 75 || !strings.Contains(out, "the passkeys for https://vault.example.com were already removed (the move had stopped after removing them)") ||
		!strings.Contains(out, "Links were issued at") {
		t.Fatalf("the rerun after a stop: %d\n%s", code, out)
	}
	if raw, _ := os.ReadFile(journalPath); !strings.Contains(string(raw), `"passkeysRetiredAt"`) {
		t.Fatalf("the rerun did not record the removal: %s", raw)
	}
}
