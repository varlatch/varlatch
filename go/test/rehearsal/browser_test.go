// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The browser step of the tailnet case (VL_RH_TAILNET_BROWSER=1; G10's "the
// handoffs keep the same origin and RP ID", and 7.5's "a browser checks"): a
// person at this workstation, with a passkey of their own, before the
// handoff, after it, and after the rollback.
//
// What a tailnet handoff moves is the tailnet's name. The dashboard is at the
// public URL, before and after (the Go server serves none on the tailnet), and
// the passkey is bound to that URL's host (the RP ID). On Tailscale the
// dashboard reads a protected value over the tailnet browser endpoint, https
// at the name that moves, with that name's certificate: the same address,
// answered by another node after each move. So the step proves both: the
// passkey still signs in at the same origin, and the same browser still reads
// over the same name, with a certificate it accepts.
//
// The person's word is not taken for it: the run's proxy sees the passkey's
// ceremony answered, at the public URL's origin, and the audit has the
// disclosure, on the tailnet listener, by the client node.
//
// The workstation joins no tailnet. The browser maps the name to the host's
// address on the run's network, where the run carries each connection, as it
// is, into the tailnet from the client node (`tailscale nc`): TLS is the
// browser's own, end to end. The address is a private one, which the
// dashboard's request to the endpoint says it expects (a proxy would not do:
// the browser refuses such a request through one).

// endpointPort is the tailnet browser endpoint's (the release's default).
const endpointPort = "8688"

// browserValue is the protected value's text, which a screen shows to whoever
// is at it: nothing secret.
const browserValue = "read-over-the-tailnet"

// ceremony is a passkey request the public URL answered.
type ceremony struct {
	at     time.Time
	path   string
	origin string
	status int
}

// ceremonies are those the run's proxy saw.
type ceremonies struct {
	mu   sync.Mutex
	seen []ceremony
}

// passkeyPaths are a passkey ceremony's last request, in either server: an
// enrollment's and a sign-in's.
var passkeyPaths = map[string]string{
	"/auth/passkey/verify-registration":   "enrollment",
	"/auth/passkey/registration":          "enrollment",
	"/auth/passkey/verify-authentication": "sign-in",
	"/auth/passkey/sign-in":               "sign-in",
}

// see is the proxy's ModifyResponse.
func (c *ceremonies) see(r *http.Response) error {
	if r.Request.Method == http.MethodPost && passkeyPaths[r.Request.URL.Path] != "" {
		c.mu.Lock()
		c.seen = append(c.seen, ceremony{time.Now(), r.Request.URL.Path, r.Request.Header.Get("Origin"), r.StatusCode})
		c.mu.Unlock()
	}
	return nil
}

// since are the ceremonies of kind since a time, and whether one succeeded at
// origin.
func (c *ceremonies) since(t time.Time, kind, origin string) (said string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var all []string
	for _, s := range c.seen {
		if s.at.Before(t) || passkeyPaths[s.path] != kind {
			continue
		}
		all = append(all, fmt.Sprintf("%s from %s: %d", s.path, s.origin, s.status))
		ok = ok || s.status >= 200 && s.status < 300 && s.origin == origin
	}
	if len(all) == 0 {
		return "no " + kind + " reached the server", false
	}
	return strings.Join(all, "; "), ok
}

// browserExtra is what the installation gets for the step: its public URL on
// localhost (a passkey cannot be bound to an address), and on Tailscale the
// browser endpoint of both servers.
func (w *tailnetWorld) browserExtra(x *installExtra, machine string) {
	x.publicHost = "localhost"
	if w.headscale {
		return
	}
	for k, v := range map[string]string{
		"VARLATCH_TAILNET_HTTPS_PORT": endpointPort, "VARLATCH_TAILNET_NODE": machine, "VARLATCH_TAILNET_CERT_UID": "999",
		"VARLATCH_TAILNET_ENDPOINT": "https://" + machine + "." + w.suffix + ":" + endpointPort,
	} {
		x.env[k] = v
	}
	x.conf += "tailnet_https_port = " + endpointPort + "\n"
}

// browserStep is the person's part of the run.
type browserStep struct {
	w       *tailnetWorld
	in      *installation
	machine string
	api     *apiClient
	admin   string // the administrator the passkey is enrolled for
	dir     string // the link and the command, the person's
	uid     int
	gid     int
}

// startBrowser prepares the installation and the command the person runs.
func (w *tailnetWorld) startBrowser(in *installation, machine string) *browserStep {
	t := w.t
	b := &browserStep{w: w, in: in, machine: machine, dir: filepath.Join(workDir, "browser")}
	st, err := os.Stat(binDir)
	if err != nil {
		t.Fatal(err)
	}
	// The run's directory is its user's; this process is root in the runner.
	sys, _ := st.Sys().(*syscall.Stat_t)
	b.uid, b.gid = int(sys.Uid), int(sys.Gid)
	b.api = adminClient(t, in)
	if b.admin = firstAdmin(in.admin(nil, "bootstrap-status").stdout); b.admin == "" {
		t.Fatal("bootstrap-status names no administrator")
	}
	const acme = "/v1/organizations/acme"
	b.api.ok("POST", "/v1/organizations", map[string]any{"name": "Acme", "slug": "acme"})
	b.api.ok("POST", acme+"/projects", map[string]any{"name": "Web", "slug": "web", "contractAuthority": "managed"})
	b.api.ok("POST", acme+"/projects/web/environments", map[string]any{"name": "production", "tier": "production"})
	b.api.ok("PUT", acme+"/projects/web/environments/production/values/PROTECTED", map[string]any{"value": browserValue})
	b.api.ok("POST", acme+"/requirements", map[string]any{"kind": "tailnet", "target": map[string]any{"kind": "tier", "tier": "production"},
		"selector": map[string]any{"tailnet": w.suffix, "nodes": []string{w.clientID}}})
	if err := w.carry(machine); err != nil {
		t.Fatal(err)
	}
	return b
}

// carry listens on the host's address on the run's network, and carries each
// connection from the client node to machine's port of the tailnet, as it is.
func (w *tailnetWorld) carry(machine string) error {
	r := w.docker("network", "inspect", "-f", `{{(index .IPAM.Config 0).Gateway}}`, w.network)
	w.gateway = strings.TrimSpace(r.stdout)
	if ip := net.ParseIP(w.gateway); ip == nil || !ip.IsPrivate() {
		return fmt.Errorf("the run's network has no private gateway: %q", w.gateway)
	}
	l, err := net.Listen("tcp", net.JoinHostPort(w.gateway, w.carriedPort()))
	if err != nil {
		return err
	}
	w.t.Cleanup(func() { _ = l.Close() })
	fqdn := machine + "." + w.suffix
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go w.carryOne(c, fqdn)
		}
	}()
	return nil
}

// carriedPort is the browser endpoint's on Tailscale; on Headscale, which has
// none, the tailnet listener's.
func (w *tailnetWorld) carriedPort() string {
	if w.headscale {
		return tailnetPort
	}
	return endpointPort
}

func (w *tailnetWorld) carryOne(c net.Conn, fqdn string) {
	defer c.Close()
	cmd := exec.Command("docker", "exec", "-i", w.client, "tailscale", "nc", fqdn, w.carriedPort())
	in, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if cmd.Start() != nil {
		return
	}
	go func() {
		_, _ = io.Copy(in, c)
		_ = in.Close()
	}()
	_, _ = io.Copy(c, out)
	_ = c.Close()
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

// step is one of the three waits: enroll is the first one's.
func (b *browserStep) step(when string, serves func(*installation, string) bool, enroll bool) bool {
	const item = tailnetItem
	w, t := b.w, b.w.t
	t.Helper()
	name := "browser, " + when + ": "
	if _, meta := b.in.get("/v1/meta"); !serves(b.in, meta) {
		record(t, item, name+"the public URL answers from the right server", false, trim(meta))
		return false
	}
	began := time.Now()
	kind := "sign-in"
	lines := []string{
		"1. In the same window, sign out if you are signed in (the icon beside your name),",
		"   then reload, press Continue with passkey, and use the passkey on your phone.",
	}
	if enroll {
		kind = "enrollment"
		if err := b.prepare(); err != nil {
			record(t, item, name+"the enrollment link", false, err.Error())
			return false
		}
		lines = []string{
			"1. In another terminal:  " + filepath.Join(b.dir, "browser.sh"),
			"   Type any name, press Create passkey, choose your phone, scan the code.",
		}
	}
	if w.headscale {
		lines = append(lines, "2. (Headscale has no browser endpoint: the run reads over the tailnet itself.)")
	} else {
		lines = append(lines,
			"2. Open "+b.in.publicURL+"/o/acme/p/web/e/production , press Connect to tailnet",
			"   (allow the local network if the browser asks), and Reveal PROTECTED: "+browserValue+".")
	}
	b.say(when, lines)
	limit, err := time.ParseDuration(env("VL_RH_PAUSE_TIMEOUT", "2h"))
	if err != nil || limit <= 0 {
		t.Fatalf("VL_RH_PAUSE_TIMEOUT: %v", err)
	}
	var signed, read bool
	var ceremony, disclosure string
	pollUntil(limit, time.Second, func() bool {
		if ceremony, signed = b.in.ceremonies.since(began, kind, b.in.publicURL); !signed {
			return false
		}
		if w.headscale && !read {
			b.readItself()
		}
		disclosure, read = b.disclosed(began)
		return read
	})
	measure("item 14: "+name+"took", time.Since(began).Round(time.Second).String())
	record(t, item, name+"the passkey's "+kind+" at "+b.in.publicURL+", the origin of the whole run", signed, ceremony)
	record(t, item, name+"the protected value read over "+b.machine+"."+w.suffix+":"+w.carriedPort()+" by the client node", read, disclosure)
	if enroll {
		_ = os.Remove(filepath.Join(b.dir, "link"))
	}
	fmt.Fprintf(os.Stderr, "\n==== seen: signed in %v, read %v. The run goes on. Keep the window open. ====\n\n", signed, read)
	return signed && read
}

func (b *browserStep) say(when string, lines []string) {
	fmt.Fprintf(os.Stderr, "\n==== at the browser: %s ====\n", when)
	for _, l := range lines {
		fmt.Fprintln(os.Stderr, "  "+l)
	}
	fmt.Fprint(os.Stderr, "  The run goes on by itself when the server has seen both.\n\n")
}

// prepare writes the enrollment link (a one-time one, never printed) and the
// command that opens it, for the run's user.
func (b *browserStep) prepare() error {
	r := b.in.admin(nil, "recover", "--identity", b.admin)
	link := enrollLink.FindString(r.stdout)
	if link == "" {
		return fmt.Errorf("no link: %s", r)
	}
	secret(link)
	_, fragment, _ := strings.Cut(link, "#")
	secret(fragment)
	if err := os.MkdirAll(b.dir, 0o700); err != nil {
		return err
	}
	script := fmt.Sprintf(`#!/bin/sh
# Written by the rehearsal's browser step: a browser of the run's own.
d=%s
[ -s "$d/link" ] || { echo "the link is used: keep the window you have open" >&2; exit 1; }
for b in "${G1_BROWSER:-}" chromium google-chrome-stable; do [ -n "$b" ] && command -v "$b" >/dev/null 2>&1 && break; done
exec "$b" --user-data-dir="$d/profile" --no-first-run --no-default-browser-check --window-size=1300,900 \
  --host-resolver-rules="MAP %s.%s %s" "$(cat "$d/link")" >/dev/null 2>&1
`, b.dir, b.machine, b.w.suffix, b.w.gateway)
	for name, f := range map[string]struct {
		text string
		mode os.FileMode
	}{"link": {link + "\n", 0o600}, "browser.sh": {script, 0o700}} {
		if err := os.WriteFile(filepath.Join(b.dir, name), []byte(f.text), f.mode); err != nil {
			return err
		}
	}
	for _, p := range []string{b.dir, filepath.Join(b.dir, "link"), filepath.Join(b.dir, "browser.sh")} {
		if err := os.Chown(p, b.uid, b.gid); err != nil {
			return err
		}
	}
	return nil
}

// readItself is the step's read on Headscale: the run's own, over the carried
// connection.
func (b *browserStep) readItself() {
	c := &apiClient{t: b.w.t, base: "http://" + net.JoinHostPort(b.w.gateway, b.w.carriedPort()), token: b.api.token,
		http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}}
	code, out := c.send("POST", "/v1/organizations/acme/projects/web/environments/production/disclosures", map[string]any{"items": []string{"PROTECTED"}})
	if raw, _ := json.Marshal(out); code != 200 || !strings.Contains(string(raw), browserValue) {
		measure("item 14: the run's own read over the carried connection", fmt.Sprintf("%d %s", code, trim(redact(string(raw)))))
	}
}

var disclosedType = regexp.MustCompile(`^(secret|value)\.disclosed$`)

// disclosed is the audit's newest disclosure since began on the tailnet
// listener by the client node, or what the audit has instead.
func (b *browserStep) disclosed(began time.Time) (string, bool) {
	code, out := b.api.send("GET", "/v1/organizations/acme/audit-events?limit=50", nil)
	items, _ := out["items"].([]any)
	if code != 200 {
		return fmt.Sprintf("the audit answers %d", code), false
	}
	var said []string
	for _, it := range items {
		e, _ := it.(map[string]any)
		typ, _ := e["eventType"].(string)
		at, err := time.Parse(time.RFC3339, fmt.Sprint(e["occurredAt"]))
		// The server's clock is this host's; its times are to the millisecond.
		if err != nil || at.Before(began.Add(-time.Second)) || !disclosedType.MatchString(typ) && typ != "authorization.denied" {
			continue
		}
		ctx, _ := e["tailnetContext"].(map[string]any)
		said = append(said, fmt.Sprintf("%s on the %v listener by node %v %v", typ, e["listener"], ctx["nodeId"], ctx["refused"]))
		if disclosedType.MatchString(typ) && e["listener"] == "tailnet" && ctx["nodeId"] == b.w.clientID {
			return said[len(said)-1], true
		}
	}
	if len(said) == 0 {
		return "no disclosure and no refusal in the audit since the step began", false
	}
	return strings.Join(said, "; "), false
}
