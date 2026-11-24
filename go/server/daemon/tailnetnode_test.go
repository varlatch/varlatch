// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/tailnet"
	"github.com/varlatch/varlatch/go/server/tailnet/tailnettest"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

func TestNodeArgs(t *testing.T) {
	for _, c := range []struct {
		args []string
		ok   bool
	}{
		{[]string{"enroll", "--hostname", "vault-vl-1-n"}, true},
		{[]string{"enroll", "--hostname", "vault-vl-1-n", "--certificate", "--timeout", "90s", "--json"}, true},
		{[]string{"enroll"}, false},
		{[]string{"enroll", "--hostname", "Vault"}, false},
		{[]string{"enroll", "--hostname", "--json"}, false},
		{[]string{"enroll", "--hostname", "vault-vl-1-n", "--name", "vault"}, false},
		{[]string{"certificate", "obtain", "--name", "vault"}, true},
		{[]string{"certificate", "expiry", "--name", "Vault", "--json"}, true},
		{[]string{"certificate", "expiry", "--name", "vault", "--timeout", "1s"}, false},
		{[]string{"certificate", "renew", "--name", "vault"}, false},
		{[]string{"certificate", "obtain"}, false},
		{[]string{"open"}, true},
		{[]string{"open", "--json"}, true},
		{[]string{"open", "--name", "vault"}, false},
		{[]string{"reaches", "--name", "vault", "--stable-id", "nAbC123CNTRL", "--wait", "30s", "--json"}, true},
		{[]string{"reaches", "--name", "vault", "--stable-id", "../x"}, false},
		{[]string{"reaches", "--name", "vault"}, false},
		{[]string{"reaches", "--name", "vault", "--stable-id", "1", "--wait", "11m"}, false},
	} {
		_, msg := nodeArgs(c.args)
		if (msg == "") != c.ok {
			t.Errorf("%q: %q", c.args, msg)
		}
	}
}

// hostOfLabel is the tailnet address of the peer named label, as peer
// sees it.
func hostOfLabel(t *testing.T, ctx context.Context, peer *tsnet.Server, label string) string {
	t.Helper()
	lc, err := peer.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	for ctx.Err() == nil {
		st, err := lc.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range st.Peer {
			dns := strings.ToLower(strings.TrimSuffix(p.DNSName, "."))
			if l, _, _ := strings.Cut(dns, "."); l == label && len(p.TailscaleIPs) > 0 {
				return p.TailscaleIPs[0].String()
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the peer never saw %s", label)
	return ""
}

// The node's side of a tailnet handoff (go-step7 decision 11): enrolled
// offline under its temporary name, held, pinned, its certificate obtained
// and read back without issuing; a varlatchd started on it joins under the
// temporary name and serves nothing on the tailnet until `tailnet open`,
// through its control socket; the reach check sees the name reach exactly
// that node.
func TestTheHandoffNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	control := startTestControl(t)
	ca, err := tailnettest.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var obtained []string
	prevControl, prevObtain := nodeControlURL, obtainNodeCert
	nodeControlURL = control.BaseURL()
	// The refusals below wait for the name the control plane never gives.
	shortNodeWait(t, 2*time.Second)
	// The test CA stands in for Let's Encrypt, and writes the node's cache
	// as tsnet's ACME store does.
	obtainNodeCert = func(ctx context.Context, _ *tailnet.TSNode, dataDir, domain string) ([]byte, error) {
		certPEM, keyPEM, err := ca.CertPair(ctx, domain, 0)
		clear(keyPEM)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(tailnet.CertFile(dataDir, domain)), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(tailnet.CertFile(dataDir, domain), certPEM, 0o600); err != nil {
			return nil, err
		}
		mu.Lock()
		obtained = append(obtained, domain)
		mu.Unlock()
		return certPEM, nil
	}
	t.Cleanup(func() { nodeControlURL, obtainNodeCert = prevControl, prevObtain })

	in := newInstall(t, "")
	keyFile := filepath.Join(in.dir, "tailnet-auth-key")
	if err := os.WriteFile(keyFile, []byte("hermetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in.write(t, fmt.Sprintf("tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_auth_key_file = %s\n", keyFile))
	const temp = "vault-vl-0a1b2c3d4e5f-n"

	if code, _, errOut := runAdmin(t, "tailnet", "enroll", "--hostname", "vault", "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "configured name") {
		t.Fatalf("enrolling under the configured name: %d %q", code, errOut)
	}
	// A temporary name that reads as the control plane's suffix of the
	// configured one would latch the tailnet closed: refused.
	if code, _, errOut := runAdmin(t, "tailnet", "enroll", "--hostname", "vault-1", "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "suffix of the configured name") {
		t.Fatalf("enrolling under vault-1: %d %q", code, errOut)
	}
	// A hold written for another name (a run stopped after it), not yet
	// enrolled: refused, and the hold stays.
	if err := tailnet.SaveHold(in.data, &tailnet.Hold{Hostname: "vault-vl-aaaaaaaaaaaa-n", Since: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runAdmin(t, "tailnet", "enroll", "--hostname", temp, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "held under vault-vl-aaaaaaaaaaaa-n") {
		t.Fatalf("enrolling under another hold's name: %d %q", code, errOut)
	}
	if err := tailnet.ClearHold(in.data); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runAdmin(t, "tailnet", "certificate", "expiry", "--name", temp, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "no pinned tailnet") {
		t.Fatalf("expiry before enrolment: %d %q", code, errOut)
	}
	code, out, errOut := runAdmin(t, "tailnet", "enroll", "--hostname", temp, "--certificate", "--json", "--config", in.conf)
	if code != ExitOK {
		t.Fatalf("enroll: %d %q %q", code, out, errOut)
	}
	var en enrollResult
	if err := json.Unmarshal([]byte(out), &en); err != nil {
		t.Fatal(err)
	}
	if en.DNSName != temp+".corp.ts.net" || en.StableID == "" || en.Pinned != "corp.ts.net" || !en.Open || !en.Held || en.CertificateNotAfter == nil || en.ControlURL != control.BaseURL() {
		t.Fatalf("enroll: %+v", en)
	}
	if hold, err := tailnet.LoadHold(in.data); err != nil || hold == nil || hold.Hostname != temp {
		t.Fatalf("the hold: %+v %v", hold, err)
	}
	if st, err := os.Stat(filepath.Join(in.data, tailnet.HoldFile)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the hold's mode: %v %v", st, err)
	}
	// Run again (a resumed handoff): the same node, no new key needed.
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = runAdmin(t, "tailnet", "enroll", "--hostname", temp, "--json", "--config", in.conf)
	var again enrollResult
	if code != ExitOK || json.Unmarshal([]byte(out), &again) != nil || again.StableID != en.StableID {
		t.Fatalf("enroll again: %d %q %q", code, out, errOut)
	}
	if code, _, errOut := runAdmin(t, "tailnet", "enroll", "--hostname", "vault-vl-ffffffffffff-n", "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "held under "+temp) {
		t.Fatalf("a second handoff's enrolment: %d %q", code, errOut)
	}
	// The control plane names the node otherwise (its temporary name
	// another node's: temp-1): refused, and nothing is latched into the
	// pin; once the collision is cleared, the node enrols as before.
	rename := func(label string) {
		t.Helper()
		for _, n := range control.AllNodes() {
			if string(n.StableID) == en.StableID {
				n.Name = label + ".corp.ts.net."
				control.UpdateNode(n)
				return
			}
		}
		t.Fatal("the node is not in the control server")
	}
	rename(temp + "-1")
	if err := os.WriteFile(keyFile, []byte("hermetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, suffixed := runAdmin(t, "tailnet", "enroll", "--hostname", temp, "--config", in.conf); code != ExitFailure || !strings.Contains(suffixed, "joined as "+temp+"-1.corp.ts.net, not "+temp) {
		t.Fatalf("a suffixed temporary name: %d %q", code, suffixed)
	}
	if pin, err := tailnet.LoadPin(filepath.Join(in.data, tailnet.PinFile)); err != nil || pin == nil || pin.Closed != nil {
		t.Fatalf("a suffixed temporary name latched the pin: %+v %v", pin, err)
	}
	rename(temp)
	code, out, errOut = runAdmin(t, "tailnet", "enroll", "--hostname", temp, "--json", "--config", in.conf)
	if code != ExitOK || json.Unmarshal([]byte(out), &again) != nil || !again.Open {
		t.Fatalf("enroll once the collision is cleared: %d %q %q", code, out, errOut)
	}
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	// Expiry reads the cache: never an issuance.
	mu.Lock()
	issued := len(obtained)
	mu.Unlock()
	code, out, errOut = runAdmin(t, "tailnet", "certificate", "expiry", "--name", temp, "--json", "--config", in.conf)
	var ex certResult
	if code != ExitOK || json.Unmarshal([]byte(out), &ex) != nil || ex.NotAfter == nil || !ex.NotAfter.Equal(*en.CertificateNotAfter) || !ex.Held {
		t.Fatalf("expiry: %d %q %q", code, out, errOut)
	}
	code, out, _ = runAdmin(t, "tailnet", "certificate", "expiry", "--name", "vault", "--json", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, `"notAfter":null`) {
		t.Fatalf("expiry of a name without a certificate: %d %q", code, out)
	}
	mu.Lock()
	if len(obtained) != issued {
		t.Fatalf("expiry issued: %v", obtained)
	}
	mu.Unlock()
	if code, out, errOut := runAdmin(t, "tailnet", "certificate", "expiry", "--name", temp, "--timeout", "1m", "--config", in.conf); code != 64 {
		t.Fatalf("expiry with --timeout: %d %q %q", code, out, errOut)
	}
	// Offline, obtain starts the enrolled node for it (never enrolling).
	code, out, errOut = runAdmin(t, "tailnet", "certificate", "obtain", "--name", temp, "--json", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, `"domain":"`+temp+`.corp.ts.net"`) || !strings.Contains(out, `"held":true`) {
		t.Fatalf("obtain offline: %d %q %q", code, out, errOut)
	}
	mu.Lock()
	issued = len(obtained)
	mu.Unlock()
	// The node's files stay the data directory's: no database was made.
	if _, err := os.Stat(filepath.Join(in.data, "varlatch.db")); err == nil {
		t.Fatal("a node command created the database")
	}

	// Started held: the node joins under its temporary name, and nothing
	// listens on the tailnet.
	if err := os.WriteFile(keyFile, []byte("hermetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := startWith(t, in, &hooks{tailnetControl: control.BaseURL()})
	peer := &tsnet.Server{Dir: t.TempDir(), Hostname: "ci-1", ControlURL: control.BaseURL(), Ephemeral: true, AdvertiseTags: []string{"tag:ci"}, Logf: logger.Discard}
	t.Cleanup(func() { _ = peer.Close() })
	if _, err := peer.Up(ctx); err != nil {
		t.Fatal(err)
	}
	addr := hostOfLabel(t, ctx, peer, temp)
	client := peer.HTTPClient()
	client.Timeout = 5 * time.Second
	if res, err := client.Get("http://" + addr + ":8687/v1/meta"); err == nil {
		res.Body.Close()
		t.Fatalf("a held node answered on the tailnet: %d", res.StatusCode)
	}
	// Without a directory it may make its own in: this host's failure, by
	// its exit status, not the tailnet's.
	was := os.Getenv("TMPDIR")
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "none"))
	if code, _, errOut := runAdmin(t, "tailnet", "reaches", "--name", temp, "--stable-id", en.StableID, "--wait", "60s", "--json", "--config", in.conf); code != ExitConfig || !strings.Contains(errOut, "no such file") {
		t.Fatalf("no temporary directory: %d %q", code, errOut)
	}
	t.Setenv("TMPDIR", was)
	// The reach check, from a client node.
	code, out, errOut = runAdmin(t, "tailnet", "reaches", "--name", temp, "--stable-id", en.StableID, "--wait", "60s", "--json", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, `"reaches":true`) {
		t.Fatalf("reaches: %d %q %q", code, out, errOut)
	}
	if code, out, _ := runAdmin(t, "tailnet", "reaches", "--name", temp, "--stable-id", "nSomeoneElse", "--config", in.conf); code != ExitFailure || !strings.Contains(out, "does not reach") {
		t.Fatalf("reaches another node: %d %q", code, out)
	}
	// A name the probe cannot see at all: the access rules are named, with
	// the tags involved, and the check fails closed.
	code, out, _ = runAdmin(t, "tailnet", "reaches", "--name", "nobody", "--stable-id", en.StableID, "--json", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, `"reaches":false`) || !strings.Contains(out, "access rules must let the node's tags (tag:varlatch) see each other") {
		t.Fatalf("reaches a name nobody holds: %d %q", code, out)
	}
	if code, out, _ := runAdmin(t, "tailnet", "reaches", "--name", "nobody", "--stable-id", en.StableID, "--config", in.conf); code != ExitFailure || !strings.Contains(out, "saw no node named nobody") {
		t.Fatalf("reaches a name nobody holds, as text: %d %q", code, out)
	}
	// A certificate through the running varlatchd's node.
	code, out, errOut = runAdmin(t, "tailnet", "certificate", "obtain", "--name", temp, "--json", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, `"domain":"`+temp+`.corp.ts.net"`) {
		t.Fatalf("obtain: %d %q %q", code, out, errOut)
	}
	// Open, through the control socket: the listener answers at once.
	code, out, errOut = runAdmin(t, "tailnet", "open", "--json", "--config", in.conf)
	if code != ExitOK || out != `{"opened":true,"wasHeld":true,"running":true}`+"\n" {
		t.Fatalf("open: %d %q %q", code, out, errOut)
	}
	res, err := client.Get("http://" + addr + ":8687/v1/meta")
	if err != nil {
		t.Fatalf("the opened listener: %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the opened listener: %d", res.StatusCode)
	}
	if hold, err := tailnet.LoadHold(in.data); err != nil || hold != nil {
		t.Fatalf("the hold after open: %+v %v", hold, err)
	}
	// Again (a resumed handoff): nothing to do.
	code, out, errOut = runAdmin(t, "tailnet", "open", "--json", "--config", in.conf)
	if code != ExitOK || out != `{"opened":true,"wasHeld":false,"running":true}`+"\n" {
		t.Fatalf("open again: %d %q %q", code, out, errOut)
	}
	r.stop(t)

	// Offline, open with no hold removes nothing.
	if code, out, errOut := runAdmin(t, "tailnet", "open", "--json", "--config", in.conf); code != ExitOK || out != `{"opened":true,"wasHeld":false,"running":false}`+"\n" {
		t.Fatalf("open offline: %d %q %q", code, out, errOut)
	}
	// An opened node no handoff holds: enroll holds it again only under
	// the name the control plane gives it now (a handoff undone after it
	// opened gave it its temporary name back).
	if code, _, errOut := runAdmin(t, "tailnet", "enroll", "--hostname", "vault-vl-ffffffffffff-n", "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "not held for a handoff") {
		t.Fatalf("enroll an opened node under another name: %d %q", code, errOut)
	}
	if hold, err := tailnet.LoadHold(in.data); err != nil || hold != nil {
		t.Fatalf("a refused enrolment held the node: %+v %v", hold, err)
	}
	code, out, errOut = runAdmin(t, "tailnet", "enroll", "--hostname", temp, "--json", "--config", in.conf)
	if code != ExitOK || json.Unmarshal([]byte(out), &again) != nil || again.StableID != en.StableID {
		t.Fatalf("hold an opened node again: %d %q %q", code, out, errOut)
	}
	if hold, err := tailnet.LoadHold(in.data); err != nil || hold == nil || hold.Hostname != temp {
		t.Fatalf("the hold again: %+v %v", hold, err)
	}
}

// A held varlatchd reads its name back as the hold's, not the configured
// one: a hold whose name has the shape of the configured name's collision
// suffix (made by hand here: enroll refuses one) latches nothing; and an
// enrolment needs the data directory setup made.
func TestAHeldNodeReadsBackItsHoldsName(t *testing.T) {
	control := startTestControl(t)
	prev := nodeControlURL
	nodeControlURL = control.BaseURL()
	t.Cleanup(func() { nodeControlURL = prev })
	in := newInstall(t, "")
	keyFile := filepath.Join(in.dir, "tailnet-auth-key")
	if err := os.WriteFile(keyFile, []byte("hermetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in.write(t, fmt.Sprintf("tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_auth_key_file = %s\n", keyFile))
	if err := tailnet.SaveHold(in.data, &tailnet.Hold{Hostname: "vault-1", Since: time.Now()}); err != nil {
		t.Fatal(err)
	}
	r := startWith(t, in, &hooks{tailnetControl: control.BaseURL()})
	report := filepath.Join(in.data, tailnet.ListenersFile)
	var b []byte
	for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		b, _ = os.ReadFile(report)
		if strings.Contains(string(b), "vault-1.corp.ts.net") {
			break
		}
	}
	if !strings.Contains(string(b), "vault-1.corp.ts.net") {
		t.Fatalf("the held node never reported its name: %s\n%s", b, r.stderr.String())
	}
	r.stop(t)
	if strings.Contains(string(b), tailnet.NameSuffixed) {
		t.Fatalf("a held node latched name-suffixed: %s", b)
	}
	if pin, err := tailnet.LoadPin(filepath.Join(in.data, tailnet.PinFile)); err != nil || pin == nil || pin.Closed != nil {
		t.Fatalf("the pin: %+v %v", pin, err)
	}

	gone := newInstall(t, "")
	gone.write(t, fmt.Sprintf("tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_auth_key_file = %s\n", keyFile))
	if err := os.Remove(gone.data); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runAdmin(t, "tailnet", "enroll", "--hostname", "vault-vl-0a1b2c3d4e5f-n", "--config", gone.conf); code != ExitFailure || !strings.Contains(errOut, "does not exist") {
		t.Fatalf("enroll on a missing data directory: %d %q", code, errOut)
	}
	if _, err := os.Stat(gone.data); err == nil {
		t.Fatal("enroll made the data directory")
	}
}

// The no-retry trigger: a certificate authority's rate-limit refusal is
// named so, whatever its wording; nothing else is.
func TestCertRefusal(t *testing.T) {
	for msg, limited := range map[string]bool{
		"acme: error: 429 :: POST :: urn:ietf:params:acme:error:rateLimited :: too many certificates": true,
		"Rate limit exceeded for this name":       true,
		"too many certificates already issued":    true,
		"context deadline exceeded":               false,
		"acme: authorization failed: dns problem": false,
	} {
		got := certRefusal(errors.New(msg))
		if strings.HasPrefix(got.Error(), "rate-limited: ") != limited {
			t.Errorf("%q: %v", msg, got)
		}
	}
}

// What a killed reach probe left is swept: this user's own directories,
// older than the cutoff; a newer one (a probe running now) and a link stay.
func TestTheReachDirsAreSwept(t *testing.T) {
	tmp := t.TempDir()
	old, recent := filepath.Join(tmp, reachDirPrefix+"old"), filepath.Join(tmp, reachDirPrefix+"new")
	for _, d := range []string{old, recent} {
		if err := os.MkdirAll(filepath.Join(d, "state"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	// A probe at its longest (its largest --wait, its join and logout) is
	// younger than the cutoff: never swept while it runs.
	if reachSweepAfter <= reachMaxWait+reachSlack {
		t.Fatalf("the sweep's cutoff %v is within a probe's lifetime %v", reachSweepAfter, reachMaxWait+reachSlack)
	}
	running := time.Now().Add(-(reachMaxWait + reachSlack))
	if err := os.Chtimes(recent, running, running); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(tmp, reachDirPrefix+"link")); err != nil {
		t.Fatal(err)
	}
	sweepReachDirs(tmp, time.Now().Add(-reachSweepAfter))
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("the old probe's directory stayed: %v", err)
	}
	if _, err := os.Stat(recent); err != nil {
		t.Errorf("a running probe's directory went: %v", err)
	}
	if _, err := os.Stat(elsewhere); err != nil {
		t.Errorf("a link was followed: %v", err)
	}
}

// A socket-routed obtain waits as long as it asked the daemon to try.
func TestObtainsCommandTimeout(t *testing.T) {
	if got := commandTimeout([]string{"tailnet", "certificate", "obtain", "--name", "vault", "--timeout", "9m"}); got != 9*time.Minute+30*time.Second {
		t.Fatalf("%v", got)
	}
	if got := commandTimeout([]string{"tailnet", "certificate", "obtain", "--name", "vault"}); got != controlTimeout {
		t.Fatalf("%v", got)
	}
}
