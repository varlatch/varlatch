// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"encoding/json"
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
	// The reach check, from a client node.
	code, out, errOut = runAdmin(t, "tailnet", "reaches", "--name", temp, "--stable-id", en.StableID, "--wait", "60s", "--json", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, `"reaches":true`) {
		t.Fatalf("reaches: %d %q %q", code, out, errOut)
	}
	if code, out, _ := runAdmin(t, "tailnet", "reaches", "--name", temp, "--stable-id", "nSomeoneElse", "--config", in.conf); code != ExitFailure || !strings.Contains(out, "does not reach") {
		t.Fatalf("reaches another node: %d %q", code, out)
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

	// Offline, enroll refuses a node no handoff holds; open removes nothing.
	if code, _, errOut := runAdmin(t, "tailnet", "enroll", "--hostname", temp, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "not held") {
		t.Fatalf("enroll an opened node: %d %q", code, errOut)
	}
	if code, out, errOut := runAdmin(t, "tailnet", "open", "--json", "--config", in.conf); code != ExitOK || out != `{"opened":true,"wasHeld":false,"running":false}`+"\n" {
		t.Fatalf("open offline: %d %q %q", code, out, errOut)
	}
}
