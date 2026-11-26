// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The tailnet case (VL_RH_INGRESS=tailnet; B4 of internal#221): a source
// on the release's Tailscale topology (its docker-compose.tailscale.yml:
// the sidecar owns the network, varlatchd shares it), behind the own
// proxy, its tailnet name moved to the target's node by varlatch migrate's
// handoff. Three runs: the forward migration with the handoff, a rollback
// after it (which starts the old sidecar again, #380), and, on a second
// installation, a migration killed mid-handoff, then --abort. After each,
// the name must be on the right node, and a client node of the tailnet
// must reach the right server under it.
//
// The control server is a Headscale the harness starts, by default, so
// the case runs without the owner: in a container of the run's own, its
// https on its address on a network of the run's own, with a CA made for
// the run (the sidecar, the client node, migrate and the target varlatchd
// trust it); its authority migrate's --headscale-url with an API key that
// expires within the hour, a new one for each run. With VL_RH_TAILSCALE_*
// (the owner's session on the box), the control server is Tailscale's,
// the owner's throwaway tailnet, its authority the owner's OAuth client.

// tailnetItem is the case's must-cover item.
const tailnetItem = 14

const (
	// headscaleImage is headscaletest.Image: Headscale 0.29.7.
	headscaleImage = "docker.io/headscale/headscale@sha256:11f81665e842809db9fe3006a38c56a66e968baa5abd4bac498e86445572b970"
	// tailscaleImage is the release overlay's tailscale/tailscale:v1.102.3,
	// by its digest: the client node.
	tailscaleImage = "tailscale/tailscale@sha256:8c42c4574ab066384fcb72f69e086a2ff1dd3652eb6f56856cee34bcf0d2f680"
	headscalePort  = "8443"
	// headscaleDomain is the run's MagicDNS suffix (Headscale's base_domain).
	headscaleDomain = "rh.example"
	headscaleUser   = "rh"
	tailnetTag      = "tag:varlatch"
	// publishedPort is Headscale's on an address of the host's.
	publishedPort = "18443"
	// tailnetPort is the release's tailnet listener (VARLATCH_TAILNET_PORT).
	tailnetPort = "8687"
	// clientProxy is the client node's outbound HTTP proxy, on its loopback.
	clientProxy = "127.0.0.1:1055"
)

// tailnetWorld is the run's tailnet: its control server, the nodes' auth
// key and the client node.
type tailnetWorld struct {
	t         *testing.T
	headscale bool
	network   string
	dir       string
	// Headscale's: its container, the one holding its network namespace,
	// its address and control URL.
	server, holder string
	ip, url        string
	// published is the address of the host's Headscale is published on,
	// for nodes in networks that are not the run's ("": in holder's
	// network, on the run's).
	published   string
	suffix      string
	nodeKeyFile string // the sidecars' and targets' reusable tagged key
	oauthFile   string // the owner's OAuth client (Tailscale)
	client      string // the client node's container
	clientID    string // the client node (its StableID)
	gateway     string // the host's address on the run's network
	runs        int
}

// writeTailnetCerts writes the run's CA (ca.pem) and Headscale's
// certificate for ip, signed by it (hs/tls.crt), and its key (hs/tls.key,
// 0600: Headscale runs as root in its container).
func writeTailnetCerts(dir string, ip net.IP) error {
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vl-rh tailnet CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: ip.String()}, IPAddresses: []net.IP{ip},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "hs"), 0o755); err != nil {
		return err
	}
	for _, f := range []struct {
		name  string
		block *pem.Block
		mode  os.FileMode
	}{
		{"ca.pem", &pem.Block{Type: "CERTIFICATE", Bytes: caDER}, 0o644},
		{"hs/tls.crt", &pem.Block{Type: "CERTIFICATE", Bytes: leafDER}, 0o644},
		{"hs/tls.key", &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}, 0o600},
	} {
		path := filepath.Join(dir, f.name)
		if err := os.WriteFile(path, pem.EncodeToMemory(f.block), f.mode); err != nil {
			return err
		}
		if err := os.Chmod(path, f.mode); err != nil {
			return err
		}
	}
	return nil
}

// headscaleConfig is Headscale's configuration (headscaletest's, on the
// run's network): https on url with the run's certificate, the embedded
// DERP server only, at ip, no traffic of its own outside the run.
func headscaleConfig(url, ip string) string {
	return fmt.Sprintf(`server_url: %s
listen_addr: 0.0.0.0:%s
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: false
noise:
  private_key_path: /var/lib/headscale/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: true
    region_id: 999
    region_code: "rh"
    region_name: "the rehearsal's embedded DERP"
    verify_clients: true
    stun_listen_addr: "0.0.0.0:3478"
    private_key_path: /var/lib/headscale/derp_server_private.key
    automatically_add_embedded_derp_region: true
    ipv4: %s
  urls: []
  paths: []
  auto_update_enabled: false
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
    write_ahead_log: true
tls_cert_path: /etc/headscale/tls.crt
tls_key_path: /etc/headscale/tls.key
log:
  level: info
  format: text
policy:
  mode: file
  path: /etc/headscale/policy.hujson
dns:
  magic_dns: true
  base_domain: %s
  override_local_dns: false
  nameservers:
    global: []
    split: {}
  search_domains: []
  extra_records: []
unix_socket: /var/run/headscale/headscale.sock
unix_socket_permission: "0770"
logtail:
  enabled: false
taildrop:
  enabled: false
`, url, headscalePort, ip, headscaleDomain)
}

// headscalePolicy lets every node reach every other, and the user own the
// tag.
func headscalePolicy() []byte {
	b, _ := json.Marshal(map[string]any{
		"tagOwners": map[string][]string{tailnetTag: {headscaleUser + "@"}},
		"acls":      []map[string]any{{"action": "accept", "src": []string{"*"}, "dst": []string{"*:*"}}},
	})
	return b
}

// tailnetOverlay is the source's Compose overlay on Headscale: the
// sidecar logs in to it (--login-server, as an operator's override gives
// it), trusts the run's CA, and reaches the run's network.
func tailnetOverlay(url, network, dir string) string {
	return fmt.Sprintf("# Written by the rehearsal's tailnet case: the run's Headscale.\nservices:\n  tailscale:\n    environment:\n      TS_EXTRA_ARGS: --login-server=%s\n      SSL_CERT_FILE: /vl-rh-tailnet/ca.pem\n    volumes:\n      - %s/ca.pem:/vl-rh-tailnet/ca.pem:ro\n    networks:\n      vl-rh-tailnet: {}\nnetworks:\n  vl-rh-tailnet:\n    external: true\n    name: %s\n",
		url, dir, network)
}

// tailnetConf is the target's tailnet configuration for machine; {keys}
// is its keys directory (newInstallation fills it in).
func tailnetConf(machine, controlURL string) string {
	c := fmt.Sprintf("tailnet = on\ntailnet_hostname = %s\ntailnet_tags = %s\ntailnet_port = %s\ntailnet_auth_key_file = {keys}/tailnet-auth-key\n", machine, tailnetTag, tailnetPort)
	if controlURL != "" {
		c += "tailnet_control_url = " + controlURL + "\n"
	}
	return c
}

func (w *tailnetWorld) docker(args ...string) ran { return run("", nil, nil, "docker", args...) }

// dropEnvLines removes the lines starting with prefix from an .env file,
// keeping its mode, atomically (a temporary file beside it, synced, then
// renamed over it: an interrupted cleanup leaves the old file or the new
// one, never half of either); a missing file is nothing to do.
func dropEnvLines(path, prefix string) error {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	var keep []string
	for _, l := range strings.SplitAfter(string(b), "\n") {
		if !strings.HasPrefix(l, prefix) {
			keep = append(keep, l)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err := tmp.WriteString(strings.Join(keep, "")); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(fi.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	done = true
	return nil
}

// headscaleCLI runs the headscale command in its container.
func (w *tailnetWorld) headscaleCLI(args ...string) ran {
	return w.docker(append([]string{"exec", w.server, "headscale"}, args...)...)
}

// startTailnet starts the run's tailnet: its control server (Headscale,
// or the owner's Tailscale tailnet) and a client node, by the run's names,
// removed by those names when the case ends.
func startTailnet(t *testing.T) *tailnetWorld { return startTailnetOn(t, "") }

// startTailnetOn is startTailnet, Headscale published on address.
func startTailnetOn(t *testing.T, address string) *tailnetWorld {
	t.Helper()
	w := &tailnetWorld{t: t, published: address, headscale: prof.tailscaleOAuth == "", network: "vl-rh-" + runID + "-tailnet", dir: filepath.Join(workDir, "tailnet-net"),
		server: "vl-rh-" + runID + "-headscale", holder: "vl-rh-" + runID + "-headscale-net", client: "vl-rh-" + runID + "-tailnet-client"}
	if err := os.MkdirAll(w.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(w.dir, 0o755)
	// Last: the keys, whatever VL_RH_KEEP says (the installations' .env
	// lose their TS_AUTHKEY line: on Tailscale it is the owner's reusable
	// key), and the directory, unless VL_RH_KEEP=1 keeps the
	// installations, which mount its CA.
	t.Cleanup(func() {
		for _, f := range []string{"hs/tls.key", "node-auth-key", "client.env"} {
			_ = os.Remove(filepath.Join(w.dir, f))
		}
		for _, name := range []string{"tailnet", "tailnet-abort"} {
			_ = dropEnvLines(filepath.Join(workDir, name, "compose", ".env"), "TS_AUTHKEY=")
		}
		if os.Getenv("VL_RH_KEEP") != "1" {
			_ = os.RemoveAll(w.dir)
		}
	})
	must(t, w.docker("network", "create", "--label", "org.varlatch.rehearsal="+runID, w.network), "create the tailnet's network")
	t.Cleanup(func() { w.docker("network", "rm", w.network) })
	clientKey := ""
	if w.headscale {
		w.startHeadscale()
		w.suffix = headscaleDomain
		key := w.preauthKey(true)
		w.nodeKeyFile = filepath.Join(w.dir, "node-auth-key")
		if err := os.WriteFile(w.nodeKeyFile, []byte(key+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		clientKey = w.preauthKey(false)
	} else {
		w.suffix, w.nodeKeyFile, w.oauthFile = prof.tailscaleTailnet, prof.tailscaleAuthKey, prof.tailscaleOAuth
		b, err := os.ReadFile(w.nodeKeyFile)
		if err != nil {
			t.Fatal(err)
		}
		clientKey = secret(strings.TrimSpace(string(b)))
	}
	w.startClient(clientKey)
	return w
}

// startHeadscale runs Headscale in the network namespace of a holder
// container of the run's network, whose address is known before Headscale
// starts: its certificate and server_url name it.
func (w *tailnetWorld) startHeadscale() {
	t := w.t
	if w.published != "" {
		w.ip = w.published
		w.serveHeadscale(publishedPort, "--network", w.network, "-p", w.ip+":"+publishedPort+":"+headscalePort)
		return
	}
	must(t, w.docker("run", "-d", "--name", w.holder, "--network", w.network, "-u", "1000:1000", fakesImage, "sleep", "infinity"), "start the Headscale network holder")
	t.Cleanup(func() { w.docker("rm", "-fv", w.holder) })
	w.ip = strings.TrimSpace(must(t, w.docker("inspect", "-f", `{{(index .NetworkSettings.Networks "`+w.network+`").IPAddress}}`, w.holder), "the holder's address").stdout)
	w.serveHeadscale(headscalePort, "--network", "container:"+w.holder)
}

// serveHeadscale runs Headscale with docker's network arguments, known as
// https on the world's address and port.
func (w *tailnetWorld) serveHeadscale(port string, network ...string) {
	t := w.t
	ip := net.ParseIP(w.ip)
	if ip == nil {
		t.Fatalf("Headscale has no address (%q)", w.ip)
	}
	w.url = "https://" + w.ip + ":" + port
	if err := writeTailnetCerts(w.dir, ip); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"config.yaml": []byte(headscaleConfig(w.url, w.ip)), "policy.hujson": headscalePolicy()} {
		if err := os.WriteFile(filepath.Join(w.dir, "hs", name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must(t, w.docker(slices.Concat([]string{"run", "-d", "--name", w.server}, network, []string{"--read-only",
		"-v", filepath.Join(w.dir, "hs") + ":/etc/headscale:ro", "--tmpfs", "/var/lib/headscale", "--tmpfs", "/var/run/headscale",
		headscaleImage, "serve"})...), "start Headscale")
	t.Cleanup(func() { w.docker("rm", "-fv", w.server) })
	ready := pollUntil(90*time.Second, 500*time.Millisecond, func() bool { return w.headscaleCLI("users", "list", "--output", "json").code == 0 })
	if !ready {
		t.Fatalf("Headscale did not answer: %s", lastLines(w.docker("logs", "--tail", "20", w.server).stderr, 20))
	}
	must(t, w.headscaleCLI("users", "create", headscaleUser), "headscale users create")
}

// preauthKey is a reusable pre-auth key for six hours (a run with pauses): tagged with the
// nodes' tag (the sidecars' and the targets', which Headscale makes tagged
// devices) or the user's (the client node). Never shown.
func (w *tailnetWorld) preauthKey(tagged bool) string {
	t := w.t
	args := []string{"preauthkeys", "create", "--reusable", "--expiration", "6h", "--output", "json"}
	if tagged {
		args = append(args, "--tags", tailnetTag)
	} else {
		r := w.headscaleCLI("users", "list", "--output", "json")
		var users []struct {
			ID   json.RawMessage `json:"id"`
			Name string          `json:"name"`
		}
		_ = json.Unmarshal([]byte(r.stdout), &users)
		id := ""
		for _, u := range users {
			if u.Name == headscaleUser {
				id = strings.Trim(string(u.ID), `"`)
			}
		}
		if id == "" {
			t.Fatalf("headscale users list: no user %s", headscaleUser)
		}
		args = append(args, "--user", id)
	}
	r := w.headscaleCLI(args...)
	var k struct {
		Key string `json:"key"`
	}
	if r.code != 0 || json.Unmarshal([]byte(r.stdout), &k) != nil || k.Key == "" {
		// Headscale's output can carry the key: never shown.
		t.Fatalf("headscale preauthkeys create failed (exit %d)", r.code)
	}
	return secret(k.Key)
}

// startClient runs the client node: a tailscale container on the run's
// network, in userspace mode, its outbound HTTP proxy on its loopback,
// which the case's requests to the tailnet name go through.
func (w *tailnetWorld) startClient(key string) {
	t := w.t
	env := "TS_AUTHKEY=" + key + "\nTS_USERSPACE=true\nTS_STATE_DIR=/tmp/ts\nTS_OUTBOUND_HTTP_PROXY_LISTEN=" + clientProxy + "\n"
	args := []string{"run", "-d", "--name", w.client, "--network", w.network, "--hostname", "vl-rh-" + runID + "-client"}
	if w.headscale {
		env += "TS_EXTRA_ARGS=--login-server=" + w.url + "\nSSL_CERT_FILE=/vl-rh-tailnet/ca.pem\n"
		args = append(args, "-v", filepath.Join(w.dir, "ca.pem")+":/vl-rh-tailnet/ca.pem:ro")
	}
	envFile := filepath.Join(w.dir, "client.env")
	if err := os.WriteFile(envFile, []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	must(t, w.docker(append(args, "--env-file", envFile, tailscaleImage)...), "start the client node")
	t.Cleanup(func() {
		if !w.headscale {
			// The owner's tailnet keeps no node of the client's.
			w.docker("exec", w.client, "tailscale", "logout")
		}
		w.docker("rm", "-fv", w.client)
	})
	if !pollUntil(120*time.Second, time.Second, func() bool {
		st, ok := w.status()
		w.clientID = st.Self.ID
		return ok && st.BackendState == "Running"
	}) {
		t.Fatalf("the client node did not join: %s", lastLines(w.docker("logs", "--tail", "20", w.client).stderr, 20))
	}
}

// tailnetStatus is the part of `tailscale status --json` the case reads.
type tailnetStatus struct {
	BackendState string      `json:"BackendState"`
	Self         tailnetPeer `json:"Self"`
	Peer         map[string]tailnetPeer
}

type tailnetPeer struct {
	ID       string `json:"ID"`
	HostName string `json:"HostName"`
	DNSName  string `json:"DNSName"`
	Online   bool   `json:"Online"`
}

func (w *tailnetWorld) status() (tailnetStatus, bool) {
	r := w.docker("exec", w.client, "tailscale", "status", "--json")
	var st tailnetStatus
	return st, r.code == 0 && json.Unmarshal([]byte(r.stdout), &st) == nil
}

// machine is an installation's tailnet name: its own in the run's
// Headscale, the run's in the owner's tailnet.
func (w *tailnetWorld) machine(name string) string {
	if w.headscale {
		return "rh-" + name
	}
	return "vl-rh-" + runID + "-" + name
}

// holderOf is the node the client's map gives machine's name to (its
// StableID; on Headscale its node id), "" when none; ok is false when the
// client's status could not be read, which says nothing of the holder.
func (w *tailnetWorld) holderOf(machine string) (string, bool) {
	st, ok := w.status()
	if !ok {
		return "", false
	}
	return holderIn(st, machine+"."+w.suffix), true
}

// holderIn is the peer of st named fqdn, "" when none.
func holderIn(st tailnetStatus, fqdn string) string {
	for _, p := range st.Peer {
		if strings.EqualFold(strings.TrimSuffix(p.DNSName, "."), fqdn) {
			return p.ID
		}
	}
	return ""
}

// meta is /v1/meta of the server the tailnet name reaches, from the
// client node: through its proxy, to the tailnet listener.
func (w *tailnetWorld) meta(machine string) (string, bool) {
	r := w.docker("exec", "-e", "http_proxy=http://"+clientProxy, w.client, "wget", "-q", "-O", "-", "-T", "15",
		"http://"+machine+"."+w.suffix+":"+tailnetPort+"/v1/meta")
	return r.stdout, r.code == 0
}

// served is the name's holder and what it serves, polled until holds
// accepts them or d passes.
func (w *tailnetWorld) served(machine string, d time.Duration, holds func(id, meta string) bool) (string, string, bool) {
	var id, meta string
	ok := pollUntil(d, 2*time.Second, func() bool {
		id, _ = w.holderOf(machine)
		meta, _ = w.meta(machine)
		return holds(id, meta)
	})
	return id, meta, ok
}

// authority is migrate's tailnet options for one run: on Headscale, its
// API with a new key (each run expires its own when it ends), on
// Tailscale, the owner's OAuth client; and the nodes' auth key.
func (w *tailnetWorld) authority() []string {
	if !w.headscale {
		return []string{"--tailscale-oauth-client-file", w.oauthFile, "--tailnet-auth-key-file", w.nodeKeyFile}
	}
	t := w.t
	w.runs++
	r := w.headscaleCLI("apikeys", "create", "--expiration", "1h")
	key := strings.Trim(strings.TrimSpace(r.stdout), `"`)
	if r.code != 0 || key == "" || strings.ContainsAny(key, " \n\t") {
		// Headscale's output can carry the key: never shown.
		t.Fatalf("headscale apikeys create failed (exit %d)", r.code)
	}
	secret(key)
	file := filepath.Join(w.dir, fmt.Sprintf("api-key-%d", w.runs))
	if err := os.WriteFile(file, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(file) })
	return []string{"--headscale-url", w.url, "--headscale-api-key-file", file, "--tailnet-auth-key-file", w.nodeKeyFile}
}

// liveAPIKeys counts Headscale's API keys that have not expired.
func (w *tailnetWorld) liveAPIKeys() int {
	r := w.headscaleCLI("apikeys", "list", "--output", "json")
	var keys []map[string]json.RawMessage
	if json.Unmarshal([]byte(r.stdout), &keys) != nil {
		return -1
	}
	live := 0
	for _, k := range keys {
		var s string
		if json.Unmarshal(k["expiration"], &s) == nil {
			if end, err := time.Parse(time.RFC3339Nano, s); err == nil && !end.After(time.Now()) {
				continue
			}
		}
		var ts struct {
			Seconds json.Number `json:"seconds"`
		}
		if json.Unmarshal(k["expiration"], &ts) == nil && ts.Seconds != "" {
			if sec, err := ts.Seconds.Int64(); err == nil && !time.Unix(sec, 0).After(time.Now()) {
				continue
			}
		}
		live++
	}
	return live
}

// nodeNames are Headscale's node names (given names), for the report.
func (w *tailnetWorld) nodeNames() string {
	if !w.headscale {
		return "(Tailscale: the owner's console)"
	}
	r := w.headscaleCLI("nodes", "list", "--output", "json")
	var nodes []struct {
		ID        json.RawMessage `json:"id"`
		GivenName string          `json:"given_name"`
		Online    bool            `json:"online"`
	}
	if json.Unmarshal([]byte(r.stdout), &nodes) != nil {
		return "unreadable"
	}
	var out []string
	for _, n := range nodes {
		out = append(out, fmt.Sprintf("%s=%s(online %v)", strings.Trim(string(n.ID), `"`), n.GivenName, n.Online))
	}
	return strings.Join(out, ", ")
}

// extra is what an installation named name gets for the tailnet: the
// release's tailnet overlay with the sidecar's key and name, the run's
// overlay on Headscale, the target's tailnet configuration, and the run's
// CA for the target and for migrate (which calls Headscale's API).
func (w *tailnetWorld) extra(name string) installExtra {
	machine := w.machine(name)
	b, err := os.ReadFile(w.nodeKeyFile)
	if err != nil {
		w.t.Fatal(err)
	}
	x := installExtra{
		env:         map[string]string{"TS_AUTHKEY": secret(strings.TrimSpace(string(b))), "VARLATCH_TAILNET_MACHINE": machine, "VARLATCH_TAILNET_NAME": w.suffix},
		bundleFiles: []string{"docker-compose.tailscale.yml"},
		conf:        tailnetConf(machine, w.url),
	}
	if prof.browser && name == "tailnet" {
		w.browserExtra(&x, machine)
	}
	if w.headscale {
		roots, err := goRoots(w.dir, "/etc/ssl/certs/ca-certificates.crt")
		if err != nil {
			w.t.Fatal(err)
		}
		x.composeFile, x.composeText = "docker-compose.tailnet-rh.yml", tailnetOverlay(w.url, w.network, w.dir)
		x.serviceEnv = []string{"SSL_CERT_FILE=" + roots}
		x.migrateEnv = []string{"SSL_CERT_FILE=" + roots}
	}
	return x
}

// sidecarID is the source's sidecar's node (its StableID), "" when it
// does not run.
func (in *installation) sidecarID() string {
	r := in.compose("exec", "-T", "tailscale", "tailscale", "status", "--json")
	var st tailnetStatus
	if r.code != 0 || json.Unmarshal([]byte(r.stdout), &st) != nil {
		return ""
	}
	return st.Self.ID
}

// sidecarRunning is whether the source's sidecar container runs.
func (in *installation) sidecarRunning() bool {
	r := in.compose("ps", "--status", "running", "--services")
	return r.code == 0 && strings.Contains(" "+strings.Join(strings.Fields(r.stdout), " ")+" ", " tailscale ")
}

// isSource is /v1/meta of the source's own installation, from the
// TypeScript release.
func isSource(in *installation, meta string) bool {
	return strings.Contains(meta, in.installationID) && strings.Contains(meta, `"serverVersion":"0.23.1"`)
}

// isTarget is /v1/meta of the migrated installation, from Go.
func isTarget(in *installation, meta string) bool {
	return strings.Contains(meta, in.installationID) && !strings.Contains(meta, `"serverVersion":"0.23.1"`)
}

func tailnetCase(t *testing.T, rel release, s3 *s3Server) {
	const item = tailnetItem
	w := startTailnet(t)
	if !w.headscale {
		measure("item 14: left in the owner's tailnet", "the case's sidecars' and targets' devices (vl-rh-"+runID+"-tailnet, vl-rh-"+runID+"-tailnet-abort and their -vl-<op>-o and -n renames) stay; only the client node logs out: delete vl-rh-"+runID+"-* in the admin console")
	}
	measure("item 14: the control server", map[bool]string{true: "the run's Headscale at " + w.url, false: "Tailscale's (the owner's tailnet " + w.suffix + ")"}[w.headscale])

	// 1. The forward migration with the name handoff, then a rollback.
	in := newInstallation(t, rel, s3, "tailnet", w.extra("tailnet"))
	registerSecrets(in)
	machine := w.machine("tailnet")
	sidecar := in.sidecarID()
	id, meta, ok := w.served(machine, 120*time.Second, func(id, meta string) bool { return id != "" && id == sidecar && isSource(in, meta) })
	record(t, item, "before: the name is the source's sidecar's, and the client reaches the TypeScript server", sidecar != "" && ok,
		fmt.Sprintf("sidecar %q; the name's node %q; /v1/meta over the tailnet: %s", sidecar, id, trim(meta)))
	if !ok {
		measure("item 14: the nodes before", w.nodeNames())
		return
	}
	var b *browserStep
	if prof.browser {
		if b = w.startBrowser(in, machine); b == nil || !b.step("before the handoff, on TypeScript", isSource, true) {
			return
		}
	}
	r := in.migrateEnv(rel, true, rel.pin(), w.authority()...)
	record(t, item, "the migration with the name handoff opens", r.code == 0, r.String()+" "+lastLines(r.stdout, 6))
	if r.code != 0 {
		measure("item 14: migrate's stdout", lastLines(r.stdout, 20))
		measure("item 14: the nodes after the failed migration", w.nodeNames())
		measure("item 14: the source's containers after the failed migration", strings.TrimSpace(in.compose("ps", "-a", "--format", "{{.Service}} {{.State}} {{.Status}}").stdout))
		measure("item 14: the source's varlatchd log after the failed migration", lastLines(in.compose("logs", "--no-color", "--tail", "15", "varlatchd").stdout, 15))
	} else {
		forwardAndBack(t, w, in, rel, machine, sidecar, b)
	}
	// The first installation's containers and target go before the
	// second starts (its cleanup runs again, finding nothing).
	in.remove()
	abortMidHandoff(t, w, rel, s3)
}

// forwardAndBack checks the name after the switch, then rolls back.
func forwardAndBack(t *testing.T, w *tailnetWorld, in *installation, rel release, machine, sidecar string, b *browserStep) {
	const item = tailnetItem
	id, meta, ok := w.served(machine, 180*time.Second, func(id, meta string) bool { return id != "" && id != sidecar && isTarget(in, meta) })
	record(t, item, "after the switch: the name is the target's node, and the client reaches the Go server", ok,
		fmt.Sprintf("the name's node %q (the sidecar's %q); /v1/meta over the tailnet: %s", id, sidecar, trim(meta)))
	_, pub := in.get("/v1/meta")
	record(t, item, "the public URL answers from the Go server too", isTarget(in, pub), trim(pub))
	record(t, item, "the old sidecar is stopped after the switch", !in.sidecarRunning(), strings.TrimSpace(in.compose("ps", "--format", "{{.Service}} {{.State}}").stdout))
	measure("item 14: the nodes after the switch", w.nodeNames())
	if w.headscale {
		record(t, item, "the forward run's Headscale API key expired when it ended", w.liveAPIKeys() == 0, fmt.Sprintf("%d live", w.liveAPIKeys()))
	}
	if b != nil {
		// Whatever it finds, the rollback runs: the name goes back.
		b.step("after the handoff, on Go", isTarget, false)
	}
	target := id
	rb := run(in.dir, in.migrateEnvVars(rel, true, rel.pin()), nil, filepath.Join(binDir, "varlatch"), in.rollbackArgs(w.authority()...)...)
	record(t, item, "the rollback after the handoff ends rolled back", rb.code == 0, rb.String()+" "+lastLines(rb.stdout, 6))
	if rb.code == 0 {
		record(t, item, "the rollback started the old sidecar again, as the same node (#380)", in.sidecarRunning() && in.sidecarID() == sidecar,
			fmt.Sprintf("running %v, node %q (was %q)", in.sidecarRunning(), in.sidecarID(), sidecar))
		id, meta, ok = w.served(machine, 180*time.Second, func(id, meta string) bool { return id == sidecar && isSource(in, meta) })
		record(t, item, "after the rollback: the name is the sidecar's again, and the client reaches the TypeScript server", ok,
			fmt.Sprintf("the name's node %q (the sidecar's %q, the target's %q); /v1/meta over the tailnet: %s", id, sidecar, target, trim(meta)))
		code, pub := in.get("/v1/meta")
		record(t, item, "the public URL answers from the TypeScript server again", code == 200 && isSource(in, pub), fmt.Sprintf("%d %s", code, trim(pub)))
		measure("item 14: the nodes after the rollback", w.nodeNames())
		if b != nil {
			b.step("after the rollback, on TypeScript", isSource, false)
		}
	} else {
		measure("item 14: the rollback's stdout", lastLines(rb.stdout, 20))
		measure("item 14: the nodes", w.nodeNames())
	}
	if w.headscale {
		record(t, item, "every finished run's Headscale API key expired", w.liveAPIKeys() == 0, fmt.Sprintf("%d live", w.liveAPIKeys()))
	}
}

// abortMidHandoff: a migration killed mid-handoff (the sidecar's node
// renamed away, the target's not yet named), then --abort: the name goes
// back to the sidecar's node, which serves again.
func abortMidHandoff(t *testing.T, w *tailnetWorld, rel release, s3 *s3Server) {
	const item = tailnetItem
	in2 := newInstallation(t, rel, s3, "tailnet-abort", w.extra("tailnet-abort"))
	registerSecrets(in2)
	machine2 := w.machine("tailnet-abort")
	sidecar2 := in2.sidecarID()
	if _, _, ok := w.served(machine2, 120*time.Second, func(id, meta string) bool { return id != "" && id == sidecar2 && isSource(in2, meta) }); !ok {
		record(t, item, "the second source's sidecar holds its name", false, fmt.Sprintf("sidecar %q; nodes %s", sidecar2, w.nodeNames()))
		return
	}
	// A crash point is reached once its step is journalled, before its
	// act: at "incoming renamed" the sidecar's node is renamed away and the
	// target's not yet named (run r17v: at "serving renamed" the sidecar's
	// node still held the name).
	const point = "tailnet forward incoming renamed"
	log := filepath.Join(in2.state, "crashpoints.log")
	cmd := exec.Command(filepath.Join(binDir, "varlatch"), in2.migrateArgs(w.authority()...)...)
	cmd.Dir = in2.dir
	cmd.Env = append(append(os.Environ(), in2.migrateEnvVars(rel, true, rel.pin())...), "VARLATCH_MIGRATE_LOG="+log, "VARLATCH_MIGRATE_PAUSE="+point)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	reached := pollUntil(10*time.Minute, 100*time.Millisecond, func() bool {
		b, _ := os.ReadFile(log)
		if bytes.Contains(b, []byte("paused "+point+"\n")) {
			return true
		}
		select {
		case err := <-done:
			done <- err
			return true
		default:
			return false
		}
	})
	b, _ := os.ReadFile(log)
	paused := reached && bytes.Contains(b, []byte("paused "+point+"\n"))
	_ = cmd.Process.Signal(syscall.SIGKILL)
	<-done
	record(t, item, "a migration killed mid-handoff ("+point+")", paused, lastLines(out.String(), 3))
	if !paused {
		return
	}
	measure("item 14: the nodes at the kill", w.nodeNames())
	// The kill left the name off the sidecar's node (renamed away, the
	// target's not yet named): so the name coming back proves the undo.
	// A status that cannot be read is not a move.
	var atKill string
	moved := pollUntil(60*time.Second, 2*time.Second, func() bool {
		id, ok := w.holderOf(machine2)
		atKill = id
		return ok && id != sidecar2
	})
	record(t, item, "at the kill the name is off the sidecar's node", moved, fmt.Sprintf("the name's node %q (the sidecar's %q)", atKill, sidecar2))
	ab := in2.migrateEnv(rel, true, rel.pin(), append([]string{"--abort"}, w.authority()...)...)
	record(t, item, "--abort after the kill mid-handoff", ab.code == 0, ab.String()+" "+lastLines(ab.stdout, 4))
	id, meta, ok := w.served(machine2, 180*time.Second, func(id, meta string) bool { return id == sidecar2 && isSource(in2, meta) })
	record(t, item, "after --abort: the name is the sidecar's again, and the client reaches the TypeScript server", ok && in2.sidecarRunning(),
		fmt.Sprintf("the name's node %q (the sidecar's %q), sidecar running %v; /v1/meta over the tailnet: %s", id, sidecar2, in2.sidecarRunning(), trim(meta)))
	code, pub := in2.get("/v1/meta")
	record(t, item, "after --abort the public URL answers from the TypeScript server", code == 200 && isSource(in2, pub), fmt.Sprintf("%d %s", code, trim(pub)))
	measure("item 14: the nodes after --abort", w.nodeNames())
	if w.headscale {
		// The killed run could not expire its key: it lives out its hour.
		measure("item 14: live Headscale API keys after the kill and --abort (the killed run's)", fmt.Sprint(w.liveAPIKeys()))
	}
}
