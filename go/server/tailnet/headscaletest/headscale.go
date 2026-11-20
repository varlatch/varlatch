// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build headscale

// Package headscaletest runs a Headscale control server in a container for
// the tailnet tests that need a self-hosted one (ADR-0059 Decision 5 as
// amended for step 7.5c; internal docs/design/go-step7.md 7.5). Its own
// build tag (headscale) and CI step: it needs Docker.
//
//   - The image is pinned by digest. The container has a name of its own,
//     and only that container is ever removed (docker rm -fv <its name>);
//     it runs unprivileged, its state in tmpfs.
//   - The control URL is https on an IP address (https://127.0.0.1:<port>),
//     as varlatchd.conf takes a self-hosted one: never a host name, so no
//     lookup, and so no bootstrap DNS query, can happen.
//   - Its certificate is made here, at run time, by a CA whose certificate
//     the test process trusts through SSL_CERT_FILE (Trust, before any TLS
//     use); no key or certificate is ever committed.
//   - Only the embedded DERP server: no Tailscale DERP map, no update
//     check, no log upload. Nothing leaves the host.
//   - Users and pre-auth keys come from `docker exec ... headscale` at run
//     time, and are never logged.
package headscaletest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Image is Headscale 0.29.7 (the version go-step7's G10 names), by its
// index digest.
const Image = "docker.io/headscale/headscale@sha256:11f81665e842809db9fe3006a38c56a66e968baa5abd4bac498e86445572b970"

// BaseDomain is the tailnet's MagicDNS suffix (Headscale's base_domain).
const BaseDomain = "g10.example"

// User is the Headscale user the pre-auth keys belong to, and the owner of
// the tags the tests advertise.
const User = "g10"

// Tags are the tags a node may advertise.
var Tags = []string{"tag:varlatch", "tag:prod", "tag:ci"}

// CA is the run's certificate authority: SSL_CERT_FILE names its
// certificate.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	// File is its certificate's PEM file.
	File string
}

// Trust makes a CA in dir and points SSL_CERT_FILE at its certificate.
// Call it from TestMain, before anything in the process uses TLS: Go reads
// the system roots once.
func Trust(dir string) (*CA, error) {
	if _, set := os.LookupEnv("SSL_CERT_FILE"); set {
		return nil, errors.New("headscaletest: SSL_CERT_FILE is set already; the run's CA would not be the one trusted")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "headscaletest CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	file := filepath.Join(dir, "headscaletest-ca.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	if err := os.Setenv("SSL_CERT_FILE", file); err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, File: file}, nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	return n
}

// leaf is a server certificate for ip, signed by the CA: its PEM
// certificate and key.
func (ca *CA) leaf(ip netip.Addr) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: ip.String()},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IP(ip.AsSlice())},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), nil
}

// Server is a running Headscale.
type Server struct {
	// URL is its control URL, https://127.0.0.1:<port>.
	URL  string
	name string
	t    testing.TB
}

// Skip skips t when Docker is not reachable.
func Skip(t testing.TB) {
	t.Helper()
	if err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").Run(); err != nil {
		t.Skipf("Docker is not reachable: %v", err)
	}
}

// Start runs Headscale and waits until it answers; t's cleanup removes its
// container.
func Start(t testing.TB, ca *CA) *Server {
	t.Helper()
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("127.0.0.1")
	certPEM, keyPEM, err := ca.leaf(ip)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	url := "https://" + ip.String() + ":" + strconv.Itoa(port)
	files := map[string][]byte{"config.yaml": []byte(config(url, port)), "tls.crt": certPEM, "tls.key": keyPEM, "policy.hujson": policy()}
	for name, b := range files {
		// Read by the container's root user; the key is this run's only.
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	s := &Server{URL: url, name: "varlatch-headscaletest-" + hex.EncodeToString(suffix), t: t}
	t.Cleanup(s.remove)
	if out, err := s.docker("run", "-d", "--name", s.name, "--read-only",
		"-p", "127.0.0.1:"+strconv.Itoa(port)+":"+strconv.Itoa(port),
		"-v", dir+":/etc/headscale:ro", "--tmpfs", "/var/lib/headscale", "--tmpfs", "/var/run/headscale",
		Image, "serve"); err != nil {
		t.Fatalf("starting Headscale: %v: %s", err, out)
	}
	s.waitReady(t)
	if out, err := s.headscale("users", "create", User); err != nil {
		t.Fatalf("headscale users create: %v: %s", err, out)
	}
	return s
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// config is Headscale's configuration: https on url's IP with the run's
// certificate, the embedded DERP server only (on the same port), no
// outbound traffic of its own.
func config(url string, port int) string {
	return fmt.Sprintf(`server_url: %s
listen_addr: 0.0.0.0:%d
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
    region_code: "g10"
    region_name: "headscaletest embedded DERP"
    verify_clients: true
    stun_listen_addr: "127.0.0.1:3478"
    private_key_path: /var/lib/headscale/derp_server_private.key
    automatically_add_embedded_derp_region: true
    ipv4: 127.0.0.1
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
`, url, port, BaseDomain)
}

// policy lets every node reach every other, and User own Tags.
func policy() []byte {
	owners := map[string][]string{}
	for _, tag := range Tags {
		owners[tag] = []string{User + "@"}
	}
	b, _ := json.Marshal(map[string]any{
		"tagOwners": owners,
		"acls":      []map[string]any{{"action": "accept", "src": []string{"*"}, "dst": []string{"*:*"}}},
	})
	return b
}

func (s *Server) docker(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.Bytes(), err
}

// headscale runs the headscale CLI in the container.
func (s *Server) headscale(args ...string) ([]byte, error) {
	return s.docker(append([]string{"exec", s.name, "headscale"}, args...)...)
}

func (s *Server) waitReady(t testing.TB) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		out, err := s.headscale("users", "list", "--output", "json")
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			logs, _ := s.docker("logs", "--tail", "40", s.name)
			t.Fatalf("Headscale did not answer: %v: %s\n%s", err, out, logs)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// PreauthKey is a reusable pre-auth key expiring within the hour: a tagged
// key for the tags (the node is a tagged device, as varlatchd's always is;
// Headscale takes a pre-auth key's tags, not the ones a node advertises),
// or User's key without tags. The caller passes it to the node only, never
// to a log.
func (s *Server) PreauthKey(t testing.TB, tags ...string) string {
	t.Helper()
	args := []string{"preauthkeys", "create", "--reusable", "--expiration", "1h", "--output", "json"}
	if len(tags) > 0 {
		args = append(args, "--tags", strings.Join(tags, ","))
	} else {
		id, err := s.userID()
		if err != nil {
			t.Fatal(err)
		}
		args = append(args, "--user", id)
	}
	out, err := s.headscale(args...)
	if err != nil {
		// Headscale's output can carry the key: never shown.
		t.Fatalf("headscale preauthkeys create failed: %v", err)
	}
	var k struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(out, &k); err != nil || k.Key == "" {
		t.Fatalf("headscale preauthkeys create: an answer without a key (%d bytes)", len(out))
	}
	return k.Key
}

func (s *Server) userID() (string, error) {
	out, err := s.headscale("users", "list", "--output", "json")
	if err != nil {
		return "", fmt.Errorf("headscale users list: %v: %s", err, out)
	}
	var users []struct {
		ID   json.RawMessage `json:"id"`
		Name string          `json:"name"`
	}
	if err := json.Unmarshal(out, &users); err != nil {
		return "", fmt.Errorf("headscale users list: %v", err)
	}
	for _, u := range users {
		if u.Name == User {
			return strings.Trim(string(u.ID), `"`), nil
		}
	}
	return "", fmt.Errorf("headscale users list: no user %s", User)
}

// Stop makes the control server unreachable: its container is paused
// (docker pause), so connections to it hang as to a server that is down,
// and its state, in tmpfs, is kept for Resume. A stopped container would
// lose that state.
func (s *Server) Stop(t testing.TB) {
	t.Helper()
	if out, err := s.docker("pause", s.name); err != nil {
		t.Fatalf("pausing Headscale: %v: %s", err, out)
	}
}

// Resume undoes Stop.
func (s *Server) Resume(t testing.TB) {
	t.Helper()
	if out, err := s.docker("unpause", s.name); err != nil {
		t.Fatalf("resuming Headscale: %v: %s", err, out)
	}
}

// Logs is the end of Headscale's log, for a failure's message.
func (s *Server) Logs() string {
	out, _ := s.docker("logs", "--tail", "60", s.name)
	pol, err := s.headscale("policy", "get")
	return string(out) + "\npolicy get (" + fmt.Sprint(err) + "):\n" + string(pol)
}

// remove removes the container by its own name, its volumes with it.
func (s *Server) remove() {
	if out, err := s.docker("rm", "-fv", s.name); err != nil {
		s.t.Logf("removing %s: %v: %s", s.name, err, out)
	}
}
