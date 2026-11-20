// SPDX-License-Identifier: AGPL-3.0-or-later

package publictls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// selfSigned is a certificate for host valid from notBefore to notAfter,
// and its key, both PEM.
func selfSigned(t *testing.T, host string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, Issuer: pkix.Name{CommonName: "test"},
		DNSNames: []string{host}, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

func newManager(t *testing.T, o Options) *Manager {
	t.Helper()
	if o.DataDir == "" {
		o.DataDir = t.TempDir()
	}
	if o.CA == "" {
		o.CA = "https://ca.invalid/directory"
	}
	if o.TLSPort == 0 {
		o.TLSPort = 5001
	}
	m, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}

// serveTLS serves m's TLS on a loopback listener; the address.
func serveTLS(t *testing.T, m *Manager) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "served") }),
		TLSConfig: m.TLSConfig()}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func handshake(addr string, cfg *tls.Config) error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return err
	}
	return conn.Close()
}

// TestTLSRefusesUntilACertificate: before a certificate exists, every
// handshake is refused (nothing is served); then only the host's name is
// served, over TLS 1.2 or later, with modern suites; a handshake offering
// only acme-tls/1 while no challenge is pending is refused, and so is
// every other name, and no name at all.
func TestTLSRefusesUntilACertificate(t *testing.T) {
	const host = "vault.example.com"
	m := newManager(t, Options{Host: host})
	addr := serveTLS(t, m)
	trusting := func(certPEM []byte) *x509.CertPool {
		p := x509.NewCertPool()
		p.AppendCertsFromPEM(certPEM)
		return p
	}
	if err := handshake(addr, &tls.Config{ServerName: host, InsecureSkipVerify: true}); err == nil {
		t.Fatal("a handshake succeeded before any certificate")
	}
	now := time.Now()
	certPEM, keyPEM := selfSigned(t, host, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	m.current.Store(&loaded{cert: &pair, leaf: pair.Leaf})
	roots := trusting(certPEM)
	if err := handshake(addr, &tls.Config{ServerName: host, RootCAs: roots}); err != nil {
		t.Fatalf("the host's handshake: %v", err)
	}
	if err := handshake(addr, &tls.Config{ServerName: strings.ToUpper(host), RootCAs: roots}); err != nil {
		t.Fatalf("the host's name in another case: %v", err)
	}
	for name, cfg := range map[string]*tls.Config{
		"another name":             {ServerName: "other.example.com", InsecureSkipVerify: true},
		"no name":                  {InsecureSkipVerify: true},
		"TLS 1.1":                  {ServerName: host, RootCAs: roots, MaxVersion: tls.VersionTLS11},
		"a CBC suite":              {ServerName: host, RootCAs: roots, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}},
		"acme-tls/1, no challenge": {ServerName: host, InsecureSkipVerify: true, NextProtos: []string{ACMETLS1}},
	} {
		if err := handshake(addr, cfg); err == nil {
			t.Errorf("%s: the handshake succeeded", name)
		}
	}
	// An expired certificate is no longer served.
	old, oldKey := selfSigned(t, host, now.Add(-48*time.Hour), now.Add(-time.Hour))
	pair, err = tls.X509KeyPair(old, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	m.current.Store(&loaded{cert: &pair, leaf: pair.Leaf})
	if err := handshake(addr, &tls.Config{ServerName: host, InsecureSkipVerify: true}); err == nil {
		t.Error("an expired certificate was served")
	}
	if got, _ := m.Report().Get("status"); got != "expired" {
		t.Errorf("status %v, want expired", got)
	}
}

// TestRedirectHandler: the plain listener redirects every request to the
// same path on the public origin, whatever Host the request names, and
// answers a challenge path it has no pending challenge for with 404,
// never a page.
func TestRedirectHandler(t *testing.T) {
	m := newManager(t, Options{Host: "vault.example.com", HTTPPort: 5002})
	origin, _ := url.Parse("https://vault.example.com")
	h := m.RedirectHandler(origin)
	for _, c := range []struct{ method, host, target, location string }{
		{"GET", "vault.example.com", "/dashboard?x=1", "https://vault.example.com/dashboard?x=1"},
		{"POST", "evil.example", "/v1/values", "https://vault.example.com/v1/values"},
		{"GET", "vault.example.com", "/", "https://vault.example.com/"},
	} {
		r, _ := http.NewRequest(c.method, "http://"+c.host+c.target, nil)
		r.RequestURI = c.target
		w := &recorder{header: http.Header{}}
		h.ServeHTTP(w, r)
		if w.status != http.StatusPermanentRedirect || w.header.Get("Location") != c.location || w.body.Len() != 0 {
			t.Errorf("%s %s%s: %d %q %q", c.method, c.host, c.target, w.status, w.header.Get("Location"), w.body.String())
		}
	}
	r, _ := http.NewRequest("GET", "http://vault.example.com/.well-known/acme-challenge/abc", nil)
	w := &recorder{header: http.Header{}}
	h.ServeHTTP(w, r)
	if w.status != http.StatusNotFound || w.header.Get("Location") != "" {
		t.Errorf("an unknown challenge: %d %q", w.status, w.header.Get("Location"))
	}
}

type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = 200
	}
	return r.body.Write(b)
}
func (r *recorder) WriteHeader(s int) { r.status = s }

// TestStoreIsPrivate: the store's directory is made 0700; one others can
// enter, or a symbolic link, is refused.
func TestStoreIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix modes")
	}
	data := t.TempDir()
	newManager(t, Options{Host: "vault.example.com", DataDir: data})
	info, err := os.Lstat(filepath.Join(data, StorageDir))
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("the store: %v %v", info.Mode(), err)
	}
	open := t.TempDir()
	if err := os.Mkdir(filepath.Join(open, StorageDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(open, StorageDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Host: "vault.example.com", CA: "https://ca.invalid/d", DataDir: open, TLSPort: 443}); err == nil || !strings.Contains(err.Error(), "make it 0700") {
		t.Errorf("a 0755 store: %v", err)
	}
	linked := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(linked, StorageDir)); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Host: "vault.example.com", CA: "https://ca.invalid/d", DataDir: linked, TLSPort: 443}); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a linked store: %v", err)
	}
}

// TestReportBeforeAnything: the report of a manager that has done
// nothing: configured, pending, no certificate, no attempt.
func TestReportBeforeAnything(t *testing.T) {
	m := newManager(t, Options{Host: "vault.example.com", TLSPort: 443})
	r := m.Report()
	want := map[string]any{"status": "pending", "certificate": nil, "attempting": false, "lastAttempt": nil, "lastError": nil, "failures": 0, "nextAttempt": nil}
	for k, v := range want {
		if got, ok := r.Get(k); !ok || got != v {
			t.Errorf("%s = %v, want %v", k, got, v)
		}
	}
	configured, _ := r.Get("configured")
	if c, _ := configured.(interface{ Get(string) (any, bool) }); c != nil {
		if p, _ := c.Get("httpPort"); p != nil {
			t.Errorf("httpPort %v, want null with HTTP-01 off", p)
		}
	}
}

func TestOneLine(t *testing.T) {
	long := strings.Repeat("x", 400)
	if got := oneLine(errors.New("a\nb\t c\x1b[31m")); got != "a b c[31m" {
		t.Errorf("%q", got)
	}
	if got := oneLine(errors.New(long)); len(got) > 304 {
		t.Errorf("not cut: %d", len(got))
	}
}

// pebble is the Pebble test CA go/server/publictls/testdata/pebble.sh starts, or a skip.
func pebble(t *testing.T) (string, *x509.CertPool) {
	t.Helper()
	dir, root := os.Getenv("VARLATCH_TEST_PEBBLE"), os.Getenv("VARLATCH_TEST_PEBBLE_ROOT")
	if dir == "" || root == "" {
		if os.Getenv("VARLATCH_REQUIRE_PEBBLE") != "" {
			t.Fatal("VARLATCH_REQUIRE_PEBBLE is set, but Pebble is not (go/server/publictls/testdata/pebble.sh start <dir>)")
		}
		t.Skip("no Pebble: go/server/publictls/testdata/pebble.sh start <dir>, then set the variables it prints")
	}
	pem, err := os.ReadFile(root)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("no certificate in VARLATCH_TEST_PEBBLE_ROOT")
	}
	return dir, pool
}

// issuedRoots are the roots Pebble issues from now (they change at each
// Pebble start), from its management API.
func issuedRoots(t *testing.T, api *x509.CertPool) *x509.CertPool {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: api}}}
	pool := x509.NewCertPool()
	for _, path := range []string{"/roots/0", "/intermediates/0"} {
		res, err := client.Get("https://localhost:15000" + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if !pool.AppendCertsFromPEM(b) {
			t.Fatalf("%s: no certificate", path)
		}
	}
	return pool
}

// logBuffer collects a log, safely across goroutines.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// pebbleSetup is a manager for host against Pebble, with its HTTP-01
// listener on 5002 (handler: the manager's, unless broken) and its
// TLS listener on 5001, and its log.
type pebbleSetup struct {
	m       *Manager
	log     *logBuffer
	tlsAddr string
	plain   *swappable
	data    string
}

// swappable is a handler that can be replaced while it serves.
type swappable struct {
	mu sync.Mutex
	h  http.Handler
}

func (s *swappable) set(h http.Handler) { s.mu.Lock(); s.h = h; s.mu.Unlock() }
func (s *swappable) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	h := s.h
	s.mu.Unlock()
	h.ServeHTTP(w, r)
}

func startPebble(t *testing.T, host string, data string, http01, tlsALPN bool, backoff []time.Duration) *pebbleSetup {
	t.Helper()
	return startPebbleAs(t, "ops@varlatch.test", host, data, http01, tlsALPN, backoff)
}

// startPebbleAs is startPebble with the ACME account's contact ("" for
// none).
func startPebbleAs(t *testing.T, email, host string, data string, http01, tlsALPN bool, backoff []time.Duration) *pebbleSetup {
	t.Helper()
	ca, roots := pebble(t)
	logs := &logBuffer{}
	o := Options{Host: host, CA: ca, CARoots: roots, Email: email, DataDir: data, TLSPort: 5001,
		Log: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})), CheckInterval: 500 * time.Millisecond, Backoff: backoff}
	if http01 {
		o.HTTPPort = 5002
	}
	m := newManager(t, o)
	m.issuer.DisableTLSALPNChallenge = !tlsALPN
	s := &pebbleSetup{m: m, log: logs, data: data, plain: &swappable{}}
	origin, _ := url.Parse("https://" + host)
	s.plain.set(m.RedirectHandler(origin))
	// The listeners, as varlatchd opens them: bound before Run, so that
	// certmagic finds the ports in use and starts no server of its own.
	tlsLn, err := net.Listen("tcp", ":5001")
	if err != nil {
		t.Fatal(err)
	}
	plainLn, err := net.Listen("tcp", ":5002")
	if err != nil {
		t.Fatal(err)
	}
	tlsSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "served over https") }),
		TLSConfig: m.TLSConfig(), TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){ACMETLS1: ChallengeOnly}}
	plainSrv := &http.Server{Handler: s.plain}
	go func() { _ = tlsSrv.ServeTLS(tlsLn, "", "") }()
	go func() { _ = plainSrv.Serve(plainLn) }()
	s.tlsAddr = "127.0.0.1:5001"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); m.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = tlsSrv.Close()
		_ = plainSrv.Close()
	})
	return s
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s", what, d)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func servedCert(t *testing.T, s *pebbleSetup, host string, roots *x509.CertPool) *x509.Certificate {
	t.Helper()
	conn, err := tls.Dial("tcp", s.tlsAddr, &tls.Config{ServerName: host, RootCAs: roots})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0]
}

// noKeyIn fails when text holds a private key or any line of one of the
// store's key files.
func noKeyIn(t *testing.T, what, text, data string) {
	t.Helper()
	if strings.Contains(text, "PRIVATE KEY") {
		t.Errorf("%s holds a PEM private key", what)
	}
	_ = filepath.WalkDir(filepath.Join(data, StorageDir), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".key") {
			return nil
		}
		b, _ := os.ReadFile(path)
		for _, line := range strings.Split(string(b), "\n") {
			if len(line) >= 40 && !strings.HasPrefix(line, "-----") && strings.Contains(text, line) {
				t.Errorf("%s holds a line of %s", what, filepath.Base(path))
			}
		}
		return nil
	})
}

// TestPebbleIssuanceAndRenewal: against Pebble, with each challenge on
// its own: the certificate is obtained and served for the host and
// verifies against Pebble's roots; the store holds the account key and
// the certificate's key in 0600 files under 0700 directories; nothing of
// a key is logged; a second manager on the same store serves the stored
// certificate at once, without asking the CA; and before the end of its
// 45 seconds the certificate is renewed (a new serial is served).
func TestPebbleIssuanceAndRenewal(t *testing.T) {
	_, api := pebble(t)
	for _, c := range []struct {
		name          string
		http, tlsALPN bool
	}{{"http-01", true, false}, {"tls-alpn-01", false, true}} {
		t.Run(c.name, func(t *testing.T) {
			host := c.name + ".varlatch.test"
			data := t.TempDir()
			s := startPebble(t, host, data, c.http, c.tlsALPN, []time.Duration{time.Second})
			waitFor(t, "the first certificate", 30*time.Second, s.m.HasCertificate)
			roots := issuedRoots(t, api)
			first := servedCert(t, s, host, roots)
			if first.Subject.CommonName != host && (len(first.DNSNames) != 1 || first.DNSNames[0] != host) {
				t.Errorf("served for %v %v", first.Subject.CommonName, first.DNSNames)
			}
			if got, _ := s.m.Report().Get("status"); got != "valid" {
				t.Errorf("status %v", got)
			}
			if !strings.Contains(s.log.String(), "the public certificate was obtained") {
				t.Errorf("the log does not say it was obtained:\n%s", s.log.String())
			}
			// The store: every directory 0700, every file 0600 (lock files
			// aside: certmagic's, without a key, 0644).
			keys := 0
			_ = filepath.WalkDir(filepath.Join(data, StorageDir), func(path string, d os.DirEntry, err error) error {
				if err != nil {
					t.Fatal(err)
				}
				info, _ := d.Info()
				switch {
				case d.IsDir():
					if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
						t.Errorf("%s: %04o", path, info.Mode().Perm())
					}
				case strings.HasSuffix(path, ".lock"):
				default:
					if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
						t.Errorf("%s: %04o", path, info.Mode().Perm())
					}
					if strings.HasSuffix(path, ".key") {
						keys++
					}
				}
				return nil
			})
			if keys < 2 {
				t.Errorf("%d key files in the store, want the account's and the certificate's", keys)
			}
			// A restart: the stored certificate is served before any ACME call.
			again := newManager(t, Options{Host: host, CA: s.m.o.CA, CARoots: s.m.o.CARoots, DataDir: data, TLSPort: 5001})
			if err := again.load(context.Background()); err != nil || !again.HasCertificate() {
				t.Errorf("the stored certificate: %v", err)
			}
			// Renewal: Pebble's certificates last 45 seconds; the last third.
			waitFor(t, "a renewal", 45*time.Second, func() bool {
				l := s.m.current.Load()
				return l != nil && l.leaf.SerialNumber.Cmp(first.SerialNumber) != 0
			})
			if second := servedCert(t, s, host, roots); second.SerialNumber.Cmp(first.SerialNumber) == 0 {
				t.Error("the renewed certificate is not served")
			}
			if !strings.Contains(s.log.String(), "the public certificate was renewed") {
				t.Error("the log does not say it was renewed")
			}
			noKeyIn(t, "the log", s.log.String(), data)
			noKeyIn(t, "the report", fmtReport(s.m), data)
		})
	}
}

func fmtReport(m *Manager) string {
	return string(jsvalue.Stringify(m.Report()))
}

// TestPebbleFailureAndBackoff: a challenge that fails (the HTTP-01
// listener answers 404 to everything, TLS-ALPN-01 is off) is reported
// (failures, lastError, nextAttempt one backoff step later), nothing is
// served, and attempts back off; once the listener answers, the next
// attempt obtains the certificate and the failures are cleared.
func TestPebbleFailureAndBackoff(t *testing.T) {
	host := "backoff.varlatch.test"
	s := startPebble(t, host, t.TempDir(), true, false, []time.Duration{2 * time.Second, 3 * time.Second})
	answers := s.plain.h
	s.plain.set(http.NotFoundHandler())
	waitFor(t, "two failures", 40*time.Second, func() bool {
		f, _ := s.m.Report().Get("failures")
		return f.(int) >= 2
	})
	r := s.m.Report()
	if st, _ := r.Get("status"); st != "pending" || s.m.HasCertificate() {
		t.Errorf("status %v after failures", st)
	}
	lastErr, _ := r.Get("lastError")
	if e, _ := lastErr.(string); e == "" || strings.ContainsAny(e, "\n\r") {
		t.Errorf("lastError %q", lastErr)
	}
	next, _ := r.Get("nextAttempt")
	last, _ := r.Get("lastAttempt")
	nt, err1 := time.Parse(time.RFC3339Nano, next.(string))
	lt, err2 := time.Parse(time.RFC3339Nano, last.(string))
	// The second failure's wait is the second step (3 s), counted from
	// when that attempt ended: at least 3 s after it began.
	if err1 != nil || err2 != nil || nt.Sub(lt) < 3*time.Second {
		t.Errorf("nextAttempt %v, lastAttempt %v", next, last)
	}
	if !strings.Contains(s.log.String(), "the public certificate could not be obtained; varlatchd tries again") {
		t.Error("the failure is not logged")
	}
	if err := handshake(s.tlsAddr, &tls.Config{ServerName: host, InsecureSkipVerify: true}); err == nil {
		t.Error("a handshake succeeded without a certificate")
	}
	s.plain.set(answers)
	waitFor(t, "the certificate after the failures", 40*time.Second, s.m.HasCertificate)
	r = s.m.Report()
	if f, _ := r.Get("failures"); f != 0 {
		t.Errorf("failures %v after a success", f)
	}
	if e, _ := r.Get("lastError"); e != nil {
		t.Errorf("lastError %v after a success", e)
	}
}
