// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/publictls"
)

// pebbleDaemon is varlatchd for host with public HTTPS against Pebble
// (go/server/publictls/testdata/pebble.sh): listen_https on 127.0.0.1:5001
// and, unless redirect is "off", listen_http_redirect on 127.0.0.1:5002;
// a client that reaches the HTTPS listener as host, trusting the roots
// Pebble issues from.
func pebbleDaemon(t *testing.T, host, redirect string) (*running, install, *http.Client) {
	t.Helper()
	ca, rootFile := os.Getenv("VARLATCH_TEST_PEBBLE"), os.Getenv("VARLATCH_TEST_PEBBLE_ROOT")
	if ca == "" || rootFile == "" {
		if os.Getenv("VARLATCH_REQUIRE_PEBBLE") != "" {
			t.Fatal("VARLATCH_REQUIRE_PEBBLE is set, but Pebble is not (go/server/publictls/testdata/pebble.sh start <dir>)")
		}
		t.Skip("no Pebble: go/server/publictls/testdata/pebble.sh start <dir>, then set the variables it prints")
	}
	in := newInstall(t, "public_url = https://"+host+":5001\nlisten_https = 127.0.0.1:5001\nlisten_http_redirect = "+redirect+"\n"+
		"acme_ca = "+ca+"\nacme_ca_root = "+rootFile+"\nacme_email = ops@varlatch.test\n")
	var httpsAddr, httpAddr net.Addr
	r := startWith(t, in, &hooks{
		publicTLS: func(o *publictls.Options) {
			o.CheckInterval, o.Backoff = 500*time.Millisecond, []time.Duration{time.Second}
		},
		publicReady: func(https, http net.Addr) { httpsAddr, httpAddr = https, http },
	})
	if httpsAddr == nil || httpsAddr.String() != "127.0.0.1:5001" || addrString(httpAddr) != redirect {
		r.stop(t)
		t.Fatalf("the public listeners: %v %v", httpsAddr, httpAddr)
	}
	// Pebble's issuing roots, from its management API.
	apiPEM, err := os.ReadFile(rootFile)
	if err != nil {
		t.Fatal(err)
	}
	api := x509.NewCertPool()
	api.AppendCertsFromPEM(apiPEM)
	mgmt := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: api}}}
	roots := x509.NewCertPool()
	for _, path := range []string{"/roots/0", "/intermediates/0"} {
		res, err := mgmt.Get("https://localhost:15000" + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		roots.AppendCertsFromPEM(b)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{ServerName: host, RootCAs: roots},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:5001")
		}}}
	return r, in, client
}

// waitHTTPS is GET https://host:5001/readyz through client once varlatchd
// serves it, within 60 seconds.
func waitHTTPS(t *testing.T, r *running, client *http.Client, host string) *http.Response {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		res, err := client.Get("https://" + host + ":5001/readyz")
		if err == nil {
			res.Body.Close()
			return res
		}
		if time.Now().After(deadline) {
			t.Fatalf("no HTTPS within 60 s: %v\n%s", err, r.stderr.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestPublicHTTPSAgainstPebble: varlatchd with listen_https, against
// Pebble (go/server/publictls/testdata/pebble.sh): it obtains a certificate for the public
// URL's host, serves the API over HTTPS with it (HTTP/2), and nothing
// before; its plain HTTP listener only redirects, to the public URL
// whatever the Host; the plain loopback listener is as it was; the ACME
// store is in the data directory, 0700; nothing of a key is logged.
func TestPublicHTTPSAgainstPebble(t *testing.T) {
	const host = "daemon.varlatch.test"
	r, in, client := pebbleDaemon(t, host, "127.0.0.1:5002")
	defer r.stop(t)
	res := waitHTTPS(t, r, client, host)
	if res.StatusCode != 200 || res.ProtoMajor != 2 {
		t.Errorf("readyz over HTTPS: %d %s", res.StatusCode, res.Proto)
	}
	if !strings.Contains(r.stderr.String(), "the public certificate was obtained") {
		t.Errorf("the log does not say the certificate was obtained:\n%s", r.stderr.String())
	}

	// The plain HTTP listener: a redirect to the public URL, never a page,
	// whatever Host the request names.
	plain := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, h := range []string{host, "evil.example"} {
		req, _ := http.NewRequest("GET", "http://127.0.0.1:5002/v1/meta?x=1", nil)
		req.Host = h
		res, err := plain.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusPermanentRedirect || res.Header.Get("Location") != "https://"+host+":5001/v1/meta?x=1" || len(body) != 0 {
			t.Errorf("plain HTTP, Host %s: %d %q %q", h, res.StatusCode, res.Header.Get("Location"), body)
		}
	}
	// The loopback listener is as it was: plain HTTP, the same API.
	if code := getJSON(t, "http://"+r.addr+"/readyz", nil); code != 200 {
		t.Errorf("the loopback listener: %d", code)
	}
	// Another name over HTTPS is refused.
	if conn, err := tls.Dial("tcp", "127.0.0.1:5001", &tls.Config{ServerName: "other.varlatch.test", InsecureSkipVerify: true}); err == nil {
		conn.Close()
		t.Error("a handshake for another name succeeded")
	}
	info, err := os.Lstat(filepath.Join(in.data, publictls.StorageDir))
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Errorf("the ACME store: %v %v", info, err)
	}
	if strings.Contains(r.stderr.String(), "PRIVATE KEY") {
		t.Error("the log holds a private key")
	}
}

// TestPublicHTTPSTLSALPNAgainstPebble: with listen_http_redirect = off,
// the only challenge is TLS-ALPN-01, answered by varlatchd's own HTTPS
// server (servePublic's Protocols and TLSNextProto): the certificate is
// obtained and served; no plain listener is open; and once no challenge
// is pending, a handshake offering only acme-tls/1 is refused.
func TestPublicHTTPSTLSALPNAgainstPebble(t *testing.T) {
	const host = "alpn.varlatch.test"
	r, _, client := pebbleDaemon(t, host, "off")
	defer r.stop(t)
	if res := waitHTTPS(t, r, client, host); res.StatusCode != 200 || res.ProtoMajor != 2 {
		t.Errorf("readyz over HTTPS: %d %s", res.StatusCode, res.Proto)
	}
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:5002", 2*time.Second); err == nil {
		conn.Close()
		t.Error("a plain listener is open with listen_http_redirect = off")
	}
	if conn, err := tls.Dial("tcp", "127.0.0.1:5001", &tls.Config{ServerName: host, InsecureSkipVerify: true, NextProtos: []string{publictls.ACMETLS1}}); err == nil {
		conn.Close()
		t.Error("an acme-tls/1 handshake succeeded with no challenge pending")
	}
	if !strings.Contains(r.stderr.String(), "the public certificate was obtained") {
		t.Errorf("the log does not say the certificate was obtained:\n%s", r.stderr.String())
	}
}
