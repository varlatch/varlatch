// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/publictls"
)

// pebbleDaemon is varlatchd for host with public HTTPS against Pebble
// (go/server/publictls/testdata/pebble.sh): listen_https on 127.0.0.1:5001
// and, unless redirect is "off", listen_http_redirect on 127.0.0.1:5002;
// a client that reaches the HTTPS listener as host, trusting the roots
// Pebble issues from.
func pebbleDaemon(t *testing.T, host, redirect, extra string) (*running, install, *http.Client) {
	t.Helper()
	ca, rootFile := os.Getenv("VARLATCH_TEST_PEBBLE"), os.Getenv("VARLATCH_TEST_PEBBLE_ROOT")
	if ca == "" || rootFile == "" {
		if os.Getenv("VARLATCH_REQUIRE_PEBBLE") != "" {
			t.Fatal("VARLATCH_REQUIRE_PEBBLE is set, but Pebble is not (go/server/publictls/testdata/pebble.sh start <dir>)")
		}
		t.Skip("no Pebble: go/server/publictls/testdata/pebble.sh start <dir>, then set the variables it prints")
	}
	in := newInstall(t, "public_url = https://"+host+":5001\nlisten_https = 127.0.0.1:5001\nlisten_http_redirect = "+redirect+"\n"+
		"acme_ca = "+ca+"\nacme_ca_root = "+rootFile+"\nacme_email = ops@varlatch.test\n"+extra)
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
	roots := pebbleRoots(t, rootFile)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{ServerName: host, RootCAs: roots},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:5001")
		}}}
	return r, in, client
}

// pebbleRoots are the roots Pebble issues from, from its management API
// (trusted through rootFile, its API's own root).
func pebbleRoots(t *testing.T, rootFile string) *x509.CertPool {
	t.Helper()
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
	return roots
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
	r, in, client := pebbleDaemon(t, host, "127.0.0.1:5002", "")
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
	r, _, client := pebbleDaemon(t, host, "off", "")
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

// TestIngressModesSideBySide (step 6.3b): public HTTPS beside the plain
// loopback listener, with a proxy trusted for the loopback one. Each
// keeps its rules:
//   - the HTTPS listener believes no X-Forwarded-For (its clients connect
//     directly); the loopback listener believes its trusted proxy's;
//   - the HTTPS listener serves the public URL's host only: another Host
//     is 421, under the same certificate;
//   - a passkey ceremony is accepted from the public URL's exact origin
//     (its port included) over HTTPS, and refused from the loopback
//     listener's origin, on either listener.
func TestIngressModesSideBySide(t *testing.T) {
	const host = "modes.varlatch.test"
	r, in, client := pebbleDaemon(t, host, "127.0.0.1:5002", "trusted_proxies = 127.0.0.1\n")
	defer r.stop(t)
	waitHTTPS(t, r, client, host)
	public := "https://" + host + ":5001"

	get := func(c *http.Client, target string, header map[string]string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest("GET", target, nil)
		for k, v := range header {
			if k == "Host" {
				req.Host = v
				continue
			}
			req.Header.Set(k, v)
		}
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res
	}
	// The client address: believed from the trusted proxy on the loopback
	// listener, never on the HTTPS listener.
	get(client, public+"/healthz?via=https", map[string]string{"X-Forwarded-For": "203.0.113.9"})
	get(http.DefaultClient, "http://"+r.addr+"/healthz?via=loopback", map[string]string{"X-Forwarded-For": "203.0.113.7"})
	clients := map[string]string{}
	deadline := time.Now().Add(10 * time.Second)
	for len(clients) < 2 && time.Now().Before(deadline) {
		raw, _ := os.ReadFile(in.accessLog)
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			var e struct {
				Client, Path string
				ForwardedFor *string
			}
			if json.Unmarshal([]byte(line), &e) == nil && e.ForwardedFor != nil && strings.HasPrefix(e.Path, "/healthz") {
				clients[*e.ForwardedFor] = e.Client
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if clients["203.0.113.9"] != "127.0.0.1" {
		t.Errorf("the HTTPS listener believed X-Forwarded-For: client %q", clients["203.0.113.9"])
	}
	if clients["203.0.113.7"] != "203.0.113.7" {
		t.Errorf("the loopback listener did not believe its trusted proxy: client %q", clients["203.0.113.7"])
	}

	// Another Host on the HTTPS listener: 421, never served, and in the
	// access log like any other request.
	if res := get(client, public+"/readyz?probe=misdirected", map[string]string{"Host": "other.varlatch.test"}); res.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("another Host over HTTPS: %d", res.StatusCode)
	}
	logged := false
	for deadline := time.Now().Add(10 * time.Second); !logged && time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		raw, _ := os.ReadFile(in.accessLog)
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			var e struct {
				Client, Path string
				Status       int
			}
			if json.Unmarshal([]byte(line), &e) == nil && e.Status == http.StatusMisdirectedRequest && e.Path == "/readyz" && e.Client == "127.0.0.1" {
				logged = true
			}
		}
	}
	if !logged {
		t.Error("the 421 is not in the access log")
	}
	if res := get(client, public+"/readyz", map[string]string{"Host": strings.ToUpper(host) + ":5001"}); res.StatusCode != 200 {
		t.Errorf("the public host in capitals, with its port: %d", res.StatusCode)
	}

	// A ceremony's origin, over each listener.
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Timeout: 10 * time.Second, Transport: client.Transport, Jar: jar}
	var sess struct{ CsrfToken string }
	res, err := browser.Get(public + "/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(res.Body).Decode(&sess); err != nil || res.StatusCode != 200 || sess.CsrfToken == "" {
		t.Fatalf("the session over HTTPS: %d %v", res.StatusCode, err)
	}
	res.Body.Close()
	options := func(c *http.Client, base, origin string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("POST", base+"/auth/passkey/sign-in/options", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		req.Header.Set(httpserver.CSRFHeader, sess.CsrfToken)
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res.StatusCode, string(b)
	}
	loopback := "http://" + r.addr
	if code, body := options(browser, public, public); code != 200 || !strings.Contains(body, `"rpId":"`+host+`"`) {
		t.Errorf("sign-in options from the public origin over HTTPS: %d %s", code, body)
	}
	for _, c := range []struct {
		name, base, origin string
		client             *http.Client
	}{
		{"the loopback origin over HTTPS", public, loopback, browser},
		{"the public host without its port over HTTPS", public, "https://" + host, browser},
		{"the redirect listener's scheme over HTTPS", public, "http://" + host + ":5001", browser},
		{"the loopback origin over the loopback listener", loopback, loopback, http.DefaultClient},
	} {
		if code, body := options(c.client, c.base, c.origin); code != http.StatusForbidden || !strings.Contains(body, `"reason":"origin"`) {
			t.Errorf("%s: %d %s", c.name, code, body)
		}
	}
}
