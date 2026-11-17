// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build conformance

package outbound

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// fakeGitHub is an HTTPS server on loopback with a certificate for
// api.github.com, and the client TLS configuration that trusts it.
func fakeGitHub(t *testing.T) (*httptest.Server, int, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "api.github.com"}, DNSNames: []string{"api.github.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("fake " + r.Host))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, portText, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return srv, port, &tls.Config{RootCAs: roots}
}

func withConformanceHosts(t *testing.T, spec string) {
	t.Helper()
	saved := conformanceHosts
	conformanceHosts = parseConformanceHosts(spec)
	t.Cleanup(func() { conformanceHosts = saved })
}

// noDNS fails every lookup: the override never asks DNS.
func noDNS(_ context.Context, name string) ([]Answer, error) {
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// TestRedirectStillDecidedByThePolicy: with the override on, a request to
// api.github.com reaches the fake only when the allow list names the
// fake's address and port; without that entry, or with another port, it
// is refused with the original host name; the configuration-time check
// decides the same; a host the override does not name is untouched.
func TestRedirectStillDecidedByThePolicy(t *testing.T) {
	_, port, tlsConfig := fakeGitHub(t)
	withConformanceHosts(t, "api.github.com=127.0.0.1:"+strconv.Itoa(port))
	policy := func(allow string) *Policy {
		entries, err := ParseAllow(allow)
		if err != nil {
			t.Fatal(err)
		}
		p := New(entries, Options{Resolve: noDNS, TLS: tlsConfig})
		t.Cleanup(p.Close)
		return p
	}

	allowed := policy("127.0.0.1/32:" + strconv.Itoa(port))
	res, err := allowed.Client(SyncDelivery).Get("https://api.github.com/repos/acme/api/actions/secrets/public-key")
	if err != nil {
		t.Fatalf("an allowed redirect: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("an allowed redirect answered %d", res.StatusCode)
	}

	for name, allow := range map[string]string{"no entry": "", "another port": "127.0.0.1/32:1", "another address": "127.0.0.2/32:" + strconv.Itoa(port)} {
		p := policy(allow)
		_, err := p.Client(SyncDelivery).Get("https://api.github.com/x")
		var refused *RefusedError
		if !errors.As(err, &refused) {
			t.Errorf("%s: %v, want the outbound policy's refusal", name, err)
			continue
		}
		if refused.Destination.Host != "api.github.com" || refused.Destination.Port != port || len(refused.Addresses) != 1 || refused.Addresses[0] != "127.0.0.1" {
			t.Errorf("%s: refused %+v", name, refused)
		}
		c, err := p.Check(context.Background(), "https://api.github.com", nil)
		if err != nil || c.Outcome != "refused" {
			t.Errorf("%s: the configuration-time check %+v %v, want refused", name, c, err)
		}
	}
	if c, err := allowed.Check(context.Background(), "https://api.github.com", nil); err != nil || c.Outcome != "allowed" || c.Addresses[0] != "127.0.0.1" {
		t.Errorf("the configuration-time check with the entry: %+v %v", c, err)
	}

	// A host the override does not name resolves as usual (here: not at all).
	if _, err := allowed.Client(SyncDelivery).Get("https://coolify.example.invalid/"); err == nil || RefusalOf(err) != nil {
		t.Errorf("an unlisted host: %v, want a DNS failure", err)
	}
}

// TestRedirectOffUnlessConfigured: without VARLATCH_CONFORMANCE_OUTBOUND_HOSTS
// nothing is redirected and nothing is announced; a malformed value stops
// the process.
func TestRedirectOffUnlessConfigured(t *testing.T) {
	withConformanceHosts(t, "")
	p := New(nil, Options{Resolve: noDNS})
	t.Cleanup(p.Close)
	if d, _, ok := p.redirect(Destination{Scheme: "https", Host: "api.github.com", Port: 443}); ok {
		t.Errorf("redirected to %+v with the override off", d)
	}
	if r := ConformanceRedirects(); r != "" {
		t.Errorf("announced %q with the override off", r)
	}
	for _, bad := range []string{"api.github.com", "api.github.com=localhost:443", "api.github.com=127.0.0.1", "=127.0.0.1:443", "api.github.com=127.0.0.1:0"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%q was accepted", bad)
				}
			}()
			parseConformanceHosts(bad)
		}()
	}
}
