// SPDX-License-Identifier: AGPL-3.0-or-later

package servecli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/lib/release/releasetest"
	"github.com/varlatch/varlatch/go/server/outbound"
)

// fakeGitHub is github.com, its release storage host and Sigstore's TUF
// CDN on one local HTTPS server, with a certificate made for those names
// now, reached through a real outbound policy that resolves them to it
// (objects.githubusercontent.com to a private address the policy refuses).
type fakeGitHub struct {
	srv    *httptest.Server
	port   string
	policy *outbound.Policy
	mu     sync.Mutex
	hits   []string // host and path of every request served
	// files, when set, are a release's on the storage host, by name;
	// stallOnce makes the first SHA256SUMS sent stop after its headers.
	files     map[string][]byte
	stallOnce atomic.Bool
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "tuf-repo-cdn.sigstore.dev"}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake github"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: names, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGitHub{}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	_, f.port, _ = net.SplitHostPort(f.srv.Listener.Addr().String())
	allow, err := outbound.ParseAllow("127.0.0.1/32:" + f.port)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	f.policy = outbound.New(allow, outbound.Options{
		TLS: &tls.Config{RootCAs: roots},
		Resolve: func(_ context.Context, name string) ([]outbound.Answer, error) {
			switch name {
			case "github.com", "release-assets.githubusercontent.com", "tuf-repo-cdn.sigstore.dev":
				return []outbound.Answer{{Address: "127.0.0.1", Family: 4}}, nil
			case "objects.githubusercontent.com":
				return []outbound.Answer{{Address: "10.0.0.5", Family: 4}}, nil
			}
			return nil, errors.New("no such host")
		},
	})
	return f
}

func (f *fakeGitHub) host(name string) string { return name + ":" + f.port }

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits = append(f.hits, r.Host+r.URL.Path)
	f.mu.Unlock()
	host, _, _ := strings.Cut(r.Host, ":")
	switch {
	case host == "github.com" && strings.HasPrefix(r.URL.Path, "/releases/download/"):
		// As github.com answers a release file: a redirect to storage.
		http.Redirect(w, r, "https://"+f.host("release-assets.githubusercontent.com")+"/storage/"+strings.TrimPrefix(r.URL.Path, "/releases/download/")+"?signed=query", http.StatusFound)
	case host == "github.com" && r.URL.Path == "/loop":
		http.Redirect(w, r, "/loop", http.StatusFound)
	case host == "github.com" && r.URL.Path == "/elsewhere":
		http.Redirect(w, r, "https://storage.example.invalid:"+f.port+"/x", http.StatusFound)
	case host == "github.com" && r.URL.Path == "/private":
		http.Redirect(w, r, "https://"+f.host("objects.githubusercontent.com")+"/x", http.StatusFound)
	case host == "release-assets.githubusercontent.com" && f.files != nil && strings.HasPrefix(r.URL.Path, "/storage/"):
		_, name, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/storage/"), "/")
		body, ok := f.files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if name == Sums && f.stallOnce.CompareAndSwap(true, false) {
			_, _ = w.Write(body[:1])
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = w.Write(body)
	case host == "release-assets.githubusercontent.com" && strings.HasPrefix(r.URL.Path, "/storage/"):
		_, _ = w.Write([]byte("the file " + strings.TrimPrefix(r.URL.Path, "/storage/")))
	case host == "tuf-repo-cdn.sigstore.dev":
		// A TUF repository that redirects every request.
		http.Redirect(w, r, "https://"+f.host("release-assets.githubusercontent.com")+"/tuf"+r.URL.Path, http.StatusFound)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeGitHub) served() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.hits...)
}

// The Downloader as varlatchd wires it (daemon.go: the outbound policy's
// transport for the github purpose): github.com's redirect to its storage
// host is followed, each hop a request of its own through the policy.
func TestDownloaderThroughTheOutboundPolicy(t *testing.T) {
	f := newFakeGitHub(t)
	d := release.Downloader{
		Hosts:     []string{f.host("github.com"), f.host("release-assets.githubusercontent.com"), f.host("objects.githubusercontent.com")},
		Transport: f.policy.Transport(outbound.GitHub),
	}
	ctx := context.Background()
	got, err := d.Get(ctx, "https://"+f.host("github.com")+"/releases/download/v0.50.0/SHA256SUMS", 1<<10)
	if err != nil || string(got) != "the file v0.50.0/SHA256SUMS" {
		t.Fatalf("%q %v", got, err)
	}

	// A redirect to a host releases do not come from: refused before it is
	// requested (or even looked up).
	if _, err := d.Get(ctx, "https://"+f.host("github.com")+"/elsewhere", 1<<10); err == nil || !strings.Contains(err.Error(), "not a host releases come from") {
		t.Fatalf("elsewhere: %v", err)
	}
	// A redirect loop: at most five redirects, six requests.
	before := len(f.served())
	if _, err := d.Get(ctx, "https://"+f.host("github.com")+"/loop", 1<<10); err == nil || !strings.Contains(err.Error(), "too many redirects") {
		t.Fatalf("loop: %v", err)
	}
	if n := len(f.served()) - before; n != 6 {
		t.Fatalf("the loop made %d requests", n)
	}
	// Each hop is checked by the policy when it connects: an allowed host
	// whose address the policy refuses is never reached.
	_, err = d.Get(ctx, "https://"+f.host("github.com")+"/private", 1<<10)
	if outbound.RefusalOf(err) == nil {
		t.Fatalf("private: %v, want the outbound policy's refusal", err)
	}
	for _, hit := range f.served() {
		if strings.HasPrefix(hit, "objects.") || strings.HasPrefix(hit, "storage.example.invalid") {
			t.Fatalf("reached %s", hit)
		}
	}
}

// Sigstore's TUF repository is read through the policy's client, which
// never follows a redirect: Sigstore's CDN answers its metadata and
// targets directly (checked 2026-11-20), and one that redirects makes the
// refresh fail, so nothing is cached or served, never a stale root used.
func TestTrustedRootNeverFollowsARedirect(t *testing.T) {
	f := newFakeGitHub(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := release.LiveTrustedRootFrom(ctx, "", "https://"+f.host("tuf-repo-cdn.sigstore.dev"), f.policy.Client(outbound.GitHub))
	if err == nil {
		t.Fatal("a trusted root from a repository that redirects")
	}
	for _, hit := range f.served() {
		if strings.Contains(hit, "/tuf/") {
			t.Fatalf("followed the redirect to %s", hit)
		}
	}
}

// serve_cli as varlatchd wires it, against a github.com whose first
// SHA256SUMS stops after its headers: that attempt fails within the
// Downloader's bound, and the Manager's next one serves the release.
func TestManagerRetriesAStalledDownload(t *testing.T) {
	f := newFakeGitHub(t)
	s := releasetest.New()
	src := published(t, s)
	f.files = map[string][]byte{Sums: src.sums, Bundle: src.bundle}
	for n, b := range src.files {
		f.files[n] = b
	}
	f.stallOnce.Store(true)
	d := release.Downloader{
		Hosts:     []string{f.host("github.com"), f.host("release-assets.githubusercontent.com")},
		Transport: f.policy.Transport(outbound.GitHub),
		Stall:     200 * time.Millisecond,
	}
	o := options(t, s, nil, t.TempDir())
	// GitHub's source, at the fake's port.
	o.Source = sourceFunc(func(ctx context.Context, name string, limit int64) ([]byte, error) {
		return d.Get(ctx, "https://"+f.host("github.com")+"/releases/download/v"+version+"/"+name, limit)
	})
	o.RetryAfter = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := Start(ctx, o, slog.New(slog.NewTextHandler(io.Discard, nil)))
	deadline := time.Now().Add(10 * time.Second)
	for m.Current() == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if m.Current() == nil {
		t.Fatal("never served after a stalled download")
	}
	sums := 0
	for _, hit := range f.served() {
		if strings.HasSuffix(hit, "/"+Sums) && strings.Contains(hit, "/storage/") {
			sums++
		}
	}
	if sums < 2 || f.stallOnce.Load() {
		t.Fatalf("SHA256SUMS served %d times, stalled %v", sums, !f.stallOnce.Load())
	}
}

// sourceFunc is a Source from a function.
type sourceFunc func(ctx context.Context, name string, limit int64) ([]byte, error)

func (f sourceFunc) Get(ctx context.Context, name string, limit int64) ([]byte, error) {
	return f(ctx, name, limit)
}
