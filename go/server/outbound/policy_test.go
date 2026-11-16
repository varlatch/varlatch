// SPDX-License-Identifier: AGPL-3.0-or-later

package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDNS answers from a table and counts its lookups.
type fakeDNS struct {
	mu      sync.Mutex
	answers map[string][]Answer
	asked   map[string]int
}

func (f *fakeDNS) resolve(_ context.Context, name string) ([]Answer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked[name]++
	a, ok := f.answers[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return a, nil
}

func (f *fakeDNS) set(name string, answers ...Answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[name] = answers
}

func (f *fakeDNS) count(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.asked[name]
}

func v4(a string) Answer { return Answer{a, 4} }
func v6(a string) Answer { return Answer{a, 6} }

func policyOf(t *testing.T, allow string, dns *fakeDNS, tlsConf *tls.Config) *Policy {
	t.Helper()
	entries, err := ParseAllow(allow)
	if err != nil {
		t.Fatal(err)
	}
	p := New(entries, Options{Resolve: dns.resolve, TLS: tlsConf, ConnectTimeout: 2 * time.Second})
	t.Cleanup(p.Close)
	return p
}

// counting is a local server that counts its requests.
func counting(t *testing.T, h http.HandlerFunc) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if h != nil {
			h(w, r)
			return
		}
		io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func port(srv *httptest.Server) string {
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return p
}

func get(c *http.Client, url string) (string, error) {
	res, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b), nil
}

// The connection check: a name that resolves to a loopback address is
// refused unless a CIDR entry inside the loopback range opens it, before
// any connection; then the request reaches the checked address only.
func TestConnectionCheck(t *testing.T) {
	srv, hits := counting(t, nil)
	dns := &fakeDNS{answers: map[string][]Answer{}, asked: map[string]int{}}
	dns.set("hooks.test", v4("127.0.0.1"))
	url := "http://hooks.test:" + port(srv) + "/x"

	strict := policyOf(t, "", dns, nil)
	_, err := get(strict.Client(Webhook), url)
	r := RefusalOf(err)
	if r == nil || r.Reason != HostOnlyAddress || r.Destination.Host != "hooks.test" || r.Error() != Message(HostOnlyAddress) || hits.Load() != 0 {
		t.Fatalf("strict: %v (%+v), %d requests", err, r, hits.Load())
	}
	// A hostname entry never opens loopback.
	if _, err := get(policyOf(t, "hooks.test:*", dns, nil).Client(Webhook), url); RefusalOf(err) == nil || hits.Load() != 0 {
		t.Fatalf("a hostname entry for loopback: %v", err)
	}
	open := policyOf(t, "127.0.0.1/32:*", dns, nil)
	if body, err := get(open.Client(Webhook), url); err != nil || body != "ok" || hits.Load() != 1 {
		t.Fatalf("allowed: %q %v", body, err)
	}
	// Another port than the entry's.
	if _, err := get(policyOf(t, "127.0.0.1/32:1", dns, nil).Client(Webhook), url); RefusalOf(err) == nil || RefusalOf(err).Reason != PortReason {
		t.Fatalf("another port: %v", err)
	}
	// One refused answer refuses the name.
	dns.set("mixed.test", v4("127.0.0.1"), v4("10.0.0.1"))
	if _, err := get(open.Client(Webhook), "http://mixed.test:"+port(srv)+"/x"); RefusalOf(err) == nil || RefusalOf(err).Reason != MixedAnswers || hits.Load() != 1 {
		t.Fatalf("mixed answers: %v", err)
	}
	// A literal address is decided as it is, never looked up.
	before := len(dns.asked)
	if _, err := get(strict.Client(Webhook), "http://127.0.0.1:"+port(srv)+"/x"); RefusalOf(err) == nil || len(dns.asked) != before {
		t.Fatalf("a literal loopback address: %v", err)
	}
	if body, err := get(open.Client(Webhook), "http://127.0.0.1:"+port(srv)+"/x"); err != nil || body != "ok" {
		t.Fatalf("a literal allowed address: %q %v", body, err)
	}
	// A name that does not resolve is not a refusal.
	if _, err := get(open.Client(Webhook), "http://nowhere.test/x"); err == nil || RefusalOf(err) != nil {
		t.Fatalf("an unresolved name: %v", err)
	}
	// Plain http to a public address needs an entry.
	dns.set("public.test", v4("93.184.216.34"))
	if _, err := get(strict.Client(Webhook), "http://public.test/x"); RefusalOf(err) == nil || RefusalOf(err).Reason != Scheme {
		t.Fatalf("plain http to a public address: %v", err)
	}
}

// DNS rebinding: the name is resolved once per connection, by the check,
// and the connection goes to an address it checked. A resolver whose next
// answer is a refused address changes nothing for a connection already
// checked, and refuses the next new one.
func TestRebinding(t *testing.T) {
	srv, hits := counting(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		io.WriteString(w, "ok")
	})
	dns := &fakeDNS{answers: map[string][]Answer{}, asked: map[string]int{}}
	dns.set("rebind.test", v4("127.0.0.1"))
	c := policyOf(t, "127.0.0.1/32:*", dns, nil).Client(Webhook)
	url := "http://rebind.test:" + port(srv) + "/x"
	if body, err := get(c, url); err != nil || body != "ok" || dns.count("rebind.test") != 1 {
		t.Fatalf("first: %q %v, %d lookups", body, err, dns.count("rebind.test"))
	}
	dns.set("rebind.test", v4("169.254.169.254"))
	if _, err := get(c, url); RefusalOf(err) == nil || RefusalOf(err).Reason != HostOnlyAddress || hits.Load() != 1 || dns.count("rebind.test") != 2 {
		t.Fatalf("after the answer changed: %v, %d requests, %d lookups", err, hits.Load(), dns.count("rebind.test"))
	}
}

// Redirects are never followed, credentials never sent, and no
// environment proxy applies.
func TestNoRedirectsProxiesOrCredentials(t *testing.T) {
	target, targetHits := counting(t, nil)
	redirect, _ := counting(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/elsewhere", http.StatusFound)
	})
	proxy, proxyHits := counting(t, nil)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	dns := &fakeDNS{answers: map[string][]Answer{}, asked: map[string]int{}}
	c := policyOf(t, "127.0.0.1/32:*", dns, nil).Client(Webhook)
	_, err := get(c, redirect.URL+"/x")
	if err == nil || !errors.Is(err, errRedirect) || targetHits.Load() != 0 {
		t.Fatalf("a redirect: %v, %d requests to its target", err, targetHits.Load())
	}
	if body, err := get(c, target.URL+"/y"); err != nil || body != "ok" || proxyHits.Load() != 0 {
		t.Fatalf("through a proxy? %q %v, %d proxy requests", body, err, proxyHits.Load())
	}
	req, _ := http.NewRequest("GET", target.URL, nil)
	req.URL.User = nil
	req.URL.Host = "user:secret@" + req.URL.Host
	u := *req.URL
	u.Host = strings.TrimPrefix(u.Host, "user:secret@")
	u.User = urlUser("user", "secret")
	req.URL = &u
	if _, err := c.Do(req); err == nil || !strings.Contains(err.Error(), "never carry credentials") {
		t.Fatalf("credentials: %v", err)
	}
}

// TLS uses the URL's name: the certificate is checked against it, though
// the connection goes to the checked address.
func TestTLSUsesTheName(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.TLS.ServerName+" "+r.Host)
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	dns := &fakeDNS{answers: map[string][]Answer{}, asked: map[string]int{}}
	dns.set("example.com", v4("127.0.0.1"))
	dns.set("other.test", v4("127.0.0.1"))
	c := policyOf(t, "127.0.0.1/32:*", dns, &tls.Config{RootCAs: pool}).Client(Webhook)
	body, err := get(c, "https://example.com:"+port(srv)+"/x")
	if err != nil || body != "example.com example.com:"+port(srv) {
		t.Fatalf("%q %v", body, err)
	}
	// The certificate does not name other.test.
	if _, err := get(c, "https://other.test:"+port(srv)+"/x"); err == nil || RefusalOf(err) != nil {
		t.Fatalf("a certificate for another name: %v", err)
	}
}

// Happy Eyeballs over the checked addresses only: the first answer's
// family first, the other when it fails.
func TestHappyEyeballs(t *testing.T) {
	srv, _ := counting(t, nil) // listens on 127.0.0.1 only
	dns := &fakeDNS{answers: map[string][]Answer{}, asked: map[string]int{}}
	dns.set("dual.test", v6("::1"), v4("127.0.0.1"))
	c := policyOf(t, "127.0.0.1/32:*,[::1/128]:*", dns, nil).Client(Webhook)
	if body, err := get(c, "http://dual.test:"+port(srv)+"/x"); err != nil || body != "ok" {
		t.Fatalf("%q %v", body, err)
	}
	// Without an entry for ::1, the name is refused: one answer refused.
	if _, err := get(policyOf(t, "127.0.0.1/32:*", dns, nil).Client(Webhook), "http://dual.test:"+port(srv)+"/x"); RefusalOf(err) == nil || RefusalOf(err).Reason != MixedAnswers {
		t.Fatalf("one family refused: %v", err)
	}
}

func TestCheck(t *testing.T) {
	dns := &fakeDNS{answers: map[string][]Answer{}, asked: map[string]int{}}
	dns.set("private.test", v4("10.1.2.3"))
	p := policyOf(t, "", dns, nil)
	ctx := context.Background()
	c, err := p.Check(ctx, "https://private.test/hook?x=1", nil)
	if err != nil || c.Outcome != "refused" || c.Verdict.Reason != PrivateAddress || c.Destination != (Destination{"https:", "private.test", 443}) {
		t.Fatalf("%+v %v", c, err)
	}
	if c, _ := p.Check(ctx, "https://missing.test/", nil); c.Outcome != "unresolved" || c.Error != "ENOTFOUND" {
		t.Errorf("unresolved: %+v", c)
	}
	if c, _ := p.Check(ctx, "https://8.8.8.8/", nil); c.Outcome != "allowed" || c.Verdict.Via != "public" {
		t.Errorf("a public literal: %+v", c)
	}
	if _, err := p.Check(ctx, "ftp://x.test/", nil); !errors.Is(err, ErrNotChecked) {
		t.Errorf("ftp: %v", err)
	}
	if r, err := p.RefusalFor(ctx, "https://private.test/", Webhook); err != nil || r == nil || r.Reason != PrivateAddress {
		t.Errorf("refusalFor: %v %v", r, err)
	}
	if r, _ := p.RefusalFor(ctx, "https://8.8.8.8/", Webhook); r != nil {
		t.Errorf("refusalFor a public address: %v", r)
	}
}

// The audit bound (ADR-0057 Decision 8).
func TestLimiter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewLimiter(func() time.Time { return now })
	if ok, s := l.Admit("a"); !ok || s != 0 {
		t.Fatal("first")
	}
	for range 3 {
		if ok, _ := l.Admit("a"); ok {
			t.Fatal("the same key within the hour")
		}
	}
	if ok, s := l.Admit("b"); !ok || s != 3 {
		t.Fatalf("another key: %v, %d held back", ok, s)
	}
	if s := l.Always(); s != 0 {
		t.Fatalf("always: %d", s)
	}
	now = now.Add(time.Hour)
	if ok, _ := l.Admit("a"); !ok || l.Size() != 1 {
		t.Fatalf("after the hour: %v, %d keys", ok, l.Size())
	}
	// The process cap: 100 an hour in all.
	now = now.Add(2 * time.Hour)
	admitted := 0
	for i := range 150 {
		if ok, _ := l.Admit(string(rune('a'+i%26)) + strings.Repeat("x", i)); ok {
			admitted++
		}
	}
	if admitted != 100 || l.Always() != 50 {
		t.Fatalf("admitted %d", admitted)
	}
	// MaxKeys: a key beyond it counts toward the cap without an entry.
	m := NewLimiter(func() time.Time { return now })
	m.MaxKeys = 2
	m.Admit("1")
	m.Admit("2")
	if ok, _ := m.Admit("3"); !ok || m.Size() != 2 {
		t.Fatalf("beyond MaxKeys: %v, %d keys", ok, m.Size())
	}
	if ok, _ := m.Admit("3"); !ok {
		t.Fatal("a key without an entry is admitted again")
	}
}

func TestReasonOfStatus(t *testing.T) {
	for text, want := range map[string]Reason{
		"outbound_refused": "unknown", "outbound_refused: private_address": PrivateAddress, "outbound_refused:port": PortReason,
		"outbound_refused: bogus": "unknown", "outbound_refused: scheme and more": Scheme, "200": "", "": "",
	} {
		if got := ReasonOfStatus(text); got != want {
			t.Errorf("%q: %q, want %q", text, got, want)
		}
	}
}

func urlUser(name, password string) *url.Userinfo { return url.UserPassword(name, password) }

// One deadline bounds the whole connection: a name with several
// unreachable checked addresses (a blackhole: the attempt never
// completes) fails within ConnectTimeout, not one timeout per address, in
// one family and across two.
func TestConnectDeadline(t *testing.T) {
	var attempts atomic.Int64
	blackhole := func(ctx context.Context, _, _ string) (net.Conn, error) {
		attempts.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	dns := &fakeDNS{answers: map[string][]Answer{}, asked: map[string]int{}}
	dns.set("black.test", v4("192.0.2.1"), v4("192.0.2.2"), v4("192.0.2.3"), v4("192.0.2.4"))
	dns.set("dual.test", v6("2001:db8::1"), v6("2001:db8::2"), v4("192.0.2.1"), v4("192.0.2.2"))
	entries, _ := ParseAllow("192.0.2.0/24:*,[2001:db8::/32]:*")
	const timeout = 500 * time.Millisecond
	p := New(entries, Options{Resolve: dns.resolve, ConnectTimeout: timeout, Dial: blackhole})
	t.Cleanup(p.Close)
	for _, host := range []string{"black.test", "dual.test"} {
		attempts.Store(0)
		start := time.Now()
		_, err := get(p.Client(Webhook), "http://"+host+":8080/x")
		elapsed := time.Since(start)
		if err == nil || RefusalOf(err) != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if elapsed < timeout || elapsed > timeout+400*time.Millisecond {
			t.Errorf("%s: failed after %s with a %s deadline (%d attempts)", host, elapsed, timeout, attempts.Load())
		}
	}
}

// A lookup has its own deadline, and a failed one never names the
// resolver's address.
func TestLookupDeadlineAndErrors(t *testing.T) {
	hang := func(ctx context.Context, _ string) ([]Answer, error) {
		<-ctx.Done()
		return nil, &net.DNSError{Err: "i/o timeout", Name: "slow.test", Server: "172.17.0.1:53", IsTimeout: true}
	}
	p := New(nil, Options{Resolve: hang, LookupTimeout: 200 * time.Millisecond})
	start := time.Now()
	_, err := p.Lookup(context.Background(), "slow.test")
	var dns *net.DNSError
	if !errors.As(err, &dns) || !dns.IsTimeout || dns.Server != "" || strings.Contains(err.Error(), "172.17.0.1") || time.Since(start) > time.Second {
		t.Errorf("a hung lookup: %v after %s", err, time.Since(start))
	}
	if c, _ := p.Check(context.Background(), "https://slow.test/", nil); c.Outcome != "unresolved" || c.Error != "EAI_AGAIN" {
		t.Errorf("check of a hung name: %+v", c)
	}
	refused := New(nil, Options{Resolve: func(context.Context, string) ([]Answer, error) {
		return nil, &net.DNSError{Err: "server misbehaving", Name: "x.test", Server: "172.17.0.1:53"}
	}})
	if _, err := refused.Lookup(context.Background(), "x.test"); err == nil || strings.Contains(err.Error(), "172.17.0.1") || !strings.Contains(err.Error(), "no such host") {
		t.Errorf("a resolver error: %v", err)
	}
	if _, err := get(refused.Client(Webhook), "https://x.test/"); err == nil || strings.Contains(err.Error(), "172.17.0.1") {
		t.Errorf("a request's resolver error: %v", err)
	}
}

// The transport refuses a redirect even under a client of the caller's
// that would follow one.
func TestTransportRefusesRedirects(t *testing.T) {
	target, hits := counting(t, nil)
	redirect, _ := counting(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/elsewhere", http.StatusFound)
	})
	dns := &fakeDNS{answers: map[string][]Answer{}, asked: map[string]int{}}
	c := &http.Client{Transport: policyOf(t, "127.0.0.1/32:*", dns, nil).Transport(AuditExport)}
	if _, err := get(c, redirect.URL+"/x"); err == nil || !errors.Is(err, errRedirect) || hits.Load() != 0 {
		t.Fatalf("a redirect through the transport: %v, %d requests to its target", err, hits.Load())
	}
}

// The Control hook refuses a socket to any address the dial did not check,
// whatever made the dialer try it, and allows the checked ones in the
// forms a socket names them (a mapped address as IPv4, a zone dropped).
func TestControlRefusesUncheckedAddresses(t *testing.T) {
	control := checkedControl([]Answer{v4("192.0.2.1"), v6("2001:db8::1"), v6("::ffff:198.51.100.7"), v6("fe80::1%eth0")})
	for _, address := range []string{"192.0.2.1:443", "[2001:db8::1]:443", "198.51.100.7:443", "[::ffff:192.0.2.1]:443", "[fe80::1%eth1]:443"} {
		if err := control("tcp", address, nil); err != nil {
			t.Errorf("%s: %v", address, err)
		}
	}
	for _, address := range []string{"192.0.2.2:443", "10.0.0.1:443", "[2001:db8::2]:443", "127.0.0.1:443", "[::1]:443", "192.0.2.1", "not an address"} {
		if err := control("tcp", address, nil); err == nil || !strings.Contains(err.Error(), "unchecked address") {
			t.Errorf("%s: %v, want a refusal", address, err)
		}
	}
}

// Each attempt's context is released when the attempt ends, not when the
// dial returns: a failed attempt's timer does not live on beside the next.
func TestAttemptContextsReleased(t *testing.T) {
	var mu sync.Mutex
	var ended []bool
	var previous context.Context
	refuse := func(ctx context.Context, _, _ string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if previous != nil {
			ended = append(ended, previous.Err() != nil)
		}
		previous = ctx
		return nil, errors.New("connection refused")
	}
	dns := &fakeDNS{answers: map[string][]Answer{}, asked: map[string]int{}}
	dns.set("refused.test", v4("192.0.2.1"), v4("192.0.2.2"), v4("192.0.2.3"))
	entries, _ := ParseAllow("192.0.2.0/24:*")
	p := New(entries, Options{Resolve: dns.resolve, ConnectTimeout: 5 * time.Second, Dial: refuse})
	t.Cleanup(p.Close)
	if _, err := p.dialer("https:")(context.Background(), "tcp", "refused.test:443"); err == nil {
		t.Fatal("connected")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(ended) != 2 || !ended[0] || !ended[1] || previous.Err() == nil {
		t.Errorf("attempt contexts ended %v, the last %v", ended, previous.Err())
	}
}
