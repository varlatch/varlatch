// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/tailnet/tailnettest"
)

const certHost = "varlatch.corp.ts.net"

func newCA(t *testing.T) *tailnettest.CA {
	t.Helper()
	ca, err := tailnettest.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// A pair is used only when it is one key with a chain whose leaf names the
// host exactly, is valid now, and matches the key (cert.ts's decodePair).
func TestDecodePair(t *testing.T) {
	ca := newCA(t)
	now := time.Now()
	good := func(names ...string) ([]byte, []byte) {
		c, k, err := ca.Issue(names, now.Add(-time.Hour), now.Add(24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return c, k
	}
	certPEM, keyPEM := good(certHost)
	if pair, nb, na, reason := DecodePair(certPEM, keyPEM, certHost, now); reason != "" || pair == nil || !nb.Before(now) || !na.After(now) {
		t.Fatalf("a good pair: %q", reason)
	}
	if _, _, _, reason := DecodePair(certPEM, keyPEM, "VARLATCH.corp.ts.net", now); reason != "" {
		t.Errorf("the host's letter case: %q", reason)
	}
	_, otherKey := good(certHost)
	wildcard, wildcardKey := good("*.corp.ts.net")
	other, otherHostKey := good("other.corp.ts.net")
	for name, c := range map[string]struct {
		cert, key []byte
		at        time.Time
		want      string
	}{
		"no key":           {certPEM, nil, now, "the answer is not one key with a certificate"},
		"two keys":         {certPEM, append(append([]byte{}, keyPEM...), otherKey...), now, "the answer is not one key with a certificate"},
		"no certificate":   {nil, keyPEM, now, "the answer is not one key with a certificate"},
		"garbage":          {[]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), keyPEM, now, "the certificate does not parse"},
		"another host":     {other, otherHostKey, now, "the certificate does not name " + certHost},
		"a wildcard":       {wildcard, wildcardKey, now, "the certificate does not name " + certHost},
		"not yet valid":    {certPEM, keyPEM, now.Add(-2 * time.Hour), "the certificate is not valid now"},
		"expired":          {certPEM, keyPEM, now.Add(25 * time.Hour), "the certificate is not valid now"},
		"a key of another": {certPEM, otherKey, now, "the key does not match the certificate"},
	} {
		if _, _, _, reason := DecodePair(c.cert, c.key, certHost, c.at); reason != c.want {
			t.Errorf("%s: %q, want %q", name, reason, c.want)
		}
	}
	// The subject's common name alone never names the host.
	cnOnly, cnKey, err := ca.Issue(nil, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, reason := DecodePair(cnOnly, cnKey, certHost, now); reason != "the certificate does not name "+certHost {
		t.Errorf("no DNS names: %q", reason)
	}
}

// clock is a settable clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// The last valid certificate serves while renewal fails, until it
// expires; a pair for another host is never served; renewal asks for a
// third of the lifetime; the refresh pace follows cert.ts.
func TestCertificateKeepsTheLastValidPair(t *testing.T) {
	ctx := context.Background()
	ca := newCA(t)
	clk := &clock{t: time.Now()}
	ca.Now = clk.now
	host := certHost
	var hostMu sync.Mutex
	changes := 0
	c := NewCertificate(ca, func() string { hostMu.Lock(); defer hostMu.Unlock(); return host }, nil, clk.now, func() { changes++ })
	if c.Current() != nil || !c.NotAfter().IsZero() {
		t.Fatal("a certificate before the first fetch")
	}
	if !c.Refresh(ctx) || c.Current() == nil || c.LastError() != "" || changes != 1 {
		t.Fatalf("the first fetch: %q, %d changes", c.LastError(), changes)
	}
	if d := c.nextDelay(true); d != day {
		t.Errorf("after a success: %s", d)
	}
	ca.Fail = tailnettest.ErrUnavailable
	if c.Refresh(ctx) || c.Current() == nil || c.LastError() != "the node gave no certificate (500 Internal Server Error: the certificate is not available)" {
		t.Fatalf("a failed renewal must keep the valid pair: %q", c.LastError())
	}
	for i, want := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, hour, hour} {
		if d := c.nextDelay(false); d != want {
			t.Errorf("failure %d: %s, want %s", i+1, d, want)
		}
	}
	// 90 days: renewal asks for a third of it, at most a week.
	ca.Fail = nil
	c.Refresh(ctx)
	reqs := ca.Requested()
	if got := reqs[len(reqs)-1]; got.Domain != certHost || got.MinValidity != 7*day {
		t.Errorf("the renewal's request: %+v", got)
	}
	clk.add(88 * day)
	if d := c.nextDelay(true); d != hour {
		t.Errorf("in its last two days: %s", d)
	}
	ca.Fail = errors.New("429 Too Many Requests\nretry later, with details on a second line")
	c.Refresh(ctx)
	if c.LastError() != "the node gave no certificate (429 Too Many Requests)" {
		t.Errorf("only the first line of an error: %q", c.LastError())
	}
	clk.add(2 * day)
	if c.Current() != nil {
		t.Fatal("an expired certificate is served")
	}
	// The name changed (a re-pin): the old pair is never served.
	ca.Fail = nil
	c.Refresh(ctx)
	hostMu.Lock()
	host = "varlatch.renamed.ts.net"
	hostMu.Unlock()
	if c.Current() != nil {
		t.Fatal("a pair for the old name is served")
	}
	c.Refresh(ctx)
	if cur := c.Current(); cur == nil || cur.Leaf.DNSNames[0] != "varlatch.renamed.ts.net" {
		t.Fatal("no pair for the new name")
	}
}

// slowSource blocks every fetch until released, and counts them.
type slowSource struct {
	ca      *tailnettest.CA
	release chan struct{}
	calls   atomic.Int32
}

func (s *slowSource) CertPair(ctx context.Context, domain string, minValidity time.Duration) ([]byte, []byte, error) {
	s.calls.Add(1)
	<-s.release
	return s.ca.CertPair(ctx, domain, minValidity)
}

// Concurrent refreshes share one fetch.
func TestRefreshesShareAFetch(t *testing.T) {
	src := &slowSource{ca: newCA(t), release: make(chan struct{})}
	c := NewCertificate(src, func() string { return certHost }, nil, nil, nil)
	var wg sync.WaitGroup
	var ok atomic.Int32
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.Refresh(context.Background()) {
				ok.Add(1)
			}
		}()
	}
	for src.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(src.release)
	wg.Wait()
	if src.calls.Load() != 1 || ok.Load() != 5 {
		t.Fatalf("%d fetches, %d successes", src.calls.Load(), ok.Load())
	}
}

// handshake runs a TLS handshake against c's configuration on a pipe.
func handshake(t *testing.T, c *Certificate, client *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	sc, cc := net.Pipe()
	srv := tls.Server(sc, c.TLSConfig())
	done := make(chan error, 1)
	go func() { done <- srv.Handshake(); _ = sc.Close() }()
	cl := tls.Client(cc, client)
	err := cl.Handshake()
	state := cl.ConnectionState()
	if err == nil {
		// TLS 1.3 sends its tickets after the handshake: read them.
		_ = cl.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		_, _ = cl.Read(make([]byte, 1))
	}
	_ = cc.Close()
	if serr := <-done; err == nil {
		err = serr
	}
	return state, err
}

// The endpoint answers only as its host, only with a valid certificate,
// TLS 1.2 at least, and never resumes a session.
func TestBrowserTLS(t *testing.T) {
	ca := newCA(t)
	c := NewCertificate(ca, func() string { return certHost }, nil, nil, nil)
	client := func() *tls.Config { return &tls.Config{RootCAs: ca.Pool, ServerName: certHost} }
	if _, err := handshake(t, c, client()); err == nil {
		t.Fatal("a handshake without a certificate loaded")
	}
	if !c.Refresh(context.Background()) {
		t.Fatal(c.LastError())
	}
	if st, err := handshake(t, c, client()); err != nil || st.Version < tls.VersionTLS12 {
		t.Fatalf("the host's handshake: %v", err)
	}
	other := client()
	other.ServerName, other.InsecureSkipVerify = "other.corp.ts.net", true
	if _, err := handshake(t, c, other); err == nil {
		t.Error("a handshake for another name")
	}
	noSNI := &tls.Config{InsecureSkipVerify: true}
	if _, err := handshake(t, c, noSNI); err == nil {
		t.Error("a handshake without a server name")
	}
	old := client()
	old.MaxVersion = tls.VersionTLS11
	if _, err := handshake(t, c, old); err == nil {
		t.Error("a TLS 1.1 handshake")
	}
	for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		resuming := client()
		resuming.MinVersion, resuming.MaxVersion = v, v
		resuming.ClientSessionCache = tls.NewLRUClientSessionCache(4)
		for i := range 2 {
			st, err := handshake(t, c, resuming)
			if err != nil || st.DidResume {
				t.Fatalf("TLS %x, connection %d: resumed %v, %v", v, i+1, st.DidResume, err)
			}
		}
	}
}

// #224 review P2 (cert.go:100): a pair whose chain holds a certificate that
// does not parse is refused, and the working pair stays in service.
func TestAMalformedChainNeverReplacesAWorkingPair(t *testing.T) {
	ca := newCA(t)
	now := time.Now()
	certPEM, keyPEM, err := ca.Issue([]string{certHost}, now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	bad := append(append([]byte{}, certPEM...), []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")...)
	if _, _, _, reason := DecodePair(bad, keyPEM, certHost, now); reason != "a certificate of its chain does not parse" {
		t.Fatalf("a bad intermediate: %q", reason)
	}
	src := &badChain{ca: ca}
	c := NewCertificate(src, func() string { return certHost }, nil, nil, nil)
	if !c.Refresh(context.Background()) {
		t.Fatal(c.LastError())
	}
	good := c.Current()
	src.bad = true
	if c.Refresh(context.Background()) || c.Current() != good || c.LastError() != "a certificate of its chain does not parse" {
		t.Fatalf("a bad chain replaced the working pair: %q", c.LastError())
	}
}

// badChain is the CA, its chain spoiled on demand.
type badChain struct {
	ca  *tailnettest.CA
	bad bool
}

func (b *badChain) CertPair(ctx context.Context, domain string, minValidity time.Duration) ([]byte, []byte, error) {
	certPEM, keyPEM, err := b.ca.CertPair(ctx, domain, minValidity)
	if b.bad {
		certPEM = append(certPEM, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")...)
	}
	return certPEM, keyPEM, err
}

// #224 review P2 (cert.go:332): a handshake made for the old name is
// refused once the host changed (a re-pin), even when a certificate for
// the new name is loaded meanwhile; the name is checked and the
// certificate chosen from one reading of the host.
func TestAHandshakeForTheOldNameAfterARepin(t *testing.T) {
	ca := newCA(t)
	var mu sync.Mutex
	host := "varlatch.corp.ts.net"
	c := NewCertificate(ca, func() string { mu.Lock(); defer mu.Unlock(); return host }, nil, nil, nil)
	if !c.Refresh(context.Background()) {
		t.Fatal(c.LastError())
	}
	cfg := c.TLSConfig()
	chosen, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "varlatch.corp.ts.net"})
	if err != nil || chosen.Leaf.DNSNames[0] != "varlatch.corp.ts.net" {
		t.Fatalf("the old name's certificate: %v", err)
	}
	// The host changes and the new name's pair loads after the choice.
	mu.Lock()
	host = "varlatch.renamed.ts.net"
	mu.Unlock()
	if !c.Refresh(context.Background()) {
		t.Fatal(c.LastError())
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{ServerName: "varlatch.corp.ts.net"}); err == nil {
		t.Fatal("a handshake for the old name was accepted after the host changed")
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{ServerName: "varlatch.renamed.ts.net"}); err != nil {
		t.Fatalf("a handshake for the new name: %v", err)
	}
	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "varlatch.corp.ts.net"}); err == nil {
		t.Fatal("the old name is still served")
	}
}

// #224 review P2 (cert.go:193): when the host changes (enrolment, a
// re-pin), the new host's certificate is fetched at once, not at the next
// daily round.
func TestARepinFetchesTheNewHostsCertificate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca := newCA(t)
	status := &statusNode{st: Status{BackendState: "NeedsLogin"}}
	m := enrolling(t, status, "", t.TempDir(), nil)
	m.SetBrowser("varlatch", 8443)
	c := NewCertificate(ca, m.BrowserHost, nil, nil, nil)
	m.SetCertificate(c)
	go c.Run(ctx)
	waitFor := func(host string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if cur := c.Current(); cur != nil && cur.Leaf.DNSNames[0] == host {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("no certificate for %s within 5 s: %q", host, c.LastError())
	}
	// Enrolment: the host becomes known after Run's first, failed fetch.
	status.set(running("Tabc123", "corp.ts.net"), nil)
	m.Check(ctx)
	waitFor("varlatch.corp.ts.net")
	status.set(running("Tabc123", "corp-new.ts.net"), nil)
	m.Check(ctx)
	if _, _, err := m.Repin(ctx, false, nil); err != nil {
		t.Fatal(err)
	}
	waitFor("varlatch.corp-new.ts.net")
}
