// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// The browser endpoint's certificate (ADR-0046 Decision 3, cert.ts): the
// node's own Let's Encrypt pair, which the node obtains through Tailscale's
// control plane (MagicDNS and HTTPS certificates on in the tailnet). The
// pair is fetched at start and daily, sooner after a failure. One that
// does not name the host, is not valid now, or whose key does not match
// is never swapped in. When renewal keeps failing the last valid
// certificate serves until it expires; after that Current is nil and the
// endpoint refuses every handshake.

// CertSource gives the node's certificate pair for a name: TSNode, or a
// stand-in in tests (a real pair needs Let's Encrypt).
type CertSource interface {
	CertPair(ctx context.Context, domain string, minValidity time.Duration) (certPEM, keyPEM []byte, err error)
}

// CertPair is the local API's certificate pair (the key never leaves the
// process, apart from the node's own cache in its state directory).
func (n *TSNode) CertPair(ctx context.Context, domain string, minValidity time.Duration) ([]byte, []byte, error) {
	return n.lc.CertPairWithValidity(ctx, domain, minValidity)
}

const (
	hour = time.Hour
	day  = 24 * hour
	// fetchTimeout: an ACME order (first issuance or renewal) takes far
	// longer than other local API calls.
	fetchTimeout = 180 * time.Second
	retryFirst   = 30 * time.Second
)

// loadedCert is a pair in use, for the host it names.
type loadedCert struct {
	host                string
	cert                *tls.Certificate
	notBefore, notAfter time.Time
}

// DecodePair checks a pair for host at now: one key, a chain whose every
// certificate parses, whose leaf names host exactly (no wildcard, never
// the subject) and is valid now, and the key matching it. A non-empty
// reason says why it cannot be used.
func DecodePair(certPEM, keyPEM []byte, host string, now time.Time) (*tls.Certificate, time.Time, time.Time, string) {
	var zero time.Time
	keys, chain := 0, 0
	for rest := append(append([]byte{}, keyPEM...), certPEM...); ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		switch {
		case strings.HasSuffix(b.Type, "PRIVATE KEY"):
			keys++
		case b.Type == "CERTIFICATE":
			chain++
		}
	}
	if keys != 1 || chain == 0 {
		return nil, zero, zero, "the answer is not one key with a certificate"
	}
	// Every certificate of the chain: tls.X509KeyPair parses the leaf only,
	// and a chain a client cannot read must never replace a working pair.
	var chainCerts []*x509.Certificate
	for rest := certPEM; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			if len(chainCerts) == 0 {
				return nil, zero, zero, "the certificate does not parse"
			}
			return nil, zero, zero, "a certificate of its chain does not parse"
		}
		chainCerts = append(chainCerts, cert)
	}
	if len(chainCerts) == 0 {
		return nil, zero, zero, "the answer is not one key with a certificate"
	}
	leaf := chainCerts[0]
	if !namesExactly(leaf, host) {
		return nil, zero, zero, "the certificate does not name " + host
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, zero, zero, "the certificate is not valid now"
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		if strings.Contains(err.Error(), "does not match") {
			return nil, zero, zero, "the key does not match the certificate"
		}
		return nil, zero, zero, "the key does not parse"
	}
	pair.Leaf = leaf
	return &pair, leaf.NotBefore, leaf.NotAfter, ""
}

// namesExactly: one of the leaf's DNS names is host, letter case aside.
func namesExactly(leaf *x509.Certificate, host string) bool {
	for _, n := range leaf.DNSNames {
		if strings.EqualFold(strings.TrimSuffix(n, "."), host) {
			return true
		}
	}
	return false
}

// Certificate keeps the browser endpoint's certificate for the host host
// names (the node's MagicDNS name; "" while it is not known).
type Certificate struct {
	src      CertSource
	host     func() string
	now      func() time.Time
	log      *slog.Logger
	onChange func()

	// wake asks Run to fetch now: the host changed (Wake).
	wake chan struct{}

	mu         sync.Mutex
	loaded     *loadedCert
	lastError  string
	failures   int
	inFlight   chan struct{}
	inFlightOK bool
}

// NewCertificate keeps host's certificate from src; onChange hears of every
// pair swapped in, so the report need not wait for its next round.
func NewCertificate(src CertSource, host func() string, log *slog.Logger, now func() time.Time, onChange func()) *Certificate {
	if log == nil {
		log = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	if onChange == nil {
		onChange = func() {}
	}
	return &Certificate{src: src, host: host, now: now, log: log, onChange: onChange, wake: make(chan struct{}, 1)}
}

// Wake makes Run fetch at once instead of at its next round: the host
// changed (enrolment, a re-pin, an adoption), so the loaded pair no longer
// serves and the new host's is needed now.
func (c *Certificate) Wake() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Current is what to serve now: nil while no valid certificate for the
// current host is loaded, and the handshake is then refused.
func (c *Certificate) Current() *tls.Certificate { return c.CurrentFor(c.host()) }

// CurrentFor is Current for a host the caller already knows (the manager,
// under its own lock).
func (c *Certificate) CurrentFor(host string) *tls.Certificate {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	l := c.loaded
	if l == nil || host == "" || l.host != host || now.Before(l.notBefore) || !now.Before(l.notAfter) {
		return nil
	}
	return l.cert
}

// NotAfter is when the certificate in use expires (zero before one loads).
func (c *Certificate) NotAfter() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loaded == nil {
		return time.Time{}
	}
	return c.loaded.notAfter
}

// LastError is why the last fetch was not used ("" after a success).
func (c *Certificate) LastError() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastError
}

// Run fetches now, then keeps refreshing until ctx ends: daily, hourly in
// a certificate's last two days, and after a failure from 30 seconds,
// doubling, to an hour; at once when woken (Wake).
func (c *Certificate) Run(ctx context.Context) {
	for {
		ok := c.Refresh(ctx)
		t := time.NewTimer(c.nextDelay(ok))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-c.wake:
			t.Stop()
		}
	}
}

func (c *Certificate) nextDelay(ok bool) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ok {
		c.failures = 0
		if c.loaded.notAfter.Sub(c.now()) < 2*day {
			return hour
		}
		return day
	}
	c.failures++
	return min(hour, retryFirst<<min(c.failures-1, 7))
}

// minValidity asks the node to renew early: once a lifetime is known, the
// pair must stay valid for a third of it (at most a week), so a daily
// fetch renews well before expiry without asking for more than a fresh
// certificate could give, which would renew on every fetch.
func (c *Certificate) minValidity() time.Duration {
	if c.loaded == nil {
		return 0
	}
	lifetime := c.loaded.notAfter.Sub(c.loaded.notBefore)
	return max(hour, min(7*day, lifetime/3).Truncate(hour))
}

// Refresh fetches once and swaps in a valid pair; concurrent callers share
// the fetch. It reports whether a valid pair is now loaded from this fetch.
func (c *Certificate) Refresh(ctx context.Context) bool {
	c.mu.Lock()
	if ch := c.inFlight; ch != nil {
		c.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return false
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.inFlightOK
	}
	ch := make(chan struct{})
	c.inFlight = ch
	minValidity := c.minValidity()
	c.mu.Unlock()

	ok := c.fetch(ctx, minValidity)

	c.mu.Lock()
	c.inFlight, c.inFlightOK = nil, ok
	c.mu.Unlock()
	close(ch)
	return ok
}

func (c *Certificate) fetch(ctx context.Context, minValidity time.Duration) bool {
	host := c.host()
	var reason string
	var pair *tls.Certificate
	var notBefore, notAfter time.Time
	if host == "" {
		reason = "the node's name is not known yet"
	} else {
		fctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		certPEM, keyPEM, err := c.src.CertPair(fctx, host, minValidity)
		cancel()
		if err != nil {
			reason = refusal(err)
		} else {
			pair, notBefore, notAfter, reason = DecodePair(certPEM, keyPEM, host, c.now())
		}
	}
	c.mu.Lock()
	if reason != "" {
		if reason != c.lastError {
			// Once per distinct reason: retries must not flood the log.
			c.log.Warn("tailnet browser endpoint certificate not loaded", "host", host, "reason", reason)
		}
		c.lastError = reason
		c.mu.Unlock()
		return false
	}
	replaced := c.loaded
	c.loaded = &loadedCert{host: host, cert: pair, notBefore: notBefore, notAfter: notAfter}
	c.lastError = ""
	changed := replaced == nil || replaced.host != host || !replaced.notAfter.Equal(notAfter)
	c.mu.Unlock()
	if changed {
		c.log.Info("tailnet browser endpoint certificate loaded", "host", host, "notAfter", notAfter.UTC().Format(time.RFC3339))
		c.onChange()
	}
	return true
}

// refusal is why the node gave no pair. Only the error's first line is
// kept: whatever else it holds stays out of the log and the report.
func refusal(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "no answer from the node within " + fetchTimeout.String()
	}
	msg, _, _ := strings.Cut(err.Error(), "\n")
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return fmt.Sprintf("the node gave no certificate (%s)", msg)
}

// TLSConfig is the browser endpoint's TLS (listener.ts): TLS 1.2 at
// least, only host's name (a handshake for another name, without SNI, or
// while no valid certificate is loaded is refused), and no session ever
// resumed (a resumed handshake would skip those checks): tickets are off,
// and a connection that resumed anyway, or completed without a valid
// certificate, fails before a request is read.
func (c *Certificate) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
		NextProtos:             []string{"http/1.1"},
		// The name is checked against one reading of the host, and the
		// certificate taken for that same host.
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := c.host()
			if host == "" || !strings.EqualFold(hello.ServerName, host) {
				return nil, errors.New("unknown server name")
			}
			cert := c.CurrentFor(host)
			if cert == nil {
				return nil, errors.New("no valid certificate")
			}
			return cert, nil
		},
		// Again once the handshake is done: the host may have changed (a
		// re-pin) since the certificate was chosen, and a handshake for the
		// old name never serves a request.
		VerifyConnection: func(cs tls.ConnectionState) error {
			host := c.host()
			if cs.DidResume || host == "" || !strings.EqualFold(cs.ServerName, host) || c.CurrentFor(host) == nil {
				return errors.New("refused: a resumed session, a name that is not the endpoint's now, or no valid certificate")
			}
			return nil
		},
	}
}
