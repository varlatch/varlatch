// SPDX-License-Identifier: AGPL-3.0-or-later

// Package publictls is varlatchd's public HTTPS (ADR-0059 Decision 5; step
// 6, slice 6.3a): one certificate, for the public URL's host name, obtained
// and renewed over ACME (HTTP-01 and TLS-ALPN-01) with certmagic, kept in
// the data directory, and served on the HTTPS listener.
//
// certmagic is the ACME client and the certificate store only. The
// schedule is this package's: when to obtain, when to renew (a third of
// the certificate's lifetime before it ends), and how long to wait after a
// failure (Backoff), so that the state it reports (Report) is what it
// does, and the tests can run it in seconds. certmagic's own certificate
// cache and its on-demand issuance are not used: the handshake is served
// from the one certificate this package loaded, and a handshake for any
// other name is refused.
//
// What stays private: the ACME account key and the certificate's private
// key are files in <data dir>/acme (directories 0700, files 0600, as
// certmagic's file storage writes them; Manager checks the directory at
// start). They are never logged, never in the environment, and never in a
// backup archive, which holds the database and the settings only: a
// restored installation obtains its certificate again.
package publictls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"

	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// StorageDir is the ACME store's directory in the data directory.
const StorageDir = "acme"

// LetsEncrypt is the default certificate authority's directory.
const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// DefaultCheckInterval is how often the certificate is looked at when
// nothing is due sooner.
const DefaultCheckInterval = 10 * time.Minute

// DefaultBackoff is the wait after each failed attempt in a row; the last
// one repeats. Close to certmagic's own schedule, without its 30-day cap:
// varlatchd keeps trying while it runs, and reports each failure.
var DefaultBackoff = []time.Duration{
	time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute,
	20 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 6 * time.Hour,
}

// RenewalRatio is the part of a certificate's lifetime left when it is
// renewed (certmagic's default, and Let's Encrypt's advice for 90 days).
const RenewalRatio = 1.0 / 3

// Options configure a Manager.
type Options struct {
	// Host is the certificate's one name: the public URL's host.
	Host string
	// CA is the ACME directory URL.
	CA string
	// CARoots, when not nil, are the roots trusted for the CA's own API
	// (acme_ca_root: a private CA, or Pebble in tests); nil is the
	// system's.
	CARoots *x509.CertPool
	// Email is the ACME account's contact; "" registers without one.
	Email string
	// DataDir is the data directory; the store is DataDir/acme.
	DataDir string
	// HTTPPort is the port HTTP-01 challenges are answered on (the
	// redirect listener's); 0 turns HTTP-01 off.
	HTTPPort int
	// TLSPort is the HTTPS listener's port, where TLS-ALPN-01 challenges
	// are answered.
	TLSPort int
	// ListenHost is the listeners' host ("" for every address), so that
	// certmagic sees them bound and starts no challenge server of its own.
	ListenHost string
	// Log is varlatchd's log.
	Log *slog.Logger
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// CheckInterval and Backoff: tests shorten them.
	CheckInterval time.Duration
	Backoff       []time.Duration
	// Issuances keeps the issuance count (count.go); nil keeps none.
	Issuances Issuances
	// IssuanceLimit is the most attempts for the name in IssuanceWindow
	// (LimitFor the CA); 0 is no limit.
	IssuanceLimit int
}

// Manager keeps the public certificate.
type Manager struct {
	o      Options
	cache  *certmagic.Cache
	cm     *certmagic.Config
	issuer *certmagic.ACMEIssuer

	current atomic.Pointer[loaded]
	wake    chan struct{}

	mu    sync.Mutex
	state state
}

// loaded is the certificate served, and its leaf.
type loaded struct {
	cert *tls.Certificate
	leaf *x509.Certificate
}

// state is what Report shows.
type state struct {
	attempting  bool
	lastAttempt time.Time
	lastSuccess time.Time
	lastError   string
	failures    int
	nextAttempt time.Time
}

// New makes a Manager: the store's directory is made (0700) or checked
// (a directory, not reachable by others), nothing is fetched yet.
func New(o Options) (*Manager, error) {
	if o.Host == "" || o.CA == "" || o.DataDir == "" || o.TLSPort <= 0 {
		return nil, errors.New("publictls: a host, a CA, a data directory and the HTTPS port are needed")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.CheckInterval <= 0 {
		o.CheckInterval = DefaultCheckInterval
	}
	if len(o.Backoff) == 0 {
		o.Backoff = DefaultBackoff
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	dir := filepath.Join(o.DataDir, StorageDir)
	if err := privateDir(dir); err != nil {
		return nil, err
	}
	zlog := zap.New(newSlogCore(o.Log.With("component", "acme")))
	m := &Manager{o: o, wake: make(chan struct{}, 1)}
	m.cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return m.cm, nil },
		// Nothing is ever cached as managed; the cache's maintenance has
		// nothing to do, so it looks rarely.
		RenewCheckInterval: 24 * time.Hour,
		OCSPCheckInterval:  24 * time.Hour,
		Logger:             zlog,
	})
	m.cm = certmagic.New(m.cache, certmagic.Config{
		Storage:            &certmagic.FileStorage{Path: dir},
		Logger:             zlog,
		OCSP:               certmagic.OCSPConfig{DisableStapling: true},
		DisableARI:         true,
		RenewalWindowRatio: RenewalRatio,
	})
	m.issuer = certmagic.NewACMEIssuer(m.cm, certmagic.ACMEIssuer{
		CA:           o.CA,
		Email:        o.Email,
		Agreed:       true,
		TrustedRoots: o.CARoots,
		// Challenges are answered by this process only: from memory, never
		// from the store (a request names a host; the store is not looked
		// up by what a request says), and never blindly.
		DisableDistributedSolvers: true,
		DisableHTTPChallenge:      o.HTTPPort == 0,
		AltHTTPPort:               o.HTTPPort,
		AltTLSALPNPort:            o.TLSPort,
		ListenHost:                o.ListenHost,
		Logger:                    zlog,
	})
	// certmagic's pre-check never asks: a synchronous obtain is
	// "interactive" to it, and with no email it would print a question on
	// stdout and read stdin. varlatchd is a service: without acme_email the
	// account is registered without a contact, which is said once here.
	m.cm.Issuers = []certmagic.Issuer{nonInteractive{m.issuer}}
	if o.Email == "" {
		o.Log.Info("acme_email is not set: the ACME account is registered without a contact address, so the CA cannot send expiry notices", "host", o.Host)
	}
	return m, nil
}

// nonInteractive is the ACME issuer with its pre-check never interactive:
// no prompt for an email address or the CA's terms, ever (Agreed is set).
type nonInteractive struct{ *certmagic.ACMEIssuer }

// PreCheck is the issuer's, with interactive always false.
func (n nonInteractive) PreCheck(ctx context.Context, names []string, _ bool) error {
	return n.ACMEIssuer.PreCheck(ctx, names, false)
}

// privateDir makes dir (0700), or checks the one there: a directory (not
// a symbolic link) that neither its group nor others may enter.
func privateDir(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("publictls: cannot make %s: %w", dir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("publictls: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("publictls: %s is not a directory", dir)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("publictls: %s may be read by others (mode %04o); it holds private keys: make it 0700", dir, info.Mode().Perm())
	}
	return nil
}

// Close stops certmagic's cache.
func (m *Manager) Close() { m.cache.Stop() }

// Run obtains the certificate, then keeps it renewed, until ctx ends. A
// certificate already in the store is served at once. An attempt that ctx
// cut short is due again at once (it records no failure), so ctx is looked
// at before each one.
func (m *Manager) Run(ctx context.Context) {
	if err := m.load(ctx); err != nil && !errors.Is(err, fs.ErrNotExist) {
		m.o.Log.Warn("the stored public certificate could not be loaded; obtaining a new one", "host", m.o.Host, "error", oneLine(err))
	}
	for ctx.Err() == nil {
		wait := m.due(m.o.Now())
		if wait <= 0 {
			m.attempt(ctx)
			continue
		}
		t := time.NewTimer(min(wait, m.o.CheckInterval))
		select {
		case <-ctx.Done():
		case <-m.wake:
		case <-t.C:
		}
		t.Stop()
	}
}

// due is how long until the next attempt: 0 or less when one is due now.
func (m *Manager) due(now time.Time) time.Duration {
	m.mu.Lock()
	next := m.state.nextAttempt
	m.mu.Unlock()
	if l := m.current.Load(); l != nil && !m.renewalDue(l.leaf, now) {
		return renewAt(l.leaf).Sub(now)
	}
	return next.Sub(now)
}

// renewalDue is whether leaf is in its last third (or over).
func (m *Manager) renewalDue(leaf *x509.Certificate, now time.Time) bool {
	return !now.Before(renewAt(leaf))
}

// renewAt is when leaf enters its renewal window.
func renewAt(leaf *x509.Certificate) time.Time {
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	return leaf.NotAfter.Add(-time.Duration(float64(lifetime) * RenewalRatio))
}

// attempt obtains or renews once, then loads what the store holds.
func (m *Manager) attempt(ctx context.Context) {
	now := m.o.Now()
	m.mu.Lock()
	m.state.attempting, m.state.lastAttempt = true, now
	m.mu.Unlock()
	var err error
	// A certificate in the store (served, or expired and no longer) is
	// renewed; certmagic's obtain would see it there and do nothing.
	renewing := m.current.Load() != nil || m.cm.Storage.Exists(ctx, certmagic.StorageKeys.SiteCert(m.issuer.IssuerKey(), m.o.Host))
	// The issuance count: the attempt is recorded before the CA is asked,
	// and refused, without asking, when it would pass the limit.
	issuance, until, err := m.beginIssuance(ctx, now)
	if err == nil && until.IsZero() {
		if renewing {
			err = m.cm.RenewCertSync(ctx, m.o.Host, true)
		} else {
			err = m.cm.ObtainCertSync(ctx, m.o.Host)
		}
		m.endIssuance(issuance, err)
		if err == nil {
			err = m.load(ctx)
		}
	}
	if !until.IsZero() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.state.attempting = false
		m.state.failures++
		m.state.lastError = fmt.Sprintf("the issuance count: %d certificates for %s in %s, Let's Encrypt's limit; varlatchd asks again from %s",
			m.o.IssuanceLimit, m.o.Host, "7 days", until.UTC().Format(time.RFC3339))
		m.state.nextAttempt = until
		m.o.Log.Warn("the public certificate is not asked for: the issuance count is at its limit", "host", m.o.Host,
			"limit", m.o.IssuanceLimit, "until", until.UTC().Format(time.RFC3339))
		return
	}
	if ctx.Err() != nil {
		m.mu.Lock()
		m.state.attempting = false
		m.mu.Unlock()
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.attempting = false
	if err != nil {
		m.failedLocked(err)
		return
	}
	m.state.failures, m.state.lastError, m.state.nextAttempt, m.state.lastSuccess = 0, "", time.Time{}, m.o.Now()
	l := m.current.Load()
	msg := "the public certificate was obtained"
	if renewing {
		msg = "the public certificate was renewed"
	}
	m.o.Log.Info(msg, "host", m.o.Host, "notAfter", l.leaf.NotAfter.UTC().Format(time.RFC3339), "issuer", l.leaf.Issuer.CommonName)
}

// beginIssuance records an attempt; until is not zero when the count is at
// its limit (the attempt is then not recorded, nor made): the time the
// oldest counted attempt leaves the window.
func (m *Manager) beginIssuance(ctx context.Context, now time.Time) (id int64, until time.Time, err error) {
	if m.o.Issuances == nil {
		return -1, time.Time{}, nil
	}
	n, oldest, err := m.o.Issuances.Count(ctx, strings.ToLower(m.o.Host), now.Add(-IssuanceWindow))
	if err != nil {
		return -1, time.Time{}, fmt.Errorf("the issuance count cannot be read: %w", err)
	}
	if m.o.IssuanceLimit > 0 && n >= m.o.IssuanceLimit {
		// An hour past the week: the CA's own window may end a little
		// after this installation's clock says.
		return -1, oldest.Add(IssuanceWindow + IssuanceSlack), nil
	}
	id, err = m.o.Issuances.Begin(ctx, strings.ToLower(m.o.Host), now)
	if err != nil {
		return -1, time.Time{}, fmt.Errorf("the issuance count cannot be recorded: %w", err)
	}
	return id, time.Time{}, nil
}

// failedLocked records a failed attempt: the next one after the backoff, or
// when the CA's rate limit says, if that is later.
func (m *Manager) failedLocked(err error) {
	wait := m.o.Backoff[min(m.state.failures, len(m.o.Backoff)-1)]
	m.state.failures++
	m.state.lastError = oneLine(err)
	m.state.nextAttempt = m.o.Now().Add(wait)
	if _, until := rateLimitedUntil(err); until.After(m.state.nextAttempt) {
		m.state.nextAttempt, wait = until, until.Sub(m.o.Now())
	}
	m.o.Log.Warn("the public certificate could not be obtained; varlatchd tries again", "host", m.o.Host,
		"failures", m.state.failures, "retryIn", wait.String(), "error", m.state.lastError)
}

// rateLimited is the CA's rate-limit problem (RFC 8555 §6.7).
const rateLimited = "urn:ietf:params:acme:error:rateLimited"

// retryAfter is the time Let's Encrypt names in a rate-limit problem's
// detail ("retry after 2026-11-21 08:37:05 UTC"); acmez does not carry the
// Retry-After header of an order's error.
var retryAfter = regexp.MustCompile(`retry after (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) UTC`)

// rateLimitedUntil reports whether err is the CA's rate-limit problem, and
// the time it says to retry after (zero when it says none).
func rateLimitedUntil(err error) (bool, time.Time) {
	var problem acme.Problem
	if !errors.As(err, &problem) || problem.Type != rateLimited {
		return false, time.Time{}
	}
	if m := retryAfter.FindStringSubmatch(problem.Detail); m != nil {
		if t, perr := time.ParseInLocation(time.DateTime, m[1], time.UTC); perr == nil {
			return true, t
		}
	}
	return true, time.Time{}
}

// endIssuance records how an attempt ended: issued, or refused when the CA
// answered with a problem. Any other failure (a timeout, the network) is
// left started, which counts as issued: the CA may have issued. So is the
// CA's rate-limit problem: the CA counts what this installation asked for.
func (m *Manager) endIssuance(id int64, err error) {
	if id < 0 {
		return
	}
	outcome := OutcomeIssued
	if err != nil {
		var problem acme.Problem
		if !errors.As(err, &problem) {
			return
		}
		if limited, _ := rateLimitedUntil(err); limited {
			return
		}
		outcome = OutcomeRefused
	}
	// Recorded even when the run is stopping: the attempt happened.
	if err := m.o.Issuances.End(context.WithoutCancel(context.Background()), id, outcome, m.o.Now()); err != nil {
		m.o.Log.Warn("the issuance count could not record an attempt's end; it counts as issued", "host", m.o.Host, "error", err)
	}
}

// load reads the certificate and its key from the store and serves them
// when they are valid now for the host.
func (m *Manager) load(ctx context.Context) error {
	key := m.issuer.IssuerKey()
	certPEM, err := m.cm.Storage.Load(ctx, certmagic.StorageKeys.SiteCert(key, m.o.Host))
	if err != nil {
		return err
	}
	keyPEM, err := m.cm.Storage.Load(ctx, certmagic.StorageKeys.SitePrivateKey(key, m.o.Host))
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	clear(keyPEM)
	if err != nil {
		return fmt.Errorf("the stored certificate and key do not form a pair: %w", err)
	}
	leaf := pair.Leaf
	if leaf == nil {
		return errors.New("the stored certificate has no leaf")
	}
	if err := leaf.VerifyHostname(m.o.Host); err != nil {
		return fmt.Errorf("the stored certificate is not for %s", m.o.Host)
	}
	if now := m.o.Now(); now.After(leaf.NotAfter) {
		return fmt.Errorf("the stored certificate expired on %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	m.current.Store(&loaded{cert: &pair, leaf: leaf})
	return nil
}

// Wake asks Run to look again now (a test, or a changed clock).
func (m *Manager) Wake() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// valid is the certificate to serve now; nil before one is obtained or
// once it expired.
func (m *Manager) valid() *loaded {
	l := m.current.Load()
	if l == nil {
		return nil
	}
	now := m.o.Now()
	if now.Before(l.leaf.NotBefore) || now.After(l.leaf.NotAfter) {
		return nil
	}
	return l
}

// HasCertificate is whether a valid certificate is served now.
func (m *Manager) HasCertificate() bool { return m.valid() != nil }

// modernCiphers are TLS 1.2's suites served: ECDHE with an AEAD only (TLS
// 1.3's are Go's, not configurable).
var modernCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// TLSConfig is the HTTPS listener's: TLS 1.2 at least with modern suites,
// HTTP/2 and HTTP/1.1, and the host's name only. A handshake for another
// name, without one, or before a valid certificate exists is refused, so
// nothing is served before the certificate is. A TLS-ALPN-01 challenge
// handshake (ALPN acme-tls/1 alone, for the host) gets certmagic's
// challenge certificate while a challenge is pending, and nothing else.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: modernCiphers,
		NextProtos:   []string{"h2", "http/1.1", acmez.ACMETLS1Protocol},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if !strings.EqualFold(hello.ServerName, m.o.Host) {
				return nil, errors.New("unknown server name")
			}
			if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acmez.ACMETLS1Protocol {
				if _, ok := certmagic.GetACMEChallenge(m.o.Host); !ok {
					return nil, errors.New("no challenge pending")
				}
				return m.cm.GetCertificate(hello)
			}
			l := m.valid()
			if l == nil {
				return nil, errors.New("no certificate yet")
			}
			return l.cert, nil
		},
	}
}

// ChallengeOnly ends a connection that negotiated acme-tls/1: a
// TLS-ALPN-01 handshake serves no request (http.Server.TLSNextProto).
func ChallengeOnly(_ *http.Server, c *tls.Conn, _ http.Handler) { _ = c.Close() }

// ACMETLS1 is the ALPN protocol of TLS-ALPN-01.
const ACMETLS1 = acmez.ACMETLS1Protocol

// RedirectHandler is the plain HTTP listener's handler: an HTTP-01
// challenge for the host, while it is pending, gets its answer; any other
// challenge path is 404; everything else is a permanent redirect to the
// same path on origin (the public URL's origin, never the request's Host).
// No page of Varlatch is ever served in plain text.
func (m *Manager) RedirectHandler(origin *url.URL) http.Handler {
	base := origin.Scheme + "://" + origin.Host
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			if !m.answerHTTPChallenge(w, r) {
				http.NotFound(w, r)
			}
			return
		}
		w.Header().Set("Location", base+r.URL.RequestURI())
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusPermanentRedirect)
	})
}

// answerHTTPChallenge answers a pending HTTP-01 challenge for the host,
// from memory, and nothing else.
func (m *Manager) answerHTTPChallenge(w http.ResponseWriter, r *http.Request) bool {
	if m.o.HTTPPort == 0 || r.Method != http.MethodGet || !strings.EqualFold(hostOnly(r.Host), m.o.Host) {
		return false
	}
	chal, ok := certmagic.GetACMEChallenge(m.o.Host)
	if !ok || chal.Type != acme.ChallengeTypeHTTP01 {
		return false
	}
	return certmagic.SolveHTTPChallenge(m.issuer.Logger, w, r, chal.Challenge)
}

// hostOnly is a Host header without its port.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// Report is the public listener's state, for the listeners report and
// doctor: what is configured, the certificate served (its dates and
// issuer, never its key), and the last attempt.
func (m *Manager) Report() jsvalue.Object {
	m.mu.Lock()
	st := m.state
	m.mu.Unlock()
	now := m.o.Now()
	status := "pending"
	var certificate any
	if l := m.current.Load(); l != nil {
		switch {
		case now.After(l.leaf.NotAfter):
			status = "expired"
		case m.renewalDue(l.leaf, now):
			status = "renewal-due"
		default:
			status = "valid"
		}
		certificate = jsvalue.Object{
			{Key: "notBefore", Value: iso(l.leaf.NotBefore)},
			{Key: "notAfter", Value: iso(l.leaf.NotAfter)},
			{Key: "renewAfter", Value: iso(renewAt(l.leaf))},
			{Key: "issuer", Value: l.leaf.Issuer.CommonName},
		}
	}
	challenges := []any{"tls-alpn-01"}
	if m.o.HTTPPort != 0 {
		challenges = []any{"http-01", "tls-alpn-01"}
	}
	var lastError any
	if st.lastError != "" {
		lastError = st.lastError
	}
	return jsvalue.Object{
		{Key: "configured", Value: jsvalue.Object{
			{Key: "host", Value: m.o.Host},
			{Key: "httpsPort", Value: m.o.TLSPort},
			{Key: "httpPort", Value: nullIfZero(m.o.HTTPPort)},
			{Key: "ca", Value: m.o.CA},
			{Key: "challenges", Value: challenges},
		}},
		{Key: "status", Value: status},
		{Key: "certificate", Value: certificate},
		{Key: "attempting", Value: st.attempting},
		{Key: "lastAttempt", Value: isoOrNull(st.lastAttempt)},
		{Key: "lastSuccess", Value: isoOrNull(st.lastSuccess)},
		{Key: "lastError", Value: lastError},
		{Key: "failures", Value: st.failures},
		{Key: "nextAttempt", Value: isoOrNull(st.nextAttempt)},
	}
}

func iso(t time.Time) string { return audit.ISOTime(t.UnixMicro()) }

func isoOrNull(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return iso(t)
}

func nullIfZero(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

// oneLine is an error as one printable line of at most 300 characters:
// what the CA or the network said, never a key (no key is ever in an
// error certmagic or acmez makes).
func oneLine(err error) string {
	s := strings.Join(strings.Fields(err.Error()), " ")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// PortOf is the port of a host:port listener address (0 when it has
// none); the address was validated by the configuration.
func PortOf(address string) int {
	_, p, err := net.SplitHostPort(address)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}
