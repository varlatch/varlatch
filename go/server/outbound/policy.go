// SPDX-License-Identifier: AGPL-3.0-or-later

package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/whatwg"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Purpose is what a request is for (OutboundPurpose).
type Purpose string

// The purposes.
const (
	Webhook      Purpose = "webhook"
	SyncCheck    Purpose = "sync_check"
	SyncListing  Purpose = "sync_listing"
	SyncDelivery Purpose = "sync_delivery"
	GitHub       Purpose = "github"
	OIDC         Purpose = "oidc"
	AuditExport  Purpose = "audit_export"
)

// Answer is one DNS answer.
type Answer struct {
	Address string
	Family  int // 4 or 6
}

// Resolver resolves a name to its addresses.
type Resolver func(ctx context.Context, name string) ([]Answer, error)

// systemResolve is the system resolver, in its order.
func systemResolve(ctx context.Context, name string) ([]Answer, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return nil, err
	}
	out := make([]Answer, 0, len(addrs))
	for _, a := range addrs {
		a = a.WithZone("")
		family := 6
		if a.Is4() || a.Is4In6() {
			a, family = a.Unmap(), 4
		}
		out = append(out, Answer{Address: a.String(), Family: family})
	}
	return out, nil
}

// Options configure a Policy.
type Options struct {
	// Resolve replaces the system resolver (tests).
	Resolve Resolver
	Log     *slog.Logger
	Now     func() time.Time
	// TLS is the client's TLS configuration (tests: a private CA).
	TLS *tls.Config
	// ConnectTimeout bounds a connection: every attempt to every checked
	// address of a name, together (10 s, as undici's connect timeout with
	// autoSelectFamily).
	ConnectTimeout time.Duration
	// LookupTimeout bounds one name's resolution (10 s).
	LookupTimeout time.Duration
	// dial replaces the connection attempt to one checked address (tests:
	// a blackhole).
	dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// Policy is OutboundPolicy: the allow list, the resolver, the refusal
// audit bound, and the transports every governed request uses (pools per
// origin, shared by every purpose, each connection checked as it opens).
type Policy struct {
	Entries []Entry
	Limiter *Limiter

	resolve        Resolver
	log            *slog.Logger
	tls            *tls.Config
	connectTimeout time.Duration
	lookupTimeout  time.Duration
	dial           func(ctx context.Context, network, address string) (net.Conn, error)

	// mu guards the transports, made on first use.
	mu    sync.Mutex
	https *http.Transport
	http  *http.Transport

	lookups lookups
	scans   scans
}

// New is the policy of an allow list.
func New(entries []Entry, o Options) *Policy {
	if o.Resolve == nil {
		o.Resolve = systemResolve
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = 10 * time.Second
	}
	if o.LookupTimeout == 0 {
		o.LookupTimeout = 10 * time.Second
	}
	return &Policy{Entries: entries, Limiter: NewLimiter(o.Now), resolve: o.Resolve, log: o.Log, tls: o.TLS,
		connectTimeout: o.ConnectTimeout, lookupTimeout: o.LookupTimeout, dial: o.dial}
}

// Lookup resolves a name with the policy's resolver, within LookupTimeout
// (the configured destinations check bounds and shares its lookups).
// Decides nothing. A failure is a *net.DNSError naming only the name:
// never the resolver's own address.
func (p *Policy) Lookup(ctx context.Context, name string) ([]Answer, error) {
	ctx, cancel := context.WithTimeout(ctx, p.lookupTimeout)
	defer cancel()
	answers, err := p.resolve(ctx, name)
	if err == nil {
		return answers, nil
	}
	clean := &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	var dns *net.DNSError
	switch {
	case errors.As(err, &dns) && (dns.IsTimeout || dns.IsTemporary):
		clean = &net.DNSError{Err: "temporary failure in name resolution", Name: name, IsTimeout: dns.IsTimeout, IsTemporary: true}
	case ctx.Err() != nil:
		clean = &net.DNSError{Err: "lookup timed out", Name: name, IsTimeout: true, IsTemporary: true}
	}
	return nil, clean
}

// Decide is decide with the policy's allow list.
func (p *Policy) Decide(d Destination, addresses []string) Verdict {
	return Decide(p.Entries, d, addresses)
}

// CheckOutcome is a configuration-time check's outcome: allowed, refused,
// or unresolved (a DNS failure, which is not a refusal; ADR-0057 Decision
// 6). Error is the resolver's error code for an unresolved name.
type CheckOutcome struct {
	Outcome     string
	Destination Destination
	Addresses   []string
	Verdict     *Verdict
	Error       string
}

// ErrNotChecked is a URL that is neither https nor http.
var ErrNotChecked = errors.New("Only https and http destinations are checked")

// Check is check (ADR-0057 Decision 6): parse, resolve and classify, for a
// friendly error before anything is saved. Never call it inside a write
// job. It decides nothing at connection time. lookup replaces the
// resolution (nil: the policy's).
func (p *Policy) Check(ctx context.Context, raw string, lookup Resolver) (CheckOutcome, error) {
	u, ok := whatwg.ParseURL(raw)
	if !ok {
		return CheckOutcome{}, fmt.Errorf("Invalid URL")
	}
	return p.CheckURL(ctx, u, lookup)
}

// CheckURL is Check of a parsed URL.
func (p *Policy) CheckURL(ctx context.Context, u whatwg.URL, lookup Resolver) (CheckOutcome, error) {
	d, ok := DestinationOf(u)
	if !ok {
		return CheckOutcome{}, ErrNotChecked
	}
	if whatwg.IsIP(d.Host) != 0 {
		v := p.Decide(d, []string{d.Host})
		return CheckOutcome{Outcome: outcome(v), Destination: d, Addresses: []string{d.Host}, Verdict: &v}, nil
	}
	if lookup == nil {
		lookup = p.Lookup
	}
	answers, err := lookup(ctx, d.Host)
	if err != nil {
		return CheckOutcome{Outcome: "unresolved", Destination: d, Addresses: []string{}, Error: dnsCode(err)}, nil
	}
	if len(answers) == 0 {
		return CheckOutcome{Outcome: "unresolved", Destination: d, Addresses: []string{}, Error: "ENOTFOUND"}, nil
	}
	addresses := make([]string, len(answers))
	for i, a := range answers {
		addresses[i] = a.Address
	}
	v := p.Decide(d, addresses)
	return CheckOutcome{Outcome: outcome(v), Destination: d, Addresses: addresses, Verdict: &v}, nil
}

func outcome(v Verdict) string {
	if v.Allowed {
		return "allowed"
	}
	return "refused"
}

// dnsCode is the resolver error's code, as Node names it: ENOTFOUND for a
// name that does not exist, EAI_AGAIN for a temporary failure.
func dnsCode(err error) string {
	var dns *net.DNSError
	if errors.As(err, &dns) && (dns.IsTimeout || dns.IsTemporary) {
		return "EAI_AGAIN"
	}
	return "ENOTFOUND"
}

// RefusalFor is refusalFor: the configuration-time check as an error, the
// refusal (logged), or nil when allowed or unresolved.
func (p *Policy) RefusalFor(ctx context.Context, raw string, purpose Purpose) (*RefusedError, error) {
	c, err := p.Check(ctx, raw, nil)
	if err != nil {
		return nil, err
	}
	if c.Outcome != "refused" {
		return nil, nil
	}
	r := &RefusedError{Reason: c.Verdict.Reason, Destination: c.Destination, Addresses: c.Addresses}
	p.logRefusal(purpose, "configuration", r)
	return r, nil
}

func (p *Policy) logRefusal(purpose Purpose, phase string, r *RefusedError) {
	resolved := ""
	if len(r.Addresses) > 0 {
		resolved = " resolved to " + strings.Join(r.Addresses, ", ")
	}
	p.log.Warn(fmt.Sprintf("varlatchd: outbound %s request refused at %s (%s): %s//%s:%d%s", purpose, phase, r.Reason, r.Destination.Scheme, r.Destination.Host, r.Destination.Port, resolved))
}

// errRedirect refuses a redirect: outbound requests never follow one.
var errRedirect = errors.New("Outbound requests never follow redirects")

// Client is the client for a purpose (OutboundPolicy.fetch): the policy's
// transports, never an environment proxy, redirects never followed, and
// URLs without credentials. A refusal is an error RefusalOf finds; the
// caller records it (RefusalEvent), within the rate bound.
func (p *Policy) Client(purpose Purpose) *http.Client {
	return &http.Client{
		Transport:     p.Transport(purpose),
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect },
	}
}

// Transport is the round tripper for a purpose: for clients that take a
// transport rather than a client (the audit export's S3 client, 4.11). It
// refuses a redirect itself (a request the client made from a redirect
// response), so a client of the caller's that would follow one cannot.
func (p *Policy) Transport(purpose Purpose) http.RoundTripper {
	p.transports()
	return roundTripper{p: p, purpose: purpose}
}

func (p *Policy) transports() (*http.Transport, *http.Transport) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.https == nil {
		p.build()
	}
	return p.https, p.http
}

func (p *Policy) build() {
	mk := func(scheme string) *http.Transport {
		t := &http.Transport{
			Proxy:                 nil,
			DialContext:           p.dialer(scheme),
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   p.connectTimeout,
			ExpectContinueTimeout: time.Second,
		}
		if p.tls != nil {
			t.TLSClientConfig = p.tls.Clone()
		}
		return t
	}
	p.https, p.http = mk("https:"), mk("http:")
}

type roundTripper struct {
	p       *Policy
	purpose Purpose
}

func (rt roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.User != nil {
		return nil, errors.New("Outbound request URLs never carry credentials")
	}
	if req.Response != nil {
		return nil, errRedirect
	}
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	https, http := rt.p.transports()
	switch req.URL.Scheme {
	case "https":
		return https.RoundTrip(req)
	case "http":
		return http.RoundTrip(req)
	}
	return nil, fmt.Errorf("Outbound requests use https or http, not %s:", req.URL.Scheme)
}

// dialer is the connection check (ADR-0057 Decision 4): it resolves the
// name once, decides every answer, and connects only to the addresses it
// checked; a literal address is decided as it is, never looked up.
func (p *Policy) dialer(scheme string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, portText, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			return nil, err
		}
		d := Destination{Scheme: scheme, Host: NormalizeHost(host), Port: port}
		var answers []Answer
		if fam := whatwg.IsIP(d.Host); fam != 0 {
			answers = []Answer{{Address: d.Host, Family: fam}}
		} else {
			if answers, err = p.Lookup(ctx, d.Host); err != nil {
				return nil, err
			}
			if len(answers) == 0 {
				return nil, &net.DNSError{Err: "no such host", Name: d.Host, IsNotFound: true}
			}
		}
		addresses := make([]string, len(answers))
		for i, a := range answers {
			addresses[i] = a.Address
		}
		if v := p.Decide(d, addresses); !v.Allowed {
			return nil, &RefusedError{Reason: v.Reason, Destination: d, Addresses: addresses}
		}
		var wanted []Answer
		for _, a := range answers {
			if network == "tcp" || network == "tcp4" && a.Family == 4 || network == "tcp6" && a.Family == 6 {
				wanted = append(wanted, a)
			}
		}
		if len(wanted) == 0 {
			return nil, &net.DNSError{Err: "no such host", Name: d.Host, IsNotFound: true}
		}
		// One deadline for every attempt to every checked address.
		ctx, cancel := context.WithTimeout(ctx, p.connectTimeout)
		defer cancel()
		return p.dialChecked(ctx, wanted, portText)
	}
}

// fallbackDelay is Happy Eyeballs' head start of the first family (RFC
// 8305), as Go's own dialer gives it.
const fallbackDelay = 300 * time.Millisecond

// dialChecked connects to one of the checked addresses: the first answer's
// family first, the other after fallbackDelay or the first family's
// failure, each family's addresses in order; the first connection wins.
func (p *Policy) dialChecked(ctx context.Context, answers []Answer, port string) (net.Conn, error) {
	var primary, fallback []Answer
	for _, a := range answers {
		if a.Family == answers[0].Family {
			primary = append(primary, a)
		} else {
			fallback = append(fallback, a)
		}
	}
	// The checked addresses as the socket names them (mapped addresses
	// in their IPv4 form, zones dropped).
	same := func(address string) string {
		a, err := netip.ParseAddr(address)
		if err != nil {
			return address
		}
		return a.WithZone("").Unmap().String()
	}
	checked := map[string]bool{}
	for _, a := range answers {
		checked[same(a.Address)] = true
	}
	dial := p.dial
	if dial == nil {
		// Control sees the address the socket connects to: one this dial
		// checked, or nothing is sent.
		d := net.Dialer{Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil || !checked[same(host)] {
				return fmt.Errorf("outbound: a connection to an unchecked address %s", address)
			}
			return nil
		}}
		dial = d.DialContext
	}
	// serial tries a family's addresses in order within ctx's deadline,
	// each attempt given an equal share of what remains (at least 2 s, as
	// Go's own dialer), so a name of several unreachable addresses is
	// bounded by the one deadline.
	serial := func(ctx context.Context, list []Answer) (net.Conn, error) {
		var last error
		for i, a := range list {
			attempt := ctx
			if deadline, ok := ctx.Deadline(); ok {
				share := time.Until(deadline) / time.Duration(len(list)-i)
				share = max(share, min(2*time.Second, time.Until(deadline)))
				var cancel context.CancelFunc
				attempt, cancel = context.WithTimeout(ctx, share)
				defer cancel()
			}
			c, err := dial(attempt, "tcp", net.JoinHostPort(a.Address, port))
			if err == nil {
				return c, nil
			}
			last = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, last
	}
	if len(fallback) == 0 {
		return serial(ctx, primary)
	}
	type result struct {
		c       net.Conn
		err     error
		primary bool
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, 2)
	start := func(list []Answer, isPrimary bool) {
		go func() {
			c, err := serial(ctx, list)
			results <- result{c, err, isPrimary}
		}()
	}
	start(primary, true)
	timer := time.NewTimer(fallbackDelay)
	defer timer.Stop()
	started, pending := false, 1
	var firstErr error
	for {
		select {
		case <-timer.C:
			if !started {
				started = true
				pending++
				start(fallback, false)
			}
		case r := <-results:
			pending--
			if r.err == nil {
				// The other attempt, if one connects later, is closed.
				go func(left int) {
					for ; left > 0; left-- {
						if o := <-results; o.c != nil {
							o.c.Close()
						}
					}
				}(pending)
				return r.c, nil
			}
			if firstErr == nil {
				firstErr = r.err
			}
			if !started {
				started = true
				pending++
				timer.Stop()
				start(fallback, false)
				continue
			}
			if pending == 0 {
				return nil, firstErr
			}
		}
	}
}

// RefusalRecord is a refusal to record as outbound.refused: the
// Organization, the purpose, the phase ("configuration" or "connection"),
// the refusal, and the object the request was for ({webhookId},
// {connectionId}, {targetId}, {oidcBindingId}).
type RefusalRecord struct {
	OrganizationID  string
	Purpose         Purpose
	Phase           string
	Refusal         *RefusedError
	Resource        jsvalue.Object
	ActorIdentityID *string
	RequestID       *string
}

// RefusalEvent is recordRefusal's event (ADR-0057 Decision 8), within the
// rate bound: configuration-phase refusals always; connection-phase ones
// once per Organization, purpose, object and reason per hour, and at most
// 100 an hour in all (false: held back, counted on the next one). Never
// the resolved address, a path, a query or a credential. The caller
// records it in its job.
func (p *Policy) RefusalEvent(rec RefusalRecord) (audit.Event, bool) {
	suppressed := 0
	if rec.Phase == "configuration" {
		suppressed = p.Limiter.Always()
	} else {
		var object []string
		for _, m := range rec.Resource {
			s, _ := m.Value.(string)
			object = append(object, s)
		}
		admitted, held := p.Limiter.Admit(rec.OrganizationID + "|" + string(rec.Purpose) + "|" + strings.Join(object, ",") + "|" + string(rec.Refusal.Reason))
		if !admitted {
			return audit.Event{}, false
		}
		suppressed = held
		p.logRefusal(rec.Purpose, "connection", rec.Refusal)
	}
	d := rec.Refusal.Destination
	meta := jsvalue.Object{
		{Key: "purpose", Value: string(rec.Purpose)},
		{Key: "phase", Value: rec.Phase},
		{Key: "scheme", Value: strings.TrimSuffix(d.Scheme, ":")},
		{Key: "host", Value: d.Host},
		{Key: "port", Value: float64(d.Port)},
		{Key: "reason", Value: string(rec.Refusal.Reason)},
	}
	if suppressed > 0 {
		meta = append(meta, jsvalue.Member{Key: "suppressed", Value: float64(suppressed)})
	}
	org := rec.OrganizationID
	resource := rec.Resource
	if resource == nil {
		resource = jsvalue.Object{}
	}
	return audit.Event{
		Type: "outbound.refused", Decision: audit.Deny,
		ActorIdentityID: rec.ActorIdentityID, OrganizationID: &org, RequestID: rec.RequestID,
		Resource: resource, Metadata: meta,
	}, true
}

// RecordRefusal records a refusal in a write job of its own, within the
// rate bound (for a refusal outside any other job: a delivery's).
func (p *Policy) RecordRefusal(ctx context.Context, store *storage.DB, rec RefusalRecord) error {
	e, ok := p.RefusalEvent(rec)
	if !ok {
		return nil
	}
	return store.Write(ctx, func(tx *storage.Tx) error {
		_, err := audit.Record(ctx, tx, e)
		return err
	})
}

// Close closes pooled connections.
func (p *Policy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.https != nil {
		p.https.CloseIdleConnections()
		p.http.CloseIdleConnections()
	}
}
