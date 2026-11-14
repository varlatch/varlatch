// SPDX-License-Identifier: AGPL-3.0-or-later

// Package clientaddr finds a request's client address behind trusted
// proxies, as the TypeScript server does (services/varlatchd/src/http/
// client-address.ts). The request window and device sign-in's per-peer
// limits need the caller's own address, while in many deployments requests
// reach varlatchd through a reverse proxy or a TLS ingress.
//
// Each proxy appends the address it received the request from to
// X-Forwarded-For. varlatchd believes the header only from the proxies
// trusted_proxies names, and reads it from the right: the first address
// that is not a trusted proxy is the client. Whatever a caller writes into
// the header sits to the left of the address its first trusted proxy
// appended, so it is never reached; a caller that is not a trusted proxy has
// its header ignored entirely.
package clientaddr

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MaxHops is how many X-Forwarded-For entries are read at most.
const MaxHops = 20

var (
	bracketed = regexp.MustCompile(`^\[([^\]]+)\](?::\d+)?$`)
	v4Port    = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}:\d+$`)
	hostName  = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

// Normalize returns an address without brackets, a port, a zone or the
// IPv4-mapped prefix, or "" when raw is not an IP address. IPv6 addresses
// come back in their canonical form (the TypeScript server keeps the text
// as written, lowercased; the two differ only for non-canonical IPv6 text).
func Normalize(raw string) string {
	v := strings.TrimSpace(raw)
	if m := bracketed.FindStringSubmatch(v); m != nil {
		v = m[1]
	} else if v4Port.MatchString(v) {
		v = v[:strings.LastIndexByte(v, ':')]
	}
	if i := strings.IndexByte(v, '%'); i >= 0 {
		v = v[:i]
	}
	a, err := netip.ParseAddr(strings.ToLower(v))
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

// Of returns the client of a request whose socket peer is peer and whose
// X-Forwarded-For is forwardedFor, believing the header only when trusts
// accepts the peer: the rightmost address that is not a trusted proxy.
func Of(peer, forwardedFor string, trusts func(string) bool) string {
	client := Normalize(peer)
	if client == "" {
		client = peer
	}
	if forwardedFor == "" || trusts == nil || !trusts(client) {
		return client
	}
	hops := strings.Split(forwardedFor, ",")
	for i, read := len(hops)-1, 0; i >= 0 && read < MaxHops; i, read = i-1, read+1 {
		hop := strings.TrimSpace(hops[i])
		if hop == "" {
			continue
		}
		address := Normalize(hop)
		// A malformed entry can only come from a misbehaving trusted proxy:
		// stop at the last address known good.
		if address == "" {
			return client
		}
		client = address
		if !trusts(address) {
			return address
		}
	}
	return client
}

// Entry is one trusted_proxies entry: an address, a range, or a host name.
type Entry struct {
	Prefix netip.Prefix // an address is a full-length prefix
	Name   string       // a host name to resolve, lowercase
}

// ParseTrustedProxies reads trusted_proxies: comma-separated IP addresses,
// CIDR ranges and host names.
func ParseTrustedProxies(spec string) ([]Entry, error) {
	var entries []Entry
	for _, raw := range strings.Split(spec, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if addr, bits, ok := strings.Cut(raw, "/"); ok && len(bits) >= 1 && len(bits) <= 3 && isDigits(bits) {
			a := Normalize(addr)
			n, _ := strconv.Atoi(bits)
			if a == "" {
				return nil, fmt.Errorf("%s is not a valid CIDR range", raw)
			}
			ip := netip.MustParseAddr(a)
			if n > ip.BitLen() {
				return nil, fmt.Errorf("%s is not a valid CIDR range", raw)
			}
			entries = append(entries, Entry{Prefix: netip.PrefixFrom(ip, n).Masked()})
			continue
		}
		if a := Normalize(raw); a != "" {
			ip := netip.MustParseAddr(a)
			entries = append(entries, Entry{Prefix: netip.PrefixFrom(ip, ip.BitLen())})
			continue
		}
		if len(raw) <= 253 && hostName.MatchString(raw) {
			entries = append(entries, Entry{Name: strings.ToLower(raw)})
			continue
		}
		return nil, fmt.Errorf("%s is not an IP address, a CIDR range, or a host name", raw)
	}
	return entries, nil
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Resolver resolves a host name to its addresses.
type Resolver func(ctx context.Context, name string) ([]string, error)

// TrustedProxies is the set of trusted proxies, with host names resolved at
// Start and again every refresh period: a container's address changes when
// it is recreated and may then belong to another one. Trust from a name
// lasts only as long as its resolution: a refresh that fails drops the
// name's addresses at once, and a resolution older than three refresh
// periods counts for nothing even if refreshing stalls. Addresses and
// ranges are trusted as configured.
type TrustedProxies struct {
	literal []netip.Prefix
	names   []string
	resolve Resolver
	log     *slog.Logger
	now     func() time.Time

	mu       sync.Mutex
	resolved map[string]resolution
	failing  map[string]bool
	maxAge   time.Duration
}

type resolution struct {
	addresses []string
	at        time.Time
}

// NewTrustedProxies builds the set from a trusted_proxies value. resolve
// and now may be nil (the system resolver, time.Now).
func NewTrustedProxies(spec string, resolve Resolver, log *slog.Logger, now func() time.Time) (*TrustedProxies, error) {
	entries, err := ParseTrustedProxies(spec)
	if err != nil {
		return nil, err
	}
	if resolve == nil {
		resolve = net.DefaultResolver.LookupHost
	}
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	t := &TrustedProxies{resolve: resolve, log: log, now: now, resolved: map[string]resolution{}, failing: map[string]bool{}, maxAge: 30 * time.Second}
	for _, e := range entries {
		if e.Name != "" {
			t.names = append(t.names, e.Name)
		} else {
			t.literal = append(t.literal, e.Prefix)
		}
	}
	return t, nil
}

// Start resolves the names once, then keeps refreshing them every period
// until ctx ends.
func (t *TrustedProxies) Start(ctx context.Context, period time.Duration) {
	t.mu.Lock()
	t.maxAge = 3 * period
	t.mu.Unlock()
	t.Refresh(ctx)
	if len(t.names) == 0 {
		return
	}
	go func() {
		tick := time.NewTicker(period)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				t.Refresh(ctx)
			}
		}
	}()
}

// Refresh resolves every name again.
func (t *TrustedProxies) Refresh(ctx context.Context) {
	for _, name := range t.names {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		raw, err := t.resolve(rctx, name)
		cancel()
		t.mu.Lock()
		previous := t.resolved[name].addresses
		if err != nil {
			delete(t.resolved, name)
			if !t.failing[name] {
				t.failing[name] = true
				if len(previous) > 0 {
					t.log.Warn(fmt.Sprintf("trusted proxy %s no longer resolves (%v); %s are no longer trusted", name, err, strings.Join(previous, ", ")))
				} else {
					t.log.Warn(fmt.Sprintf("trusted proxy %s does not resolve (%v); its forwarded addresses are not used until it does", name, err))
				}
			}
			t.mu.Unlock()
			continue
		}
		var addresses []string
		for _, a := range raw {
			if n := Normalize(a); n != "" {
				addresses = append(addresses, n)
			}
		}
		if !slices.Equal(addresses, previous) || t.failing[name] {
			shown := strings.Join(addresses, ", ")
			if shown == "" {
				shown = "(no address)"
			}
			t.log.Info(fmt.Sprintf("trusted proxy %s is %s", name, shown))
		}
		delete(t.failing, name)
		t.resolved[name] = resolution{addresses: addresses, at: t.now()}
		t.mu.Unlock()
	}
}

// Trusts reports whether address is a trusted proxy.
func (t *TrustedProxies) Trusts(address string) bool {
	n := Normalize(address)
	if n == "" {
		return false
	}
	a := netip.MustParseAddr(n)
	for _, p := range t.literal {
		if p.Contains(a) {
			return true
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	oldest := t.now().Add(-t.maxAge)
	for _, r := range t.resolved {
		if !r.at.Before(oldest) && slices.Contains(r.addresses, n) {
			return true
		}
	}
	return false
}
