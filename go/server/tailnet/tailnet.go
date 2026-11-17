// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tailnet is the tailnet listeners' device check (ADR-0014,
// ADR-0046; tailnet/whois.ts, tailnet/listener.ts), on a Node: what
// varlatchd's own tailnet node answers about a connection's peer (WhoIs)
// and about itself. ADR-0059 Decision 5 makes the node tsnet, in process
// (node.go, step 4.13b); in tests, a Node can be a stand-in.
//
// The check reads only the accepted socket's own peer address, never what
// the request says. Every way it can fail refuses: the peer then has no
// Tailnet Context, and every tailnet-constrained operation fails closed.
package tailnet

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Why a peer has no Tailnet Context (ADR-0046 Decision 7). Every reason
// fails closed; the reason is for audit and diagnosis, never for policy.
const (
	// ResolverUnavailable: the node could not be asked, or its answer not
	// trusted (an error, a timeout, a field missing), or its own identity
	// is unknown, so the self check cannot be made.
	ResolverUnavailable = "resolver-unavailable"
	// Unrecognized: no device known for that address and port.
	Unrecognized = "unrecognized"
	// OtherTailnet: a device of another tailnet (the pin, ADR-0014 §6).
	OtherTailnet = "other-tailnet"
	// Shared: a device shared into this tailnet from elsewhere, refused
	// whatever its name.
	Shared = "shared"
	// Self: varlatchd's own node; no forwarding hop may inherit its
	// identity.
	Self = "self"
)

// ErrUnknownPeer is a Node's WhoIs answer for an address and port it
// knows no device for.
var ErrUnknownPeer = errors.New("tailnet: no device for that peer")

// Peer is a WhoIs answer: the device, as the node knows it.
type Peer struct {
	StableID string
	// Name is its MagicDNS name (<host>.<tailnet>, a trailing dot or not).
	Name string
	Tags []string
	// Sharer is non-zero for a device shared into this tailnet.
	Sharer int64
	// LoginName is its user's login; for a tagged device, a pseudo-user
	// that is never a person.
	LoginName string
}

// Node is varlatchd's tailnet node.
type Node interface {
	// WhoIs is the device behind a peer address ("ip:port"), or
	// ErrUnknownPeer.
	WhoIs(ctx context.Context, remote string) (Peer, error)
	// SelfID is the node's own StableID.
	SelfID(ctx context.Context) (string, error)
}

// Resolution is a peer's Tailnet Context, or why there is none.
type Resolution struct {
	Context *authz.TailnetContext
	Refused string
	// valid says whether the Context still counts: false once tailnet
	// access closed after it was resolved (a pin change). Nil: always.
	valid func() bool
}

// Valid is whether the resolution's Context still counts: an
// authorization decision reads it at decision time (authz.WithTailnet).
func (r Resolution) Valid() bool { return r.valid == nil || r.valid() }

// Refusal is the resolution for a refused peer.
func Refusal(reason string) Resolution { return Resolution{Refused: reason} }

// JSValue is the resolution as audit events record it (ADR-0046
// Decision 8): the context's members, or {refused: <reason>}.
func (r Resolution) JSValue() any {
	if r.Context == nil {
		return jsvalue.Object{{Key: "refused", Value: r.Refused}}
	}
	c := r.Context
	o := jsvalue.Object{{Key: "tailnet", Value: c.Tailnet}, {Key: "nodeId", Value: c.NodeID}}
	if c.NodeName != nil {
		o = append(o, jsvalue.Member{Key: "nodeName", Value: *c.NodeName})
	}
	o = append(o, jsvalue.Member{Key: "tags", Value: tags(c.Tags)})
	if c.UserLogin != nil {
		o = append(o, jsvalue.Member{Key: "userLogin", Value: *c.UserLogin})
	}
	return o
}

// Device is the resolution in the protocol's TailnetDevice shape
// (tailnetDeviceOf): what GET /v1/tailnet/context and /v1/me report.
func (r Resolution) Device() jsvalue.Object {
	if r.Context == nil {
		reason := r.Refused
		if reason == "" {
			reason = Unrecognized
		}
		return jsvalue.Object{{Key: "recognized", Value: false}, {Key: "reason", Value: reason}}
	}
	c := r.Context
	o := jsvalue.Object{{Key: "recognized", Value: true}, {Key: "tailnet", Value: c.Tailnet}, {Key: "nodeId", Value: c.NodeID}}
	if c.NodeName != nil && *c.NodeName != "" {
		o = append(o, jsvalue.Member{Key: "nodeName", Value: *c.NodeName})
	}
	o = append(o, jsvalue.Member{Key: "tags", Value: tags(c.Tags)})
	if c.UserLogin != nil && *c.UserLogin != "" {
		o = append(o, jsvalue.Member{Key: "userLogin", Value: *c.UserLogin})
	}
	return o
}

func tags(t []string) []any {
	out := make([]any, len(t))
	for i, s := range t {
		out[i] = s
	}
	return out
}

// Resolver resolves a peer address to its Tailnet Context with ADR-0014's
// rules: shared devices refused before their name is read, the tailnet
// pinned by its MagicDNS suffix, the node itself refused, tagged devices
// known by their tags only.
type Resolver struct {
	node  Node
	state pinState
	self  *selfReader
}

// pinState is where a resolver's pin comes from: the Manager, or a fixed
// suffix (tests and the stand-in node).
type pinState interface {
	// Current is the pinned suffix, every peer's name must end in it, the
	// open period's generation, and whether tailnet access is open.
	Current() (string, uint64, bool)
	// Valid is whether access is still open in the period gen was taken in.
	Valid(gen uint64) bool
	// Closed says why access is closed: a pin change refuses every peer
	// as of another tailnet; anything else (not enrolled yet, the tailnet
	// not known) as resolver-unavailable.
	Closed() string
}

type fixedPin string

func (f fixedPin) Current() (string, uint64, bool) { return string(f), 0, true }
func (fixedPin) Valid(uint64) bool                 { return true }
func (fixedPin) Closed() string                    { return "" }

// NewResolver returns a resolver over node, pinned to suffix (the
// MagicDNS suffix, e.g. "example.ts.net").
func NewResolver(node Node, suffix string, log *slog.Logger) *Resolver {
	if log == nil {
		log = slog.Default()
	}
	return &Resolver{node: node, state: fixedPin(suffix), self: &selfReader{node: node, log: log}}
}

// NewPinnedResolver returns a resolver over node whose pin is m's: while
// m has tailnet access closed, every peer is refused before WhoIs, and a
// resolution made before access closed no longer counts.
func NewPinnedResolver(node Node, m *Manager, log *slog.Logger) *Resolver {
	r := NewResolver(node, "", log)
	r.state = m
	return r
}

// closedRefusal is the refusal while access is closed.
func (r *Resolver) closedRefusal() Resolution {
	switch r.state.Closed() {
	case PinControlURL, PinTailnet, PinSuffix:
		return Refusal(OtherTailnet)
	}
	return Refusal(ResolverUnavailable)
}

// lookupTimeout bounds one question to the node (the local API's).
const lookupTimeout = 3 * time.Second

// Resolve is resolveWhois: the peer behind remote ("ip:port", the
// accepted socket's own), or why it has none.
func (r *Resolver) Resolve(ctx context.Context, remote string) Resolution {
	suffix, gen, open := r.state.Current()
	if !open {
		return r.closedRefusal()
	}
	lctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	peer, err := r.node.WhoIs(lctx, remote)
	cancel()
	switch {
	case errors.Is(err, ErrUnknownPeer):
		return Refusal(Unrecognized)
	case err != nil, peer.StableID == "", peer.Name == "":
		return Refusal(ResolverUnavailable)
	}
	// A shared-in device is refused before its name is looked at, so the
	// pin is not the only defense against a foreign device whose tags or
	// user happen to match a selector.
	if peer.Sharer != 0 {
		return Refusal(Shared)
	}
	// Names are MagicDNS FQDNs, <host>.<tailnet>: the tailnet is pinned,
	// and a device of another one never qualifies.
	name := strings.TrimSuffix(peer.Name, ".")
	host, tailnet, _ := strings.Cut(name, ".")
	if tailnet != suffix {
		return Refusal(OtherTailnet)
	}
	// The node's own identity, as of now: unknown means refuse.
	self := r.self.get(ctx)
	if self == "" {
		return Refusal(ResolverUnavailable)
	}
	if peer.StableID == self {
		return Refusal(Self)
	}
	// Access may have closed while the node answered: nothing it said in
	// an earlier open period counts.
	if !r.state.Valid(gen) {
		return r.closedRefusal()
	}
	c := &authz.TailnetContext{Tailnet: tailnet, NodeID: peer.StableID, NodeName: &host, Tags: append([]string{}, peer.Tags...)}
	// A tagged device's identity is its tag set; its user profile is a
	// pseudo-user, never a person.
	if len(peer.Tags) == 0 && peer.LoginName != "" {
		login := peer.LoginName
		c.UserLogin = &login
	}
	return Resolution{Context: c, valid: func() bool { return r.state.Valid(gen) }}
}

// selfReader is selfNodeResolver: the node's own StableID, read fresh for
// every caller (a read that started after the caller arrived), concurrent
// callers sharing reads, at most one in flight. A changed identity is
// logged once.
type selfReader struct {
	node Node
	log  *slog.Logger

	mu      sync.Mutex
	current *read
	next    *read
	last    string
}

type read struct {
	done chan struct{}
	id   string
}

func (s *selfReader) get(ctx context.Context) string {
	s.mu.Lock()
	var r *read
	switch {
	case s.next != nil:
		// Queued after the read in flight: it starts after this caller.
		r = s.next
	case s.current == nil:
		r = s.startLocked()
	default:
		// The read in flight may predate this caller: queue the next one.
		r = &read{done: make(chan struct{})}
		s.next = r
		go func(prev *read) {
			<-prev.done
			s.mu.Lock()
			s.next = nil
			s.current = r
			s.mu.Unlock()
			s.run(r)
		}(s.current)
	}
	s.mu.Unlock()
	select {
	case <-r.done:
		return r.id
	case <-ctx.Done():
		return ""
	}
}

func (s *selfReader) startLocked() *read {
	r := &read{done: make(chan struct{})}
	s.current = r
	go s.run(r)
	return r
}

func (s *selfReader) run(r *read) {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	id, err := s.node.SelfID(ctx)
	cancel()
	if err != nil {
		id = ""
	}
	s.mu.Lock()
	if id != "" && s.last != "" && id != s.last {
		s.log.Warn("this node's tailnet identity changed; checking peers against the new one", "was", s.last, "now", id)
	}
	if id != "" {
		s.last = id
	}
	if s.current == r {
		s.current = nil
	}
	s.mu.Unlock()
	r.id = id
	close(r.done)
}
