// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tailnet is the tailnet listeners' device check (ADR-0014,
// ADR-0046; tailnet/whois.ts, tailnet/listener.ts), on a Node: what
// varlatchd's own tailnet node answers about a connection's peer (WhoIs)
// and about itself. ADR-0059 Decision 5 makes the node tsnet, in process
// (step 4.13b); until then, and in tests, a Node is a stand-in.
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
}

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
	node Node
	// suffix is the pinned tailnet: every peer's name must end in it.
	suffix string
	self   *selfReader
}

// NewResolver returns a resolver over node, pinned to suffix (the
// MagicDNS suffix, e.g. "example.ts.net").
func NewResolver(node Node, suffix string, log *slog.Logger) *Resolver {
	if log == nil {
		log = slog.Default()
	}
	return &Resolver{node: node, suffix: suffix, self: &selfReader{node: node, log: log}}
}

// lookupTimeout bounds one question to the node (the local API's).
const lookupTimeout = 3 * time.Second

// Resolve is resolveWhois: the peer behind remote ("ip:port", the
// accepted socket's own), or why it has none.
func (r *Resolver) Resolve(ctx context.Context, remote string) Resolution {
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
	if tailnet != r.suffix {
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
	c := &authz.TailnetContext{Tailnet: tailnet, NodeID: peer.StableID, NodeName: &host, Tags: append([]string{}, peer.Tags...)}
	// A tagged device's identity is its tag set; its user profile is a
	// pseudo-user, never a person.
	if len(peer.Tags) == 0 && peer.LoginName != "" {
		login := peer.LoginName
		c.UserLogin = &login
	}
	return Resolution{Context: c}
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
