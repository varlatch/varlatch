// SPDX-License-Identifier: AGPL-3.0-or-later

// Package realtime publishes the dashboard's live-update signals (ADR-0059
// Decision 4): after each commit, a changeSignal per Organization and an
// identitySignal per identity, carrying the domains touched and the last
// event id, never data. They reach the browser as server-sent events
// (go/server/httpserver events.go), on streams the browser session
// authenticates.
//
// The signals are the ones the TypeScript server pushed to Convex
// (services/varlatchd/src/mirror/publisher.ts, syncNewMirrorEvents), worked
// out from the same audit events with the same rules (Signals), checked
// against that code's own output (testdata/ts-vectors.json). Only the
// transport differs: Convex stored the latest signal of each Organization
// and identity, and a subscriber read the stored one; here a signal is
// sent to the streams open when it is published, and nothing is stored or
// replayed. A dashboard that reconnects refreshes from /v1 instead.
package realtime

import (
	"encoding/json"
	"strings"

	"github.com/varlatch/varlatch/go/server/audit"
)

// Event is the part of an audit event the signals are worked out from.
type Event struct {
	Position       int64
	ID             string
	Type           string
	OccurredAt     int64 // microseconds since the Unix epoch
	Actor          string
	CredentialID   string
	OrganizationID string
	Resource       string // the resource column's JSON text, or ""
}

// Signal kinds.
const (
	// Change is an Organization's changeSignal; Key is its id.
	Change = "change"
	// Identity is an identity's identitySignal; Key is the identity's id.
	Identity = "identity"
)

// Signal is a changeSignal or an identitySignal: metadata only.
type Signal struct {
	Kind        string
	Key         string
	LastEventID string
	OccurredAt  string // ISO 8601, milliseconds
	Domains     []string
}

// readOnlyEvents record a read or a decision, not a change (publisher.ts
// READ_ONLY_EVENTS): they advance a signal's lastEventId but touch no
// domain, so a page reading again after its own audited read does not read
// again forever.
var readOnlyEvents = map[string]bool{
	"value.disclosed":                           true,
	"value.validated":                           true,
	"secret.disclosed":                          true,
	"secret.validated":                          true,
	"authorization.denied":                      true,
	"authentication.failed":                     true,
	"authentication.passkey_enrollment_started": true,
	"authentication.device_requested":           true,
	"authentication.device_approved":            true,
	"authentication.device_denied":              true,
	"authentication.device_collected":           true,
	"authentication.device_code_rejected":       true,
	"authentication.device_code_locked":         true,
	"capability.exercised":                      true,
	"capability.denied":                         true,
}

// membershipEvents change a person's access to an Organization; the
// resource's identityId names that person (publisher.ts MEMBERSHIP_EVENTS).
var membershipEvents = map[string]bool{"membership.removed": true, "membership.role_changed": true}

// ChangedDomain is the domain an event type changes ("grant", "project",
// ...), or "" for reads and decisions (publisher.ts changedDomain).
func ChangedDomain(eventType string) string {
	if readOnlyEvents[eventType] {
		return ""
	}
	domain, _, _ := strings.Cut(eventType, ".")
	return domain
}

// pending is a signal being built: Map and Set keep insertion order in
// TypeScript, and so do these.
type pending struct {
	key        string
	domains    []string
	seen       map[string]bool
	lastEvent  string
	occurredAt int64
}

func (p *pending) add(e Event, domain string) {
	if domain != "" && !p.seen[domain] {
		p.seen[domain] = true
		p.domains = append(p.domains, domain)
	}
	p.lastEvent, p.occurredAt = e.ID, e.OccurredAt
}

type ordered struct {
	order []*pending
	byKey map[string]*pending
}

func (o *ordered) get(key string) *pending {
	if o.byKey == nil {
		o.byKey = map[string]*pending{}
	}
	if p := o.byKey[key]; p != nil {
		return p
	}
	p := &pending{key: key, seen: map[string]bool{}}
	o.byKey[key] = p
	o.order = append(o.order, p)
	return p
}

func (o *ordered) remove(key string) {
	if o.byKey[key] == nil {
		return
	}
	delete(o.byKey, key)
	for i, p := range o.order {
		if p.key == key {
			o.order = append(o.order[:i], o.order[i+1:]...)
			return
		}
	}
}

// resourceIdentity is the resource's identityId when it is a non-empty
// string.
func resourceIdentity(resource string) string {
	if resource == "" {
		return ""
	}
	var r struct {
		IdentityID any `json:"identityId"`
	}
	if json.Unmarshal([]byte(resource), &r) != nil {
		return ""
	}
	s, _ := r.IdentityID.(string)
	return s
}

// Signals works out a batch of events' signals as syncNewMirrorEvents does
// for the events it read in one pass:
//
//   - an event of an Organization adds its domain to that Organization's
//     changeSignal; reads and decisions add none but still move it;
//   - an event of no Organization moves its actor's identitySignal
//     instead (none without an actor);
//   - a membership change (membership.removed, membership.role_changed)
//     also moves the affected person's identitySignal, with the domain
//     "membership";
//   - organization.deleted drops the Organization's changeSignal from the
//     batch (later events of the batch start it again), and an
//     Organization deleted by the time of publication (deleted reports
//     which, of the ones the batch touches) gets none at all.
//
// The changeSignals come first, in the order their Organizations first
// appear, then the identitySignals, in the same order.
func Signals(events []Event, deleted func(orgIDs []string) map[string]bool) []Signal {
	var changes, identities ordered
	for _, e := range events {
		if e.OrganizationID == "" {
			if e.Actor != "" {
				identities.get(e.Actor).add(e, ChangedDomain(e.Type))
			}
			continue
		}
		if e.Type == "organization.deleted" {
			changes.remove(e.OrganizationID)
			continue
		}
		if membershipEvents[e.Type] {
			if subject := resourceIdentity(e.Resource); subject != "" {
				identities.get(subject).add(e, "membership")
			}
		}
		changes.get(e.OrganizationID).add(e, ChangedDomain(e.Type))
	}
	var gone map[string]bool
	if len(changes.order) > 0 && deleted != nil {
		keys := make([]string, 0, len(changes.order))
		for _, p := range changes.order {
			keys = append(keys, p.key)
		}
		gone = deleted(keys)
	}
	out := make([]Signal, 0, len(changes.order)+len(identities.order))
	for _, p := range changes.order {
		if !gone[p.key] {
			out = append(out, p.signal(Change))
		}
	}
	for _, p := range identities.order {
		out = append(out, p.signal(Identity))
	}
	return out
}

func (p *pending) signal(kind string) Signal {
	domains := p.domains
	if domains == nil {
		domains = []string{}
	}
	return Signal{Kind: kind, Key: p.key, LastEventID: p.lastEvent, OccurredAt: audit.ISOTime(p.occurredAt), Domains: domains}
}

// Closures are what a batch of events ends, besides sessions that are no
// longer live (which the streams' checks find themselves).
type Closures struct {
	// RevokedCredentials are the credentials the batch revoked: a stream
	// whose session one of them belongs to closes.
	RevokedCredentials []string
	// RemovedMembers are the people the batch removed from an
	// Organization (membership.removed): their streams close, after the
	// identitySignal that tells them.
	RemovedMembers map[string]bool
	// Narrowed are the Organizations that may signal fewer people from the
	// batch on: frozen for an incident, or a control changed. Streams that
	// lose one close (dispatch).
	Narrowed map[string]bool
}

// ClosuresOf finds a batch's closures.
func ClosuresOf(events []Event) Closures {
	c := Closures{RemovedMembers: map[string]bool{}, Narrowed: map[string]bool{}}
	for _, e := range events {
		switch e.Type {
		case "credential.revoked":
			if e.CredentialID != "" {
				c.RevokedCredentials = append(c.RevokedCredentials, e.CredentialID)
			}
		case "membership.removed":
			if subject := resourceIdentity(e.Resource); subject != "" {
				c.RemovedMembers[subject] = true
			}
		case "organization.frozen", "security_control.changed":
			if e.OrganizationID != "" {
				c.Narrowed[e.OrganizationID] = true
			}
		}
	}
	return c
}
