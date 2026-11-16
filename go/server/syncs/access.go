// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	vsync "github.com/varlatch/varlatch/go/lib/sync"
	"github.com/varlatch/varlatch/go/lib/whatwg"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/write"
)

// CredentialInput is a Connection's stored credential (ConnectionID, and
// Credential nil) or a replacement for it (ConnectionID and Credential), or
// a new one (Platform, BaseIdentity and Credential).
type CredentialInput struct {
	ConnectionID string
	Platform     string
	BaseIdentity string
	Credential   *string
}

// checked is checkCredentialInput's answer.
type checked struct {
	adapter      vsync.Adapter
	baseIdentity string
	connectionID string
}

// checkInput is checkCredentialInput: what resolving the credential checks
// before anything is decrypted, in its order and with its answers, read
// without a gate, so the outbound policy's check of the base identity (a
// DNS lookup) runs before the effect, as validation.
func (s *Service) checkInput(ctx context.Context, organizationID string, in CredentialInput) (checked, error) {
	platform, baseIdentity := in.Platform, in.BaseIdentity
	var out checked
	app := false
	if in.ConnectionID != "" {
		c, err := Get(ctx, s.store().Reader(), organizationID, in.ConnectionID)
		if err != nil {
			return out, err
		}
		out.connectionID, platform, baseIdentity = c.ID, c.Platform, c.BaseIdentity
		if c.CredentialKind == "github-app" {
			if in.Credential != nil {
				return out, appHasNoCredential()
			}
			app = true
		}
	}
	if !s.allowed(platform) {
		return out, adapterNotAllowed()
	}
	adapter, err := vsync.GetAdapter(platform)
	if err != nil {
		return out, validation(err)
	}
	if baseIdentity, err = adapter.CanonicalizeBaseIdentity(baseIdentity); err != nil {
		return out, validation(err)
	}
	if !app && in.Credential != nil && whatwg.Trim(*in.Credential) == "" {
		return out, emptyCredential()
	}
	if app {
		return out, appMintingNotBuilt()
	}
	out.adapter, out.baseIdentity = adapter, baseIdentity
	return out, nil
}

// resolved is resolveCredential's answer: the credential for the call.
type resolved struct {
	credential string
	supplied   bool
	// storedVersion and storedExpiresAt are the stored credential's, read
	// together; 0 and invalid for a supplied one.
	storedVersion   int64
	storedExpiresAt sql.NullInt64
}

// resolve is resolveCredential's reads in the effect's snapshot, after the
// requester's checkpoint: the Connection still there, its credential
// decrypted, or the supplied one.
func (s *Service) resolve(ctx context.Context, tx *sql.Tx, organizationID string, in CredentialInput, connectionID string) (resolved, error) {
	if in.Credential != nil {
		return resolved{credential: *in.Credential, supplied: true}, nil
	}
	stored, err := query.New(tx).ConnectionCredential(ctx, connectionID)
	if err != nil {
		return resolved{}, err
	}
	if !stored.CredentialEnvelope.Valid {
		return resolved{}, emptyCredential()
	}
	plain, err := s.open(ctx, tx, organizationID, connectionID, stored.CredentialEnvelope.String)
	if err != nil {
		return resolved{}, err
	}
	if whatwg.Trim(plain) == "" {
		return resolved{}, emptyCredential()
	}
	return resolved{credential: plain, storedVersion: stored.Version, storedExpiresAt: stored.CredentialExpiresAt}, nil
}

// existsIn is resolveCredential's first read for a stored Connection: it
// is still there, before the requester's checkpoint.
func existsIn(ctx context.Context, tx *sql.Tx, organizationID string, in CredentialInput) error {
	if in.ConnectionID == "" {
		return nil
	}
	_, err := Get(ctx, tx, organizationID, in.ConnectionID)
	return err
}

// client is the client a check or listing sends through: the outbound
// policy's for purpose (or the test's), noting each refusal for the
// effect, as the policy's fetch records it for the Organization.
func (s *Service) clientFor(organizationID, connectionID string, purpose outbound.Purpose) *http.Client {
	base := s.client
	if base == nil {
		base = s.Policy.Client(purpose)
	}
	next := base.Transport
	if next == nil {
		// Never the default transport: a client without one is used as it is.
		return base
	}
	resource := jsvalue.Object{}
	if connectionID != "" {
		resource = jsvalue.Object{{Key: "connectionId", Value: connectionID}}
	}
	c := *base
	c.Transport = roundTripper(func(r *http.Request) (*http.Response, error) {
		// guardEffectFetch: once the effect's deadline passed, no request starts.
		if err := write.EffectAlive(r.Context()); err != nil {
			return nil, err
		}
		res, err := next.RoundTrip(r)
		if refusal := outbound.RefusalOf(err); refusal != nil {
			if e, ok := s.Policy.RefusalEvent(outbound.RefusalRecord{
				OrganizationID: organizationID, Purpose: purpose, Phase: "connection", Refusal: refusal, Resource: resource,
			}); ok {
				write.NoteRefusal(r.Context(), e)
			}
		}
		return res, err
	})
	return &c
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// refusedCheck is refusedCheck: a check the outbound policy refused,
// unreachable in its words.
func refusedCheck(r *outbound.RefusedError) vsync.AccessCheck {
	return vsync.AccessCheck{Status: vsync.StatusUnreachable, Where: vsync.WhereConnection, Message: r.Error()}
}

// withKnownExpiry is withKnownExpiry: a stored credential's recorded
// expiry stands in when this answer said nothing.
func withKnownExpiry(c vsync.AccessCheck, stored sql.NullInt64) vsync.AccessCheck {
	if c.CredentialExpiresAt == "" && stored.Valid {
		c.CredentialExpiresAt = audit.ISOTime(stored.Int64)
	}
	return c
}

// CheckJS is an access check as the API gives it.
func CheckJS(c vsync.AccessCheck) jsvalue.Object {
	o := jsvalue.Object{{Key: "status", Value: string(c.Status)}, {Key: "where", Value: string(c.Where)}}
	if c.HTTPStatus != 0 {
		o = append(o, jsvalue.Member{Key: "httpStatus", Value: c.HTTPStatus})
	}
	o = append(o, jsvalue.Member{Key: "message", Value: c.Message})
	if c.CredentialExpiresAt != "" {
		o = append(o, jsvalue.Member{Key: "credentialExpiresAt", Value: c.CredentialExpiresAt})
	}
	return o
}

func httpStatusOrNull(c vsync.AccessCheck) any {
	if c.HTTPStatus == 0 {
		return nil
	}
	return c.HTTPStatus
}

// expiryMicros reads an adapter's ISO 8601 expiry.
func expiryMicros(iso string) (int64, bool) {
	t, err := time.Parse(time.RFC3339Nano, iso)
	if err != nil {
		return 0, false
	}
	return t.UnixMicro(), true
}

func credentialWord(supplied bool) string {
	if supplied {
		return "supplied"
	}
	return "stored"
}

// recordExpiry is recordCredentialExpiry, for a stored token whose check
// or listing said when it expires.
func recordExpiry(ctx context.Context, tx query.DBTX, connectionID string, r resolved, expiresAt string, now int64) error {
	if r.supplied || connectionID == "" || expiresAt == "" {
		return nil
	}
	at, ok := expiryMicros(expiresAt)
	if !ok {
		return nil
	}
	return query.New(tx).RecordCredentialExpiry(ctx, query.RecordCredentialExpiryParams{
		ExpiresAt: sql.NullInt64{Int64: at, Valid: true}, SeenAt: sql.NullInt64{Int64: now, Valid: true}, ID: connectionID, Version: r.storedVersion,
	})
}

// called is what a check's or listing's call gives its final job.
type called[T any] struct {
	answer T
	r      resolved
}

// Check is checkConnectionAccess (ADR-0031, amendment 2026-10-09): does a
// credential reach its base identity, and the destination when one is
// named? Nothing is stored but an expiry the platform reports for a stored
// credential, no Value is read, and no platform text comes back; the
// outcome is audited.
func (s *Service) Check(ctx context.Context, req Request, org authz.Organization, in CredentialInput, destination jsvalue.Object) (jsvalue.Object, []auth.PendingReport, error) {
	actor := req.Principal.Identity.ID
	if err := write.RefuseIfDeleting(ctx, s.store().Reader(), org.ID); err != nil {
		return nil, nil, err
	}
	c, err := s.checkInput(ctx, org.ID, in)
	if err != nil {
		return nil, nil, err
	}
	// No destination fields: the check stops at the base identity.
	var dest *vsync.Destination
	for _, m := range destination {
		if m.Value != nil && m.Value != "" {
			d, err := c.adapter.CanonicalizeDestination(syncObject(destination))
			if err != nil {
				return nil, nil, validation(err)
			}
			dest = &d
			break
		}
	}
	refusal, err := s.baseIdentityRefusal(ctx, org.ID, c.baseIdentity, outbound.SyncCheck, c.connectionID, actor)
	if err != nil {
		return nil, nil, err
	}
	var r resolved
	result, reports, err := write.RunEffect(ctx, s.Writer, write.Effect[called[vsync.AccessCheck], jsvalue.Object]{
		OrganizationID: org.ID, People: []write.Gate{write.Person(actor, write.Shared)}, Principal: req.Principal,
		Check: func(ctx context.Context, tx *sql.Tx) error { return existsIn(ctx, tx, org.ID, in) },
		Checked: func(ctx context.Context, tx *sql.Tx) error {
			var err error
			r, err = s.resolve(ctx, tx, org.ID, in, c.connectionID)
			return err
		},
		Call: func(ctx context.Context) (called[vsync.AccessCheck], error) {
			if refusal != nil {
				return called[vsync.AccessCheck]{refusedCheck(refusal), r}, nil
			}
			fields := vsync.Fields{}
			if dest != nil {
				fields = dest.Fields
			}
			check := c.adapter.CheckAccess(ctx, &vsync.Request{
				BaseIdentity: c.baseIdentity, Destination: fields, Credential: r.credential, CredentialKind: vsync.Token,
				Client: s.clientFor(org.ID, c.connectionID, outbound.SyncCheck),
			})
			return called[vsync.AccessCheck]{check, r}, nil
		},
		Final: func(ctx context.Context, tx *storage.Tx, got called[vsync.AccessCheck]) (jsvalue.Object, error) {
			now := s.now().UnixMicro()
			if err := recordExpiry(ctx, tx, c.connectionID, got.r, got.answer.CredentialExpiresAt, now); err != nil {
				return nil, err
			}
			check := got.answer
			if !got.r.supplied {
				check = withKnownExpiry(check, got.r.storedExpiresAt)
			}
			var described any
			if dest != nil {
				described = string(c.adapter.Platform()) + ":" + dest.Key
			}
			action := "config.sync.manage"
			if _, err := audit.Record(ctx, tx, audit.Event{
				Type: "sync.connection_checked", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &org.ID, Action: &action,
				Resource: resourceObject(c.connectionID),
				Metadata: jsvalue.Object{
					{Key: "platform", Value: string(c.adapter.Platform())}, {Key: "baseIdentity", Value: c.baseIdentity},
					{Key: "destination", Value: described}, {Key: "credential", Value: credentialWord(got.r.supplied)},
					{Key: "credentialKind", Value: "token"}, {Key: "status", Value: string(check.Status)}, {Key: "httpStatus", Value: httpStatusOrNull(check)},
				},
			}); err != nil {
				return nil, err
			}
			return CheckJS(check), nil
		},
	})
	return result, reports, err
}

func resourceObject(connectionID string) jsvalue.Object {
	if connectionID == "" {
		return nil
	}
	return jsvalue.Object{{Key: "connectionId", Value: connectionID}}
}

// syncObject is a request's destination record for the adapters.
func syncObject(o jsvalue.Object) vsync.Object {
	out := make(vsync.Object, len(o))
	for i, m := range o {
		out[i] = vsync.Member{Key: m.Key, Value: syncValue(m.Value)}
	}
	return out
}

func syncValue(v any) any {
	switch x := v.(type) {
	case jsvalue.Object:
		return syncObject(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = syncValue(e)
		}
		return out
	case int:
		return float64(x)
	case int64:
		return float64(x)
	}
	return v
}

// Destinations is listConnectionDestinations: the destinations a
// credential can see on its base identity, for the dashboard's pickers,
// under the access check's rules. Only destinations the adapter can
// canonicalize come back; the audit records how many, never their names.
func (s *Service) Destinations(ctx context.Context, req Request, org authz.Organization, in CredentialInput) (jsvalue.Object, []auth.PendingReport, error) {
	actor := req.Principal.Identity.ID
	if err := write.RefuseIfDeleting(ctx, s.store().Reader(), org.ID); err != nil {
		return nil, nil, err
	}
	c, err := s.checkInput(ctx, org.ID, in)
	if err != nil {
		return nil, nil, err
	}
	lister, ok := c.adapter.(vsync.DestinationLister)
	if !ok {
		return nil, nil, domainerr.New("VALIDATION_FAILED", "This platform has no destinations to list: the Connection's base identity is the destination")
	}
	refusal, err := s.baseIdentityRefusal(ctx, org.ID, c.baseIdentity, outbound.SyncListing, c.connectionID, actor)
	if err != nil {
		return nil, nil, err
	}
	var r resolved
	result, reports, err := write.RunEffect(ctx, s.Writer, write.Effect[called[vsync.DestinationListing], jsvalue.Object]{
		OrganizationID: org.ID, People: []write.Gate{write.Person(actor, write.Shared)}, Principal: req.Principal,
		Check: func(ctx context.Context, tx *sql.Tx) error { return existsIn(ctx, tx, org.ID, in) },
		Checked: func(ctx context.Context, tx *sql.Tx) error {
			var err error
			r, err = s.resolve(ctx, tx, org.ID, in, c.connectionID)
			return err
		},
		Call: func(ctx context.Context) (called[vsync.DestinationListing], error) {
			if refusal != nil {
				return called[vsync.DestinationListing]{vsync.DestinationListing{Check: refusedCheck(refusal), Items: []vsync.DestinationOption{}}, r}, nil
			}
			listing := lister.ListDestinations(ctx, &vsync.Request{
				BaseIdentity: c.baseIdentity, Destination: vsync.Fields{}, Credential: r.credential, CredentialKind: vsync.Token,
				Client: s.clientFor(org.ID, c.connectionID, outbound.SyncListing),
			})
			return called[vsync.DestinationListing]{listing, r}, nil
		},
		Final: func(ctx context.Context, tx *storage.Tx, got called[vsync.DestinationListing]) (jsvalue.Object, error) {
			now := s.now().UnixMicro()
			listing := got.answer
			if err := recordExpiry(ctx, tx, c.connectionID, got.r, listing.Check.CredentialExpiresAt, now); err != nil {
				return nil, err
			}
			items := []any{}
			for _, it := range listing.Items {
				raw := make(vsync.Object, len(it.Destination))
				for i, f := range it.Destination {
					raw[i] = vsync.Member{Key: f.Key, Value: f.Value}
				}
				if _, err := c.adapter.CanonicalizeDestination(raw); err != nil {
					continue
				}
				dest := jsvalue.Object{}
				for _, f := range it.Destination {
					dest = append(dest, jsvalue.Member{Key: f.Key, Value: f.Value})
				}
				item := jsvalue.Object{{Key: "destination", Value: dest}, {Key: "label", Value: it.Label}}
				if it.Detail != "" {
					item = append(item, jsvalue.Member{Key: "detail", Value: it.Detail})
				}
				items = append(items, item)
			}
			action := "config.sync.manage"
			if _, err := audit.Record(ctx, tx, audit.Event{
				Type: "sync.destinations_listed", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &org.ID, Action: &action,
				Resource: resourceObject(c.connectionID),
				Metadata: jsvalue.Object{
					{Key: "platform", Value: string(c.adapter.Platform())}, {Key: "baseIdentity", Value: c.baseIdentity},
					{Key: "credential", Value: credentialWord(got.r.supplied)}, {Key: "credentialKind", Value: "token"},
					{Key: "status", Value: string(listing.Check.Status)}, {Key: "httpStatus", Value: httpStatusOrNull(listing.Check)},
					{Key: "count", Value: len(items)}, {Key: "truncated", Value: listing.Truncated},
				},
			}); err != nil {
				return nil, err
			}
			check := listing.Check
			if !got.r.supplied {
				check = withKnownExpiry(check, got.r.storedExpiresAt)
			}
			return jsvalue.Object{{Key: "check", Value: CheckJS(check)}, {Key: "items", Value: items}, {Key: "truncated", Value: listing.Truncated}}, nil
		},
	})
	return result, reports, err
}
