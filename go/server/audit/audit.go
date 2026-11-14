// SPDX-License-Identifier: AGPL-3.0-or-later

// Package audit records Security Audit Events (ADR-0016) and serializes
// them, as the TypeScript server's audit/ does (events.ts, attribution.ts,
// exposure.ts, serialize.ts).
//
// Events are written only through Record, inside the caller's storage write
// job: a state change and its events commit together, and a disclosure's
// event commits before any material leaves the process (the caller releases
// it only once storage.DB.Write returned nil). The input carries
// identifiers only; never plaintext, keys or credential material.
//
// Positions. An event's position (event_order) is its rowid, assigned by
// SQLite at insert as max + 1, and the schema's triggers keep the table
// append-only and gap-free (go/server/db MAPPING.md, "Audit positions in
// commit order"). Under lib/storage's single writer that gives
// commit-ordered positions: jobs run one after another, so a job's
// positions follow the previous job's; a job rolled back to its savepoint
// gives its positions back before the next job runs; a failed batch
// commits none of its jobs; and a reader sees a batch's events all at once.
// Record returns the positions, which are final once Write returned nil.
//
// Attribution (ADR-0045, ADR-0046 Decision 8). Inside an authenticated
// request (WithAttribution), an event whose actor is the request's identity
// also names the request's credential, client, listener and tailnet
// resolution, unless the caller set those fields itself: a caller's value
// always wins, null included (Opt).
package audit

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Decisions.
const (
	Allow = "allow"
	Deny  = "deny"
	Info  = "info"
)

// Opt is a field the caller may leave unset, TypeScript's undefined: unset,
// Record fills it from the request's attribution. Null sets it to null.
type Opt[T any] struct {
	set bool
	v   *T
}

// Value sets an Opt to v.
func Value[T any](v T) Opt[T] { return Opt[T]{set: true, v: &v} }

// Null sets an Opt to null.
func Null[T any]() Opt[T] { return Opt[T]{set: true} }

// IsSet reports whether the caller set the field (to a value or null).
func (o Opt[T]) IsSet() bool { return o.set }

// Get returns the value, nil for null or unset.
func (o Opt[T]) Get() *T { return o.v }

// Event is one event to record: AuditEventInput.
//
// Resource, Authz, Tailnet and Metadata are JSON values (jsvalue); nil is
// SQL NULL, as is TypeScript's null or undefined there. An empty Object is
// stored as {} (it is truthy in TypeScript).
type Event struct {
	// ID is the event's ID when the caller needs it before the insert;
	// generated when empty.
	ID                     string
	Type                   string
	Decision               string
	ActorIdentityID        *string
	AuthenticationMethodID *string
	CredentialID           Opt[string]
	// Client is the acting request's client, as clientLabel summarizes
	// its User-Agent; client-reported, never verified.
	Client         Opt[string]
	OrganizationID *string
	Action         *string
	// Resource's values are strings or nil.
	Resource jsvalue.Object
	// Authz is the evaluator's provenance (IDs and outcomes only).
	Authz    any
	Tailnet  Opt[any]
	Listener Opt[string]
	// RequestID: nil is null.
	RequestID *string
	// Metadata's values are strings, numbers, booleans or nil.
	Metadata jsvalue.Object
}

// Attribution is who is acting in the request being served (ADR-0016 §9).
// The /v1 bearer middleware puts it in the request's context once a
// principal is resolved; background work and unauthenticated requests have
// none and are never attributed.
type Attribution struct {
	IdentityID   string
	CredentialID string
	// Client is clientLabel of the request's User-Agent; nil when not
	// recognized. Never an authorization input.
	Client *string
	// Listener is "ordinary" or "tailnet".
	Listener string
	// Tailnet is, on the tailnet listener, the device WhoIs resolved the
	// peer to, or {refused: <reason>}; nil on the ordinary listener.
	Tailnet any
}

type attributionKey struct{}

// WithAttribution returns ctx carrying a.
func WithAttribution(ctx context.Context, a Attribution) context.Context {
	return context.WithValue(ctx, attributionKey{}, a)
}

// AttributionFrom returns the attribution ctx carries, if any.
func AttributionFrom(ctx context.Context) (Attribution, bool) {
	a, ok := ctx.Value(attributionKey{}).(Attribution)
	return a, ok
}

// Recorded is a recorded event: its ID, position and time (microseconds
// since the Unix epoch).
type Recorded struct {
	ID         string
	Position   int64
	OccurredAt int64
}

var known = func() map[string]bool {
	m := make(map[string]bool, len(EventTypes))
	for _, t := range EventTypes {
		m[t] = true
	}
	return m
}()

// Record records events, in order, in the caller's write job (db is the
// job's storage.Tx, or anything sqlc's DBTX the job reads and writes
// through). As recordAuditEvents: the exposure index rows of every event
// first (ADR-0052 Decision 6), then the events, so the index never lags the
// audit log. An error leaves the job to fail, which rolls all of it back.
func Record(ctx context.Context, db query.DBTX, events ...Event) ([]Recorded, error) {
	for _, e := range events {
		if !known[e.Type] {
			return nil, fmt.Errorf("audit: unknown event type %q", e.Type)
		}
		if e.Decision != Allow && e.Decision != Deny && e.Decision != Info {
			return nil, fmt.Errorf("audit: unknown decision %q", e.Decision)
		}
	}
	q := query.New(db)
	var exposures []ExposureEntry
	for _, e := range events {
		if x, ok := ExposureFromEvent(e.indexable()); ok {
			exposures = append(exposures, x)
		}
	}
	if err := IndexExposures(ctx, q, exposures, nil); err != nil {
		return nil, err
	}
	acting, attributed := AttributionFrom(ctx)
	out := make([]Recorded, 0, len(events))
	for _, e := range events {
		r, err := insert(ctx, q, e, acting, attributed)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// Row returns the columns Record stores for e in this context, without
// storing them (the vectors compare them with the TypeScript server's).
func Row(ctx context.Context, e Event) query.RecordAuditEventParams {
	acting, attributed := AttributionFrom(ctx)
	return params(e, acting, attributed)
}

func params(e Event, acting Attribution, hasActing bool) query.RecordAuditEventParams {
	// Only the request's own identity is attributed to its credential: an
	// event about someone else, or with no actor, keeps what the caller gave.
	attributed := hasActing && e.ActorIdentityID != nil && *e.ActorIdentityID == acting.IdentityID
	credential, client, listener := e.CredentialID.Get(), e.Client.Get(), e.Listener.Get()
	var tailnet any
	if t := e.Tailnet.Get(); t != nil {
		tailnet = *t
	}
	if attributed {
		if !e.CredentialID.IsSet() {
			credential = &acting.CredentialID
		}
		if !e.Client.IsSet() {
			client = acting.Client
		}
		if !e.Listener.IsSet() {
			listener = &acting.Listener
		}
		if !e.Tailnet.IsSet() {
			tailnet = acting.Tailnet
		}
	}
	return query.RecordAuditEventParams{
		ID:                     e.ID,
		EventType:              e.Type,
		ActorIdentityID:        str(e.ActorIdentityID),
		AuthenticationMethodID: str(e.AuthenticationMethodID),
		CredentialID:           str(credential),
		OrganizationID:         str(e.OrganizationID),
		Action:                 str(e.Action),
		Resource:               object(e.Resource),
		Decision:               e.Decision,
		Authz:                  jsonText(e.Authz),
		Tailnet:                jsonText(tailnet),
		Listener:               str(listener),
		RequestID:              str(e.RequestID),
		Metadata:               object(e.Metadata),
		Client:                 str(client),
	}
}

func insert(ctx context.Context, q *query.Queries, e Event, acting Attribution, attributed bool) (Recorded, error) {
	p := params(e, acting, attributed)
	// The TypeScript server's columns are jsonb, which refuses what JSON
	// text can hold and jsonb cannot: such an event fails to record there.
	for _, col := range []sql.NullString{p.Resource, p.Authz, p.Tailnet, p.Metadata} {
		if !col.Valid {
			continue
		}
		v, err := jsvalue.Parse([]byte(col.String))
		if err != nil {
			return Recorded{}, fmt.Errorf("audit: recording %s: %w", e.Type, err)
		}
		if err := jsvalue.JsonbRefuses(v); err != nil {
			return Recorded{}, fmt.Errorf("audit: recording %s: %w", e.Type, err)
		}
	}
	if p.ID == "" {
		p.ID = ids.New(ids.AuditEvent)
	}
	row, err := q.RecordAuditEvent(ctx, p)
	if err != nil {
		return Recorded{}, fmt.Errorf("audit: recording %s: %w", e.Type, err)
	}
	return Recorded{ID: p.ID, Position: row.EventOrder, OccurredAt: row.OccurredAt}, nil
}

func str(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

func object(o jsvalue.Object) sql.NullString {
	if o == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(jsvalue.Stringify(o)), Valid: true}
}

// jsonText is TypeScript's `v ? JSON.stringify(v) : null` for an object
// value: nil (and a nil Object) is null.
func jsonText(v any) sql.NullString {
	if v == nil {
		return sql.NullString{}
	}
	if o, ok := v.(jsvalue.Object); ok && o == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(jsvalue.Stringify(v)), Valid: true}
}

func (e Event) indexable() Indexable {
	return Indexable{
		EventType:       e.Type,
		ActorIdentityID: e.ActorIdentityID,
		OrganizationID:  e.OrganizationID,
		Resource:        e.Resource,
		Metadata:        e.Metadata,
	}
}

// IndexExposures is indexExposures: one upsert per (Organization, person,
// version, Environment, way), for people only (a machine's deliveries are
// machine activity, never a person's exposure). at, when not nil, gives
// each entry's event time in microseconds (the backfill's); nil is now. The
// first and last times only ever widen, so a replay changes nothing.
func IndexExposures(ctx context.Context, q *query.Queries, entries []ExposureEntry, at []*int64) error {
	type row struct {
		org, identity, version, item, env, way string
		first, last                            *int64
	}
	rows := map[string]*row{}
	var keys []string
	people := map[string]bool{}
	for i, e := range entries {
		var t *int64
		if at != nil {
			t = at[i]
		}
		people[e.IdentityID] = true
		for _, it := range e.Items {
			key := strings.Join([]string{e.OrganizationID, e.IdentityID, it.VersionID, e.EnvironmentID, e.Way}, "\x00")
			r, ok := rows[key]
			if !ok {
				rows[key] = &row{e.OrganizationID, e.IdentityID, it.VersionID, it.ItemName, e.EnvironmentID, e.Way, t, t}
				keys = append(keys, key)
				continue
			}
			if t != nil {
				if r.first == nil || *t < *r.first {
					r.first = t
				}
				if r.last == nil || *t > *r.last {
					r.last = t
				}
			}
		}
	}
	if len(rows) == 0 {
		return nil
	}
	humans, err := q.HumanIdentities(ctx, keysOf(people))
	if err != nil {
		return err
	}
	human := map[string]bool{}
	for _, h := range humans {
		human[h] = true
	}
	slices.Sort(keys)
	for _, k := range keys {
		r := rows[k]
		if !human[r.identity] {
			continue
		}
		if err := q.IndexExposure(ctx, query.IndexExposureParams{
			OrganizationID: r.org, IdentityID: r.identity, VersionID: r.version, ItemName: r.item,
			EnvironmentID: r.env, Way: r.way, FirstAt: nullInt(r.first), LastAt: nullInt(r.last),
		}); err != nil {
			return fmt.Errorf("audit: indexing an exposure: %w", err)
		}
	}
	return nil
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func nullInt(v *int64) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *v, Valid: true}
}
