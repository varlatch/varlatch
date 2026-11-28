// SPDX-License-Identifier: AGPL-3.0-or-later

// Package webhooks is an Organization's audit webhooks (ADR-0016,
// ADR-0029 section 8; domain/webhooks.ts; ADR-0059 step 4.7b): an HTTPS
// (or allowed http) endpoint that receives batches of the Organization's
// own audit events, signed with a per-webhook secret (HMAC-SHA256 over
// "<unix-seconds>.<body>", so receivers can verify origin and reject
// replays). Delivery is a cursor walk over audit_events, at least once, in
// order, with no queue, starting at registration: a webhook never
// receives history. The append-only audit log stays the authoritative
// record.
//
// Registering, changing and revoking one are protected operations
// (ADR-0054, security.Prepare): admin-step-up's webhook.create, .update
// and .delete. A URL the outbound policy refuses is refused before any
// approval is asked for, and the refusal recorded (ADR-0057 Decision 6);
// a name that does not resolve is saved, and delivery decides later.
package webhooks

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/whatwg"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// Service is what the operations and the delivery loop work with.
type Service struct {
	Writer    *write.Writer
	Approvals *auth.Service
	RootKEK   []byte
	// Policy is the outbound policy; every delivery goes through its
	// webhook client.
	Policy *outbound.Policy
	Now    func() time.Time
	Log    *slog.Logger
	// client replaces the policy's client (tests only).
	client *http.Client
}

func (s *Service) store() *storage.DB { return s.Writer.Store }

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Webhook is a webhook row as the API serializes it (WebhookRow).
type Webhook struct {
	ID            string
	URL           string
	EventTypes    []string // nil: every event
	CreatedAt     int64
	FailureCount  int64
	LastAttemptAt sql.NullInt64
	LastStatus    sql.NullString
	Version       int64
	UpdatedAt     sql.NullInt64
}

func iso(n sql.NullInt64) any {
	if !n.Valid {
		return nil
	}
	return audit.ISOTime(n.Int64)
}

func eventTypesJS(types []string) any {
	if types == nil {
		return nil
	}
	out := make([]any, len(types))
	for i, t := range types {
		out[i] = t
	}
	return out
}

// JS is serializeWebhook.
func (w Webhook) JS() jsvalue.Object {
	var status any
	if w.LastStatus.Valid {
		status = w.LastStatus.String
	}
	return jsvalue.Object{
		{Key: "id", Value: w.ID}, {Key: "url", Value: w.URL}, {Key: "eventTypes", Value: eventTypesJS(w.EventTypes)},
		{Key: "createdAt", Value: audit.ISOTime(w.CreatedAt)}, {Key: "failureCount", Value: w.FailureCount},
		{Key: "lastAttemptAt", Value: iso(w.LastAttemptAt)}, {Key: "lastStatus", Value: status},
		{Key: "version", Value: w.Version}, {Key: "updatedAt", Value: iso(w.UpdatedAt)},
	}
}

// parseEventTypes reads the stored filter: a JSON array, or NULL.
func parseEventTypes(text sql.NullString) ([]string, error) {
	if !text.Valid {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(text.String), &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

// storedEventTypes is the filter as stored: the request's order, or NULL.
func storedEventTypes(types []string) (sql.NullString, error) {
	if types == nil {
		return sql.NullString{}, nil
	}
	for _, t := range types {
		if _, err := write.Text(t); err != nil {
			return sql.NullString{}, err
		}
	}
	return sql.NullString{String: string(jsvalue.Stringify(eventTypesJS(types))), Valid: true}, nil
}

func joined(types []string) any {
	if types == nil {
		return nil
	}
	s := ""
	for i, t := range types {
		if i > 0 {
			s += ","
		}
		s += t
	}
	return s
}

func notFound() error { return domainerr.New("RESOURCE_NOT_FOUND", "Webhook not found") }

func conflict() error {
	return domainerr.New("VERSION_CONFLICT", "Webhook was modified concurrently; reload and retry")
}

func fromRow(id, url string, types sql.NullString, createdAt, failures int64, attempt sql.NullInt64, status sql.NullString, version int64, updated sql.NullInt64) (Webhook, error) {
	et, err := parseEventTypes(types)
	return Webhook{ID: id, URL: url, EventTypes: et, CreatedAt: createdAt, FailureCount: failures, LastAttemptAt: attempt,
		LastStatus: status, Version: version, UpdatedAt: updated}, err
}

// List is listWebhooks: the Organization's live webhooks, oldest first,
// each URL its envelope's (URLs).
func List(ctx context.Context, db query.DBTX, rootKEK []byte, organizationID string) ([]any, error) {
	rows, err := query.New(db).OrganizationWebhooks(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	urls := NewURLs(rootKEK, db)
	defer urls.Close()
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		url, err := urls.Of(ctx, r.OrganizationID, r.ID, r.Url, r.UrlEnvelope)
		if err != nil {
			return nil, err
		}
		w, err := fromRow(r.ID, url, r.EventTypes, r.CreatedAt, r.FailureCount, r.LastAttemptAt, r.LastStatus, r.Version, r.UpdatedAt)
		if err != nil {
			return nil, err
		}
		out = append(out, w.JS())
	}
	return out, nil
}

// read is readWebhook (and updateWebhook's row read): a live webhook of
// the Organization, its URL its envelope's; nil when there is none.
func read(ctx context.Context, db query.DBTX, rootKEK []byte, organizationID, webhookID string) (*Webhook, error) {
	r, err := query.New(db).LiveWebhook(ctx, query.LiveWebhookParams{ID: webhookID, OrganizationID: organizationID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	urls := NewURLs(rootKEK, db)
	defer urls.Close()
	url, err := urls.Of(ctx, r.OrganizationID, r.ID, r.Url, r.UrlEnvelope)
	if err != nil {
		return nil, err
	}
	w, err := fromRow(r.ID, url, r.EventTypes, r.CreatedAt, r.FailureCount, r.LastAttemptAt, r.LastStatus, r.Version, r.UpdatedAt)
	return &w, err
}

func (w Webhook) ref() Ref {
	return Ref{ID: w.ID, URL: w.URL, EventTypes: w.EventTypes, Version: w.Version}
}

// ValidateURL is validateWebhookUrl: a URL (WHATWG), http or https, with
// no userinfo, so audit diffs stay credential-safe.
func ValidateURL(raw string) error {
	u, ok := whatwg.ParseURL(raw)
	if !ok {
		return domainerr.New("VALIDATION_FAILED", "Invalid webhook URL")
	}
	if u.Protocol != "https:" && u.Protocol != "http:" {
		return domainerr.New("VALIDATION_FAILED", "Webhook URL must be http(s)")
	}
	if u.Username != "" || u.Password != "" {
		return domainerr.New("VALIDATION_FAILED", "Webhook URL must not contain userinfo credentials")
	}
	return nil
}

// refuseOutbound is refuseOutboundWebhook: a URL the outbound policy
// refuses is refused (ADR-0057 Decision 6), with wording that names the
// class, never the address, and its refusal recorded in a job of its own
// when record is set (the TypeScript server records it on the request's
// connection: kept, except inside withIdempotency's transaction, which the
// refusal rolls back).
func (s *Service) refuseOutbound(ctx context.Context, organizationID, url, webhookID, actor string, record bool) error {
	refusal, err := s.Policy.RefusalFor(ctx, url, outbound.Webhook)
	if err != nil || refusal == nil {
		return err
	}
	if !record {
		return refused(refusal)
	}
	resource := jsvalue.Object{}
	if webhookID != "" {
		resource = jsvalue.Object{{Key: "webhookId", Value: webhookID}}
	}
	if err := s.Policy.RecordRefusal(ctx, s.store(), outbound.RefusalRecord{
		OrganizationID: organizationID, Purpose: outbound.Webhook, Phase: "configuration", Refusal: refusal,
		Resource: resource, ActorIdentityID: &actor,
	}); err != nil {
		return err
	}
	return refused(refusal)
}

func refused(r *outbound.RefusedError) error {
	return &domainerr.Error{Code: "VALIDATION_FAILED", Message: r.Error(), Details: jsvalue.Object{{Key: "outbound", Value: string(r.Reason)}}}
}

// Request is who asks, with what Varlatch-Approval header (nil for none),
// the request's id and its Idempotency-Key ("" for none).
type Request struct {
	Principal      *auth.Principal
	Approval       *string
	RequestID      string
	IdempotencyKey string
}

func (r Request) security(approvals *auth.Service) security.Request {
	out := security.Request{Principal: r.Principal, Approvals: approvals}
	if r.Approval != nil {
		if out.ApprovalID = auth.ParseApprovalID(*r.Approval); out.ApprovalID == "" {
			out.ApprovalMalformed = true
		}
	}
	return out
}

// manageIn is actionIn's organization.manage, rechecked in a protected
// operation's job once its approval was consumed; a denial's event is
// recorded after the job (authorizeInTransaction).
func manageIn(p *auth.Principal, organizationID, requestID string) func(ctx context.Context, tx query.DBTX) error {
	return func(ctx context.Context, tx query.DBTX) error {
		ap := authz.Principal{IdentityID: p.Identity.ID, IdentityKind: p.Identity.Kind, CredentialID: p.Credential.ID}
		if p.Identity.OrganizationID != nil {
			ap.OrganizationID = *p.Identity.OrganizationID
		}
		d, err := authz.Decide(ctx, tx, ap, "organization.manage", authz.Resource{OrganizationID: organizationID}, authz.Options{HideExistence: true, RequestID: requestID})
		if err != nil || d.Allowed {
			return err
		}
		if d.DenialEvent != nil {
			return &security.DeferredDenial{Err: d.Err, Event: *d.DenialEvent}
		}
		return d.Err
	}
}

// NewSecret is a signing secret: vlt_whsec_ and 32 random bytes,
// base64url without padding.
func NewSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "vlt_whsec_" + base64.RawURLEncoding.EncodeToString(b)
}

// orgKEK is orgKekOf, read in db: a deleted Organization's KEK is
// destroyed, so it fails closed.
func (s *Service) orgKEK(organizationID string, wrapped sql.NullString) ([]byte, error) {
	return unwrapOrgKEK(s.RootKEK, organizationID, wrapped)
}

// Created is createWebhook's answer: the webhook and its signing secret,
// shown once.
type Created struct {
	Webhook Webhook
	Secret  string
}

// JS is the answer as the API gives it.
func (c Created) JS() jsvalue.Object {
	return append(c.Webhook.JS(), jsvalue.Member{Key: "secret", Value: c.Secret})
}

// Create is createWebhook: refused while the Organization is being
// deleted (the incident freeze refused at entry), then the URL validated
// and checked by the outbound policy, both before any approval; then the
// protected operation. The secret rests encrypted under the Organization
// KEK (it must be recoverable to sign deliveries, so hashing does not
// apply). The cursor starts at the creation event itself, so a webhook
// never receives its own registration nor anything before.
func (s *Service) Create(ctx context.Context, req Request, org authz.Organization, url string, eventTypes []string) (Created, []auth.PendingReport, error) {
	actor := req.Principal.Identity.ID
	reader := s.store().Reader()
	if err := write.RefuseIfDeleting(ctx, reader, org.ID); err != nil {
		return Created{}, nil, err
	}
	if err := ValidateURL(url); err != nil {
		return Created{}, nil, err
	}
	if err := s.refuseOutbound(ctx, org.ID, url, "", actor, true); err != nil {
		return Created{}, nil, err
	}
	id := ids.New(ids.Webhook)
	secret := NewSecret()
	o, err := query.New(reader).RetrievalOrganization(ctx, org.ID)
	if err != nil {
		return Created{}, nil, err
	}
	kek, err := s.orgKEK(org.ID, o.WrappedOrgKek)
	if err != nil {
		return Created{}, nil, err
	}
	sealed, err := envelope.Seal(kek, []byte(secret), envelope.WebhookSecretContext(org.ID, id))
	if err != nil {
		return Created{}, nil, err
	}
	sealedText, err := json.Marshal(sealed)
	if err != nil {
		return Created{}, nil, err
	}
	sealedURL, err := SealURL(kek, org.ID, id, url)
	if err != nil {
		return Created{}, nil, err
	}
	r := req.security(s.Approvals)
	var out Created
	var reports []auth.PendingReport
	err = s.Writer.Job(ctx, r.Gates(org.ID), func(ctx context.Context, tx *storage.Tx) error {
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: org.ID},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: "webhook.create"}},
			Binding: func(context.Context, query.DBTX, *int64) (*auth.Binding, error) {
				return createBinding(org.ID, org.Name, url, eventTypes), nil
			},
			AuthorizeIn: manageIn(req.Principal, org.ID, req.RequestID),
		}, s.now)
		if err != nil {
			return err
		}
		reports = p.Access
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		md := jsvalue.Object{{Key: "url", Value: audit.RedactWebhookURL(url)}}
		if eventTypes != nil {
			md = append(md, jsvalue.Member{Key: "eventTypes", Value: joined(eventTypes)})
		}
		action := "organization.manage"
		recorded, err := audit.Record(ctx, tx, audit.Event{
			Type: "webhook.created", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &org.ID, Action: &action,
			Resource: jsvalue.Object{{Key: "webhookId", Value: id}}, Metadata: append(md, security.ApprovalMetadata(p.Approval)...),
		})
		if err != nil {
			return err
		}
		stored, err := write.Text(url)
		if err != nil {
			return err
		}
		types, err := storedEventTypes(eventTypes)
		if err != nil {
			return err
		}
		at := recorded[0].OccurredAt
		if err := query.New(tx).InsertWebhook(ctx, query.InsertWebhookParams{
			ID: id, OrganizationID: org.ID, Url: stored, UrlEnvelope: sql.NullString{String: sealedURL, Valid: true}, EventTypes: types, SecretEnvelope: string(sealedText),
			CreatedBy: sql.NullString{String: actor, Valid: true}, CreatedAt: at,
			CursorOccurredAt: at, CursorEventID: recorded[0].ID, CursorOrder: recorded[0].Position,
		}); err != nil {
			return err
		}
		out = Created{Webhook: Webhook{ID: id, URL: url, EventTypes: eventTypes, CreatedAt: at, Version: 1}, Secret: secret}
		return nil
	})
	if err != nil {
		return Created{}, nil, err
	}
	return out, reports, nil
}

// Patch is updateWebhook's patch: the version the request expects, and
// what it changes.
type Patch struct {
	ExpectedVersion int64
	URL             *string // nil: unchanged
	// EventTypes replaces the whole filter when SetEventTypes; nil then
	// clears it (every event).
	EventTypes    []string
	SetEventTypes bool
	// Body is zod's output, which the Idempotency-Key's digest covers.
	Body jsvalue.Object
}

// Update is updateWebhook (ADR-0029 section 8), in place: the signing
// secret and the cursor are untouched, so what is not delivered yet goes
// to the new URL and filter. A URL that changes is validated and checked
// by the outbound policy before the job (a filter change keeps working on
// a refused URL). Under an Idempotency-Key when the request has one. A
// protected operation (webhook.update): a patch that means the same
// webhook (a reordering included) needs no approval and is not counted,
// yet is written; one that changes nothing answers the current row.
func (s *Service) Update(ctx context.Context, req Request, organizationID, webhookID string, patch Patch) (write.Response, []auth.PendingReport, error) {
	actor := req.Principal.Identity.ID
	claim := write.Claim{IdentityID: actor, Endpoint: "PATCH webhooks " + webhookID, Key: req.IdempotencyKey, Digest: write.BodyHash(patch.Body, s.RootKEK)}
	// The TypeScript route runs updateWebhook inside withIdempotency: a
	// key's length first, then its claim, whose INSERT fails on U+0000 in
	// the key or the endpoint's webhook id (a replay answers its stored
	// response, another body IDEMPOTENCY_CONFLICT), and only then the URL's
	// checks, whose refusal record that transaction rolls back. The checks
	// run before the job here, so the policy's DNS lookups never hold the
	// writer; a claim made in between is still answered by the job.
	claimed, err := write.Claimed(ctx, s.store().Reader(), claim)
	if err != nil {
		return write.Response{}, nil, err
	}
	if patch.URL != nil && !claimed {
		if err := ValidateURL(*patch.URL); err != nil {
			return write.Response{}, nil, err
		}
		reader := s.store().Reader()
		row, err := query.New(reader).StoredWebhookURL(ctx, query.StoredWebhookURLParams{ID: webhookID, OrganizationID: organizationID})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return write.Response{}, nil, err
		}
		stored := ""
		if err == nil {
			urls := NewURLs(s.RootKEK, reader)
			stored, err = urls.Of(ctx, organizationID, webhookID, row.Url, row.UrlEnvelope)
			urls.Close()
			if err != nil {
				return write.Response{}, nil, err
			}
		}
		if err != nil || stored != *patch.URL {
			if err := s.refuseOutbound(ctx, organizationID, *patch.URL, webhookID, actor, req.IdempotencyKey == ""); err != nil {
				return write.Response{}, nil, err
			}
		}
	}
	next := func(current Webhook) (string, []string) {
		url, types := current.URL, current.EventTypes
		if patch.URL != nil {
			url = *patch.URL
		}
		if patch.SetEventTypes {
			types = patch.EventTypes
		}
		return url, types
	}
	r := req.security(s.Approvals)
	return security.IdempotentProtected(ctx, s.Writer, r, organizationID, claim, func(ctx context.Context, tx *storage.Tx, reports *[]auth.PendingReport) (write.Response, error) {
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: "webhook.update"}},
			Preflight: func(ctx context.Context, db query.DBTX) error {
				w, err := read(ctx, db, s.RootKEK, organizationID, webhookID)
				if err == nil && w == nil {
					err = notFound()
				}
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				current, err := read(ctx, db, s.RootKEK, organizationID, webhookID)
				switch {
				case err != nil:
					return nil, err
				case current == nil:
					return nil, notFound()
				case current.Version != patch.ExpectedVersion:
					return nil, conflict()
				}
				url, types := next(*current)
				if Same(current.URL, current.EventTypes, url, types) {
					return nil, nil
				}
				return updateBinding(organizationID, current.ref(), url, types, patch.ExpectedVersion), nil
			},
			AuthorizeIn: manageIn(req.Principal, organizationID, req.RequestID),
		}, s.now)
		if err != nil {
			return write.Response{}, err
		}
		*reports = p.Access
		row, err := read(ctx, tx, s.RootKEK, organizationID, webhookID)
		switch {
		case err != nil:
			return write.Response{}, err
		case row == nil:
			return write.Response{}, notFound()
		case row.Version != patch.ExpectedVersion:
			return write.Response{}, conflict()
		}
		url, types := next(*row)
		unchanged := url == row.URL && (types == nil) == (row.EventTypes == nil) && equal(types, row.EventTypes)
		if unchanged {
			return write.Response{Status: 200, Payload: row.JS()}, nil
		}
		stored, err := write.Text(url)
		if err != nil {
			return write.Response{}, err
		}
		storedTypes, err := storedEventTypes(types)
		if err != nil {
			return write.Response{}, err
		}
		// Both forms of the URL, the envelope sealed again whatever changed.
		o, err := query.New(tx).RetrievalOrganization(ctx, organizationID)
		if err != nil {
			return write.Response{}, err
		}
		kek, err := s.orgKEK(organizationID, o.WrappedOrgKek)
		if err != nil {
			return write.Response{}, err
		}
		sealedURL, err := SealURL(kek, organizationID, webhookID, url)
		clear(kek)
		if err != nil {
			return write.Response{}, err
		}
		at := s.now().UnixMicro()
		updated, err := query.New(tx).UpdateWebhook(ctx, query.UpdateWebhookParams{Url: stored, UrlEnvelope: sql.NullString{String: sealedURL, Valid: true},
			EventTypes: storedTypes, UpdatedAt: sql.NullInt64{Int64: at, Valid: true}, ID: webhookID})
		if err != nil {
			return write.Response{}, err
		}
		// Report mode counts what enforce would ask an approval for: a
		// change of the URL or of the set of event types, not a reordering.
		if !Same(row.URL, row.EventTypes, url, types) {
			if err := p.Count(ctx, tx); err != nil {
				return write.Response{}, err
			}
		}
		action := "organization.manage"
		md := jsvalue.Object{
			{Key: "oldUrl", Value: audit.RedactWebhookURL(row.URL)}, {Key: "newUrl", Value: audit.RedactWebhookURL(url)},
			{Key: "oldEventTypes", Value: joined(row.EventTypes)}, {Key: "newEventTypes", Value: joined(types)},
			{Key: "version", Value: updated.Version},
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "webhook.updated", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "webhookId", Value: webhookID}}, Metadata: append(md, security.ApprovalMetadata(p.Approval)...),
		}); err != nil {
			return write.Response{}, err
		}
		out := *row
		out.URL, out.EventTypes, out.Version, out.UpdatedAt = url, types, updated.Version, updated.UpdatedAt
		return write.Response{Status: 200, Payload: out.JS()}, nil
	})
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stateChanged() error {
	return domainerr.New("STATE_CHANGED", "The webhook changed since the approval was asked for; nothing was changed. Read it again and ask for a new approval")
}

// Revoke is revokeWebhook: a protected operation (webhook.delete), bound
// to the version the server read and checked again in the job. Not a
// recovery operation: an incident freeze refuses it (ADR-0055 Decision
// 3), so a stolen admin credential cannot cut the audit stream.
func (s *Service) Revoke(ctx context.Context, req Request, organizationID, webhookID string) ([]auth.PendingReport, error) {
	actor := req.Principal.Identity.ID
	r := req.security(s.Approvals)
	var reports []auth.PendingReport
	err := s.Writer.Job(ctx, r.Gates(organizationID), func(ctx context.Context, tx *storage.Tx) error {
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: "webhook.delete"}},
			Preflight: func(ctx context.Context, db query.DBTX) error {
				w, err := read(ctx, db, s.RootKEK, organizationID, webhookID)
				if err == nil && w == nil {
					err = notFound()
				}
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				w, err := read(ctx, db, s.RootKEK, organizationID, webhookID)
				switch {
				case err != nil:
					return nil, err
				case w == nil:
					return nil, notFound()
				}
				return deleteBinding(organizationID, w.ref()), nil
			},
			AuthorizeIn: manageIn(req.Principal, organizationID, req.RequestID),
		}, s.now)
		if err != nil {
			return err
		}
		reports = p.Access
		if p.Binding != nil {
			locked, err := read(ctx, tx, s.RootKEK, organizationID, webhookID)
			switch {
			case err != nil:
				return err
			case locked == nil:
				return notFound()
			case p.Binding.ExpectedVersion != nil && locked.Version != *p.Binding.ExpectedVersion:
				return stateChanged()
			}
		}
		_, err = query.New(tx).RevokeWebhook(ctx, query.RevokeWebhookParams{RevokedAt: sql.NullInt64{Int64: s.now().UnixMicro(), Valid: true}, ID: webhookID, OrganizationID: organizationID})
		if errors.Is(err, sql.ErrNoRows) {
			return notFound()
		}
		if err != nil {
			return err
		}
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		action := "organization.manage"
		e := audit.Event{Type: "webhook.revoked", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "webhookId", Value: webhookID}}}
		if p.Approval != nil {
			e.Metadata = security.ApprovalMetadata(p.Approval)
		}
		_, err = audit.Record(ctx, tx, e)
		return err
	})
	return reports, err
}
