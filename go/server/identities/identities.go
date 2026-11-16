// SPDX-License-Identifier: AGPL-3.0-or-later

// Package identities is an Organization's machine identities and their
// credentials (ADR-0015, ADR-0034; domain/identities.ts and the issuing side
// of auth/credentials.ts; ADR-0059 step 4.4a): creating one with its first
// service credential, issuing another, revoking one, retiring, reactivating
// and renaming, and the reads. Creation, issuance and reactivation are
// protected operations (ADR-0054, go/server/security.Prepare): admin-step-up
// and credential-lifetime decide them in their write job.
package identities

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"
	"unicode/utf16"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// ServiceCredentialKinds is SERVICE_CREDENTIAL_KINDS: the machine kinds
// that hold service credentials, the ones creation issues one for. CI
// identities federate instead and Agents never hold a reusable credential.
var ServiceCredentialKinds = []string{"service", "workload", "broker"}

func notFound() error { return domainerr.New("RESOURCE_NOT_FOUND", "Not found") }

// jsLength is a string's length as JavaScript counts it.
func jsLength(s string) int { return len(utf16.Encode([]rune(s))) }

// ReadMachine is readMachineIdentity: a machine identity of the
// Organization; nil when there is none.
func ReadMachine(ctx context.Context, db query.DBTX, organizationID, identityID string) (*Machine, error) {
	r, err := query.New(db).MachineIdentityOf(ctx, query.MachineIdentityOfParams{ID: identityID, OrganizationID: sql.NullString{String: organizationID, Valid: true}})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &Machine{ID: r.ID, Name: r.Name, Kind: r.Kind, Disabled: r.Disabled, SuspendedByDeletion: r.SuspendedByDeletion.Valid}, nil
}

// ref is an identity of the Organization as the routes load it: its kind
// and whether it is disabled; nil when the Organization has none with the id.
type ref struct {
	Kind     string
	Disabled bool
}

func load(ctx context.Context, db query.DBTX, organizationID, identityID string) (*ref, error) {
	r, err := query.New(db).IdentityInOrganization(ctx, query.IdentityInOrganizationParams{ID: identityID, OrganizationID: sql.NullString{String: organizationID, Valid: true}})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ref{Kind: r.Kind, Disabled: r.Disabled}, nil
}

// LoadMachine is the route's loadMachineIdentity: a machine identity of the
// Organization (a person, or none, is not found). It returns its kind and
// whether it is disabled.
func LoadMachine(ctx context.Context, db query.DBTX, organizationID, identityID string) (kind string, disabled bool, err error) {
	r, err := load(ctx, db, organizationID, identityID)
	if err != nil {
		return "", false, err
	}
	if r == nil || r.Kind == "human" {
		return "", false, notFound()
	}
	return r.Kind, r.Disabled, nil
}

// LoadAgent is loadAgentIdentity: an enabled Agent identity of the
// Organization; wrong Organization, kind or a disabled one are not found.
func LoadAgent(ctx context.Context, db query.DBTX, organizationID, identityID string) error {
	r, err := load(ctx, db, organizationID, identityID)
	if err != nil {
		return err
	}
	if r == nil || r.Kind != "agent" || r.Disabled {
		return notFound()
	}
	return nil
}

func iso(n sql.NullInt64) any {
	if !n.Valid {
		return nil
	}
	return audit.ISOTime(n.Int64)
}

func str(n sql.NullString) any {
	if !n.Valid {
		return nil
	}
	return n.String
}

// List is GET …/identities' items (listOrgIdentities): the Organization's
// machines and every person with a membership, former members with no role
// and the time they left, people with their profile's email and image.
func List(ctx context.Context, db query.DBTX, organizationID string) ([]any, error) {
	rows, err := query.New(db).OrganizationIdentities(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		var role any
		if !r.RemovedAt.Valid {
			role = str(r.OrgRole)
		}
		out = append(out, jsvalue.Object{
			{Key: "id", Value: r.ID}, {Key: "name", Value: r.Name}, {Key: "kind", Value: r.Kind}, {Key: "disabled", Value: r.Disabled},
			{Key: "lastSeenAt", Value: iso(r.LastSeenAt)}, {Key: "orgRole", Value: role}, {Key: "removedAt", Value: iso(r.RemovedAt)},
			{Key: "email", Value: str(r.Email)}, {Key: "image", Value: str(r.Image)},
		})
	}
	return out, nil
}

// Credentials is GET …/identities/{identity}/credentials' items
// (listIdentityCredentials): metadata only, newest first.
func Credentials(ctx context.Context, db query.DBTX, identityID string) ([]any, error) {
	rows, err := query.New(db).CredentialsOfIdentityNewestFirst(ctx, identityID)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, jsvalue.Object{
			{Key: "id", Value: r.ID}, {Key: "kind", Value: r.Kind}, {Key: "name", Value: str(r.Name)},
			{Key: "createdAt", Value: audit.ISOTime(r.CreatedAt)}, {Key: "expiresAt", Value: iso(r.ExpiresAt)},
			{Key: "revokedAt", Value: iso(r.RevokedAt)}, {Key: "lastUsedAt", Value: iso(r.LastUsedAt)}, {Key: "client", Value: str(r.Client)},
		})
	}
	return out, nil
}

// expiryOf is expiryOf: ttl seconds from now, or never without one. As a
// JavaScript Date, in milliseconds.
func expiryOf(now time.Time, ttl *int64) *int64 {
	if ttl == nil || *ttl == 0 {
		return nil
	}
	at := (now.UnixMilli() + *ttl*1000) * 1000
	return &at
}

// approvalRequest is withApproval's input: the header as sent (nil for
// none; an empty one is sent, and cannot be an approval id).
func approvalRequest(p *auth.Principal, approval *string, approvals *auth.Service) security.Request {
	r := security.Request{Principal: p, Approvals: approvals}
	if approval != nil {
		if r.ApprovalID = auth.ParseApprovalID(*approval); r.ApprovalID == "" {
			r.ApprovalMalformed = true
		}
	}
	return r
}

// authorizeIn is identityManageIn: identity.manage rechecked in a
// protected operation's job once its approval was consumed. A denial's
// event is recorded after the job (authorizeInTransaction).
func authorizeIn(p *auth.Principal, organizationID, requestID string) func(ctx context.Context, tx query.DBTX) error {
	return func(ctx context.Context, tx query.DBTX) error {
		ap := authz.Principal{IdentityID: p.Identity.ID, IdentityKind: p.Identity.Kind, CredentialID: p.Credential.ID}
		if p.Identity.OrganizationID != nil {
			ap.OrganizationID = *p.Identity.OrganizationID
		}
		d, err := authz.Decide(ctx, tx, ap, "identity.manage", authz.Resource{OrganizationID: organizationID}, authz.Options{HideExistence: true, RequestID: requestID})
		if err != nil || d.Allowed {
			return err
		}
		if d.DenialEvent != nil {
			return &security.DeferredDenial{Err: d.Err, Event: *d.DenialEvent}
		}
		return d.Err
	}
}

// Request is who asks, with what Varlatch-Approval header (nil for none;
// read only when an approval is due), and the request's id.
type Request struct {
	Principal *auth.Principal
	Approval  *string
	RequestID string
}

// Created is createServiceIdentity's answer.
type Created struct {
	ID, Name, Kind string
	// Credential is the service credential's token, shown once; "" for none.
	Credential          string
	CredentialExpiresAt *int64
}

// JS is the answer as the API gives it.
func (c Created) JS() jsvalue.Object {
	var token, expires any
	if c.Credential != "" {
		token = c.Credential
	}
	if c.CredentialExpiresAt != nil {
		expires = audit.ISOTime(*c.CredentialExpiresAt)
	}
	return jsvalue.Object{
		{Key: "id", Value: c.ID}, {Key: "name", Value: c.Name}, {Key: "kind", Value: c.Kind}, {Key: "disabled", Value: false},
		{Key: "credential", Value: token}, {Key: "credentialExpiresAt", Value: expires},
	}
}

func lifetimeMetadata(p *security.Prepared) jsvalue.Object {
	if p.TTLDefaulted {
		return jsvalue.Object{{Key: "lifetimeDefaulted", Value: true}}
	}
	return nil
}

// Create is createMachineIdentity (ADR-0015 §9): a machine identity of the
// Organization with zero Grants; a service, workload or broker identity
// gets its first service credential, shown once. A protected operation:
// admin-step-up's identity.create, and credential-lifetime's when a
// credential is issued (its default for a request without a TTL, its
// refusal of one above the maximum, before anything is created). It
// returns the answer and the report counts to record.
func Create(ctx context.Context, w *write.Writer, approvals *auth.Service, req Request, organizationID string, in CreateInput, now func() time.Time) (Created, []auth.PendingReport, error) {
	if in.Name == "" || jsLength(in.Name) > 200 {
		return Created{}, nil, domainerr.New("VALIDATION_FAILED", "Invalid identity name")
	}
	r := approvalRequest(req.Principal, req.Approval, approvals)
	actor := req.Principal.Identity.ID
	issues := slices.Contains(ServiceCredentialKinds, in.Kind)
	checks := []security.Check{{Control: security.AdminStepUp, Operation: "identity.create"}}
	if issues {
		checks = append(checks, security.Check{Control: security.CredentialLifetime, Operation: "identity.create", TTLSeconds: in.CredentialTTLSeconds})
	}
	var out Created
	var reports []auth.PendingReport
	err := w.Job(ctx, r.Gates(organizationID), func(ctx context.Context, tx *storage.Tx) error {
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID},
			Checks: checks,
			Binding: func(_ context.Context, _ query.DBTX, effective *int64) (*auth.Binding, error) {
				return createBinding(organizationID, in, issues, effective), nil
			},
			AuthorizeIn: authorizeIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		name, err := write.Text(in.Name)
		if err != nil {
			return err
		}
		at := now()
		id := ids.New(ids.Identity)
		q := query.New(tx)
		if err := q.InsertMachineIdentity(ctx, query.InsertMachineIdentityParams{
			ID: id, Kind: in.Kind, Name: name, OrganizationID: sql.NullString{String: organizationID, Valid: true}, CreatedAt: at.UnixMicro(),
		}); err != nil {
			return err
		}
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		action := "identity.manage"
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "identity.created", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID,
			Action: &action, Resource: jsvalue.Object{{Key: "identityId", Value: id}},
			Metadata: append(jsvalue.Object{{Key: "kind", Value: in.Kind}}, security.ApprovalMetadata(p.Approval)...),
		}); err != nil {
			return err
		}
		out = Created{ID: id, Name: in.Name, Kind: in.Kind}
		if !issues {
			return nil
		}
		out.CredentialExpiresAt = expiryOf(at, p.EffectiveTTL)
		credName := in.Name + " credential"
		md := append(lifetimeMetadata(p), security.ApprovalMetadata(p.Approval)...)
		issued, err := auth.IssueCredential(ctx, tx, at.UnixMicro(), auth.Issue{
			IdentityID: id, Kind: "service", Name: &credName, ExpiresAt: out.CredentialExpiresAt, MaxUses: in.CredentialMaxUses,
			ActorIdentityID: &actor, OrganizationID: &organizationID, Metadata: md,
		})
		if err != nil {
			return err
		}
		out.Credential = issued.Token
		return nil
	})
	if err != nil {
		return Created{}, nil, err
	}
	return out, reports, nil
}

// IssuedCredential is issueIdentityCredential's answer for a service
// credential.
type IssuedCredential struct {
	ID, Name, Token string
	ExpiresAt       *int64
	MaxUses         *int64
}

// JS is the answer as the API gives it.
func (c IssuedCredential) JS() jsvalue.Object {
	var expires, maxUses any
	if c.ExpiresAt != nil {
		expires = audit.ISOTime(*c.ExpiresAt)
	}
	if c.MaxUses != nil {
		maxUses = *c.MaxUses
	}
	return jsvalue.Object{
		{Key: "id", Value: c.ID}, {Key: "kind", Value: "service"}, {Key: "name", Value: c.Name},
		{Key: "token", Value: c.Token}, {Key: "expiresAt", Value: expires}, {Key: "maxUses", Value: maxUses},
	}
}

func serviceKindLive(m *Machine) bool {
	return m != nil && slices.Contains(ServiceCredentialKinds, m.Kind) && !m.Disabled
}

// Issue is issueMachineCredential (capability identity.credentials.issue):
// another service credential for a live machine identity of a service
// kind, shown once. A protected operation: admin-step-up's
// credential.issue and credential-lifetime's. The identity's gate is held
// shared, so a retirement (exclusive) either committed before, and the
// identity is not found, or comes after and revokes this credential too.
func Issue(ctx context.Context, w *write.Writer, approvals *auth.Service, req Request, organizationID, identityID string, in IssueInput, now func() time.Time) (IssuedCredential, []auth.PendingReport, error) {
	if in.Name == "" || jsLength(in.Name) > 200 {
		return IssuedCredential{}, nil, domainerr.New("VALIDATION_FAILED", "Invalid credential name")
	}
	r := approvalRequest(req.Principal, req.Approval, approvals)
	actor := req.Principal.Identity.ID
	var out IssuedCredential
	var reports []auth.PendingReport
	err := w.Job(ctx, r.Gates(organizationID, write.Person(identityID, write.Shared)), func(ctx context.Context, tx *storage.Tx) error {
		live := func(ctx context.Context, db query.DBTX) (*Machine, error) {
			m, err := ReadMachine(ctx, db, organizationID, identityID)
			if err != nil {
				return nil, err
			}
			if !serviceKindLive(m) {
				return nil, notFound()
			}
			return m, nil
		}
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope: write.Scope{OrganizationID: organizationID},
			Checks: []security.Check{
				{Control: security.AdminStepUp, Operation: "credential.issue"},
				{Control: security.CredentialLifetime, Operation: "credential.issue", TTLSeconds: in.TTLSeconds},
			},
			Preflight: func(ctx context.Context, db query.DBTX) error { _, err := live(ctx, db); return err },
			Binding: func(ctx context.Context, db query.DBTX, effective *int64) (*auth.Binding, error) {
				m, err := live(ctx, db)
				if err != nil {
					return nil, err
				}
				return issueBinding(organizationID, *m, in, effective), nil
			},
			AuthorizeIn: authorizeIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		if _, err := live(ctx, tx); err != nil {
			return err
		}
		name, err := write.Text(in.Name)
		if err != nil {
			return err
		}
		at := now()
		expires := expiryOf(at, p.EffectiveTTL)
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		var expiresMD, maxUsesMD any
		if expires != nil {
			expiresMD = audit.ISOTime(*expires)
		}
		if in.MaxUses != nil {
			maxUsesMD = *in.MaxUses
		}
		md := jsvalue.Object{{Key: "name", Value: in.Name}, {Key: "expiresAt", Value: expiresMD}, {Key: "maxUses", Value: maxUsesMD}}
		md = append(md, lifetimeMetadata(p)...)
		md = append(md, security.ApprovalMetadata(p.Approval)...)
		issued, err := auth.IssueCredential(ctx, tx, at.UnixMicro(), auth.Issue{
			IdentityID: identityID, Kind: "service", Name: &name, ExpiresAt: expires, MaxUses: in.MaxUses,
			ActorIdentityID: &actor, OrganizationID: &organizationID, Metadata: md,
		})
		if err != nil {
			return err
		}
		out = IssuedCredential{ID: issued.CredentialID, Name: in.Name, Token: issued.Token, ExpiresAt: expires, MaxUses: in.MaxUses}
		return nil
	})
	if err != nil {
		return IssuedCredential{}, nil, err
	}
	return out, reports, nil
}

// AgentRunInput is a Broker's agent-run credential body.
type AgentRunInput struct {
	TTLSeconds int64
	RunID      *string
}

// IssueAgentRun is the Broker's path of issueIdentityCredential (ADR-0023):
// a short-lived, read-only agent-run credential for an enabled Agent of the
// Broker's own Organization, in a job with the writer's checks; the
// Broker's and the Agent's gates are held shared. It returns the
// credential's id, token and expiry, and the report counts.
func IssueAgentRun(ctx context.Context, w *write.Writer, p *auth.Principal, organizationID, agentID string, in AgentRunInput, now func() time.Time) (string, string, int64, []auth.PendingReport, error) {
	at := now()
	expires := (at.UnixMilli() + in.TTLSeconds*1000) * 1000
	var id, token string
	var reports []auth.PendingReport
	broker := p.Identity.ID
	gates := []write.Gate{write.Organization(organizationID, write.Shared), write.Person(broker, write.Shared), write.Person(agentID, write.Shared)}
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: organizationID}); err != nil {
			return err
		}
		var err error
		if reports, err = write.Checkpoint(ctx, tx, p, organizationID); err != nil {
			return err
		}
		if err := LoadAgent(ctx, tx, organizationID, agentID); err != nil {
			return err
		}
		// body.runId ?? "agent-run": an empty runId names it "", and only a
		// non-empty one is recorded.
		name := "agent-run"
		md := jsvalue.Object{}
		if in.RunID != nil {
			stored, err := write.Text(*in.RunID)
			if err != nil {
				return err
			}
			name = stored
			if *in.RunID != "" {
				md = append(md, jsvalue.Member{Key: "runId", Value: *in.RunID})
			}
		}
		md = append(md, jsvalue.Member{Key: "ttlSeconds", Value: in.TTLSeconds})
		issued, err := auth.IssueCredential(ctx, tx, at.UnixMicro(), auth.Issue{
			IdentityID: agentID, Kind: "agent-run", Name: &name, ExpiresAt: &expires,
			ActorIdentityID: &broker, OrganizationID: &organizationID, Metadata: md,
		})
		if err != nil {
			return err
		}
		id, token = issued.CredentialID, issued.Token
		return nil
	})
	if err != nil {
		return "", "", 0, nil, err
	}
	return id, token, expires, reports, nil
}

// Revoke is the route's revocation of a machine credential (ADR-0034 §1):
// in a job with the writer's checks (a Broker's revocation is refused while
// the Organization is frozen; identity.manage's is recovery), the
// credential.revoked event. The caller checked the credential is the
// identity's and of a kind it may revoke.
func Revoke(ctx context.Context, w *write.Writer, p *auth.Principal, organizationID, credentialID string, recovery bool, now func() time.Time) ([]auth.PendingReport, error) {
	actor := p.Identity.ID
	scope := write.Scope{OrganizationID: organizationID}
	if recovery {
		scope.DuringFreeze = authz.DuringFreezeRecovery
	}
	var reports []auth.PendingReport
	gates := []write.Gate{write.Organization(organizationID, write.Shared), write.Person(actor, write.Shared)}
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, scope); err != nil {
			return err
		}
		var err error
		if reports, err = write.Checkpoint(ctx, tx, p, organizationID); err != nil {
			return err
		}
		return auth.RevokeCredential(ctx, tx, now().UnixMicro(), credentialID, actor, &organizationID)
	})
	return reports, err
}

// CredentialOfKinds reports whether credentialID is identityID's and of one
// of kinds.
func CredentialOfKinds(ctx context.Context, db query.DBTX, identityID, credentialID string, kinds ...string) (bool, error) {
	_, err := query.New(db).CredentialOfKinds(ctx, query.CredentialOfKindsParams{ID: credentialID, IdentityID: identityID, Kinds: kinds})
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// Retire is retireIdentity (ADR-0034 §3): disable the identity and revoke
// every live credential in one job, so a later reactivation never
// resurrects a credential minted before. The identity's gate is held
// exclusive (the TypeScript code locks it FOR UPDATE). Recovery while
// frozen.
func Retire(ctx context.Context, w *write.Writer, p *auth.Principal, organizationID, identityID string, now func() time.Time) ([]auth.PendingReport, error) {
	actor := p.Identity.ID
	var reports []auth.PendingReport
	gates := []write.Gate{write.Organization(organizationID, write.Shared), write.Person(actor, write.Shared), write.Person(identityID, write.Exclusive)}
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: organizationID, DuringFreeze: authz.DuringFreezeRecovery}); err != nil {
			return err
		}
		var err error
		if reports, err = write.Checkpoint(ctx, tx, p, organizationID); err != nil {
			return err
		}
		q := query.New(tx)
		if err := q.SetIdentityDisabled(ctx, query.SetIdentityDisabledParams{Disabled: true, ID: identityID}); err != nil {
			return err
		}
		live, err := q.LiveCredentialsOfIdentity(ctx, identityID)
		if err != nil {
			return err
		}
		at := now().UnixMicro()
		for _, id := range live {
			if err := auth.RevokeCredential(ctx, tx, at, id, actor, &organizationID); err != nil {
				return err
			}
		}
		action := "identity.manage"
		_, err = audit.Record(ctx, tx, audit.Event{
			Type: "identity.retired", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "identityId", Value: identityID}},
			Metadata: jsvalue.Object{{Key: "revokedCredentials", Value: len(live)}},
		})
		return err
	})
	return reports, err
}

func suspendedByDeletion() error {
	return domainerr.New("ORGANIZATION_DELETING", "This identity was suspended by the Organization's deletion; cancelling the deletion restores it")
}

// Reactivate is reactivateIdentity: clear the disabled flag only, so the
// identity has no working credential until one is issued (ADR-0034 §3). A
// protected operation: admin-step-up's identity.reactivate for a disabled
// identity; an enabled one changes nothing and needs no approval; one
// suspended by a deletion is refused before any approval is asked for. The
// identity's gate is held exclusive.
func Reactivate(ctx context.Context, w *write.Writer, approvals *auth.Service, req Request, organizationID, identityID string, now func() time.Time) ([]auth.PendingReport, error) {
	r := approvalRequest(req.Principal, req.Approval, approvals)
	actor := req.Principal.Identity.ID
	var reports []auth.PendingReport
	err := w.Job(ctx, r.Gates(organizationID, write.Person(identityID, write.Exclusive)), func(ctx context.Context, tx *storage.Tx) error {
		boundEnabled := false
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: "identity.reactivate"}},
			Preflight: func(ctx context.Context, db query.DBTX) error {
				m, err := ReadMachine(ctx, db, organizationID, identityID)
				if err == nil && m == nil {
					err = notFound()
				}
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				m, err := ReadMachine(ctx, db, organizationID, identityID)
				switch {
				case err != nil:
					return nil, err
				case m == nil:
					return nil, notFound()
				case m.SuspendedByDeletion:
					return nil, suspendedByDeletion()
				case !m.Disabled:
					boundEnabled = true
					return nil, nil
				}
				return reactivateBinding(organizationID, *m), nil
			},
			AuthorizeIn: authorizeIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		before, err := ReadMachine(ctx, tx, organizationID, identityID)
		if err != nil {
			return err
		}
		if before != nil && before.SuspendedByDeletion {
			return suspendedByDeletion()
		}
		wasDisabled := before != nil && before.Disabled
		if boundEnabled && wasDisabled {
			return domainerr.New("STATE_CHANGED", "The identity was retired while it was being reactivated; nothing changed. Reactivate it again")
		}
		if err := query.New(tx).SetIdentityDisabled(ctx, query.SetIdentityDisabledParams{Disabled: false, ID: identityID}); err != nil {
			return err
		}
		if wasDisabled {
			if err := p.Count(ctx, tx); err != nil {
				return err
			}
		}
		action := "identity.manage"
		e := audit.Event{
			Type: "identity.reactivated", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "identityId", Value: identityID}},
		}
		if p.Approval != nil {
			e.Metadata = security.ApprovalMetadata(p.Approval)
		}
		_, err = audit.Record(ctx, tx, e)
		return err
	})
	return reports, err
}

// Rename is renameIdentity (ADR-0034 §4): the display name only; Grants,
// credentials and bindings reference the id. The event carries both names.
// The identity's gate is held exclusive.
func Rename(ctx context.Context, w *write.Writer, p *auth.Principal, organizationID, identityID, name string) ([]auth.PendingReport, error) {
	if name == "" || jsLength(name) > 200 {
		return nil, domainerr.New("VALIDATION_FAILED", "Invalid identity name")
	}
	actor := p.Identity.ID
	var reports []auth.PendingReport
	gates := []write.Gate{write.Organization(organizationID, write.Shared), write.Person(actor, write.Shared), write.Person(identityID, write.Exclusive)}
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: organizationID}); err != nil {
			return err
		}
		var err error
		if reports, err = write.Checkpoint(ctx, tx, p, organizationID); err != nil {
			return err
		}
		q := query.New(tx)
		var previous any
		if prev, err := q.IdentityNameOf(ctx, identityID); err == nil {
			previous = prev
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		stored, err := write.Text(name)
		if err != nil {
			return err
		}
		if err := q.SetIdentityName(ctx, query.SetIdentityNameParams{Name: stored, ID: identityID}); err != nil {
			return err
		}
		action := "identity.manage"
		_, err = audit.Record(ctx, tx, audit.Event{
			Type: "identity.renamed", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "identityId", Value: identityID}},
			Metadata: jsvalue.Object{{Key: "previousName", Value: previous}, {Key: "name", Value: name}},
		})
		return err
	})
	return reports, err
}
