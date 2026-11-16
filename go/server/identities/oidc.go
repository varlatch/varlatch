// SPDX-License-Identifier: AGPL-3.0-or-later

package identities

import (
	"context"
	"database/sql"
	"errors"
	"time"

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

// OIDC bindings (domain/oidc.ts; ADR-0059 step 4.8): an admin binds an
// issuer, an audience and a subject (and optional exact-match claims) to
// one machine identity; a workload then exchanges its platform-issued
// token for a short-lived oidc credential (server/oidc). A binding is an
// Authentication Method: it establishes identity only; authority stays
// the identity's Grants.

// OIDCBindingInput is createOidcBinding's input, as zod leaves it. Claims
// keep the request's order; nil for none.
type OIDCBindingInput struct {
	Issuer, Audience, Subject string
	Claims                    jsvalue.Object
}

// BindingJS is serializeBinding: the binding as the API gives it, its
// claims as the jsonb column holds them.
func BindingJS(b query.OidcBinding) (jsvalue.Object, error) {
	var claims any
	if b.Claims.Valid {
		v, err := jsvalue.Parse([]byte(b.Claims.String))
		if err != nil {
			return nil, err
		}
		claims = v
	}
	return jsvalue.Object{
		{Key: "id", Value: b.ID}, {Key: "identityId", Value: b.IdentityID}, {Key: "issuer", Value: b.Issuer},
		{Key: "audience", Value: b.Audience}, {Key: "subject", Value: b.Subject}, {Key: "claims", Value: claims},
		{Key: "createdAt", Value: audit.ISOTime(b.CreatedAt)},
	}, nil
}

func claimsMap(o jsvalue.Object) map[string]string {
	out := make(map[string]string, len(o))
	for _, m := range o {
		out[m.Key], _ = m.Value.(string)
	}
	return out
}

// oidcBindingCreateBinding is oidcBindingCreateBinding: target the
// identity; body the issuer, audience, subject and claims (canonical JSON
// sorts the claims' keys).
func oidcBindingCreateBinding(organizationID string, m Machine, in OIDCBindingInput) *auth.Binding {
	claims := in.Claims
	if claims == nil {
		claims = jsvalue.Object{}
	}
	changes := []auth.ApprovalChange{
		added("issuer", security.Quoted(in.Issuer)), added("audience", security.Quoted(in.Audience)), added("subject", security.Quoted(in.Subject)),
	}
	if len(claims) > 0 {
		changes = append(changes, added("claims", security.QuotedMap(claimsMap(claims))))
	}
	org := organizationID
	return &auth.Binding{
		Operation: "oidc_binding.create", OrganizationID: &org,
		Target: map[string]string{"identityId": m.ID}, Query: map[string]string{},
		Body: jsvalue.Object{{Key: "issuer", Value: in.Issuer}, {Key: "audience", Value: in.Audience}, {Key: "subject", Value: in.Subject}, {Key: "claims", Value: claims}},
		Summary: auth.ApprovalSummary{
			Title: "Let tokens from " + security.Quoted(in.Issuer) + " with subject " + security.Quoted(in.Subject) + " act as " +
				security.LabelWithID("", m.Name, m.ID),
			Changes: changes,
		},
	}
}

// oidcBindingDeleteBinding is oidcBindingDeleteBinding of a live binding.
func oidcBindingDeleteBinding(organizationID string, m Machine, b query.OidcBinding) *auth.Binding {
	org := organizationID
	return &auth.Binding{
		Operation: "oidc_binding.delete", OrganizationID: &org,
		Target: map[string]string{"identityId": m.ID, "oidcBindingId": b.ID}, Query: map[string]string{},
		Summary: auth.ApprovalSummary{
			Title: "Remove the OIDC binding " + b.ID + " (issuer " + security.Quoted(b.Issuer) + ", subject " + security.Quoted(b.Subject) +
				", audience " + security.Quoted(b.Audience) + ") from " + security.LabelWithID("", m.Name, m.ID),
			Changes: []auth.ApprovalChange{},
		},
	}
}

func liveBinding(ctx context.Context, db query.DBTX, organizationID, identityID, bindingID string) (*query.OidcBinding, error) {
	b, err := query.New(db).LiveOidcBinding(ctx, query.LiveOidcBindingParams{ID: bindingID, OrganizationID: organizationID, IdentityID: identityID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &b, err
}

// ListOIDCBindings is listOidcBindings: the identity's live bindings,
// oldest first.
func ListOIDCBindings(ctx context.Context, db query.DBTX, organizationID, identityID string) ([]any, error) {
	rows, err := query.New(db).ListOidcBindings(ctx, query.ListOidcBindingsParams{OrganizationID: organizationID, IdentityID: identityID})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(rows))
	for _, b := range rows {
		v, err := BindingJS(b)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// claimsText is the claims as the jsonb column stores them (nil for
// none), or the failure of the statement that would write them there.
func claimsText(claims jsvalue.Object) (sql.NullString, error) {
	if claims == nil {
		return sql.NullString{}, nil
	}
	if err := jsvalue.JsonbRefuses(claims); err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{String: string(jsvalue.Stringify(jsvalue.Jsonb(claims))), Valid: true}, nil
}

// CreateOIDCBinding is createOidcBinding. The issuer must be a plain https
// URL; the outbound policy refuses it (recorded, configuration phase)
// before anything is held. A protected operation: admin-step-up's
// oidc_binding.create, bound to the identity and the binding's issuer,
// audience, subject and claims. The requester and the identity are held
// shared.
func CreateOIDCBinding(ctx context.Context, w *write.Writer, approvals *auth.Service, policy *outbound.Policy, req Request, organizationID, identityID string,
	in OIDCBindingInput, now func() time.Time) (jsvalue.Object, []auth.PendingReport, error) {
	actor := req.Principal.Identity.ID
	u, ok := whatwg.ParseURL(in.Issuer)
	if !ok {
		return nil, nil, domainerr.New("VALIDATION_FAILED", "Invalid issuer URL")
	}
	// OIDC issuers are https, with no query or fragment (OIDC Core 2).
	if u.Protocol != "https:" || u.Search != "" || u.Hash != "" {
		return nil, nil, domainerr.New("VALIDATION_FAILED", "Issuer must be a plain https URL")
	}
	// The outbound policy (ADR-0057 Decision 6), before anything is held.
	// The jwks_uri is unknown until discovery: the exchange checks it.
	refusal, err := policy.RefusalFor(ctx, in.Issuer, outbound.OIDC)
	if err != nil {
		return nil, nil, err
	}
	if refusal != nil {
		if err := policy.RecordRefusal(ctx, w.Store, outbound.RefusalRecord{
			OrganizationID: organizationID, Purpose: outbound.OIDC, Phase: "configuration", Refusal: refusal,
			Resource: jsvalue.Object{{Key: "identityId", Value: identityID}}, ActorIdentityID: &actor,
		}); err != nil {
			return nil, nil, err
		}
		return nil, nil, &domainerr.Error{Code: "VALIDATION_FAILED", Message: refusal.Error(), Details: jsvalue.Object{{Key: "outbound", Value: string(refusal.Reason)}}}
	}
	r := approvalRequest(req.Principal, req.Approval, approvals)
	var out jsvalue.Object
	var reports []auth.PendingReport
	err = w.Job(ctx, r.Gates(organizationID, write.Person(identityID, write.Shared)), func(ctx context.Context, tx *storage.Tx) error {
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: "oidc_binding.create"}},
			Preflight: func(ctx context.Context, db query.DBTX) error {
				m, err := ReadMachine(ctx, db, organizationID, identityID)
				if err == nil && m == nil {
					err = notFound()
				}
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				m, err := ReadMachine(ctx, db, organizationID, identityID)
				if err != nil {
					return nil, err
				}
				if m == nil {
					return nil, notFound()
				}
				return oidcBindingCreateBinding(organizationID, *m, in), nil
			},
			AuthorizeIn: authorizeIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		texts := make([]string, 3)
		for i, s := range []string{in.Issuer, in.Audience, in.Subject} {
			if texts[i], err = write.Text(s); err != nil {
				return err
			}
		}
		claims, err := claimsText(in.Claims)
		if err != nil {
			return err
		}
		b, err := query.New(tx).InsertOidcBinding(ctx, query.InsertOidcBindingParams{
			ID: ids.New(ids.OIDCBinding), IdentityID: identityID, OrganizationID: organizationID, Issuer: texts[0], Audience: texts[1],
			Subject: texts[2], Claims: claims, CreatedBy: sql.NullString{String: actor, Valid: true}, CreatedAt: now().UnixMicro(),
		})
		if err != nil {
			return err
		}
		// Report mode (ADR-0054 Decision 9), before the audit insert.
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		action := "identity.manage"
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "oidc_binding.created", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "identityId", Value: identityID}, {Key: "oidcBindingId", Value: b.ID}},
			Metadata: append(jsvalue.Object{{Key: "issuer", Value: in.Issuer}, {Key: "audience", Value: in.Audience}, {Key: "subject", Value: in.Subject}},
				security.ApprovalMetadata(p.Approval)...),
		}); err != nil {
			return err
		}
		out, err = BindingJS(b)
		return err
	})
	if err != nil {
		return nil, reports, err
	}
	return out, reports, nil
}

func bindingNotFound() error { return domainerr.New("RESOURCE_NOT_FOUND", "Binding not found") }

// RevokeOIDCBinding is revokeOidcBinding. A protected operation:
// admin-step-up's oidc_binding.delete, bound to the identity and the
// binding (a revoked binding never comes back, so its id pins it: no
// version). A recovery operation during an incident freeze, where its
// approval may still be asked for.
func RevokeOIDCBinding(ctx context.Context, w *write.Writer, approvals *auth.Service, req Request, organizationID, identityID, bindingID string,
	now func() time.Time) ([]auth.PendingReport, error) {
	actor := req.Principal.Identity.ID
	r := approvalRequest(req.Principal, req.Approval, approvals)
	var reports []auth.PendingReport
	err := w.Job(ctx, r.Gates(organizationID), func(ctx context.Context, tx *storage.Tx) error {
		read := func(ctx context.Context, db query.DBTX) (*Machine, *query.OidcBinding, error) {
			m, err := ReadMachine(ctx, db, organizationID, identityID)
			if err != nil || m == nil {
				return nil, nil, err
			}
			b, err := liveBinding(ctx, db, organizationID, identityID, bindingID)
			return m, b, err
		}
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID, DuringFreeze: authz.DuringFreezeRecovery},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: "oidc_binding.delete"}},
			Preflight: func(ctx context.Context, db query.DBTX) error {
				m, b, err := read(ctx, db)
				if err == nil && (m == nil || b == nil) {
					err = bindingNotFound()
				}
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				m, b, err := read(ctx, db)
				if err != nil {
					return nil, err
				}
				if m == nil || b == nil {
					return nil, bindingNotFound()
				}
				return oidcBindingDeleteBinding(organizationID, *m, *b), nil
			},
			AuthorizeIn: authorizeIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		_, err = query.New(tx).RevokeOidcBinding(ctx, query.RevokeOidcBindingParams{
			RevokedAt: sql.NullInt64{Int64: now().UnixMicro(), Valid: true}, ID: bindingID, OrganizationID: organizationID, IdentityID: identityID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return bindingNotFound()
		}
		if err != nil {
			return err
		}
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		action := "identity.manage"
		e := audit.Event{
			Type: "oidc_binding.revoked", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "identityId", Value: identityID}, {Key: "oidcBindingId", Value: bindingID}},
		}
		if p.Approval != nil {
			e.Metadata = security.ApprovalMetadata(p.Approval)
		}
		_, err = audit.Record(ctx, tx, e)
		return err
	})
	return reports, err
}
