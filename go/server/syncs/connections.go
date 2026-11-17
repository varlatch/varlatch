// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"

	"github.com/varlatch/varlatch/go/lib/storage"
	vsync "github.com/varlatch/varlatch/go/lib/sync"
	"github.com/varlatch/varlatch/go/lib/whatwg"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/contracts"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

var httpOrigin = regexp.MustCompile(`^https?://`)

// baseIdentityRefusal is baseIdentityRefusal (ADR-0057 Decision 6): for a
// platform whose base identity is an address (Coolify, Convex), the outbound
// policy's verdict on it, recorded in a job of its own when refused.
// GitHub's host is fixed; its requests are checked when they connect.
func (s *Service) baseIdentityRefusal(ctx context.Context, organizationID, baseIdentity string, purpose outbound.Purpose, connectionID, actor string) (*outbound.RefusedError, error) {
	if !httpOrigin.MatchString(baseIdentity) {
		return nil, nil
	}
	refusal, err := s.Policy.RefusalFor(ctx, baseIdentity, purpose)
	if err != nil || refusal == nil {
		return nil, err
	}
	resource := jsvalue.Object{}
	if connectionID != "" {
		resource = jsvalue.Object{{Key: "connectionId", Value: connectionID}}
	}
	if err := s.Policy.RecordRefusal(ctx, s.store(), outbound.RefusalRecord{
		OrganizationID: organizationID, Purpose: purpose, Phase: "configuration", Refusal: refusal, Resource: resource, ActorIdentityID: &actor,
	}); err != nil {
		return nil, err
	}
	return refusal, nil
}

func refused(r *outbound.RefusedError) error {
	return &domainerr.Error{Code: "VALIDATION_FAILED", Message: r.Error(), Details: jsvalue.Object{{Key: "outbound", Value: string(r.Reason)}}}
}

// CreateInput is createConnection's input, as zod leaves it.
type CreateInput struct {
	Platform, BaseIdentity, Name, Credential string
}

// Create is createConnection, a token Connection: refused while the
// Organization is being deleted; the adapter, the base identity and the
// credential validated and the outbound policy asked, all before any
// approval; then the protected operation (connection.create), bound to the
// credential itself.
func (s *Service) Create(ctx context.Context, req Request, org authz.Organization, in CreateInput) (Connection, []auth.PendingReport, error) {
	actor := req.Principal.Identity.ID
	if err := write.RefuseIfDeleting(ctx, s.store().Reader(), org.ID); err != nil {
		return Connection{}, nil, err
	}
	adapter, err := vsync.GetAdapter(in.Platform)
	if err != nil {
		return Connection{}, nil, validation(err)
	}
	baseIdentity, err := adapter.CanonicalizeBaseIdentity(in.BaseIdentity)
	if err != nil {
		return Connection{}, nil, validation(err)
	}
	if whatwg.Trim(in.Credential) == "" {
		return Connection{}, nil, emptyCredential()
	}
	refusal, err := s.baseIdentityRefusal(ctx, org.ID, baseIdentity, outbound.SyncCheck, "", actor)
	if err != nil {
		return Connection{}, nil, err
	}
	if refusal != nil {
		return Connection{}, nil, refused(refusal)
	}
	id := ids.New(ids.PlatformConnection)
	sealed, err := s.seal(ctx, org.ID, id, in.Credential)
	if err != nil {
		return Connection{}, nil, err
	}
	platform := string(adapter.Platform())
	r := req.security(s.Approvals)
	var out Connection
	var reports []auth.PendingReport
	err = s.Writer.Job(ctx, r.Gates(org.ID), func(ctx context.Context, tx *storage.Tx) error {
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: org.ID},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: "connection.create"}},
			Binding: func(context.Context, query.DBTX, *int64) (*auth.Binding, error) {
				return createBinding(org.ID, platform, baseIdentity, in.Name, in.Credential), nil
			},
			AuthorizeIn: ManageIn(req.Principal, org.ID, req.RequestID),
		}, s.now)
		if err != nil {
			return err
		}
		reports = p.Access
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		at := s.now().UnixMicro()
		if err := indexIntegration(ctx, tx, org.ID, actor, "connection", id, []string{"created"}, at); err != nil {
			return err
		}
		action := "config.sync.manage"
		md := jsvalue.Object{{Key: "platform", Value: platform}, {Key: "baseIdentity", Value: baseIdentity}, {Key: "name", Value: in.Name}}
		recorded, err := audit.Record(ctx, tx, audit.Event{
			Type: "sync.connection_created", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &org.ID, Action: &action,
			Resource: jsvalue.Object{{Key: "connectionId", Value: id}}, Metadata: append(md, approvalMetadata(p.Approval)...),
		})
		if err != nil {
			return err
		}
		name, err := write.Text(in.Name)
		if err != nil {
			return err
		}
		created := recorded[0].OccurredAt
		if err := query.New(tx).InsertConnection(ctx, query.InsertConnectionParams{
			ID: id, OrganizationID: org.ID, Platform: platform, BaseIdentity: baseIdentity, Name: name,
			CredentialEnvelope: sql.NullString{String: sealed, Valid: true}, CreatedBy: sql.NullString{String: actor, Valid: true}, CreatedAt: created,
		}); err != nil {
			return err
		}
		out = Connection{ID: id, OrganizationID: org.ID, Platform: platform, BaseIdentity: baseIdentity, Name: name,
			CreatedAt: created, Version: 1, CredentialKind: "token"}
		return nil
	})
	if err != nil {
		return Connection{}, nil, err
	}
	return out, reports, nil
}

// Gate is the re-authorization gate a credential replacement runs for each
// live Target it re-authorizes: the decisions to record for it, or the
// refusal.
type Gate func(ctx context.Context, db query.DBTX, t Target) (any, error)

// DisclosureGate is reauthorizationGate (http/app.ts): each Target's
// write-time disclosure gate (ADR-0031 §2) for this requester, which
// refuses the whole change with refusal when it fails. A Target whose
// Project or Environment is gone passes with nothing recorded.
func DisclosureGate(p *auth.Principal, organizationID, requestID, refusal string) Gate {
	return func(ctx context.Context, db query.DBTX, t Target) (any, error) {
		scope, err := query.New(db).TargetScope(ctx, query.TargetScopeParams{ProjectID: t.ProjectID, EnvironmentID: t.EnvironmentID})
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		active, err := contracts.Active(ctx, db, scope.ProjectID, scope.ActiveContractRevisionID)
		if err != nil {
			return nil, err
		}
		sensitive := func(name string) bool {
			if active != nil {
				for _, it := range active.Items {
					if it.Name == name {
						return it.Sensitive
					}
				}
			}
			return true
		}
		actions, err := requiredDisclosureActions(t.Mapping, sensitive)
		if err != nil {
			return nil, err
		}
		root := scope.EnvironmentID
		if scope.ParentEnvironmentID.Valid {
			root = scope.ParentEnvironmentID.String
		}
		resource := authz.Resource{OrganizationID: organizationID, ProjectID: scope.ProjectID,
			Environment: &authz.Environment{ID: scope.EnvironmentID, RootID: root, Tier: scope.Tier}}
		decisions := jsvalue.Object{}
		for _, action := range actions {
			d, err := authz.Decide(ctx, db, authzPrincipal(p), action, resource, authz.Options{RequestID: requestID})
			if err != nil {
				return nil, err
			}
			if !d.Allowed {
				denied := &domainerr.Error{Code: "PERMISSION_DENIED", Message: refusal,
					Details: jsvalue.Object{{Key: "targetId", Value: t.ID}, {Key: "environmentId", Value: t.EnvironmentID}}}
				if d.DenialEvent != nil {
					return nil, &security.DeferredDenial{Err: denied, Event: *d.DenialEvent}
				}
				return nil, denied
			}
			decisions = append(decisions, jsvalue.Member{Key: action, Value: authz.AuditAuthz(d.Evaluation)})
		}
		return decisions, nil
	}
}

// requiredDisclosureActions is requiredDisclosureActions: a wildcard needs
// both; explicit items each need their class's, in their order.
func requiredDisclosureActions(mappingText string, sensitive func(string) bool) ([]string, error) {
	v, err := jsvalue.Parse([]byte(mappingText))
	if err != nil {
		return nil, err
	}
	m, _ := v.(jsvalue.Object)
	kind, _ := m.Get("kind")
	if kind == "wildcard" {
		return []string{"secret.reveal", "config.value.read"}, nil
	}
	var out []string
	items, _ := m.Get("items")
	list, _ := items.([]any)
	for _, it := range list {
		o, _ := it.(jsvalue.Object)
		name, _ := o.Get("name")
		s, _ := name.(string)
		action := "config.value.read"
		if sensitive(s) {
			action = "secret.reveal"
		}
		if !strings.Contains(" "+strings.Join(out, " ")+" ", " "+action+" ") {
			out = append(out, action)
		}
	}
	return out, nil
}

// ReplaceInput is replaceConnectionCredential's input.
type ReplaceInput struct {
	Credential      string
	ExpectedVersion int64
}

// ReplaceCredential is replaceConnectionCredential: a new disclosure grant
// for every live Target of the Connection at once (ADR-0031 §2), so gate
// runs for each, before an approval is asked for and again in the job;
// any refusal refuses the whole replacement. A protected operation
// (connection.replace_credential), bound to the credential and the version
// the request expects. Targets the old credential stopped resume.
func (s *Service) ReplaceCredential(ctx context.Context, req Request, org authz.Organization, connectionID string, in ReplaceInput, gate Gate) (Connection, []auth.PendingReport, error) {
	actor := req.Principal.Identity.ID
	if err := write.RefuseIfDeleting(ctx, s.store().Reader(), org.ID); err != nil {
		return Connection{}, nil, err
	}
	if whatwg.Trim(in.Credential) == "" {
		return Connection{}, nil, emptyCredential()
	}
	sealed, err := s.seal(ctx, org.ID, connectionID, in.Credential)
	if err != nil {
		return Connection{}, nil, err
	}
	r := req.security(s.Approvals)
	var out Connection
	var reports []auth.PendingReport
	err = s.Writer.Job(ctx, r.Gates(org.ID), func(ctx context.Context, tx *storage.Tx) error {
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: org.ID},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: "connection.replace_credential"}},
			Preflight: func(ctx context.Context, db query.DBTX) error {
				c, err := read(ctx, db, org.ID, connectionID)
				if err == nil && c == nil {
					err = connectionNotFound()
				}
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				c, err := read(ctx, db, org.ID, connectionID)
				switch {
				case err != nil:
					return nil, err
				case c == nil:
					return nil, connectionNotFound()
				case c.CredentialKind == "github-app":
					return nil, appHasNoCredential()
				case c.Version != in.ExpectedVersion:
					return nil, versionConflict()
				}
				targets, err := query.New(db).ConnectionTargets(ctx, connectionID)
				if err != nil {
					return nil, err
				}
				for _, t := range targets {
					if _, err := gate(ctx, db, t); err != nil {
						return nil, err
					}
				}
				return replaceBinding(ctx, db, org.ID, *c, in.Credential, in.ExpectedVersion)
			},
			AuthorizeIn: ManageIn(req.Principal, org.ID, req.RequestID),
		}, s.now)
		if err != nil {
			return err
		}
		reports = p.Access
		c, err := read(ctx, tx, org.ID, connectionID)
		switch {
		case err != nil:
			return err
		case c == nil:
			return connectionNotFound()
		case c.CredentialKind == "github-app":
			return appHasNoCredential()
		case c.Version != in.ExpectedVersion:
			return versionConflict()
		}
		q := query.New(tx)
		targets, err := q.ConnectionTargets(ctx, connectionID)
		if err != nil {
			return err
		}
		provenance := jsvalue.Object{}
		for _, t := range targets {
			d, err := gate(ctx, tx, t)
			if err != nil {
				return err
			}
			provenance = append(provenance, jsvalue.Member{Key: t.ID, Value: d})
		}
		at := s.now().UnixMicro()
		if err := q.ReplaceConnectionCredential(ctx, query.ReplaceConnectionCredentialParams{
			CredentialEnvelope: sql.NullString{String: sealed, Valid: true}, UpdatedAt: sql.NullInt64{Int64: at, Valid: true}, ID: connectionID,
		}); err != nil {
			return err
		}
		// The old credential's failures were the credential's (#57): a
		// Target whose last attempt it failed starts afresh, and one it
		// stopped (its failure budget used up) resumes.
		var rejected, resumed []Target
		for _, t := range targets {
			if t.LastResult.Valid && credentialRejection.MatchString(t.LastResult.String) {
				rejected = append(rejected, t)
				if t.State == "disabled" && t.DisabledReason.Valid && t.DisabledReason.String == "failure-budget-exhausted" {
					resumed = append(resumed, t)
				}
			}
		}
		for _, t := range resumed {
			if err := q.ResumeTarget(ctx, query.ResumeTargetParams{At: sql.NullInt64{Int64: at, Valid: true}, ID: t.ID}); err != nil {
				return err
			}
		}
		for _, t := range rejected {
			if err := q.ResetTargetFailures(ctx, t.ID); err != nil {
				return err
			}
		}
		// A Target mutation class trigger (ADR-0031 §6): enqueued directly.
		if err := q.QueueConnectionTargets(ctx, connectionID); err != nil {
			return err
		}
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		if err := indexIntegration(ctx, tx, org.ID, actor, "connection", connectionID, []string{"credential_replaced"}, at); err != nil {
			return err
		}
		joined := func(list []Target) any {
			if len(list) == 0 {
				return nil
			}
			parts := make([]string, len(list))
			for i, t := range list {
				parts[i] = t.ID
			}
			return strings.Join(parts, ",")
		}
		action := "config.sync.manage"
		md := jsvalue.Object{{Key: "reauthorizedTargets", Value: joined(targets)}, {Key: "resumedTargets", Value: joined(resumed)}}
		events := []audit.Event{{
			Type: "sync.connection_credential_replaced", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &org.ID, Action: &action,
			Resource: jsvalue.Object{{Key: "connectionId", Value: connectionID}},
			Authz:    jsvalue.Object{{Key: "reauthorizedTargets", Value: provenance}},
			Metadata: append(md, approvalMetadata(p.Approval)...),
		}}
		for _, t := range resumed {
			events = append(events, audit.Event{
				Type: "sync.target_resumed", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &org.ID, Action: &action,
				Resource: jsvalue.Object{{Key: "targetId", Value: t.ID}, {Key: "environmentId", Value: t.EnvironmentID}},
				Metadata: jsvalue.Object{{Key: "cause", Value: "credential_replaced"}, {Key: "connectionId", Value: connectionID}},
			})
		}
		if _, err := audit.Record(ctx, tx, events...); err != nil {
			return err
		}
		updated, err := read(ctx, tx, org.ID, connectionID)
		if err != nil {
			return err
		}
		out = *updated
		return nil
	})
	if err != nil {
		return Connection{}, nil, err
	}
	return out, reports, nil
}

func connectionStateChanged() error {
	return domainerr.New("STATE_CHANGED", "The connection changed since the approval was asked for; nothing was changed. Read it again and ask for a new approval")
}

// Revoke is revokeConnection: a protected operation (connection.delete),
// bound to the version the server read and checked again in the job; a
// recovery operation during an incident freeze (ADR-0055 Decision 3).
// Every live Target the Connection feeds is disabled, fenced, and keeps
// its destination claim.
func (s *Service) Revoke(ctx context.Context, req Request, organizationID, connectionID string) ([]auth.PendingReport, error) {
	actor := req.Principal.Identity.ID
	r := req.security(s.Approvals)
	var reports []auth.PendingReport
	err := s.Writer.Job(ctx, r.Gates(organizationID), func(ctx context.Context, tx *storage.Tx) error {
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID, DuringFreeze: authz.DuringFreezeRecovery},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: "connection.delete"}},
			Preflight: func(ctx context.Context, db query.DBTX) error {
				c, err := read(ctx, db, organizationID, connectionID)
				if err == nil && c == nil {
					err = connectionNotFound()
				}
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				c, err := read(ctx, db, organizationID, connectionID)
				switch {
				case err != nil:
					return nil, err
				case c == nil:
					return nil, connectionNotFound()
				}
				return deleteBinding(ctx, db, organizationID, *c)
			},
			AuthorizeIn: ManageIn(req.Principal, organizationID, req.RequestID),
		}, s.now)
		if err != nil {
			return err
		}
		reports = p.Access
		if p.Binding != nil {
			c, err := read(ctx, tx, organizationID, connectionID)
			if err != nil {
				return err
			}
			if c != nil && p.Binding.ExpectedVersion != nil && c.Version != *p.Binding.ExpectedVersion {
				return connectionStateChanged()
			}
		}
		q := query.New(tx)
		at := s.now().UnixMicro()
		if _, err := q.RevokeConnection(ctx, query.RevokeConnectionParams{At: sql.NullInt64{Int64: at, Valid: true}, ID: connectionID, OrganizationID: organizationID}); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return connectionNotFound()
			}
			return err
		}
		targets, err := q.ConnectionTargets(ctx, connectionID)
		if err != nil {
			return err
		}
		var disabled []string
		for _, t := range targets {
			id, err := q.DisableTarget(ctx, query.DisableTargetParams{At: sql.NullInt64{Int64: at, Valid: true}, ID: t.ID})
			if err != nil {
				return err
			}
			disabled = append(disabled, id)
		}
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		var list any
		if len(disabled) > 0 {
			list = strings.Join(disabled, ",")
		}
		action := "config.sync.manage"
		_, err = audit.Record(ctx, tx, audit.Event{
			Type: "sync.connection_revoked", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "connectionId", Value: connectionID}},
			Metadata: append(jsvalue.Object{{Key: "disabledTargets", Value: list}}, approvalMetadata(p.Approval)...),
		})
		return err
	})
	return reports, err
}
