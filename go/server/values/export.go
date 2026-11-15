// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import (
	"context"
	"database/sql"
	"errors"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// admin-step-up for an export (ADR-0054 Decision 5, amendment C;
// domain/exportstepup.ts): a Secret disclosure with purpose "export", under
// the control's enforce, needs a step-up approval bound to the exact set of
// Secrets disclosed (security.ExportBinding). An export is authorized in a
// read-only snapshot and an approval is consumed in a write, so it has two
// phases: the snapshot captures the authorization, the selection and the
// versions and writes nothing; then the disclosure's audit job, before
// anything is decrypted, behind the Organization's gate (shared) and the
// requester's (exclusive when the request carries a Varlatch-Approval):
//
//  1. security.Prepare: the Organization (a pending deletion still allows
//     reads, an incident freeze refuses), the control read again, the
//     passkey-verification checkpoint, the binding, a machine credential
//     refused, the approval consumed (or *auth.ApprovalNeeded, which rolls
//     the job back and creates the intent in a job of its own);
//  2. with an approval consumed: the freshness check against the live rows
//     and the live clock (freshnessOf), then secret.reveal decided again;
//  3. the report count, then the disclosure's audit event, with the
//     approval's id.
//
// A stale capture answers STATE_CHANGED before the commit and before any
// decryption: the consumption rolls back with the rest, so the approval
// stays usable, and the repeated request makes a fresh capture. The single
// writer makes the freshness check authoritative: no value write or
// Contract activation can commit inside the job, as the TypeScript share
// locks on the Project and the environments ensure there.

// exportPhase2 is exportGuard: the audit job's first step and the gates it
// runs behind.
func (s *Service) exportPhase2(req Request, st *State, dr disclosureRequest, selected []Item) (beforeAudit, []write.Gate) {
	r := security.Request{Principal: req.Principal, Approvals: s.approvals}
	if req.Approval != nil {
		if r.ApprovalID = auth.ParseApprovalID(*req.Approval); r.ApprovalID == "" {
			r.ApprovalMalformed = true
		}
	}
	names := make([]string, len(selected))
	for i, it := range selected {
		names[i] = it.Name
	}
	binding := security.ExportBinding(security.ExportTarget{
		OrganizationID: st.Org.ID, ProjectID: st.Project.ID, ProjectName: st.Project.Name,
		EnvironmentID: st.Env.ID, EnvName: st.Env.Name,
	}, dr.all, dr.items, names)
	before := func(ctx context.Context, tx *storage.Tx) (jsvalue.Object, error) {
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: st.Org.ID, AllowDeleting: true},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: "secret.export"}},
			Binding: func(context.Context, query.DBTX, *int64) (*auth.Binding, error) {
				return binding, nil
			},
		}, s.now)
		if err != nil {
			return nil, err
		}
		if p.Approval != nil {
			stale, err := s.freshnessOf(ctx, tx, st, selected)
			if err != nil {
				return nil, err
			}
			if stale != "" {
				return nil, staleCapture(p.Approval.ID, stale)
			}
			// secret.reveal decided again (authorizeInTransaction): a
			// denial's audit event is recorded after the job rolls back.
			d, err := authz.Decide(ctx, tx, req.authzPrincipal(), "secret.reveal", st.resource(), authz.Options{RequestID: req.RequestID})
			if err != nil {
				return nil, err
			}
			if !d.Allowed {
				if d.DenialEvent != nil {
					return nil, &security.DeferredDenial{Err: d.Err, Event: *d.DenialEvent}
				}
				return nil, d.Err
			}
		}
		if err := p.Count(ctx, tx); err != nil {
			return nil, err
		}
		return security.ApprovalMetadata(p.Approval), nil
	}
	return before, r.Gates(st.Org.ID)
}

// staleCapture is staleCapture: nothing committed, nothing decrypted, the
// approval still usable.
func staleCapture(approvalID, what string) error {
	return &domainerr.Error{Code: "STATE_CHANGED",
		Message: "The values changed since this export read them (" + what + "). Nothing was disclosed, and the approval was not used: repeat the request with it",
		Details: jsvalue.Object{{Key: "reason", Value: "stale-capture"}, {Key: "approvalId", Value: approvalID}}}
}

// freshnessOf is freshnessOf: why the capture is stale now, or "" when
// every disclosed name resolves exactly as captured, against the live rows
// and the live clock: the Project live with the captured active Contract
// Revision, the environment and its parent live and not expired, and each
// name from the same source environment and value row, at the same version,
// with the same retiring version.
func (s *Service) freshnessOf(ctx context.Context, tx *storage.Tx, st *State, selected []Item) (string, error) {
	now := s.now().UnixMicro()
	q := query.New(tx)
	project, err := q.ProjectFreshness(ctx, st.Project.ID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && project.DeletedAt.Valid {
		return "the project was deleted", nil
	}
	if err != nil {
		return "", err
	}
	captured := ""
	if st.revision != nil {
		captured = st.revision.ID
	}
	if project.ActiveContractRevisionID.String != captured {
		return "a new Contract Revision was activated", nil
	}
	ids := []string{st.Env.ID}
	if st.Env.ParentEnvironmentID.Valid {
		ids = append(ids, st.Env.ParentEnvironmentID.String)
	}
	envs, err := q.EnvironmentsFreshness(ctx, ids)
	if err != nil {
		return "", err
	}
	for _, id := range ids {
		var live *query.EnvironmentsFreshnessRow
		for i := range envs {
			if envs[i].ID == id {
				live = &envs[i]
			}
		}
		if live == nil || live.DeletedAt.Valid {
			return "the environment was deleted", nil
		}
		if live.ExpiresAt.Valid && live.ExpiresAt.Int64 <= now {
			return "the environment expired", nil
		}
	}
	items, err := resolveItems(ctx, q, st, now)
	if err != nil {
		return "", err
	}
	resolved := map[string]Item{}
	for _, it := range items {
		resolved[it.Name] = it
	}
	for _, c := range selected {
		name := string(jsvalue.Stringify(c.Name))
		it, ok := resolved[c.Name]
		switch {
		case !ok:
			return name + " has no value now", nil
		case it.Source != c.Source || it.ValueRowID != c.ValueRowID:
			return name + " comes from another environment now", nil
		case it.VersionID != c.VersionID:
			return name + " has a new value", nil
		case it.RetiringVersionID != c.RetiringVersionID:
			return name + " started or ended a rotation", nil
		}
	}
	return "", nil
}

// phase2Refused records what app.onError records for a refusal of phase 2,
// after its job rolled back: a denial of the recheck (auditDeferredDenial),
// and the incident freeze and passkey-verification refusals (refused).
func (s *Service) phase2Refused(ctx context.Context, req Request, t *tracker, err error) error {
	var deferred *security.DeferredDenial
	if errors.As(err, &deferred) {
		if werr := s.store.Write(ctx, func(tx *storage.Tx) error { _, e := audit.Record(ctx, tx, deferred.Event); return e }); werr != nil {
			s.log.Error("could not audit a refusal", "type", deferred.Event.Type, "requestId", req.RequestID, "error", werr)
		}
		return err
	}
	return s.refused(ctx, req, t, err)
}
