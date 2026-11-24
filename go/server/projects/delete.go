// SPDX-License-Identifier: AGPL-3.0-or-later

package projects

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

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

// Deletion is what deleteProject ended (ProjectDeletion), in the order the
// API answers it.
type Deletion struct {
	Environments, Values, VersionsErased, CapabilitiesRevoked, TargetsRevoked, TeamLinksRemoved int64
}

// JS is the counts as the answer and the audit event carry them.
func (d Deletion) JS() jsvalue.Object {
	return jsvalue.Object{
		{Key: "environments", Value: d.Environments}, {Key: "values", Value: d.Values}, {Key: "versionsErased", Value: d.VersionsErased},
		{Key: "capabilitiesRevoked", Value: d.CapabilitiesRevoked}, {Key: "targetsRevoked", Value: d.TargetsRevoked},
		{Key: "teamLinksRemoved", Value: d.TeamLinksRemoved},
	}
}

// DeleteRequest is who deletes and with which approval.
type DeleteRequest struct {
	Security security.Request
	// AuthorizeIn rechecks project.manage once an approval was consumed.
	AuthorizeIn func(ctx context.Context, tx query.DBTX) error
}

// NewDeleteRequest is the route's withApproval input: the Varlatch-Approval
// header as sent (nil for none; an empty one cannot be an approval id),
// and project.manage on the Project rechecked in the job, existence
// hidden, its denial's event recorded after the job
// (authorizeInTransaction).
func NewDeleteRequest(p *auth.Principal, approval *string, approvals *auth.Service, organizationID, projectID, requestID string) DeleteRequest {
	r := security.Request{Principal: p, Approvals: approvals}
	if approval != nil {
		if r.ApprovalID = auth.ParseApprovalID(*approval); r.ApprovalID == "" {
			r.ApprovalMalformed = true
		}
	}
	return DeleteRequest{Security: r, AuthorizeIn: func(ctx context.Context, tx query.DBTX) error {
		ap := authz.Principal{IdentityID: p.Identity.ID, IdentityKind: p.Identity.Kind, CredentialID: p.Credential.ID}
		if p.Identity.OrganizationID != nil {
			ap.OrganizationID = *p.Identity.OrganizationID
		}
		d, err := authz.Decide(ctx, tx, ap, "project.manage", authz.Resource{OrganizationID: organizationID, ProjectID: projectID},
			authz.Options{HideExistence: true, RequestID: requestID})
		if err != nil || d.Allowed {
			return err
		}
		if d.DenialEvent != nil {
			return &security.DeferredDenial{Err: d.Err, Event: *d.DenialEvent}
		}
		return d.Err
	}}
}

// Delete is deleteProject (ADR-0051 Decision 2): immediate and final. In
// one job: the protected operation's checks (admin-step-up's
// project.delete, the Project's not-found ahead of the checkpoint, the
// approval consumed and project.manage rechecked), then every environment
// tombstoned (derived ones first), every value deleted with its version
// pointers and rotation cleared, every version's ciphertext and wrapped
// key erased (the Project has no key of its own to destroy), the
// environments' outstanding Capabilities and the Project's Sync Targets
// revoked (a push in progress fenced, the destination claim released), the
// Teams' links to it removed, the Project tombstoned, and project.deleted
// last. Contract Revisions stay with the tombstone; audit events keep
// their IDs and names.
func Delete(ctx context.Context, w *write.Writer, r DeleteRequest, organizationID, projectID string, now func() time.Time) (Deletion, []auth.PendingReport, error) {
	var out Deletion
	var reports []auth.PendingReport
	actor := r.Security.Principal.Identity.ID
	err := w.Job(ctx, r.Security.Gates(organizationID), func(ctx context.Context, tx *storage.Tx) error {
		read := func(ctx context.Context, db query.DBTX) (query.ProjectForDeletionRow, error) {
			p, err := query.New(db).ProjectForDeletion(ctx, query.ProjectForDeletionParams{ID: projectID, OrganizationID: organizationID})
			if errors.Is(err, sql.ErrNoRows) {
				return p, domainerr.NotFound("Project")
			}
			return p, err
		}
		p, err := security.Prepare(ctx, tx, r.Security, security.Protected{
			Scope:                 write.Scope{OrganizationID: organizationID, ProjectID: projectID},
			Checks:                []security.Check{{Control: security.AdminStepUp, Operation: "project.delete"}},
			ScopeBeforeCheckpoint: true,
			Preflight: func(ctx context.Context, db query.DBTX) error {
				_, err := read(ctx, db)
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				project, err := read(ctx, db)
				if err != nil {
					return nil, err
				}
				return DeleteBinding(organizationID, project), nil
			},
			AuthorizeIn: r.AuthorizeIn,
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		project, err := read(ctx, tx)
		if err != nil {
			return err
		}
		at := sql.NullInt64{Int64: now().UnixMicro(), Valid: true}
		q := query.New(tx)
		out = Deletion{Environments: project.Environments}
		if err := q.DeleteDerivedEnvironmentsOfProject(ctx, query.DeleteDerivedEnvironmentsOfProjectParams{DeletedAt: at, ProjectID: projectID}); err != nil {
			return err
		}
		if err := q.DeleteEnvironmentsOfProject(ctx, query.DeleteEnvironmentsOfProjectParams{DeletedAt: at, ProjectID: projectID}); err != nil {
			return err
		}
		if out.Values, err = q.DeleteValuesOfProject(ctx, query.DeleteValuesOfProjectParams{DeletedAt: at, ProjectID: projectID}); err != nil {
			return err
		}
		// The tokens of its OAuth connections go with it (ADR-0062).
		if err := q.ForgetOAuthConnectionsOfProject(ctx, projectID); err != nil {
			return err
		}
		if out.VersionsErased, err = q.EraseVersionsOfProject(ctx, query.EraseVersionsOfProjectParams{ErasedAt: at, ProjectID: projectID}); err != nil {
			return err
		}
		if out.CapabilitiesRevoked, err = q.RevokeCapabilitiesOfProject(ctx, query.RevokeCapabilitiesOfProjectParams{RevokedAt: at, ProjectID: projectID}); err != nil {
			return err
		}
		if out.TargetsRevoked, err = q.RevokeSyncTargetsOfProject(ctx, query.RevokeSyncTargetsOfProjectParams{RevokedAt: at, ProjectID: projectID}); err != nil {
			return err
		}
		if out.TeamLinksRemoved, err = q.DeleteTeamLinksOfProject(ctx, projectID); err != nil {
			return err
		}
		if err := q.MarkProjectDeleted(ctx, query.MarkProjectDeletedParams{DeletedAt: at, ID: projectID}); err != nil {
			return err
		}
		// Report mode (ADR-0054 Decision 9), before the audit event.
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		action := "project.manage"
		md := append(jsvalue.Object{{Key: "name", Value: project.Name}}, out.JS()...)
		_, err = audit.Record(ctx, tx, audit.Event{
			Type: "project.deleted", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "projectId", Value: projectID}, {Key: "projectSlug", Value: project.Slug}},
			Metadata: append(md, security.ApprovalMetadata(p.Approval)...),
		})
		return err
	})
	if err != nil {
		return Deletion{}, nil, err
	}
	return out, reports, nil
}

// DeleteBinding is projectDeleteBinding (deletionstepup.ts): the Project
// by its id, no body, the query {}, no expected version (Projects are
// unversioned, and a deleted one never comes back).
func DeleteBinding(organizationID string, p query.ProjectForDeletionRow) *auth.Binding {
	org := organizationID
	return &auth.Binding{
		Operation: "project.delete", OrganizationID: &org, Target: map[string]string{"projectId": p.ID}, Query: map[string]string{},
		Summary: auth.ApprovalSummary{
			Title: "Delete the project " + security.LabelWithID("", p.Name, p.ID) + ", slug " + security.Quoted(p.Slug) + ", now: " +
				plural(p.Environments, "environment") + " and their values erased. This cannot be undone",
			Changes: []auth.ApprovalChange{},
		},
	}
}

func plural(n int64, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.FormatInt(n, 10) + " " + word + "s"
}
