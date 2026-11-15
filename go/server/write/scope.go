// SPDX-License-Identifier: AGPL-3.0-or-later

package write

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Scope is what a write depends on being live: lockLiveScope's LiveScope
// (domain/liveness.ts), less the lock modes, which the single writer
// makes unnecessary.
type Scope struct {
	OrganizationID string
	// AllowDeleting lets the write run while a deletion of the
	// Organization is open (ADR-0051 Decision 5, allowFrozen): only
	// approving and cancelling the deletion do.
	AllowDeleting bool
	// DuringFreeze is the exception the write runs under while the
	// Organization is frozen for an incident (authz.DuringFreeze*), ""
	// for none (ADR-0055 Decision 3).
	DuringFreeze string
	// ProjectID, when set, must be a live Project of the Organization, and
	// EnvironmentIDs live environments of that Project.
	ProjectID      string
	EnvironmentIDs []string
}

// CheckLive is lockLiveScope's checks, made inside the write job that
// depends on them (decision 4: a read before the job is advisory). In the
// TypeScript order: the Organization exists and is not deleted, no
// deletion is open, it is not frozen for an incident, then the Project and
// the environments are live. Each refusal is the TypeScript server's.
// The passkey-verification checkpoint is the caller's (Checkpoint), after
// this, as requireOrganizationAccess runs after the scope is locked.
func CheckLive(ctx context.Context, db query.DBTX, s Scope) error {
	q := query.New(db)
	deleted, err := q.OrganizationDeletedAt(ctx, s.OrganizationID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && deleted.Valid {
		return domainerr.New("RESOURCE_NOT_FOUND", "Organization not found")
	}
	if err != nil {
		return err
	}
	if !s.AllowDeleting {
		if err := RefuseIfDeleting(ctx, db, s.OrganizationID); err != nil {
			return err
		}
	}
	if err := authz.RefuseIfIncidentFrozen(ctx, db, s.OrganizationID, s.DuringFreeze); err != nil {
		return err
	}
	if s.ProjectID != "" {
		deleted, err := q.ProjectDeletedAt(ctx, query.ProjectDeletedAtParams{ID: s.ProjectID, OrganizationID: s.OrganizationID})
		if errors.Is(err, sql.ErrNoRows) || err == nil && deleted.Valid {
			return domainerr.New("RESOURCE_NOT_FOUND", "Project not found")
		}
		if err != nil {
			return err
		}
	}
	if len(s.EnvironmentIDs) > 0 {
		if s.ProjectID == "" {
			return errors.New("write: environments need their Project")
		}
		want := slices.Compact(slices.Sorted(slices.Values(s.EnvironmentIDs)))
		live, err := q.LiveEnvironmentsOf(ctx, query.LiveEnvironmentsOfParams{ProjectID: s.ProjectID, Ids: want})
		if err != nil {
			return err
		}
		if len(live) != len(want) {
			return domainerr.New("RESOURCE_NOT_FOUND", "Environment not found")
		}
	}
	return nil
}

// RefuseIfDeleting is refuseIfFrozen (domain/liveness.ts): every
// operational write is refused while the Organization has an open
// deletion (ADR-0051 Decision 5).
func RefuseIfDeleting(ctx context.Context, db query.DBTX, organizationID string) error {
	open, err := query.New(db).OpenOrganizationDeletion(ctx, organizationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	runAfter := audit.ISOTime(open.RunAfter)
	return &domainerr.Error{
		Code: "ORGANIZATION_DELETING",
		Message: fmt.Sprintf("This Organization is being deleted: it may be deleted from %s. "+
			"Only reading, and approving or cancelling the deletion, are possible. Nothing was changed.", runAfter),
		Details: jsvalue.Object{{Key: "deletionId", Value: open.ID}, {Key: "runAfter", Value: runAfter}},
	}
}

// Checkpoint is requireOrganizationAccess for a request, read in db (a
// write job, or the read snapshot of an effect): under passkey-
// verification's enforce, a person whose sign-in lacks the evidence is
// refused (*auth.VerificationRefusal); under report, the count to record
// once the request succeeds is returned. A request with no principal (a
// host command) has nothing to check.
func Checkpoint(ctx context.Context, db query.DBTX, p *auth.Principal, organizationID string) ([]auth.PendingReport, error) {
	if p == nil {
		return nil, nil
	}
	out, err := auth.PasskeyVerification(ctx, db, p, []string{organizationID})
	if err != nil {
		return nil, err
	}
	if reason, ok := out.Blocked[organizationID]; ok {
		return nil, auth.PasskeyVerificationRequired(organizationID, reason)
	}
	var reports []auth.PendingReport
	for _, r := range out.Reports {
		if r.OrganizationID == organizationID {
			reports = append(reports, r)
		}
	}
	return reports, nil
}
