// SPDX-License-Identifier: AGPL-3.0-or-later

// Package orgdeletion is deleting an Organization (the TypeScript
// domain/orgdeletion.ts, ADR-0051 Decisions 4 to 8; ADR-0059 step 4.12b): a
// request with a lifecycle. Scheduling freezes the Organization and
// suspends what can be undone; a waiting period of 1 to 30 days, and a
// second admin's approval when there was more than one admin, come before
// the deletion loop finalizes it in one write job (finalize.go). Each step
// is one job with its audit event last. The audit-access tombstone's
// readers (Decision 8) are tombstone.go.
package orgdeletion

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/githubapps"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// DefaultWaitDays is DEFAULT_WAIT_DAYS: the waiting period when the
// request names none.
const DefaultWaitDays = 7

const day = int64(24 * time.Hour / time.Microsecond)

func isoOrNull(v sql.NullInt64) any {
	if !v.Valid {
		return nil
	}
	return audit.ISOTime(v.Int64)
}

func nullStr(v sql.NullString) any {
	if !v.Valid {
		return nil
	}
	return v.String
}

// View is view: a request as the API answers it.
func View(r query.OrganizationDeletion) jsvalue.Object {
	return jsvalue.Object{
		{Key: "id", Value: r.ID},
		{Key: "requestedBy", Value: r.RequestedBy},
		{Key: "scheduledAt", Value: audit.ISOTime(r.ScheduledAt)},
		{Key: "runAfter", Value: audit.ISOTime(r.RunAfter)},
		{Key: "approvalRequired", Value: r.ApprovalRequired},
		{Key: "approvedBy", Value: nullStr(r.ApprovedBy)},
		{Key: "approvedAt", Value: isoOrNull(r.ApprovedAt)},
		{Key: "cancelledAt", Value: isoOrNull(r.CancelledAt)},
		{Key: "completedAt", Value: isoOrNull(r.CompletedAt)},
	}
}

// Get is getDeletion: the open request, nil for none.
func Get(ctx context.Context, db query.DBTX, organizationID string) (jsvalue.Object, error) {
	r, err := query.New(db).OpenDeletionRow(ctx, organizationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return View(r), nil
}

// requireLiveAdmin is requireLiveAdmin: a human with a live built-in admin
// membership, enabled; an explicit Grant does not substitute.
func requireLiveAdmin(ctx context.Context, db query.DBTX, organizationID, identityID, kind string) error {
	n, err := query.New(db).IsLiveAdmin(ctx, query.IsLiveAdminParams{OrganizationID: organizationID, IdentityID: identityID})
	if err != nil {
		return err
	}
	if kind != "human" || n == 0 {
		return domainerr.New("PERMISSION_DENIED", "Only an Organization Admin can schedule, approve or cancel its deletion")
	}
	return nil
}

// requestRow is requestRow: the request, which must be open.
func requestRow(ctx context.Context, db query.DBTX, deletionID, organizationID string) (query.OrganizationDeletion, error) {
	r, err := query.New(db).DeletionRow(ctx, query.DeletionRowParams{ID: deletionID, OrganizationID: organizationID})
	if errors.Is(err, sql.ErrNoRows) {
		return r, domainerr.New("RESOURCE_NOT_FOUND", "Deletion request not found")
	}
	if err != nil {
		return r, err
	}
	if r.CancelledAt.Valid || r.CompletedAt.Valid {
		state := "completed"
		if r.CancelledAt.Valid {
			state = "cancelled"
		}
		return r, domainerr.New("STATE_CHANGED", "This deletion request is "+state)
	}
	return r, nil
}

func alreadyDeleting() error {
	return domainerr.New("STATE_CHANGED", "This Organization is already being deleted")
}

// refuseOpen is the open-deletion refusal of scheduling.
func refuseOpen(ctx context.Context, db query.DBTX, organizationID string) error {
	_, err := query.New(db).OpenOrganizationDeletion(ctx, organizationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return alreadyDeleting()
}

func plural(n int64, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.FormatInt(n, 10) + " " + word + "s"
}

// DeleteBinding is organizationDeleteBinding (deletionstepup.ts):
// scheduling the Organization's deletion after afterDays days, bound to
// the Organization and the normalized afterDays (a left-out field and its
// default bind the same), the query {} and no expected version. No
// timestamp is bound: run_after is computed when the request commits.
func DeleteBinding(organizationID, name string, afterDays, admins int64) *auth.Binding {
	org := organizationID
	title := "Schedule the deletion of organization " + security.LabelWithID("", name, organizationID) + " in " + plural(afterDays, "day")
	if admins > 1 {
		title += ". Another admin must approve it before it can run"
	}
	to := plural(afterDays, "day")
	return &auth.Binding{
		Operation: "organization.delete", OrganizationID: &org, Target: map[string]string{"organizationId": organizationID},
		Body: jsvalue.Object{{Key: "afterDays", Value: afterDays}}, Query: map[string]string{},
		Summary: auth.ApprovalSummary{Title: title, Changes: []auth.ApprovalChange{{Field: "afterDays", To: &to}}},
	}
}

// errPeopleChanged: the people a job gated changed between the read that
// named them and the job; the caller reads them again.
var errPeopleChanged = errors.New("orgdeletion: the people to gate changed")

// gatedJob runs fn as one write job holding gates(people), where people
// is read first (advisory) and again inside the job by the same read: the
// Organization's gate, exclusive in every caller, keeps the set from
// changing once held, so a set that changed in between is read again.
func gatedJob(ctx context.Context, w *write.Writer, read func(ctx context.Context, db query.DBTX) ([]string, error),
	gates func(people []string) []write.Gate, fn func(ctx context.Context, tx *storage.Tx, people []string) error) error {
	for attempt := 0; ; attempt++ {
		people, err := read(ctx, w.Store.Reader())
		if err != nil {
			return err
		}
		err = w.Job(ctx, gates(people), func(ctx context.Context, tx *storage.Tx) error {
			now, err := read(ctx, tx)
			if err != nil {
				return err
			}
			for _, id := range now {
				if !slices.Contains(people, id) {
					return errPeopleChanged
				}
			}
			return fn(ctx, tx, now)
		})
		if !errors.Is(err, errPeopleChanged) || attempt == 4 {
			return err
		}
	}
}

// ScheduleRequest is who schedules, with which approval.
type ScheduleRequest struct {
	Security  security.Request
	AfterDays *int64
}

// Scheduled is what scheduling answers and the report counts to record.
type Scheduled struct {
	View    jsvalue.Object
	Reports []auth.PendingReport
}

// Schedule is scheduleDeletion: the deletion scheduled, which freezes the
// Organization (Decision 5). In the same job: Sync Targets paused with the
// ADR-0050 fence, webhooks and enabled machine identities suspended under
// this request's marker (a cancel restores exactly those), pending
// invitations revoked, and unfinished GitHub App registrations
// invalidated.
//
// A protected operation (ADR-0054 amendment B): admin-step-up's
// organization.delete, under enforce the requester's approval, bound to
// the Organization and the normalized afterDays. It adds to this ADR's
// checks and replaces none: run_after is computed from afterDays when
// this commits, and with more than one admin a different admin must still
// approve. An open deletion, an incident freeze and a requester who is
// not a live admin are refused before an approval is asked for, and
// checked again once it is consumed. The Organization's gate exclusive
// (its row FOR UPDATE), the requester's, and the machine identities it
// suspends, exclusive.
func Schedule(ctx context.Context, w *write.Writer, in ScheduleRequest, organizationID string, now func() time.Time) (Scheduled, error) {
	p := in.Security.Principal
	days := int64(DefaultWaitDays)
	if in.AfterDays != nil {
		days = *in.AfterDays
	}
	if days < 1 || days > 30 {
		return Scheduled{}, domainerr.New("VALIDATION_FAILED", "The waiting period is 1 to 30 days")
	}
	actor := p.Identity.ID
	var out Scheduled
	machines := func(ctx context.Context, db query.DBTX) ([]string, error) {
		return query.New(db).EnabledMachinesOf(ctx, sql.NullString{String: organizationID, Valid: true})
	}
	gates := func(people []string) []write.Gate {
		g := []write.Gate{write.Organization(organizationID, write.Exclusive), in.Security.RequesterGate()}
		for _, id := range people {
			g = append(g, write.Person(id, write.Exclusive))
		}
		return g
	}
	err := gatedJob(ctx, w, machines, gates, func(ctx context.Context, tx *storage.Tx, _ []string) error {
		q := query.New(tx)
		prepared, err := security.Prepare(ctx, tx, in.Security, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID, AllowDeleting: true},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: "organization.delete"}},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				if err := refuseOpen(ctx, db, organizationID); err != nil {
					return nil, err
				}
				if err := requireLiveAdmin(ctx, db, organizationID, actor, p.Identity.Kind); err != nil {
					return nil, err
				}
				org, err := query.New(db).OrganizationNames(ctx, organizationID)
				if err != nil {
					return nil, err
				}
				admins, err := query.New(db).LiveAdminCount(ctx, organizationID)
				if err != nil {
					return nil, err
				}
				return DeleteBinding(organizationID, org.Name, days, admins), nil
			},
		}, now)
		if err != nil {
			return err
		}
		if err := refuseOpen(ctx, tx, organizationID); err != nil {
			return err
		}
		if err := requireLiveAdmin(ctx, tx, organizationID, actor, p.Identity.Kind); err != nil {
			return err
		}
		admins, err := q.LiveAdminCount(ctx, organizationID)
		if err != nil {
			return err
		}
		at := now().UnixMicro()
		atN := sql.NullInt64{Int64: at, Valid: true}
		id := ids.New(ids.OrganizationDeletion)
		row, err := q.InsertDeletion(ctx, query.InsertDeletionParams{ID: id, OrganizationID: organizationID, RequestedBy: actor,
			ScheduledAt: at, RunAfter: at + days*day, ApprovalRequired: admins > 1})
		if err != nil {
			return err
		}
		marker := sql.NullString{String: id, Valid: true}
		paused, err := q.PauseActiveSyncTargets(ctx, query.PauseActiveSyncTargetsParams{Now: atN, OrganizationID: organizationID})
		if err != nil {
			return err
		}
		webhooks, err := q.SuspendWebhooks(ctx, query.SuspendWebhooksParams{DeletionID: marker, OrganizationID: organizationID})
		if err != nil {
			return err
		}
		identities, err := q.SuspendMachines(ctx, query.SuspendMachinesParams{DeletionID: marker, OrganizationID: sql.NullString{String: organizationID, Valid: true}})
		if err != nil {
			return err
		}
		invitations, err := q.RevokePendingInvitations(ctx, query.RevokePendingInvitationsParams{Now: atN, OrganizationID: sql.NullString{String: organizationID, Valid: true}})
		if err != nil {
			return err
		}
		if err := githubapps.EndRegistrationsForDeletion(ctx, tx, organizationID); err != nil {
			return err
		}
		// Report mode (ADR-0054 Decision 9), before the audit insert.
		if err := prepared.Count(ctx, tx); err != nil {
			return err
		}
		action := "organization.manage"
		md := jsvalue.Object{
			{Key: "runAfter", Value: audit.ISOTime(row.RunAfter)},
			{Key: "approvalRequired", Value: admins > 1},
			{Key: "targetsPaused", Value: paused},
			{Key: "webhooksSuspended", Value: webhooks},
			{Key: "identitiesSuspended", Value: identities},
			{Key: "invitationsRevoked", Value: invitations},
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "organization.deletion_scheduled", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID,
			Action: &action, Resource: jsvalue.Object{{Key: "deletionId", Value: id}},
			Metadata: append(md, security.ApprovalMetadata(prepared.Approval)...),
		}); err != nil {
			return err
		}
		out = Scheduled{View: View(row), Reports: prepared.Access}
		return nil
	})
	if err != nil {
		return Scheduled{}, err
	}
	return out, nil
}

// Approve is approveDeletion: a second admin's approval, bound to this
// request: a different, enabled human with a live admin membership,
// checked again when the deletion runs. An approval already given is
// answered as it is. Not while frozen for an incident. The Organization's
// gate exclusive, then the approver's.
func Approve(ctx context.Context, w *write.Writer, p *auth.Principal, organizationID, deletionID string, now func() time.Time) (jsvalue.Object, []auth.PendingReport, error) {
	actor := p.Identity.ID
	gates := []write.Gate{write.Organization(organizationID, write.Exclusive), write.Person(actor, write.Shared)}
	var out jsvalue.Object
	var reports []auth.PendingReport
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: organizationID, AllowDeleting: true}); err != nil {
			return err
		}
		row, err := requestRow(ctx, tx, deletionID, organizationID)
		if err != nil {
			return err
		}
		// The request exists; then passkey-verification (ADR-0054 Decision 7).
		if reports, err = write.Checkpoint(ctx, tx, p, organizationID); err != nil {
			return err
		}
		if !row.ApprovalRequired {
			return domainerr.New("VALIDATION_FAILED", "This deletion needs no approval")
		}
		if row.ApprovedBy.Valid {
			out = View(row)
			return nil
		}
		if err := requireLiveAdmin(ctx, tx, organizationID, actor, p.Identity.Kind); err != nil {
			return err
		}
		if row.RequestedBy == actor {
			return domainerr.New("PERMISSION_DENIED", "Another admin than the one who scheduled the deletion must approve it")
		}
		updated, err := query.New(tx).ApproveDeletion(ctx, query.ApproveDeletionParams{ApprovedBy: sql.NullString{String: actor, Valid: true},
			Now: sql.NullInt64{Int64: now().UnixMicro(), Valid: true}, ID: deletionID})
		if err != nil {
			return err
		}
		action := "organization.manage"
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "organization.deletion_approved", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID,
			Action: &action, Resource: jsvalue.Object{{Key: "deletionId", Value: deletionID}},
		}); err != nil {
			return err
		}
		out = View(updated)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return out, reports, nil
}

// Cancel is cancelDeletion: any admin can cancel until completion
// commits, also while frozen for an incident (recovery, ADR-0055 Decision
// 7). The machine identities and webhooks this request suspended come
// back; Sync Targets stay paused, and revoked invitations stay revoked.
// The Organization's gate exclusive, then the canceller's and the machine
// identities it restores, exclusive.
func Cancel(ctx context.Context, w *write.Writer, p *auth.Principal, organizationID, deletionID string, now func() time.Time) (jsvalue.Object, []auth.PendingReport, error) {
	actor := p.Identity.ID
	marker := sql.NullString{String: deletionID, Valid: true}
	restoring := func(ctx context.Context, db query.DBTX) ([]string, error) {
		return query.New(db).SuspendedMachinesOf(ctx, marker)
	}
	gates := func(people []string) []write.Gate {
		g := []write.Gate{write.Organization(organizationID, write.Exclusive), write.Person(actor, write.Shared)}
		for _, id := range people {
			if id != actor {
				g = append(g, write.Person(id, write.Exclusive))
			}
		}
		return g
	}
	var out jsvalue.Object
	var reports []auth.PendingReport
	err := gatedJob(ctx, w, restoring, gates, func(ctx context.Context, tx *storage.Tx, _ []string) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: organizationID, AllowDeleting: true, DuringFreeze: authz.DuringFreezeRecovery}); err != nil {
			return err
		}
		if _, err := requestRow(ctx, tx, deletionID, organizationID); err != nil {
			return err
		}
		var err error
		if reports, err = write.Checkpoint(ctx, tx, p, organizationID); err != nil {
			return err
		}
		if err := requireLiveAdmin(ctx, tx, organizationID, actor, p.Identity.Kind); err != nil {
			return err
		}
		q := query.New(tx)
		updated, err := q.CancelDeletion(ctx, query.CancelDeletionParams{CancelledBy: sql.NullString{String: actor, Valid: true},
			Now: sql.NullInt64{Int64: now().UnixMicro(), Valid: true}, ID: deletionID})
		if err != nil {
			return err
		}
		identities, err := q.RestoreMachines(ctx, marker)
		if err != nil {
			return err
		}
		webhooks, err := q.ResumeWebhooks(ctx, marker)
		if err != nil {
			return err
		}
		action := "organization.manage"
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "organization.deletion_cancelled", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID,
			Action: &action, Resource: jsvalue.Object{{Key: "deletionId", Value: deletionID}},
			Metadata: jsvalue.Object{{Key: "identitiesRestored", Value: identities}, {Key: "webhooksResumed", Value: webhooks}},
		}); err != nil {
			return err
		}
		out = View(updated)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return out, reports, nil
}
