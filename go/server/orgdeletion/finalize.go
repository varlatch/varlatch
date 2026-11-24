// SPDX-License-Identifier: AGPL-3.0-or-later

package orgdeletion

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/githubapps"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/people"
	"github.com/varlatch/varlatch/go/server/write"
)

// Interval is how often the deletion loop runs (startDeletionLoop's
// 60 seconds), after a pass at once.
const Interval = time.Minute

// Drains is the audit export's part of a deletion (ADR-0056 Decision 10):
// auditexport.Service.
type Drains interface {
	// RewrapForDrain seals the live export's key again under the Root KEK
	// in the finalization's job, before the Organization KEK is destroyed.
	RewrapForDrain(ctx context.Context, db query.DBTX, organizationID string) (string, error)
	// AbandonExpiredDrains ends drains past their fixed deadline, each
	// pass of the loop.
	AbandonExpiredDrains(ctx context.Context) ([]string, error)
}

// Service runs due deletions.
type Service struct {
	Writer    *write.Writer
	Approvals *auth.Service
	Drains    Drains
	Now       func() time.Time
	Log       *slog.Logger
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// clocked is ctx with the service's clock for the audit events it
// records.
func (s *Service) clocked(ctx context.Context) context.Context {
	if s.Now != nil {
		return audit.WithClock(ctx, s.Now)
	}
	return ctx
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Outcome is FinalizeOutcome: what one deletion ended.
type Outcome struct {
	DeletionID, OrganizationID string
	Members, Readers, Projects, VersionsErased, TargetsRevoked, IdentitiesRetired, CredentialsRevoked,
	WebhooksRemoved, ConnectionsRevoked int64
	GitHubAppRemoved bool
}

// The finalization's crash points (G7, a build with the crashpoint tag;
// lib/storage CrashPoint): before its job, and inside it once every row
// and event is written, before the commit. After the commit is
// "deletion-committed".
const (
	CrashBeforeJob = "deletion-before-job"
	CrashWritten   = "deletion-written"
	CrashCommitted = "deletion-committed"
)

// people of a finalization: "m:" a machine identity (its gate exclusive,
// it is disabled), "p:" a person it only references (shared).
func finalizePeople(organizationID, deletionID string, now int64) func(ctx context.Context, db query.DBTX) ([]string, error) {
	return func(ctx context.Context, db query.DBTX) ([]string, error) {
		q := query.New(db)
		var out []string
		r, err := q.DueDeletionRow(ctx, query.DueDeletionRowParams{ID: deletionID, OrganizationID: organizationID, Now: now})
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, "p:"+r.RequestedBy)
		referenced, err := q.DeletionReferencedPeople(ctx, organizationID)
		if err != nil {
			return nil, err
		}
		for _, id := range referenced {
			out = append(out, "p:"+id)
		}
		machines, err := q.MachinesOf(ctx, sql.NullString{String: organizationID, Valid: true})
		if err != nil {
			return nil, err
		}
		for _, id := range machines {
			out = append(out, "m:"+id)
		}
		return out, nil
	}
}

// Finalize is finalizeDeletion (Decision 6): one due deletion, if it can
// be claimed; nil when it cannot (the Organization already deleted, the
// request not open or not due, an incident freeze open, the approval
// missing or its approver no longer a live admin). One write job: on any
// failure it rolls back, the Organization stays frozen, and the loop tries
// again later. Every change comes first; the audit events are appended
// at the end.
func (s *Service) Finalize(ctx context.Context, deletionID, organizationID string) (*Outcome, error) {
	ctx = s.clocked(ctx)
	at := s.now().UnixMicro()
	gates := func(people []string) []write.Gate {
		g := []write.Gate{write.Organization(organizationID, write.Exclusive)}
		for _, p := range people {
			mode := write.Shared
			if strings.HasPrefix(p, "m:") {
				mode = write.Exclusive
			}
			g = append(g, write.Person(p[2:], mode))
		}
		return g
	}
	storage.CrashPoint(s.Writer.Store, CrashBeforeJob)
	var out *Outcome
	err := gatedJob(ctx, s.Writer, finalizePeople(organizationID, deletionID, at), gates, func(ctx context.Context, tx *storage.Tx, _ []string) error {
		var err error
		out, err = s.finalizeIn(ctx, tx, deletionID, organizationID, at)
		if err == nil && out != nil {
			storage.CrashPoint(s.Writer.Store, CrashWritten)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if out != nil {
		storage.CrashPoint(s.Writer.Store, CrashCommitted)
	}
	return out, nil
}

func (s *Service) finalizeIn(ctx context.Context, tx *storage.Tx, deletionID, organizationID string, at int64) (*Outcome, error) {
	q := query.New(tx)
	org, err := q.LiveOrganizationForDeletion(ctx, organizationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	request, err := q.DueDeletionRow(ctx, query.DueDeletionRowParams{ID: deletionID, OrganizationID: organizationID, Now: at})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// An Organization frozen for an incident waits for the lift (ADR-0055
	// Decision 7).
	if _, err := q.OpenFreeze(ctx, organizationID); err == nil {
		return nil, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if request.ApprovalRequired {
		if !request.ApprovedBy.Valid {
			return nil, nil
		}
		// The approver must still be an enabled, live admin when it runs.
		n, err := q.IsLiveAdmin(ctx, query.IsLiveAdminParams{OrganizationID: organizationID, IdentityID: request.ApprovedBy.String})
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, nil
		}
	}
	requester := request.RequestedBy
	now := sql.NullInt64{Int64: at, Valid: true}
	orgID := sql.NullString{String: organizationID, Valid: true}
	var events []audit.Event

	// Open step-up approvals end with it (ADR-0054); its Security Controls
	// rows stay with the tombstone, like its other rows.
	if _, err := s.Approvals.CloseOpenApprovals(ctx, tx, organizationID, auth.CloseOrganizationDeleted, nil, nil); err != nil {
		return nil, err
	}

	// The audit tombstone's readers (Decision 8), before memberships end:
	// the people holding Organization-level audit.read, through any Grant.
	members, err := q.LiveHumanMembers(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	var readers []string
	for _, m := range members {
		if m.Disabled {
			continue
		}
		grants, err := authz.LoadGrants(ctx, tx, organizationID, m.IdentityID)
		if err != nil {
			return nil, err
		}
		if authz.Evaluate(authz.Input{Action: "audit.read", Resource: authz.Resource{OrganizationID: organizationID}, OrgRole: m.Role, Grants: grants}).Allowed {
			readers = append(readers, m.IdentityID)
		}
	}
	for _, id := range readers {
		if err := q.InsertTombstoneReader(ctx, query.InsertTombstoneReaderParams{OrganizationID: organizationID, IdentityID: id, AddedAt: at}); err != nil {
			return nil, err
		}
	}

	// Memberships end through removal's finalization mode: the same
	// cleanup and events, without the actor check and the last-admin rule.
	for _, m := range members {
		ended, err := people.EndMembership(ctx, tx, organizationID, m.IdentityID, m.Role, requester, at)
		if err != nil {
			return nil, err
		}
		actor := requester
		events = append(events, audit.Event{
			Type: "membership.removed", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID,
			Resource: jsvalue.Object{{Key: "identityId", Value: m.IdentityID}, {Key: "removalId", Value: ended.RemovalID}},
			Metadata: jsvalue.Object{
				{Key: "role", Value: m.Role}, {Key: "left", Value: false}, {Key: "finalization", Value: true},
				{Key: "grantsRevoked", Value: ended.Grants}, {Key: "groupsLeft", Value: ended.Groups}, {Key: "invitationsRevoked", Value: ended.Invitations},
			},
		})
	}

	o := &Outcome{DeletionID: deletionID, OrganizationID: organizationID, Members: int64(len(members)), Readers: int64(len(readers))}
	if o.Projects, err = q.DeleteOrganizationProjects(ctx, query.DeleteOrganizationProjectsParams{Now: now, OrganizationID: organizationID}); err != nil {
		return nil, err
	}
	if err := q.DeleteOrganizationEnvironments(ctx, query.DeleteOrganizationEnvironmentsParams{Now: now, OrganizationID: organizationID}); err != nil {
		return nil, err
	}
	if err := q.DeleteOrganizationValues(ctx, query.DeleteOrganizationValuesParams{Now: now, OrganizationID: organizationID}); err != nil {
		return nil, err
	}
	// The tokens of its OAuth connections go with it (ADR-0062).
	if err := q.ForgetOAuthConnectionsOfOrganization(ctx, organizationID); err != nil {
		return nil, err
	}
	// And its entry links, with what their makers wrote (ADR-0063).
	if err := q.ForgetEntryLinksOfOrganization(ctx, organizationID); err != nil {
		return nil, err
	}
	if o.VersionsErased, err = q.EraseOrganizationVersions(ctx, query.EraseOrganizationVersionsParams{Now: now, OrganizationID: organizationID}); err != nil {
		return nil, err
	}
	if err := q.RevokeOrganizationCapabilities(ctx, query.RevokeOrganizationCapabilitiesParams{Now: now, OrganizationID: organizationID}); err != nil {
		return nil, err
	}
	if o.TargetsRevoked, err = q.RevokeOrganizationSyncTargets(ctx, query.RevokeOrganizationSyncTargetsParams{Now: now, OrganizationID: organizationID}); err != nil {
		return nil, err
	}
	if o.ConnectionsRevoked, err = q.RevokeOrganizationConnections(ctx, query.RevokeOrganizationConnectionsParams{Now: now, OrganizationID: organizationID}); err != nil {
		return nil, err
	}
	if o.GitHubAppRemoved, err = githubapps.RemoveForDeletion(ctx, tx, organizationID, at); err != nil {
		return nil, err
	}
	if o.WebhooksRemoved, err = q.RevokeOrganizationWebhooks(ctx, query.RevokeOrganizationWebhooksParams{Now: now, OrganizationID: organizationID}); err != nil {
		return nil, err
	}
	// Machine identities are retired: credentials revoked, bindings removed.
	machines, err := q.MachinesOf(ctx, orgID)
	if err != nil {
		return nil, err
	}
	o.IdentitiesRetired = int64(len(machines))
	if err := q.RetireOrganizationMachines(ctx, orgID); err != nil {
		return nil, err
	}
	if o.CredentialsRevoked, err = q.RevokeOrganizationMachineCredentials(ctx, query.RevokeOrganizationMachineCredentialsParams{Now: now, OrganizationID: orgID}); err != nil {
		return nil, err
	}
	if err := q.RevokeOrganizationOIDCBindings(ctx, query.RevokeOrganizationOIDCBindingsParams{Now: now, OrganizationID: organizationID}); err != nil {
		return nil, err
	}

	// The audit export (ADR-0056 Decision 10), the last domain row: its key
	// sealed again under the Root KEK before the Organization KEK is
	// destroyed below, so the final events can still be delivered.
	if s.Drains != nil {
		if _, err := s.Drains.RewrapForDrain(ctx, tx, organizationID); err != nil {
			return nil, err
		}
	}

	// Report counters go with the Organization: nothing is summarized for
	// a deleted one.
	if err := q.DeleteOrganizationCounters(ctx, organizationID); err != nil {
		return nil, err
	}
	// The tombstone, and the Organization KEK destroyed: what it protected
	// is unreadable through the key hierarchy from now on.
	if err := q.TombstoneOrganization(ctx, query.TombstoneOrganizationParams{Now: now, ID: organizationID}); err != nil {
		return nil, err
	}
	if err := q.CompleteDeletion(ctx, query.CompleteDeletionParams{Now: now, ID: deletionID}); err != nil {
		return nil, err
	}

	var approvedBy any
	if request.ApprovedBy.Valid {
		approvedBy = request.ApprovedBy.String
	}
	events = append(events, audit.Event{
		Type: "organization.deleted", Decision: audit.Info, OrganizationID: &organizationID,
		Resource: jsvalue.Object{{Key: "deletionId", Value: deletionID}, {Key: "organizationSlug", Value: org.Slug}},
		Metadata: jsvalue.Object{
			{Key: "name", Value: org.Name}, {Key: "requestedBy", Value: requester}, {Key: "approvedBy", Value: approvedBy},
			{Key: "members", Value: o.Members}, {Key: "readers", Value: o.Readers}, {Key: "projects", Value: o.Projects},
			{Key: "versionsErased", Value: o.VersionsErased}, {Key: "targetsRevoked", Value: o.TargetsRevoked},
			{Key: "identitiesRetired", Value: o.IdentitiesRetired}, {Key: "credentialsRevoked", Value: o.CredentialsRevoked},
			{Key: "webhooksRemoved", Value: o.WebhooksRemoved}, {Key: "connectionsRevoked", Value: o.ConnectionsRevoked},
			{Key: "githubAppRemoved", Value: o.GitHubAppRemoved},
		},
	})
	// Audit last: every change is done.
	if _, err := audit.Record(ctx, tx, events...); err != nil {
		return nil, err
	}
	return o, nil
}

// RunDue is runDueDeletions: one pass, every due request it can claim,
// each in its own job. A failure is logged and the request stays frozen,
// to be tried again; it never fails the pass.
func (s *Service) RunDue(ctx context.Context) []Outcome {
	ctx = s.clocked(ctx)
	due, err := query.New(s.Writer.Store.Reader()).DueDeletions(ctx, s.now().UnixMicro())
	if err != nil {
		s.log().Error("organization deletions: reading the due requests failed", "error", err)
		return nil
	}
	var done []Outcome
	for _, d := range due {
		o, err := s.Finalize(ctx, d.ID, d.OrganizationID)
		if err != nil {
			if ctx.Err() == nil {
				s.log().Error("organization deletion failed; it stays frozen and is tried again", "deletionId", d.ID, "error", err)
			}
			continue
		}
		if o != nil {
			done = append(done, *o)
		}
	}
	return done
}

// RunLoop is startDeletionLoop: in every serving varlatchd, a pass at once
// and then every interval, inside the maintenance admission. Each pass
// also ends audit export drains past their fixed deadline (ADR-0056
// Decision 10), whatever audit_export says.
func (s *Service) RunLoop(ctx context.Context, interval time.Duration, admit func() (leave func(), ok bool)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		s.pass(ctx, admit)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Service) pass(ctx context.Context, admit func() (func(), bool)) {
	if admit != nil {
		leave, ok := admit()
		if !ok {
			return
		}
		defer leave()
	}
	s.RunDue(ctx)
	if s.Drains != nil {
		if _, err := s.Drains.AbandonExpiredDrains(ctx); err != nil && ctx.Err() == nil {
			s.log().Error("audit export drain cleanup error", "error", err)
		}
	}
}
