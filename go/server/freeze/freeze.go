// SPDX-License-Identifier: AGPL-3.0-or-later

// Package freeze is the incident freeze (ADR-0055; domain/freeze.ts;
// ADR-0059 step 4.3c): one action that stops all access to an
// Organization, reads included, keeps the audit trail flowing, and leaves
// a narrow path to clean up and come back.
//
//   - Freezing needs a person's credential with organization.manage and no
//     approval. It closes every open Approval Intent of the Organization.
//   - Lifting needs a person's credential with organization.manage and,
//     always, a step-up approval bound to the freeze id
//     (organization.unfreeze), whatever the Security Controls' modes.
//   - The host operator lifts with `varlatchd admin unfreeze`, with no
//     person and no approval.
//
// Each takes the Organization's gate exclusive (the TypeScript code takes
// the Organization row FOR UPDATE), so it waits for every external effect
// of the Organization, and every effect after it reads the new state. Each
// runs while a deletion is pending and leaves it in place.
package freeze

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
	"unicode/utf16"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/whatwg"
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

// ReasonMax is FREEZE_REASON_MAX.
const ReasonMax = 200

// historyLimit is freezeHistory's default.
const historyLimit = 20

type row struct {
	ID           string
	FrozenAt     int64
	FrozenBy     string
	FrozenByName string
	Reason       string
	LiftedAt     sql.NullInt64
	LiftedBy     sql.NullString
	LiftedByName sql.NullString
	LiftMethod   sql.NullString
}

// view is FreezeView.
func (r row) view() jsvalue.Object {
	var liftedAt, liftedBy, method any
	if r.LiftedAt.Valid {
		liftedAt = audit.ISOTime(r.LiftedAt.Int64)
	}
	if r.LiftedBy.Valid {
		var name any
		if r.LiftedByName.Valid {
			name = r.LiftedByName.String
		}
		liftedBy = jsvalue.Object{{Key: "id", Value: r.LiftedBy.String}, {Key: "name", Value: name}}
	}
	if r.LiftMethod.Valid {
		method = r.LiftMethod.String
	}
	return jsvalue.Object{
		{Key: "id", Value: r.ID},
		{Key: "frozenAt", Value: audit.ISOTime(r.FrozenAt)},
		{Key: "frozenBy", Value: jsvalue.Object{{Key: "id", Value: r.FrozenBy}, {Key: "name", Value: r.FrozenByName}}},
		{Key: "reason", Value: r.Reason},
		{Key: "liftedAt", Value: liftedAt},
		{Key: "liftedBy", Value: liftedBy},
		{Key: "liftMethod", Value: method},
	}
}

// History is freezeHistory: the Organization's freezes, newest first.
func History(ctx context.Context, db query.DBTX, organizationID string) ([]any, error) {
	rows, err := query.New(db).FreezeHistory(ctx, query.FreezeHistoryParams{OrganizationID: organizationID, Lim: historyLimit})
	if err != nil {
		return nil, err
	}
	out := make([]any, len(rows))
	for i, r := range rows {
		out[i] = row(r).view()
	}
	return out, nil
}

func byID(ctx context.Context, db query.DBTX, organizationID, id string) (jsvalue.Object, error) {
	r, err := query.New(db).FreezeByID(ctx, query.FreezeByIDParams{OrganizationID: organizationID, ID: id})
	if err != nil {
		return nil, err
	}
	return row(r).view(), nil
}

// Target is ResumingTarget: a Sync Target that resumes pushing when the
// freeze is lifted.
type Target struct {
	ID, ProjectSlug, EnvironmentName, Platform, Destination string
}

// JS is the target as the API shows it.
func (t Target) JS() jsvalue.Object {
	return jsvalue.Object{
		{Key: "id", Value: t.ID}, {Key: "projectSlug", Value: t.ProjectSlug}, {Key: "environmentName", Value: t.EnvironmentName},
		{Key: "platform", Value: t.Platform}, {Key: "destination", Value: t.Destination},
	}
}

// TargetsJS is a list of targets as the API shows it.
func TargetsJS(ts []Target) []any {
	out := make([]any, len(ts))
	for i, t := range ts {
		out[i] = t.JS()
	}
	return out
}

// ResumingTargets is resumingTargets: every active Sync Target of the
// Organization (a paused or revoked one stays so, and is not listed).
func ResumingTargets(ctx context.Context, db query.DBTX, organizationID string) ([]Target, error) {
	rows, err := query.New(db).ResumingTargets(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Target, len(rows))
	for i, r := range rows {
		out[i] = Target{ID: r.ID, ProjectSlug: r.ProjectSlug, EnvironmentName: r.EnvironmentName, Platform: r.Platform, Destination: r.CanonicalDestination}
	}
	return out, nil
}

// requirePerson is requirePerson: freezing and lifting are a person's.
func requirePerson(p *auth.Principal, lift bool) error {
	if p.Identity.Kind == "human" && (p.Credential.Kind == auth.KindBrowser || p.Credential.Kind == auth.KindCLI) {
		return nil
	}
	msg := "Only a person can freeze an Organization; machine credentials never can"
	if lift {
		msg = "Only a person can lift a freeze, with a passkey approval; machine credentials never can"
	}
	return &domainerr.Error{Code: "PERMISSION_DENIED", Message: msg, Details: jsvalue.Object{{Key: "reason", Value: "machine-credential"}}}
}

// NormalizeReason is normalizeReason: trimmed as JavaScript trims, 1 to
// 200 characters as JavaScript counts them (UTF-16 code units).
func NormalizeReason(raw string) (string, error) {
	reason := whatwg.Trim(raw)
	if n := len(utf16.Encode([]rune(reason))); n < 1 || n > ReasonMax {
		return "", domainerr.New("VALIDATION_FAILED", fmt.Sprintf("reason: 1 to %d characters", ReasonMax))
	}
	return reason, nil
}

// durationSeconds is durationSeconds: whole seconds between two times, as
// JavaScript Dates (milliseconds) round them, never negative.
func durationSeconds(from, to int64) int64 {
	ms := to/1000 - from/1000
	if ms < 0 {
		return 0
	}
	return (ms + 500) / 1000
}

// FreezeInput is a freeze request.
type FreezeInput struct {
	OrganizationID string
	Principal      *auth.Principal
	Reason         string
	RequestID      string
}

// Freeze is freezeOrganization (ADR-0055 Decision 2). The requester must
// be a person; the reason is normalized. The Organization's gate
// exclusive and the freezer's shared, then one job: the Organization live
// (a pending deletion still allows it), the passkey-verification
// checkpoint, organization.manage rechecked, STATE_CHANGED if a freeze is
// already open, every open Approval Intent closed (frozen), the freeze row,
// and organization.frozen (never the reason: it is free text shown to
// members). It returns the freeze and the report counts to record.
func Freeze(ctx context.Context, w *write.Writer, approvals *auth.Service, in FreezeInput, now func() time.Time) (jsvalue.Object, []auth.PendingReport, error) {
	if err := requirePerson(in.Principal, false); err != nil {
		return nil, nil, err
	}
	reason, err := NormalizeReason(in.Reason)
	if err != nil {
		return nil, nil, err
	}
	actor := in.Principal.Identity.ID
	gates := []write.Gate{write.Organization(in.OrganizationID, write.Exclusive), write.Person(actor, write.Shared)}
	var out jsvalue.Object
	var reports []auth.PendingReport
	err = w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: in.OrganizationID, AllowDeleting: true, DuringFreeze: authz.DuringFreezeFreeze}); err != nil {
			return err
		}
		var err error
		if reports, err = write.Checkpoint(ctx, tx, in.Principal, in.OrganizationID); err != nil {
			return err
		}
		if err := security.AuthorizeControlled(ctx, tx, in.Principal, "organization.manage", in.OrganizationID, in.RequestID); err != nil {
			return err
		}
		q := query.New(tx)
		if _, err := q.OpenFreeze(ctx, in.OrganizationID); err == nil {
			return domainerr.New("STATE_CHANGED", "This Organization is already frozen")
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		closed, err := approvals.CloseOpenApprovals(ctx, tx, in.OrganizationID, auth.CloseFrozen, nil, nil)
		if err != nil {
			return err
		}
		stored, err := write.Text(reason)
		if err != nil {
			return err
		}
		id := ids.New(ids.OrganizationFreeze)
		if err := q.InsertFreeze(ctx, query.InsertFreezeParams{ID: id, OrganizationID: in.OrganizationID, FrozenBy: actor, FrozenAt: now().UnixMicro(), Reason: stored}); err != nil {
			return err
		}
		action := "organization.manage"
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "organization.frozen", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &in.OrganizationID,
			Action: &action, RequestID: &in.RequestID, Resource: jsvalue.Object{{Key: "freezeId", Value: id}},
			Metadata: jsvalue.Object{{Key: "freezeId", Value: id}, {Key: "reasonGiven", Value: true}, {Key: "approvalsClosed", Value: closed}},
		}); err != nil {
			return err
		}
		out, err = byID(ctx, tx, in.OrganizationID, id)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return out, reports, nil
}

// requireOpenFreeze is requireOpenFreeze: the freeze, which must be the
// Organization's and open.
func requireOpenFreeze(ctx context.Context, q *query.Queries, organizationID, freezeID string) (query.FreezeByIDRow, error) {
	r, err := q.FreezeByID(ctx, query.FreezeByIDParams{OrganizationID: organizationID, ID: freezeID})
	if errors.Is(err, sql.ErrNoRows) {
		return r, domainerr.New("RESOURCE_NOT_FOUND", "Freeze not found")
	}
	if err != nil {
		return r, err
	}
	if r.LiftedAt.Valid {
		return r, domainerr.New("STATE_CHANGED", "This freeze was already lifted")
	}
	return r, nil
}

// LiftInput is a lift request.
type LiftInput struct {
	OrganizationID, FreezeID string
	Principal                *auth.Principal
	// ApprovalID is the Varlatch-Approval header's approval id, "" for none.
	ApprovalID string
	RequestID  string
	// MayListTargets: the requester may read the Organization's Sync
	// Targets (config.sync.manage), so the summary and the answer name
	// them; their number otherwise.
	MayListTargets bool
}

// Lift is liftFreeze: the open freeze lifted with the requester's step-up
// approval, always. The Organization's gate exclusive and the requester's
// exclusive (its approval is consumed), then one job: the Organization
// live, organization.manage rechecked, the freeze open, the
// passkey-verification checkpoint, the approval bound to this freeze
// consumed (or *auth.ApprovalNeeded), the freeze lifted, and
// organization.unfrozen. It returns {freeze, resumingTargets} and the
// report counts.
func Lift(ctx context.Context, w *write.Writer, approvals *auth.Service, in LiftInput, now func() time.Time) (jsvalue.Object, []auth.PendingReport, error) {
	if err := requirePerson(in.Principal, true); err != nil {
		return nil, nil, err
	}
	actor := in.Principal.Identity.ID
	gates := []write.Gate{write.Organization(in.OrganizationID, write.Exclusive), write.Person(actor, write.Exclusive)}
	var out jsvalue.Object
	var reports []auth.PendingReport
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: in.OrganizationID, AllowDeleting: true, DuringFreeze: authz.DuringFreezeFreeze}); err != nil {
			return err
		}
		if err := security.AuthorizeControlled(ctx, tx, in.Principal, "organization.manage", in.OrganizationID, in.RequestID); err != nil {
			return err
		}
		q := query.New(tx)
		freeze, err := requireOpenFreeze(ctx, q, in.OrganizationID, in.FreezeID)
		if err != nil {
			return err
		}
		if reports, err = write.Checkpoint(ctx, tx, in.Principal, in.OrganizationID); err != nil {
			return err
		}
		org, err := q.OrganizationNames(ctx, in.OrganizationID)
		if err != nil {
			return err
		}
		targets, err := ResumingTargets(ctx, tx, in.OrganizationID)
		if err != nil {
			return err
		}
		str := func(s string) *string { return &s }
		changes := []auth.ApprovalChange{{Field: "freeze", From: str("frozen"), To: str("lifted"), Loosens: true}}
		switch {
		case in.MayListTargets:
			for _, t := range targets {
				changes = append(changes, auth.ApprovalChange{Field: fmt.Sprintf("Sync Target %s/%s (%s)", t.ProjectSlug, t.EnvironmentName, t.Platform),
					From: str("held"), To: str("resumes pushing"), Loosens: true})
			}
		case len(targets) > 0:
			changes = append(changes, auth.ApprovalChange{Field: "Sync Targets", From: str("held"), To: str(fmt.Sprintf("%d resume pushing", len(targets))), Loosens: true})
		}
		orgID := in.OrganizationID
		b := auth.Binding{
			Operation: "organization.unfreeze", OrganizationID: &orgID,
			// The freeze id: an approval can never lift a later freeze.
			Target: map[string]string{"freezeId": in.FreezeID}, Body: jsvalue.Object{}, Query: map[string]string{},
			Summary: auth.ApprovalSummary{Title: "Lift the incident freeze of " + org.Name, Changes: changes},
		}
		if in.ApprovalID == "" {
			return &auth.ApprovalNeeded{Binding: b}
		}
		used, err := approvals.ConsumeApproval(ctx, tx, auth.RequesterOf(in.Principal), in.ApprovalID, b)
		if err != nil {
			return err
		}
		at := now().UnixMicro()
		if _, err := q.LiftFreeze(ctx, query.LiftFreezeParams{Now: sql.NullInt64{Int64: at, Valid: true}, LiftedBy: sql.NullString{String: actor, Valid: true},
			Method: sql.NullString{String: "approval", Valid: true}, ID: in.FreezeID}); err != nil {
			return err
		}
		action := "organization.manage"
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "organization.unfrozen", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &orgID,
			Action: &action, RequestID: &in.RequestID, Resource: jsvalue.Object{{Key: "freezeId", Value: in.FreezeID}},
			Metadata: jsvalue.Object{
				{Key: "freezeId", Value: in.FreezeID}, {Key: "method", Value: "approval"},
				{Key: "durationSeconds", Value: durationSeconds(freeze.FrozenAt, at)}, {Key: "targetsResuming", Value: len(targets)},
				{Key: "approvalId", Value: used.ID}, {Key: "approvalPasskeyId", Value: used.PasskeyID}, {Key: "approvalUserVerified", Value: used.UserVerified},
			},
		}); err != nil {
			return err
		}
		view, err := byID(ctx, tx, in.OrganizationID, in.FreezeID)
		if err != nil {
			return err
		}
		var resuming any
		if in.MayListTargets {
			resuming = TargetsJS(targets)
		}
		out = jsvalue.Object{{Key: "freeze", Value: view}, {Key: "resumingTargets", Value: resuming}}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return out, reports, nil
}

// OperatorOutcome is OperatorLiftOutcome.
type OperatorOutcome struct {
	OrganizationID, OrganizationSlug string
	Freeze                           jsvalue.Object
	ApprovalsClosed                  int
	Targets                          []Target
	DeletionPending                  bool
}

// JS is the outcome as `--json` prints it.
func (o OperatorOutcome) JS() jsvalue.Object {
	return jsvalue.Object{
		{Key: "organization", Value: jsvalue.Object{{Key: "id", Value: o.OrganizationID}, {Key: "slug", Value: o.OrganizationSlug}}},
		{Key: "freeze", Value: o.Freeze}, {Key: "approvalsClosed", Value: o.ApprovalsClosed},
		{Key: "resumingTargets", Value: TargetsJS(o.Targets)}, {Key: "deletionPending", Value: o.DeletionPending},
	}
}

// Lines is unfreezeReportLines.
func (o OperatorOutcome) Lines() []string {
	frozenAt, _ := o.Freeze.Get("frozenAt")
	liftedAt, _ := o.Freeze.Get("liftedAt")
	lines := []string{
		fmt.Sprintf("Incident freeze of %s [%s] lifted by the host operator.", o.OrganizationSlug, o.OrganizationID),
		fmt.Sprintf("Frozen since %v; lifted at %v.", frozenAt, liftedAt),
		fmt.Sprintf("Open lift approvals closed: %d.", o.ApprovalsClosed),
	}
	if len(o.Targets) == 0 {
		lines = append(lines, "No Sync Target resumes pushing.")
	} else {
		lines = append(lines, fmt.Sprintf("Sync Targets that resume pushing (%d):", len(o.Targets)))
	}
	for _, t := range o.Targets {
		lines = append(lines, fmt.Sprintf("  %s/%s -> %s %s [%s]", t.ProjectSlug, t.EnvironmentName, t.Platform, t.Destination, t.ID))
	}
	if o.DeletionPending {
		lines = append(lines, "A deletion of this Organization is still pending: writes stay refused until it is cancelled.")
	}
	return append(lines, "Nothing done during the freeze was undone. Recorded as organization.unfrozen.")
}

// UnfreezeUsage is UNFREEZE_USAGE.
const UnfreezeUsage = "Usage: varlatchd admin unfreeze --org <slug> --confirm <slug> [--json]"

// UnfreezeArgs are `admin unfreeze`'s arguments.
type UnfreezeArgs struct {
	Organization, Confirm string
	JSON                  bool
}

// ParseUnfreezeArgs is parseUnfreezeArgs: the arguments, or why they are
// wrong. --confirm must repeat the slug.
func ParseUnfreezeArgs(args []string) (UnfreezeArgs, string) {
	var a UnfreezeArgs
	for i := 0; i < len(args); i++ {
		next := func() string {
			i++
			if i < len(args) {
				return args[i]
			}
			return ""
		}
		switch args[i] {
		case "--org":
			a.Organization = next()
		case "--confirm":
			a.Confirm = next()
		case "--json":
			a.JSON = true
		default:
			return a, "Unknown argument: " + args[i] + "\n" + UnfreezeUsage
		}
	}
	if a.Organization == "" || a.Confirm == "" {
		return a, UnfreezeUsage
	}
	return a, ""
}

// OperatorUnfreeze is operatorUnfreeze, the host operator's lift (ADR-0055
// Decision 2): no API reaches it. The Organization (live, by slug or id)
// and --confirm repeating its slug; then the Organization's gate exclusive
// and one job: the open freeze (STATE_CHANGED when there is none), its open
// organization.unfreeze intents closed (reset), the freeze lifted with
// method operator, and organization.unfrozen with no actor.
func OperatorUnfreeze(ctx context.Context, w *write.Writer, approvals *auth.Service, organization, confirm string, now func() time.Time) (OperatorOutcome, error) {
	notFound := domainerr.New("RESOURCE_NOT_FOUND", "No live Organization "+organization)
	org, err := query.New(w.Store.Reader()).LiveOrganizationBySlugOrID(ctx, organization)
	if errors.Is(err, sql.ErrNoRows) {
		return OperatorOutcome{}, notFound
	}
	if err != nil {
		return OperatorOutcome{}, err
	}
	if confirm != org.Slug {
		return OperatorOutcome{}, domainerr.New("VALIDATION_FAILED", "--confirm must repeat the Organization's slug: "+org.Slug)
	}
	var out OperatorOutcome
	err = w.Job(ctx, []write.Gate{write.Organization(org.ID, write.Exclusive)}, func(ctx context.Context, tx *storage.Tx) error {
		q := query.New(tx)
		live, err := q.LiveOrganizationBySlugOrID(ctx, organization)
		if errors.Is(err, sql.ErrNoRows) || err == nil && live.ID != org.ID {
			return notFound
		}
		if err != nil {
			return err
		}
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: org.ID, AllowDeleting: true, DuringFreeze: authz.DuringFreezeFreeze}); err != nil {
			return err
		}
		open, err := q.OpenFreeze(ctx, org.ID)
		if errors.Is(err, sql.ErrNoRows) {
			return domainerr.New("STATE_CHANGED", org.Slug+" is not frozen")
		}
		if err != nil {
			return err
		}
		closed, err := approvals.CloseOpenApprovals(ctx, tx, org.ID, auth.CloseReset, nil, []string{"organization.unfreeze"})
		if err != nil {
			return err
		}
		targets, err := ResumingTargets(ctx, tx, org.ID)
		if err != nil {
			return err
		}
		pending, err := q.PendingDeletionExists(ctx, org.ID)
		if err != nil {
			return err
		}
		at := now().UnixMicro()
		if _, err := q.LiftFreeze(ctx, query.LiftFreezeParams{Now: sql.NullInt64{Int64: at, Valid: true}, Method: sql.NullString{String: "operator", Valid: true}, ID: open.ID}); err != nil {
			return err
		}
		orgID := org.ID
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "organization.unfrozen", Decision: audit.Info, OrganizationID: &orgID,
			Resource: jsvalue.Object{{Key: "freezeId", Value: open.ID}},
			Metadata: jsvalue.Object{
				{Key: "freezeId", Value: open.ID}, {Key: "method", Value: "operator"}, {Key: "operator", Value: true},
				{Key: "durationSeconds", Value: durationSeconds(open.FrozenAt, at)}, {Key: "targetsResuming", Value: len(targets)},
				{Key: "approvalsClosed", Value: closed},
			},
		}); err != nil {
			return err
		}
		view, err := byID(ctx, tx, org.ID, open.ID)
		if err != nil {
			return err
		}
		out = OperatorOutcome{OrganizationID: org.ID, OrganizationSlug: org.Slug, Freeze: view, ApprovalsClosed: closed, Targets: targets, DeletionPending: pending > 0}
		return nil
	})
	return out, err
}
