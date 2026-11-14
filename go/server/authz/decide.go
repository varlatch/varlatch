// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Principal is the requesting identity and the credential it presented.
type Principal struct {
	IdentityID string
	// IdentityKind is "human" for a person, else the machine's kind.
	IdentityKind string
	// OrganizationID is a machine identity's Organization ("" for a person).
	OrganizationID string
	CredentialID   string
}

func (p Principal) human() bool { return p.IdentityKind == "human" }

// Options are decide's per-call settings.
type Options struct {
	// HideExistence maps a denial for lack of any visibility to
	// RESOURCE_NOT_FOUND.
	HideExistence bool
	// TailnetContext is the request's verified Tailnet Context, nil when it
	// has none.
	TailnetContext *TailnetContext
	// RequestID names the request in the denial's audit event.
	RequestID string
}

// Decision is one authorization decision. A denial carries its error and
// its audit event, not yet recorded (nil when the denial records nothing).
type Decision struct {
	Allowed     bool
	Evaluation  Evaluation
	Err         *domainerr.Error
	DenialEvent *audit.Event
}

// Decide is decide (http/support.ts): evaluate one action against the
// current state read through db, writing nothing, so it can run in a read
// snapshot or a write job alike. The denial classes map as the TypeScript
// server maps them: no visibility at all, RESOURCE_NOT_FOUND when hiding
// existence; visible but denied, PERMISSION_DENIED; a Requirement failed,
// TAILNET_CONTEXT_REQUIRED (no context) or TAILNET_CONTEXT_UNAVAILABLE.
// A machine identity acts only inside its own Organization: elsewhere it
// is RESOURCE_NOT_FOUND, with no audit event.
func Decide(ctx context.Context, db query.DBTX, p Principal, action string, r Resource, opts Options) (Decision, error) {
	role := ""
	if p.human() {
		var err error
		if role, err = OrgRole(ctx, db, r.OrganizationID, p.IdentityID); err != nil {
			return Decision{}, err
		}
	}
	if !p.human() && p.OrganizationID != r.OrganizationID {
		return Decision{Err: domainerr.NotFound("Organization")}, nil
	}
	grants, err := LoadGrants(ctx, db, r.OrganizationID, p.IdentityID)
	if err != nil {
		return Decision{}, err
	}
	reqs, err := LoadRequirements(ctx, db, r.OrganizationID)
	if err != nil {
		return Decision{}, err
	}
	e := Evaluate(Input{Action: action, Resource: r, OrgRole: role, Grants: grants, Requirements: reqs, TailnetContext: opts.TailnetContext})
	if e.Allowed {
		return Decision{Allowed: true, Evaluation: e}, nil
	}

	authzValue := jsvalue.Object{{Key: "denial", Value: e.Denial}}
	if len(e.Provenance.Applied) > 0 {
		authzValue = append(authzValue, jsvalue.Member{Key: "applied", Value: appliedValue(e.Provenance.Applied)})
	}
	authzValue = append(authzValue, jsvalue.Member{Key: "requirements", Value: outcomesValue(e.Requirements)})
	org, act, reqID := r.OrganizationID, action, opts.RequestID
	event := &audit.Event{
		Type:            "authorization.denied",
		Decision:        audit.Deny,
		ActorIdentityID: &p.IdentityID,
		CredentialID:    audit.Value(p.CredentialID),
		OrganizationID:  &org,
		Action:          &act,
		Resource: jsvalue.Object{
			{Key: "projectId", Value: orNull(r.ProjectID)},
			{Key: "environmentId", Value: envID(r.Environment)},
		},
		Authz:     authzValue,
		RequestID: &reqID,
	}
	d := Decision{Evaluation: e, DenialEvent: event}
	if e.Denial == RequirementFailed {
		missing := false
		for _, o := range e.Requirements {
			if !o.Satisfied && o.Reason == "no-tailnet-context" {
				missing = true
			}
		}
		if missing {
			d.Err = domainerr.New("TAILNET_CONTEXT_REQUIRED", "This operation requires trusted Tailnet Context")
		} else {
			d.Err = domainerr.New("TAILNET_CONTEXT_UNAVAILABLE", "Tailnet Context does not satisfy the required selector")
		}
		return d, nil
	}
	// No applicable Grant. Callers with no visibility at all get the
	// not-found answer; a machine identity knows its own Organization.
	visible := role != "" || len(grants) > 0 || (!p.human() && p.OrganizationID == r.OrganizationID) || !opts.HideExistence
	if visible {
		d.Err = domainerr.New("PERMISSION_DENIED", "Not authorized for this action")
	} else {
		d.Err = domainerr.NotFound("Organization")
	}
	return d, nil
}

func orNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func envID(e *Environment) any {
	if e == nil {
		return nil
	}
	return e.ID
}

// RecordDenial is recordDenial: records a denial's audit event, if it has
// one, in the caller's write job. Allowed decisions record nothing.
func RecordDenial(ctx context.Context, tx query.DBTX, d Decision) error {
	if d.Allowed || d.DenialEvent == nil {
		return nil
	}
	_, err := audit.Record(ctx, tx, *d.DenialEvent)
	return err
}

// Freeze exceptions: the routes and operations that run while an
// Organization is frozen for an incident (ADR-0055 Decisions 3 and 4).
const (
	DuringFreezeFreeze     = "freeze"
	DuringFreezeAudit      = "audit"
	DuringFreezeInspection = "inspection"
	DuringFreezeRecovery   = "recovery"
)

// FrozenError is OrganizationFrozenError: ORGANIZATION_FROZEN with the
// freeze's ID and time, and the Organization (not in the response), so the
// HTTP layer can audit the refusal once, after the work that refused it.
type FrozenError struct {
	Domain         *domainerr.Error
	FreezeID       string
	FrozenAt       string
	OrganizationID string
}

func (e *FrozenError) Error() string { return e.Domain.Error() }

// Unwrap is the DomainError the HTTP layer answers with.
func (e *FrozenError) Unwrap() error { return e.Domain }

func frozen(f query.OpenFreezeRow, organizationID string) *FrozenError {
	at := audit.ISOTime(f.FrozenAt)
	return &FrozenError{
		Domain: &domainerr.Error{
			Code: "ORGANIZATION_FROZEN",
			Message: fmt.Sprintf("This Organization is frozen for an incident since %s. Nothing was read, changed or sent. "+
				"An Organization Admin can lift the freeze with a passkey approval.", at),
			Details: jsvalue.Object{{Key: "freezeId", Value: f.ID}, {Key: "frozenAt", Value: at}},
		},
		FreezeID: f.ID, FrozenAt: at, OrganizationID: organizationID,
	}
}

func openFreeze(ctx context.Context, db query.DBTX, organizationID string) (*query.OpenFreezeRow, error) {
	f, err := query.New(db).OpenFreeze(ctx, organizationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// RefuseIfIncidentFrozen is refuseIfIncidentFrozen (domain/liveness.ts):
// a *FrozenError when the Organization is frozen for an incident, unless
// the caller names the exception it runs under ("" names none).
func RefuseIfIncidentFrozen(ctx context.Context, db query.DBTX, organizationID, exception string) error {
	if exception != "" {
		return nil
	}
	f, err := openFreeze(ctx, db, organizationID)
	if err != nil || f == nil {
		return err
	}
	return frozen(*f, organizationID)
}

// Organization is a live Organization as a request resolves it.
type Organization struct {
	ID   string
	Slug string
	Name string
}

// EnterOrganization is resolveOrganization with organizationEntryChecks
// (http/organization.ts), the incident freeze part: the route's
// Organization, by slug or ID, must be live (RESOURCE_NOT_FOUND for
// members and outsiders alike); then, for a request with a principal on a
// route that names no freeze exception, a frozen Organization refuses a
// live member or one of its machine identities with a *FrozenError. A
// principal with no standing passes on to the route's own authorization,
// which refuses it as before: an outsider learns nothing of the freeze.
// principal nil is a request without one.
func EnterOrganization(ctx context.Context, db query.DBTX, slugOrID string, principal *Principal, exception string) (Organization, error) {
	row, err := query.New(db).GetLiveOrganization(ctx, slugOrID)
	if errors.Is(err, sql.ErrNoRows) {
		return Organization{}, domainerr.NotFound("Organization")
	}
	if err != nil {
		return Organization{}, err
	}
	org := Organization{ID: row.ID, Slug: row.Slug, Name: row.Name}
	if principal == nil || exception != "" {
		return org, nil
	}
	f, err := openFreeze(ctx, db, org.ID)
	if err != nil || f == nil {
		return org, err
	}
	standing := principal.OrganizationID == org.ID
	if principal.human() {
		role, err := OrgRole(ctx, db, org.ID, principal.IdentityID)
		if err != nil {
			return org, err
		}
		standing = role != ""
	}
	if standing {
		return org, frozen(*f, org.ID)
	}
	return org, nil
}

// FrozenRefusalEvent is the event auditFrozenRefusal records for a
// request the incident freeze refused (ADR-0055 Decision 8), once, at the
// request's outcome: authorization.denied with reason organization_frozen,
// the freeze, the request's method and route pattern, attributed to the
// request's credential.
func FrozenRefusalEvent(principal *Principal, err *FrozenError, method, route, requestID string) audit.Event {
	e := audit.Event{
		Type:           "authorization.denied",
		Decision:       audit.Deny,
		CredentialID:   audit.Null[string](),
		OrganizationID: &err.OrganizationID,
		RequestID:      &requestID,
		Resource:       jsvalue.Object{{Key: "freezeId", Value: err.FreezeID}},
		Metadata: jsvalue.Object{
			{Key: "reason", Value: "organization_frozen"},
			{Key: "freezeId", Value: err.FreezeID},
			{Key: "method", Value: method},
			{Key: "route", Value: route},
		},
	}
	if principal != nil {
		id := principal.IdentityID
		e.ActorIdentityID = &id
		e.CredentialID = audit.Value(principal.CredentialID)
	}
	return e
}
