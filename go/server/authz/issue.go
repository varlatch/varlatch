// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"context"
	"slices"

	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// CapabilityIssue is the action that lets a machine identity issue a
// Capability another identity, the Broker it names, exercises (ADR-0060).
//
// It is not one of Actions: no built-in role holds it, the Organization
// Admin's included, so it is always an explicit Grant, by whoever holds
// policy.manage, with a Grant's scopes (the Organization, a Project, its
// Environments by tier or one by one). It reads nothing and uses nothing:
// the Agent's secret.use is evaluated when the Broker exercises.
const CapabilityIssue = "capability.issue"

// issuerKinds are the identities CapabilityIssue counts for: machines that
// run on their own. Never an Agent, which would name what it uses itself,
// nor a person.
var issuerKinds = []string{"service", "workload", "ci", "broker"}

// MayIssueCapabilities reports whether CapabilityIssue counts for an
// identity of this kind: a Grant of it to any other has no effect.
func MayIssueCapabilities(kind string) bool { return slices.Contains(issuerKinds, kind) }

// DecideCapabilityIssue decides CapabilityIssue for p on a resource. An
// identity whose kind it does not count for is denied as one without the
// Grant is, whatever its Grants say.
func DecideCapabilityIssue(ctx context.Context, db query.DBTX, p Principal, r Resource, opts Options) (Decision, error) {
	if MayIssueCapabilities(p.IdentityKind) {
		return Decide(ctx, db, p, CapabilityIssue, r, opts)
	}
	org, action, reqID := r.OrganizationID, CapabilityIssue, opts.RequestID
	return Decision{
		Evaluation: Evaluation{Denial: NoGrant, Requirements: []Outcome{}},
		Err:        domainerr.New("PERMISSION_DENIED", "Not authorized for this action"),
		DenialEvent: &audit.Event{
			Type: "authorization.denied", Decision: audit.Deny, ActorIdentityID: &p.IdentityID, CredentialID: audit.Value(p.CredentialID),
			OrganizationID: &org, Action: &action,
			Resource:  jsvalue.Object{{Key: "projectId", Value: orNull(r.ProjectID)}, {Key: "environmentId", Value: envID(r.Environment)}},
			Authz:     jsvalue.Object{{Key: "denial", Value: NoGrant}, {Key: "requirements", Value: []any{}}},
			RequestID: &reqID,
		},
	}, nil
}
