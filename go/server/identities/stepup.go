// SPDX-License-Identifier: AGPL-3.0-or-later

package identities

import (
	"fmt"

	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
)

// admin-step-up for machine identities and their credentials (ADR-0054
// Decision 5; domain/identitystepup.ts): what an approval binds for each
// operation, per the binding catalogue, and the summary its approver
// reads. None binds a secret (a new credential's token is the server's)
// nor a query, and no expected version: identities are unversioned.
//
//   - identity.create: target the Organization; body name, kind,
//     credentialTtlSeconds and credentialMaxUses as requested (null when
//     left out), and effectiveTtlSeconds, what credential-lifetime makes of
//     the TTL (null: no expiry); the three bind null for ci and agent,
//     which get no credential.
//   - credential.issue: target the identity; body name, ttlSeconds, maxUses
//     (null when left out) and effectiveTtlSeconds.
//   - identity.reactivate: target the identity; no body.

// Machine is a machine identity of the Organization, as a summary names it
// (MachineIdentityRef).
type Machine struct {
	ID, Name, Kind      string
	Disabled            bool
	SuspendedByDeletion bool
}

// DurationWords is durationWords: 86400 is "1 day", 5400 "90 minutes".
func DurationWords(seconds int64) string {
	unit := func(n int64, word string) string {
		if n == 1 {
			return fmt.Sprintf("%d %s", n, word)
		}
		return fmt.Sprintf("%d %ss", n, word)
	}
	switch {
	case seconds%86_400 == 0:
		return unit(seconds/86_400, "day")
	case seconds%3_600 == 0:
		return unit(seconds/3_600, "hour")
	case seconds%60 == 0:
		return unit(seconds/60, "minute")
	}
	return unit(seconds, "second")
}

func expiryWords(ttl *int64) string {
	if ttl == nil {
		return "never"
	}
	return "after " + DurationWords(*ttl)
}

// ttlSource says where an effective TTL comes from.
func ttlSource(requested, effective *int64) string {
	switch {
	case requested != nil:
		return "as requested"
	case effective != nil:
		return "the organization's default, since none was requested"
	}
	return "none was requested"
}

func expiryWithSource(requested, effective *int64) string {
	return expiryWords(effective) + " (" + ttlSource(requested, effective) + ")"
}

func usesWords(maxUses *int64) string {
	switch {
	case maxUses == nil:
		return "unlimited"
	case *maxUses == 1:
		return "1 use"
	}
	return fmt.Sprintf("%d uses", *maxUses)
}

func added(field, to string) auth.ApprovalChange {
	return auth.ApprovalChange{Field: field, To: &to}
}

func intOrNull(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

// CreateInput is createServiceIdentity's body as its zod schema leaves it.
type CreateInput struct {
	Name, Kind                              string
	CredentialTTLSeconds, CredentialMaxUses *int64
}

// createBinding is identityCreateBinding, with the TTL credential-lifetime
// decided (nil: no expiry, or no credential).
func createBinding(organizationID string, in CreateInput, issues bool, effective *int64) *auth.Binding {
	var ttl, maxUses, requested *int64
	if issues {
		ttl, maxUses, requested = effective, in.CredentialMaxUses, in.CredentialTTLSeconds
	}
	changes := []auth.ApprovalChange{added("name", security.Quoted(in.Name)), added("kind", in.Kind)}
	title := fmt.Sprintf("Create machine identity %s (%s). It gets no credential", security.Quoted(in.Name), in.Kind)
	if issues {
		changes = append(changes, added("credentialExpiry", expiryWithSource(in.CredentialTTLSeconds, ttl)), added("credentialUses", usesWords(maxUses)))
		expires := "never expires"
		if ttl != nil {
			expires = "expires " + expiryWords(ttl)
		}
		title = fmt.Sprintf("Create machine identity %s (%s), with a credential that %s (%s)", security.Quoted(in.Name), in.Kind, expires, ttlSource(in.CredentialTTLSeconds, ttl))
	}
	org := organizationID
	return &auth.Binding{
		Operation: "identity.create", OrganizationID: &org,
		Target: map[string]string{"organizationId": organizationID},
		Body: jsvalue.Object{
			{Key: "name", Value: in.Name}, {Key: "kind", Value: in.Kind},
			{Key: "credentialTtlSeconds", Value: intOrNull(requested)}, {Key: "credentialMaxUses", Value: intOrNull(maxUses)},
			{Key: "effectiveTtlSeconds", Value: intOrNull(ttl)},
		},
		Query:   map[string]string{},
		Summary: auth.ApprovalSummary{Title: title, Changes: changes},
	}
}

// IssueInput is a service credential's body as its zod schema leaves it.
type IssueInput struct {
	Name                string
	TTLSeconds, MaxUses *int64
}

// issueBinding is credentialIssueBinding for a live service identity.
func issueBinding(organizationID string, m Machine, in IssueInput, effective *int64) *auth.Binding {
	expiring := "never expiring"
	if effective != nil {
		expiring = "expiring " + expiryWords(effective)
	}
	org := organizationID
	return &auth.Binding{
		Operation: "credential.issue", OrganizationID: &org,
		Target: map[string]string{"identityId": m.ID},
		Body: jsvalue.Object{
			{Key: "name", Value: in.Name}, {Key: "ttlSeconds", Value: intOrNull(in.TTLSeconds)},
			{Key: "maxUses", Value: intOrNull(in.MaxUses)}, {Key: "effectiveTtlSeconds", Value: intOrNull(effective)},
		},
		Query: map[string]string{},
		Summary: auth.ApprovalSummary{
			Title: fmt.Sprintf("Issue credential %s for %s %s, %s (%s), %s", security.Quoted(in.Name), m.Kind, security.LabelWithID("", m.Name, m.ID),
				expiring, ttlSource(in.TTLSeconds, effective), usesWords(in.MaxUses)),
			Changes: []auth.ApprovalChange{
				added("name", security.Quoted(in.Name)), added("credentialExpiry", expiryWithSource(in.TTLSeconds, effective)),
				added("credentialUses", usesWords(in.MaxUses)),
			},
		},
	}
}

// reactivateBinding is identityReactivateBinding of a disabled identity.
func reactivateBinding(organizationID string, m Machine) *auth.Binding {
	org := organizationID
	return &auth.Binding{
		Operation: "identity.reactivate", OrganizationID: &org,
		Target: map[string]string{"identityId": m.ID}, Query: map[string]string{},
		Summary: auth.ApprovalSummary{
			Title:   "Reactivate machine identity " + security.LabelWithID("", m.Name, m.ID) + ". It has no working credential until one is issued",
			Changes: []auth.ApprovalChange{},
		},
	}
}
