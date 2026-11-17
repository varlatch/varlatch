// SPDX-License-Identifier: AGPL-3.0-or-later

package githubapps

import (
	"context"
	"strconv"

	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
)

// admin-step-up for the GitHub App (integrationstepup.ts, ADR-0054
// amendments B and D): what an approval binds, and what its approver reads.

// secretSet is SECRET_SET: what the approver reads instead of a secret.
const secretSet = "a new value (not shown)"

func plural(n int64, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.FormatInt(n, 10) + " " + word + "s"
}

func added(field, to string) auth.ApprovalChange { return auth.ApprovalChange{Field: field, To: &to} }

// Pending is a pending conversion as its binding names it
// (PendingConversion).
type Pending struct {
	RegistrationID string
	GitHubAppID    int64
	Slug, ClientID string
	OwnerLogin     string
	OwnerID        int64
	OwnerType      string
}

// RegisterBinding is githubAppRegisterBinding: the attachment of a pending
// registration, bound to the registration and what GitHub handed over.
func RegisterBinding(organizationID, organizationName string, p Pending) *auth.Binding {
	app := "GitHub App " + security.Quoted(p.Slug) + " (GitHub App id " + itoa(p.GitHubAppID) + ", client id " + security.Quoted(p.ClientID) + ")"
	owner := "GitHub " + p.OwnerType + " " + security.Quoted(p.OwnerLogin) + " (GitHub id " + itoa(p.OwnerID) + ")"
	org := organizationID
	return &auth.Binding{
		Operation: "github_app.register", OrganizationID: &org, Target: map[string]string{"registrationId": p.RegistrationID},
		Body: jsvalue.Object{
			{Key: "githubAppId", Value: p.GitHubAppID}, {Key: "slug", Value: p.Slug}, {Key: "clientId", Value: p.ClientID},
			{Key: "owner", Value: jsvalue.Object{{Key: "login", Value: p.OwnerLogin}, {Key: "id", Value: p.OwnerID}, {Key: "type", Value: p.OwnerType}}},
		},
		Query: map[string]string{},
		Summary: auth.ApprovalSummary{
			Title:   "Attach " + app + ", owned by " + owner + ", to " + security.LabelWithID("organization", organizationName, organizationID) + ", from registration " + p.RegistrationID,
			Changes: []auth.ApprovalChange{added("app", app), added("owner", owner)},
		},
	}
}

// ImportBinding is githubAppImportBinding: what is known before GitHub is
// asked, the App id and the key (the intent keeps only the body's keyed
// hash).
func ImportBinding(organizationID string, appID int64, privateKey string) *auth.Binding {
	org := organizationID
	return &auth.Binding{
		Operation: "github_app.import", OrganizationID: &org, Target: map[string]string{"organizationId": organizationID},
		Body:  jsvalue.Object{{Key: "appId", Value: appID}, {Key: "privateKey", Value: privateKey}},
		Query: map[string]string{},
		Summary: auth.ApprovalSummary{
			Title:   "Import GitHub App " + itoa(appID) + " with a private key",
			Changes: []auth.ApprovalChange{added("appId", itoa(appID)), added("privateKey", secretSet)},
		},
	}
}

// RemoveBinding is githubAppRemoveBinding: the live App the request names,
// at the version the server read.
func RemoveBinding(ctx context.Context, db query.DBTX, organizationID string, a App) (*auth.Binding, error) {
	reach, err := query.New(db).GitHubAppReach(ctx, nullStr(a.ID))
	if err != nil {
		return nil, err
	}
	org := organizationID
	version := a.Version
	return &auth.Binding{
		Operation: "github_app.remove", OrganizationID: &org, Target: map[string]string{"githubAppId": a.ID},
		Body: nil, Query: map[string]string{"appId": a.ID}, ExpectedVersion: &version,
		Summary: auth.ApprovalSummary{
			Title: "Remove " + security.LabelWithID("GitHub App", a.Slug, a.ID) + " from Varlatch: " + plural(reach.Connections, "connection") +
				" revoked, " + plural(reach.Targets, "Sync Target") + " disabled. It stays on GitHub",
			Changes: []auth.ApprovalChange{},
		},
	}, nil
}
