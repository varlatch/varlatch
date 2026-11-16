// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs

import (
	"context"
	"strconv"

	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
)

// admin-step-up for Platform Connections (ADR-0054 Decision 5;
// domain/integrationstepup.ts' Connection part). The credential is
// secret-bearing input: the parsed value itself is in the bound body, so
// the keyed hash the intent stores covers it, and the summary says only
// that one is set or replaced. Each binds the query {}.
//
//   - connection.create, token shape: target the Organization; body
//     platform and baseIdentity as canonicalized, name and credential; no
//     version.
//   - connection.replace_credential: target the Connection; body
//     credential; the version the request expects.
//   - connection.delete: target the Connection; no body; the version the
//     server reads, checked again in the job.

// secretSet and secretKept are what the approver reads instead of a
// secret (SECRET_SET, SECRET_KEPT).
const (
	secretSet  = "a new value (not shown)"
	secretKept = "the current value"
)

func plural(n int64, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.FormatInt(n, 10) + " " + word + "s"
}

func added(field, to string) auth.ApprovalChange { return auth.ApprovalChange{Field: field, To: &to} }

func label(c Connection) string { return security.LabelWithID("connection", c.Name, c.ID) }

// createBinding is connectionCreateBinding.
func createBinding(organizationID, platform, baseIdentity, name, credential string) *auth.Binding {
	org := organizationID
	return &auth.Binding{
		Operation: "connection.create", OrganizationID: &org,
		Target: map[string]string{"organizationId": organizationID},
		Body: jsvalue.Object{{Key: "platform", Value: platform}, {Key: "baseIdentity", Value: baseIdentity},
			{Key: "name", Value: name}, {Key: "credential", Value: credential}},
		Query: map[string]string{},
		Summary: auth.ApprovalSummary{
			Title: "Add connection " + security.Quoted(name) + " on platform " + security.Quoted(platform) +
				" for base identity " + security.Quoted(baseIdentity) + ", with a new credential",
			Changes: []auth.ApprovalChange{
				added("platform", security.Quoted(platform)), added("baseIdentity", security.Quoted(baseIdentity)),
				added("name", security.Quoted(name)), added("credential", secretSet),
			},
		},
	}
}

func liveTargets(ctx context.Context, db query.DBTX, connectionID string) (int64, error) {
	return query.New(db).CountConnectionTargets(ctx, connectionID)
}

// replaceBinding is connectionReplaceCredentialBinding.
func replaceBinding(ctx context.Context, db query.DBTX, organizationID string, c Connection, credential string, expectedVersion int64) (*auth.Binding, error) {
	n, err := liveTargets(ctx, db, c.ID)
	if err != nil {
		return nil, err
	}
	org, version := organizationID, expectedVersion
	from, to := secretKept, secretSet
	return &auth.Binding{
		Operation: "connection.replace_credential", OrganizationID: &org,
		Target:          map[string]string{"connectionId": c.ID},
		Body:            jsvalue.Object{{Key: "credential", Value: credential}},
		Query:           map[string]string{},
		ExpectedVersion: &version,
		Summary: auth.ApprovalSummary{
			Title: "Replace the credential of " + label(c) + " on platform " + security.Quoted(c.Platform) +
				" for base identity " + security.Quoted(c.BaseIdentity) + ". " + plural(n, "Sync Target") + " will push with it",
			Changes: []auth.ApprovalChange{{Field: "credential", From: &from, To: &to}},
		},
	}, nil
}

// deleteBinding is connectionDeleteBinding, at the version the server read.
func deleteBinding(ctx context.Context, db query.DBTX, organizationID string, c Connection) (*auth.Binding, error) {
	n, err := liveTargets(ctx, db, c.ID)
	if err != nil {
		return nil, err
	}
	verb := "are"
	if n == 1 {
		verb = "is"
	}
	org, version := organizationID, c.Version
	return &auth.Binding{
		Operation: "connection.delete", OrganizationID: &org,
		Target:          map[string]string{"connectionId": c.ID},
		Query:           map[string]string{},
		ExpectedVersion: &version,
		Summary:         auth.ApprovalSummary{Title: "Revoke " + label(c) + ". " + plural(n, "Sync Target") + " " + verb + " disabled", Changes: []auth.ApprovalChange{}},
	}, nil
}
