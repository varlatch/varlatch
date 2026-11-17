// SPDX-License-Identifier: AGPL-3.0-or-later

package githubapps

import (
	"context"

	"github.com/varlatch/varlatch/go/server/db/query"
)

// An Organization's deletion (ADR-0051, go/server/orgdeletion) ends its
// GitHub App in the deletion's own jobs, as orgdeletion.ts does. Both jobs
// hold the Organization's gate exclusive, so a completion, an attachment,
// an import or a removal of the Organization (each holding it shared)
// commits before or after, never across; the sweep takes only a
// registration's gate and finds a deleted registration gone.

// EndRegistrationsForDeletion is scheduleDeletion's part: the
// Organization's unfinished registrations deleted, so none can be
// completed or attached while it is being deleted (pending keys with
// them).
func EndRegistrationsForDeletion(ctx context.Context, db query.DBTX, organizationID string) error {
	return query.New(db).DeleteGitHubAppRegistrations(ctx, organizationID)
}

// RemoveForDeletion is finalizeDeletion's part: the App's local
// registration removed with its key, so the App can be imported into
// another Organization; GitHub still has it. Whether there was one.
func RemoveForDeletion(ctx context.Context, db query.DBTX, organizationID string, at int64) (bool, error) {
	n, err := query.New(db).RemoveOrganizationGitHubApps(ctx, query.RemoveOrganizationGitHubAppsParams{
		Now: nullInt(at), OrganizationID: organizationID})
	return n > 0, err
}
