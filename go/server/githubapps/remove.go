// SPDX-License-Identifier: AGPL-3.0-or-later

package githubapps

import (
	"context"
	"strings"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

func appChanged() error {
	return domainerr.New("STATE_CHANGED", "The Organization's GitHub App changed since you confirmed; reload and try again")
}

// joinedOrNull is ids.join(",") || null.
func joinedOrNull(ids []string) any {
	if len(ids) == 0 {
		return nil
	}
	return strings.Join(ids, ",")
}

// Remove is removeGitHubApp (domain/sync.ts): the App the request names,
// and no other, removed from Varlatch: its live Connections revoked and
// their live Targets disabled (connection-revoked, their runs fenced), its
// key deleted. It stays on GitHub. A protected operation: admin-step-up's
// github_app.remove, bound to the App and the version the server read; a
// change since (a key rotation) refuses it, consumption included.
func (s *Service) Remove(ctx context.Context, req Request, org authz.Organization, appRowID string) ([]auth.PendingReport, error) {
	r := req.security(s.Approvals)
	actor := req.Principal.Identity.ID
	var reports []auth.PendingReport
	err := s.Writer.Job(ctx, r.Gates(org.ID), func(ctx context.Context, tx *storage.Tx) error {
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: org.ID},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: "github_app.remove"}},
			Preflight: func(ctx context.Context, db query.DBTX) error {
				a, err := liveApp(ctx, db, org.ID)
				if err == nil && a == nil {
					err = noApp()
				}
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				a, err := liveApp(ctx, db, org.ID)
				if err != nil {
					return nil, err
				}
				if a == nil {
					return nil, noApp()
				}
				if a.ID != appRowID {
					return nil, appChanged()
				}
				return RemoveBinding(ctx, db, org.ID, *a)
			},
			AuthorizeIn: ManageIn(req.Principal, org.ID, req.RequestID),
		}, s.now)
		if err != nil {
			return err
		}
		reports = p.Access
		a, err := liveApp(ctx, tx, org.ID)
		if err != nil {
			return err
		}
		if a == nil {
			return noApp()
		}
		if a.ID != appRowID {
			return appChanged()
		}
		if p.Binding != nil && (p.Binding.ExpectedVersion == nil || a.Version != *p.Binding.ExpectedVersion) {
			return domainerr.New("STATE_CHANGED", "The GitHub App changed since the approval was asked for; nothing was changed. Read it again and ask for a new approval")
		}
		q := query.New(tx)
		connections, err := q.GitHubAppConnections(ctx, nullStr(a.ID))
		if err != nil {
			return err
		}
		targets, err := q.GitHubAppTargets(ctx, nullStr(a.ID))
		if err != nil {
			return err
		}
		now := nullInt(s.now().UnixMicro())
		// The Targets first: they are found through their live Connections.
		if err := q.DisableGitHubAppTargets(ctx, query.DisableGitHubAppTargetsParams{Now: now, AppID: nullStr(a.ID)}); err != nil {
			return err
		}
		if err := q.RevokeGitHubAppConnections(ctx, query.RevokeGitHubAppConnectionsParams{Now: now, AppID: nullStr(a.ID)}); err != nil {
			return err
		}
		if err := q.RemoveGitHubApp(ctx, query.RemoveGitHubAppParams{Now: now, ID: a.ID}); err != nil {
			return err
		}
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		action := "config.sync.manage"
		_, err = audit.Record(ctx, tx, audit.Event{
			Type: "sync.github_app_removed", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &org.ID, Action: &action,
			Resource: jsvalue.Object{{Key: "githubAppId", Value: a.ID}},
			Metadata: append(jsvalue.Object{
				{Key: "appId", Value: a.GitHubAppID}, {Key: "slug", Value: a.Slug},
				{Key: "revokedConnections", Value: joinedOrNull(connections)}, {Key: "disabledTargets", Value: joinedOrNull(targets)},
			}, security.ApprovalMetadata(p.Approval)...),
		})
		return err
	})
	return reports, err
}
