// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/lib/storage"
	vsync "github.com/varlatch/varlatch/go/lib/sync"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/githubapps"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// The Organization's GitHub App's part of the Connections (ADR-0047
// Decisions 2 and 5): Connections on its installations, and its key's
// rotation, which re-authorizes every Target on them.

// appCreateBinding is appConnectionCreateBinding: connection.create of an
// App Connection, bound to the App (Varlatch's row), the installation id
// and the name. The installation's account is learned from GitHub
// afterwards and is not bound.
func appCreateBinding(organizationID string, app githubapps.App, installationID int64, name string) *auth.Binding {
	org := organizationID
	installation := strconv.FormatInt(installationID, 10)
	return &auth.Binding{
		Operation: "connection.create", OrganizationID: &org,
		Target: map[string]string{"organizationId": organizationID, "githubAppId": app.ID},
		Body:   jsvalue.Object{{Key: "installationId", Value: installationID}, {Key: "name", Value: name}},
		Query:  map[string]string{},
		Summary: auth.ApprovalSummary{
			Title: "Add connection " + security.Quoted(name) + " on installation " + installation + " of " +
				security.LabelWithID("GitHub App", app.Slug, app.ID),
			Changes: []auth.ApprovalChange{added("name", security.Quoted(name)), added("installationId", installation)},
		},
	}
}

// replaceKeyBinding is githubAppReplaceKeyBinding: github_app.replace_key,
// bound to the App, the key itself (the intent keeps only its keyed hash)
// and the version the request expects.
func replaceKeyBinding(ctx context.Context, db query.DBTX, organizationID string, app githubapps.App, privateKey string, expectedVersion int64) (*auth.Binding, error) {
	reach, err := query.New(db).GitHubAppReach(ctx, sql.NullString{String: app.ID, Valid: true})
	if err != nil {
		return nil, err
	}
	org := organizationID
	from, to := secretKept, secretSet
	return &auth.Binding{
		Operation: "github_app.replace_key", OrganizationID: &org,
		Target: map[string]string{"githubAppId": app.ID},
		Body:   jsvalue.Object{{Key: "privateKey", Value: privateKey}},
		Query:  map[string]string{}, ExpectedVersion: &expectedVersion,
		Summary: auth.ApprovalSummary{
			Title: "Replace the private key of " + security.LabelWithID("GitHub App", app.Slug, app.ID) + ". " +
				plural(reach.Targets, "Sync Target") + " will push with it",
			Changes: []auth.ApprovalChange{{Field: "privateKey", From: &from, To: &to}},
		},
	}, nil
}

func noGitHubApp() error {
	return domainerr.New("RESOURCE_NOT_FOUND", "This Organization has no GitHub App")
}

// liveAppOf is the Organization's live App, or RESOURCE_NOT_FOUND.
func liveAppOf(ctx context.Context, db query.DBTX, organizationID string) (githubapps.App, error) {
	a, err := githubapps.Get(ctx, db, organizationID)
	return a, err
}

// appStillLive says whether the App row is still the Organization's live
// App (the TypeScript code's row lock under removed_at IS NULL).
func appStillLive(ctx context.Context, db query.DBTX, organizationID, appRowID string) (bool, error) {
	r, err := query.New(db).GitHubAppForCredential(ctx, query.GitHubAppForCredentialParams{ID: appRowID, OrganizationID: organizationID})
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil && !r.RemovedAt.Valid, err
}

// appTargets is readAppTargets: the live Targets of the App's live
// Connections, in id order.
func appTargets(ctx context.Context, db query.DBTX, appRowID string) ([]Target, error) {
	rows, err := query.New(db).GitHubAppTargetRows(ctx, sql.NullString{String: appRowID, Valid: true})
	if err != nil {
		return nil, err
	}
	out := make([]Target, len(rows))
	for i, r := range rows {
		out[i] = Target(r)
	}
	return out, nil
}

// AppInput is createPlatformConnection's App shape.
type AppInput struct {
	InstallationID int64
	Name           string
}

// installationRead is what reading the installation gave.
type installationRead struct {
	baseIdentity string
}

// CreateApp is createAppConnection (ADR-0047 Decision 2): a Connection on
// an installation of the Organization's GitHub App, no stored token. The
// installation is read as the App first: it must be this App's and not
// suspended, and its account becomes the base identity.
//
// A protected operation: admin-step-up's connection.create, bound to the
// App, the installation id and the name. Under enforce the installation is
// read only after a precheck found an approved intent for exactly this
// binding (amendment D); consumption is in the final job. An external
// effect: the Organization's gate shared and the requester's across the
// call (exclusive when the request carries an approval).
func (s *Service) CreateApp(ctx context.Context, req Request, org authz.Organization, in AppInput) (Connection, []auth.PendingReport, error) {
	actor := req.Principal.Identity.ID
	reader := s.store().Reader()
	if err := write.RefuseIfDeleting(ctx, reader, org.ID); err != nil {
		return Connection{}, nil, err
	}
	if err := authz.RefuseIfIncidentFrozen(ctx, reader, org.ID, ""); err != nil {
		return Connection{}, nil, err
	}
	if !s.allowed(string(vsync.GitHubActions)) {
		return Connection{}, nil, adapterNotAllowed()
	}
	r := req.security(s.Approvals)
	var started *security.Started
	var access []auth.PendingReport
	var app githubapps.App
	var key *rsa.PrivateKey
	out, _, err := write.RunEffect(ctx, s.Writer, write.Effect[installationRead, Connection]{
		OrganizationID: org.ID, People: []write.Gate{r.RequesterGate()},
		// The checkpoint is the protected operation's, after its preflight.
		Check: func(ctx context.Context, tx *sql.Tx) error {
			var bound string
			var err error
			started, err = security.Start(ctx, tx, r, security.Protected{
				Scope:  write.Scope{OrganizationID: org.ID},
				Checks: []security.Check{{Control: security.AdminStepUp, Operation: "connection.create"}},
				// The App exists, then passkey-verification (ADR-0054 Decision 7).
				Preflight: func(ctx context.Context, db query.DBTX) error {
					_, err := liveAppOf(ctx, db, org.ID)
					return err
				},
				Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
					a, err := liveAppOf(ctx, db, org.ID)
					if err != nil {
						return nil, err
					}
					bound = a.ID
					return appCreateBinding(org.ID, a, in.InstallationID, in.Name), nil
				},
				AuthorizeIn: ManageIn(req.Principal, org.ID, req.RequestID),
			}, s.now)
			if err != nil {
				return err
			}
			access = started.Access()
			// The App row an approval is bound to (pinned only when a
			// control asks for one): the key read for the installation and
			// the final write must name that same row.
			if app, err = liveAppOf(ctx, tx, org.ID); err != nil {
				return err
			}
			if started.Binding() != nil && app.ID != bound {
				return domainerr.New("STATE_CHANGED", "The Organization's GitHub App was replaced since the approval was asked for; nothing was changed. Reload and try again")
			}
			return nil
		},
		Checked: func(ctx context.Context, tx *sql.Tx) error {
			kek, err := s.orgKEK(ctx, tx, org.ID)
			if err != nil {
				return err
			}
			key, err = githubapps.OpenAppKey(kek, app)
			return err
		},
		Call: func(ctx context.Context) (installationRead, error) {
			inst, check := githubapps.ReadInstallation(ctx, s.clientFor(org.ID, "", outbound.GitHub), app.GitHubAppID, app.ClientID, key, in.InstallationID, s.now())
			if check != nil {
				if derr := write.EffectAlive(ctx); derr != nil {
					return installationRead{}, derr
				}
				return installationRead{}, &domainerr.Error{Code: "VALIDATION_FAILED", Message: check.Message,
					Details: jsvalue.Object{{Key: "check", Value: CheckJS(*check)}}}
			}
			if inst.Suspended {
				return installationRead{}, domainerr.New("VALIDATION_FAILED",
					"The GitHub App's installation on "+inst.Account.Login+" is suspended. Unsuspend it on GitHub, then try again.")
			}
			adapter, err := vsync.GetAdapter(string(vsync.GitHubActions))
			if err != nil {
				return installationRead{}, err
			}
			base, err := adapter.CanonicalizeBaseIdentity(inst.Account.Login)
			if err != nil {
				return installationRead{}, validation(err)
			}
			return installationRead{baseIdentity: base}, nil
		},
		Final: func(ctx context.Context, tx *storage.Tx, got installationRead) (Connection, error) {
			p, err := started.Finish(ctx, tx)
			if err != nil {
				return Connection{}, err
			}
			live, err := appStillLive(ctx, tx, org.ID, app.ID)
			if err != nil {
				return Connection{}, err
			}
			if !live {
				return Connection{}, domainerr.New("STATE_CHANGED", "The Organization's GitHub App was removed meanwhile")
			}
			// Report mode (ADR-0054 Decision 9): before the indexes and the audit.
			if err := p.Count(ctx, tx); err != nil {
				return Connection{}, err
			}
			id := ids.New(ids.PlatformConnection)
			at := s.now().UnixMicro()
			if err := indexIntegration(ctx, tx, org.ID, actor, "connection", id, []string{"created"}, at); err != nil {
				return Connection{}, err
			}
			platform := string(vsync.GitHubActions)
			action := "config.sync.manage"
			md := jsvalue.Object{{Key: "platform", Value: platform}, {Key: "baseIdentity", Value: got.baseIdentity}, {Key: "name", Value: in.Name},
				{Key: "credentialKind", Value: "github-app"}, {Key: "githubAppId", Value: app.ID}, {Key: "installationId", Value: in.InstallationID}}
			recorded, err := audit.Record(ctx, tx, audit.Event{
				Type: "sync.connection_created", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &org.ID, Action: &action,
				Resource: jsvalue.Object{{Key: "connectionId", Value: id}}, Metadata: append(md, approvalMetadata(p.Approval)...),
			})
			if err != nil {
				return Connection{}, err
			}
			name, err := write.Text(in.Name)
			if err != nil {
				return Connection{}, err
			}
			if err := query.New(tx).InsertAppConnection(ctx, query.InsertAppConnectionParams{
				ID: id, OrganizationID: org.ID, Platform: platform, BaseIdentity: got.baseIdentity, Name: name,
				CreatedBy: sql.NullString{String: actor, Valid: true}, CreatedAt: recorded[0].OccurredAt,
				GithubAppID: sql.NullString{String: app.ID, Valid: true}, GithubInstallationID: sql.NullInt64{Int64: in.InstallationID, Valid: true},
			}); err != nil {
				return Connection{}, err
			}
			return Get(ctx, tx, org.ID, id)
		},
	})
	if err != nil {
		return Connection{}, nil, err
	}
	return out, access, nil
}

// RotateInput is rotateGitHubAppKey's input.
type RotateInput struct {
	PrivateKey      string
	ExpectedVersion int64
}

// Rotation is a key rotation's answer: the App rotated, or the check that
// says why GitHub did not confirm the key (nothing changed).
type Rotation struct {
	App    *githubapps.App
	Failed *vsync.AccessCheck
}

// JS is the route's body: {outcome: "rotated", app} or {outcome:
// "failed", ...check}.
func (r Rotation) JS() jsvalue.Object {
	if r.App != nil {
		return jsvalue.Object{{Key: "outcome", Value: "rotated"}, {Key: "app", Value: r.App.JS()}}
	}
	return append(jsvalue.Object{{Key: "outcome", Value: "failed"}}, CheckJS(*r.Failed)...)
}

func appVersionConflict() error {
	return domainerr.New("VERSION_CONFLICT", "The GitHub App was changed concurrently; reload and retry")
}

// RotateAppKey is rotateGitHubAppKey (ADR-0047 Decision 5). The key
// belongs to the App and every App Connection uses it, so a rotation is a
// new disclosure grant for every live Target of every live Connection on
// the App: gate runs each one's write-time disclosure gate, and any
// refusal refuses the whole rotation.
//
// The new key is verified first, across the call: a JWT signed with it
// must get the App from GET /app. Then, in the final job: the App still
// the live one at the version the caller saw, every Target through the
// gate, the key replaced and the version moved, every Target queued.
//
// A protected operation: admin-step-up's github_app.replace_key, bound to
// the App, the key and the expected version. Under enforce GitHub is asked
// only after a precheck found an approved intent for exactly this binding
// (an unapproved request never sends the key out); consumption is in the
// final job, and a key GitHub does not confirm leaves the approval
// unconsumed.
func (s *Service) RotateAppKey(ctx context.Context, req Request, org authz.Organization, in RotateInput, gate Gate) (Rotation, []auth.PendingReport, error) {
	actor := req.Principal.Identity.ID
	reader := s.store().Reader()
	if err := write.RefuseIfDeleting(ctx, reader, org.ID); err != nil {
		return Rotation{}, nil, err
	}
	if err := authz.RefuseIfIncidentFrozen(ctx, reader, org.ID, ""); err != nil {
		return Rotation{}, nil, err
	}
	key := githubapps.ParseRSAKey(in.PrivateKey)
	if key == nil {
		return Rotation{}, nil, domainerr.New("VALIDATION_FAILED", "privateKey: not an RSA private key in PEM, as GitHub issues them")
	}
	replaced := func() error {
		return domainerr.New("STATE_CHANGED", "The Organization's GitHub App was replaced or removed since the approval was asked for; nothing was changed. Reload and try again")
	}
	r := req.security(s.Approvals)
	var started *security.Started
	var access []auth.PendingReport
	// pinned is the App row an approval is bound to (only when a control
	// asks for one): GitHub verifies the key for it, and the final job
	// writes that same row.
	var pinned bool
	var seen githubapps.App
	out, _, err := write.RunEffect(ctx, s.Writer, write.Effect[*vsync.AccessCheck, Rotation]{
		OrganizationID: org.ID, People: []write.Gate{r.RequesterGate()},
		Check: func(ctx context.Context, tx *sql.Tx) error {
			var bound string
			var err error
			started, err = security.Start(ctx, tx, r, security.Protected{
				Scope:  write.Scope{OrganizationID: org.ID},
				Checks: []security.Check{{Control: security.AdminStepUp, Operation: "github_app.replace_key"}},
				// The App exists, then passkey-verification, before GitHub
				// is called (ADR-0054 Decision 7).
				Preflight: func(ctx context.Context, db query.DBTX) error {
					_, err := liveAppOf(ctx, db, org.ID)
					return err
				},
				// Refusals first (amendment A); the version is checked
				// again in the final job.
				Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
					a, err := liveAppOf(ctx, db, org.ID)
					if err != nil {
						return nil, err
					}
					bound = a.ID
					if a.Version != in.ExpectedVersion {
						return nil, appVersionConflict()
					}
					targets, err := appTargets(ctx, db, a.ID)
					if err != nil {
						return nil, err
					}
					for _, t := range targets {
						if _, err := gate(ctx, db, t); err != nil {
							return nil, err
						}
					}
					return replaceKeyBinding(ctx, db, org.ID, a, in.PrivateKey, in.ExpectedVersion)
				},
				AuthorizeIn: ManageIn(req.Principal, org.ID, req.RequestID),
			}, s.now)
			if err != nil {
				return err
			}
			access = started.Access()
			pinned = started.Binding() != nil
			if seen, err = liveAppOf(ctx, tx, org.ID); err != nil {
				return err
			}
			if pinned && seen.ID != bound {
				return replaced()
			}
			return nil
		},
		Call: func(ctx context.Context) (*vsync.AccessCheck, error) {
			return githubapps.VerifyKey(ctx, s.clientFor(org.ID, "", outbound.GitHub), seen, key, s.now())
		},
		Final: func(ctx context.Context, tx *storage.Tx, failed *vsync.AccessCheck) (Rotation, error) {
			if failed != nil {
				return Rotation{Failed: failed}, nil
			}
			kek, err := s.orgKEK(ctx, tx, org.ID)
			if err != nil {
				return Rotation{}, err
			}
			sealed, err := githubapps.SealKey(kek, org.ID, seen.ID, in.PrivateKey)
			if err != nil {
				return Rotation{}, err
			}
			p, err := started.Finish(ctx, tx)
			if err != nil {
				return Rotation{}, err
			}
			// The row now: with an approval bound to it, one removed since is
			// refused as replaced (the job rolls back, consumption included).
			a, err := githubapps.Get(ctx, tx, org.ID)
			var de *domainerr.Error
			switch {
			case errors.As(err, &de) && de.Code == "RESOURCE_NOT_FOUND" || err == nil && a.ID != seen.ID:
				if pinned {
					return Rotation{}, replaced()
				}
				return Rotation{}, noGitHubApp()
			case err != nil:
				return Rotation{}, err
			case a.Version != in.ExpectedVersion:
				return Rotation{}, appVersionConflict()
			}
			q := query.New(tx)
			connections, err := q.GitHubAppConnections(ctx, sql.NullString{String: seen.ID, Valid: true})
			if err != nil {
				return Rotation{}, err
			}
			targets, err := appTargets(ctx, tx, seen.ID)
			if err != nil {
				return Rotation{}, err
			}
			provenance := jsvalue.Object{}
			for _, t := range targets {
				d, err := gate(ctx, tx, t)
				if err != nil {
					return Rotation{}, err
				}
				provenance = append(provenance, jsvalue.Member{Key: t.ID, Value: d})
			}
			if err := q.ReplaceGitHubAppKey(ctx, query.ReplaceGitHubAppKeyParams{
				KeyEnvelope: sql.NullString{String: sealed, Valid: true}, UpdatedAt: sql.NullInt64{Int64: s.now().UnixMicro(), Valid: true}, ID: seen.ID,
			}); err != nil {
				return Rotation{}, err
			}
			// A rotation is a Target mutation class trigger (ADR-0031 §6): enqueued directly.
			if err := q.QueueGitHubAppTargets(ctx, sql.NullString{String: seen.ID, Valid: true}); err != nil {
				return Rotation{}, err
			}
			rotated, err := githubapps.Get(ctx, tx, org.ID)
			if err != nil {
				return Rotation{}, err
			}
			// Report mode (ADR-0054 Decision 9), before the audit insert.
			if err := p.Count(ctx, tx); err != nil {
				return Rotation{}, err
			}
			joined := func(list []string) any {
				if len(list) == 0 {
					return nil
				}
				return strings.Join(list, ",")
			}
			targetIDs := make([]string, len(targets))
			for i, t := range targets {
				targetIDs[i] = t.ID
			}
			action := "config.sync.manage"
			md := jsvalue.Object{{Key: "appId", Value: seen.GitHubAppID}, {Key: "slug", Value: seen.Slug}, {Key: "version", Value: rotated.Version},
				{Key: "connections", Value: joined(connections)}, {Key: "reauthorizedTargets", Value: joined(targetIDs)}}
			if _, err := audit.Record(ctx, tx, audit.Event{
				Type: "sync.github_app_key_rotated", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &org.ID, Action: &action,
				Resource: jsvalue.Object{{Key: "githubAppId", Value: seen.ID}},
				Authz:    jsvalue.Object{{Key: "reauthorizedTargets", Value: provenance}},
				Metadata: append(md, approvalMetadata(p.Approval)...),
			}); err != nil {
				return Rotation{}, err
			}
			rotated.KeyEnvelope = sql.NullString{}
			return Rotation{App: &rotated}, nil
		},
	})
	if err != nil {
		return Rotation{}, nil, err
	}
	return out, access, nil
}
