// SPDX-License-Identifier: AGPL-3.0-or-later

package githubapps

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	vsync "github.com/varlatch/varlatch/go/lib/sync"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// maxInstallationPages is MAX_INSTALLATION_PAGES: 3,000 installations.
const maxInstallationPages = 30

// CheckJS is an access check as the API gives it.
func CheckJS(c vsync.AccessCheck) jsvalue.Object {
	o := jsvalue.Object{{Key: "status", Value: string(c.Status)}, {Key: "where", Value: string(c.Where)}}
	if c.HTTPStatus != 0 {
		o = append(o, jsvalue.Member{Key: "httpStatus", Value: c.HTTPStatus})
	}
	return append(o, jsvalue.Member{Key: "message", Value: c.Message})
}

// listing is readInstallations' answer.
type listing struct {
	check     vsync.AccessCheck
	items     []any
	truncated bool
}

// readInstallations is readInstallations: every page, every entry GitHub's
// and this App's (a foreign or missing app_id fails the whole listing).
func readInstallations(ctx context.Context, c *http.Client, githubAppID int64, clientID string, key *rsa.PrivateKey, now time.Time) listing {
	failed := func(ch vsync.AccessCheck) listing { return listing{check: ch, items: []any{}} }
	items := []any{}
	for page := 1; page <= maxInstallationPages; page++ {
		a, claims, refusal, err := AppRequest(ctx, c, http.MethodGet, "/app/installations?per_page=100&page="+strconv.Itoa(page), clientID, key, now, nil)
		if err != nil || a == nil {
			return failed(GitHubUnreachable(refusal))
		}
		if a.status == http.StatusUnauthorized {
			return failed(ReadJWTRefusal(a.asResponse(), claims))
		}
		if a.status < 200 || a.status > 299 {
			return failed(vsync.AccessCheck{Status: vsync.StatusFailed, Where: vsync.WhereConnection, HTTPStatus: a.status,
				Message: "GitHub refused to list the App's installations (HTTP " + strconv.Itoa(a.status) + ")."})
		}
		v, _ := a.json()
		entries, ok := v.([]any)
		if !ok {
			return failed(NotGitHub(a.status))
		}
		for _, entry := range entries {
			e, _ := entry.(jsvalue.Object)
			get := func(k string) any { x, _ := e.Get(k); return x }
			account := readAccount(get("account"))
			id, idOK := safeInt(get("id"))
			appID, _ := get("app_id").(float64)
			selection, _ := get("repository_selection").(string)
			if e == nil || account == nil || !idOK || appID != float64(githubAppID) || selection != "all" && selection != "selected" {
				return failed(NotGitHub(a.status))
			}
			suspended := false
			if s, present := e.Get("suspended_at"); present && s != nil {
				suspended = true
			}
			items = append(items, jsvalue.Object{
				{Key: "installationId", Value: id},
				{Key: "account", Value: jsvalue.Object{{Key: "login", Value: account.Login}, {Key: "id", Value: account.ID}, {Key: "type", Value: account.Type}}},
				{Key: "repositorySelection", Value: selection}, {Key: "suspended", Value: suspended},
			})
		}
		if len(entries) < 100 {
			return listing{check: vsync.AccessCheck{Status: vsync.StatusOK, Where: vsync.WhereConnection, Message: "listed"}, items: items}
		}
	}
	return listing{check: vsync.AccessCheck{Status: vsync.StatusOK, Where: vsync.WhereConnection, Message: "listed"}, items: items, truncated: true}
}

// Installations is listAppInstallations: where the App is installed
// (Decision 2: the person picks one to create a Connection), signed as the
// App, audited as a use of the stored key. An external effect: the
// Organization's gate and the requester's shared across GitHub's calls.
func (s *Service) Installations(ctx context.Context, p *auth.Principal, org authz.Organization) (jsvalue.Object, []auth.PendingReport, error) {
	reader := s.Writer.Store.Reader()
	if err := write.RefuseIfDeleting(ctx, reader, org.ID); err != nil {
		return nil, nil, err
	}
	if err := authz.RefuseIfIncidentFrozen(ctx, reader, org.ID, ""); err != nil {
		return nil, nil, err
	}
	actor := p.Identity.ID
	var app *App
	var key *rsa.PrivateKey
	out, reports, err := write.RunEffect(ctx, s.Writer, write.Effect[listing, jsvalue.Object]{
		OrganizationID: org.ID, People: []write.Gate{write.Person(actor, write.Shared)}, Principal: p,
		Check: func(ctx context.Context, tx *sql.Tx) error {
			var err error
			if app, err = liveApp(ctx, tx, org.ID); err == nil && app == nil {
				err = noApp()
			}
			return err
		},
		// The App exists; then the checkpoint (RunEffect); then its key.
		Checked: func(ctx context.Context, tx *sql.Tx) error {
			var err error
			key, err = s.appKey(ctx, tx, *app)
			return err
		},
		Call: func(ctx context.Context) (listing, error) {
			return readInstallations(ctx, s.clientFor(org.ID), app.GitHubAppID, app.ClientID, key, s.now()), nil
		},
		Final: func(ctx context.Context, tx *storage.Tx, l listing) (jsvalue.Object, error) {
			action := "config.sync.manage"
			var status any
			if l.check.HTTPStatus != 0 {
				status = l.check.HTTPStatus
			}
			if _, err := audit.Record(ctx, tx, audit.Event{
				Type: "sync.github_app_installations_listed", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &org.ID,
				Action: &action, Resource: jsvalue.Object{{Key: "githubAppId", Value: app.ID}},
				Metadata: jsvalue.Object{{Key: "status", Value: string(l.check.Status)}, {Key: "httpStatus", Value: status},
					{Key: "count", Value: len(l.items)}, {Key: "truncated", Value: l.truncated}},
			}); err != nil {
				return nil, err
			}
			return jsvalue.Object{{Key: "check", Value: CheckJS(l.check)}, {Key: "items", Value: l.items}, {Key: "truncated", Value: l.truncated}}, nil
		},
	})
	return out, reports, err
}

// appKey is the App's private key, unwrapped (appWithKey's decryption).
func (s *Service) appKey(ctx context.Context, db *sql.Tx, a App) (*rsa.PrivateKey, error) {
	kek, err := s.orgKEK(ctx, db, a.OrganizationID)
	if err != nil {
		return nil, err
	}
	return OpenAppKey(kek, a)
}
