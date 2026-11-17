// SPDX-License-Identifier: AGPL-3.0-or-later

package githubapps

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"slices"
	"strings"
	"unicode/utf16"

	"github.com/varlatch/varlatch/go/lib/storage"
	vsync "github.com/varlatch/varlatch/go/lib/sync"
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

// levels are GitHub's permission levels, weakest first.
var levels = []string{"read", "write", "admin"}

func allows(granted any, needed string) bool {
	g, ok := granted.(string)
	return ok && slices.Index(levels, g) >= slices.Index(levels, needed)
}

// readAccount is readAccount: GitHub's account object, or nil.
func readAccount(v any) *struct {
	Account
	ID int64
} {
	a, ok := v.(jsvalue.Object)
	if !ok {
		return nil
	}
	get := func(k string) any { x, _ := a.Get(k); return x }
	login, _ := get("login").(string)
	id, idOK := safeInt(get("id"))
	typ, _ := get("type").(string)
	if !loginPattern.MatchString(login) || !idOK || typ != "Organization" && typ != "User" {
		return nil
	}
	out := &struct {
		Account
		ID int64
	}{Account: Account{Login: login, Type: "user"}, ID: id}
	if typ == "Organization" {
		out.Type = "organization"
	}
	return out
}

// jsString is String(v) for a parsed JSON value.
func jsString(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		return jsvalue.Number(x)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			if e != nil {
				parts[i] = jsString(e)
			}
		}
		return strings.Join(parts, ",")
	}
	return "[object Object]"
}

// jsLess is JavaScript's default sort order: by UTF-16 code units.
func jsLess(a, b string) int { return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b))) }

// ImportOutcome is importGitHubApp's outcome: the App registered, or the
// check that failed.
type ImportOutcome struct {
	Registered bool
	App        App
	Check      vsync.AccessCheck
}

// JS is the answer's body (registered: 201).
func (o ImportOutcome) JS() jsvalue.Object {
	if o.Registered {
		return jsvalue.Object{{Key: "outcome", Value: "registered"}, {Key: "app", Value: o.App.JS()}}
	}
	out := jsvalue.Object{{Key: "outcome", Value: "failed"}, {Key: "status", Value: string(o.Check.Status)}, {Key: "where", Value: string(o.Check.Where)}}
	if o.Check.HTTPStatus != 0 {
		out = append(out, jsvalue.Member{Key: "httpStatus", Value: o.Check.HTTPStatus})
	}
	return append(out, jsvalue.Member{Key: "message", Value: o.Check.Message})
}

// imported is what GET /app confirmed.
type imported struct {
	failed   *vsync.AccessCheck
	slug     string
	clientID string
	owner    Account
	ownerID  int64
	extra    string
}

// Import is importGitHubApp: an App someone registered on GitHub, by its
// id and private key. The pair is verified first with a JWT signed by the
// key (issued as the App id) and GET /app answering that id; the client
// id, slug and owner are then GitHub's. The App needs the permissions
// Varlatch pushes with; more are named in the audit event.
//
// A protected operation: admin-step-up's github_app.import, bound to the
// App id and the key. Under enforce GitHub is asked only after a precheck
// found an approved intent for exactly this binding (amendment D);
// consumption is in the final job, and a key GitHub does not confirm
// leaves the approval unconsumed. An external effect: the Organization's
// gate shared and the requester's (exclusive when the request carries an
// approval) across the call; no resource gate (decision 4).
func (s *Service) Import(ctx context.Context, req Request, org authz.Organization, appID int64, privateKey string) (ImportOutcome, []auth.PendingReport, error) {
	reader := s.Writer.Store.Reader()
	if err := write.RefuseIfDeleting(ctx, reader, org.ID); err != nil {
		return ImportOutcome{}, nil, err
	}
	if err := authz.RefuseIfIncidentFrozen(ctx, reader, org.ID, ""); err != nil {
		return ImportOutcome{}, nil, err
	}
	key := ParseRSAKey(privateKey)
	if key == nil {
		return ImportOutcome{}, nil, domainerr.New("VALIDATION_FAILED", "privateKey: not an RSA private key in PEM, as GitHub issues them")
	}
	r := req.security(s.Approvals)
	actor := req.Principal.Identity.ID
	alreadyHasApp := func() error {
		return domainerr.New("STATE_CHANGED", "This Organization already has a GitHub App. Remove it from Varlatch before importing another.")
	}
	var started *security.Started
	var access []auth.PendingReport
	out, _, err := write.RunEffect(ctx, s.Writer, write.Effect[imported, ImportOutcome]{
		OrganizationID: org.ID, People: []write.Gate{r.RequesterGate()},
		// The checkpoint is the protected operation's, after its preflight.
		Check: func(ctx context.Context, tx *sql.Tx) error {
			var err error
			started, err = security.Start(ctx, tx, r, security.Protected{
				Scope:  write.Scope{OrganizationID: org.ID},
				Checks: []security.Check{{Control: security.AdminStepUp, Operation: "github_app.import"}},
				Preflight: func(ctx context.Context, db query.DBTX) error {
					a, err := liveApp(ctx, db, org.ID)
					if err == nil && a != nil {
						err = alreadyHasApp()
					}
					return err
				},
				Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
					used, err := appIDInUse(ctx, db, appID)
					if err != nil {
						return nil, err
					}
					if used {
						return nil, domainerr.New("STATE_CHANGED", "Another Organization on this Varlatch already uses the App "+itoa(appID)+".")
					}
					return ImportBinding(org.ID, appID, privateKey), nil
				},
				AuthorizeIn: ManageIn(req.Principal, org.ID, req.RequestID),
			}, s.now)
			if err == nil {
				access = started.Access()
			}
			return err
		},
		Call: func(ctx context.Context) (imported, error) {
			a, claims, refusal, err := AppRequest(ctx, s.clientFor(org.ID), http.MethodGet, "/app", itoa(appID), key, s.now(), nil)
			if err != nil {
				return imported{}, err
			}
			if a == nil {
				if derr := write.EffectAlive(ctx); derr != nil {
					return imported{}, derr
				}
				c := GitHubUnreachable(refusal)
				return imported{failed: &c}, nil
			}
			fail := func(c vsync.AccessCheck) (imported, error) { return imported{failed: &c}, nil }
			if a.status == http.StatusUnauthorized {
				return fail(ReadJWTRefusal(a.asResponse(), claims))
			}
			if a.status < 200 || a.status > 299 {
				return fail(vsync.AccessCheck{Status: vsync.StatusFailed, Where: vsync.WhereConnection, HTTPStatus: a.status,
					Message: "GitHub did not confirm App " + itoa(appID) + " with this key (HTTP " + itoa(int64(a.status)) + ")."})
			}
			v, _ := a.json()
			body, ok := v.(jsvalue.Object)
			get := func(k string) any { x, _ := body.Get(k); return x }
			var owner = readAccount(get("owner"))
			id, idOK := get("id").(float64)
			safe := idOK && id == float64(int64(id)) && id >= -9007199254740991 && id <= 9007199254740991
			slug, _ := get("slug").(string)
			clientID, _ := get("client_id").(string)
			permissions, permsOK := get("permissions").(jsvalue.Object)
			if !ok || owner == nil || !safe || !slugPattern.MatchString(slug) || clientID == "" || len(utf16.Encode([]rune(clientID))) > 100 || !permsOK {
				return fail(NotGitHub(a.status))
			}
			if int64(id) != appID {
				return fail(NotGitHub(a.status))
			}
			var missing []string
			for _, p := range Permissions {
				granted, _ := permissions.Get(p[0])
				if !allows(granted, p[1]) {
					missing = append(missing, p[0]+": "+p[1])
				}
			}
			if len(missing) > 0 {
				return fail(vsync.AccessCheck{Status: vsync.StatusPermissionMissing, Where: vsync.WhereConnection, HTTPStatus: a.status,
					Message: "The App " + slug + " lacks " + strings.Join(missing, ", ") + ". Give it those permissions in its settings on GitHub (and have the installation accept them), then import it again."})
			}
			var extra []string
			for _, m := range permissions {
				known := false
				for _, p := range Permissions {
					known = known || p[0] == m.Key
				}
				if !known {
					extra = append(extra, m.Key)
				}
			}
			slices.SortFunc(extra, jsLess)
			for i, name := range extra {
				granted, _ := permissions.Get(name)
				extra[i] = name + ":" + jsString(granted)
			}
			return imported{slug: slug, clientID: clientID, owner: owner.Account, ownerID: owner.ID, extra: strings.Join(extra, ",")}, nil
		},
		Final: func(ctx context.Context, tx *storage.Tx, got imported) (ImportOutcome, error) {
			if got.failed != nil {
				return ImportOutcome{Check: *got.failed}, nil
			}
			kek, err := s.orgKEK(ctx, tx, org.ID)
			if err != nil {
				return ImportOutcome{}, err
			}
			id := ids.New(ids.GitHubApp)
			sealed, err := SealKey(kek, org.ID, id, privateKey)
			if err != nil {
				return ImportOutcome{}, err
			}
			// Consumption, now that GitHub confirmed the key, then the App row.
			p, err := started.Finish(ctx, tx)
			if err != nil {
				return ImportOutcome{}, err
			}
			now := s.now().UnixMicro()
			inserted, err := query.New(tx).InsertGitHubApp(ctx, query.InsertGitHubAppParams{
				ID: id, OrganizationID: org.ID, GithubAppID: appID, Slug: got.slug, ClientID: got.clientID,
				OwnerLogin: got.owner.Login, OwnerID: got.ownerID, OwnerType: got.owner.Type, KeyEnvelope: nullStr(sealed),
				CreatedBy: nullStr(actor), CreatedAt: now,
			})
			if errors.Is(err, sql.ErrNoRows) {
				a, lerr := liveApp(ctx, tx, org.ID)
				if lerr != nil {
					return ImportOutcome{}, lerr
				}
				if a != nil {
					return ImportOutcome{}, alreadyHasApp()
				}
				return ImportOutcome{}, domainerr.New("STATE_CHANGED", "Another Organization on this Varlatch already uses the App "+got.slug+".")
			}
			if err != nil {
				return ImportOutcome{}, err
			}
			if err := p.Count(ctx, tx); err != nil {
				return ImportOutcome{}, err
			}
			if _, err := audit.Record(ctx, tx, registeredEvent(org.ID, actor, id, "import", appID, got.slug, got.owner, got.extra, p.Approval)); err != nil {
				return ImportOutcome{}, err
			}
			return ImportOutcome{Registered: true, App: insertedApp(inserted)}, nil
		},
	})
	if err != nil {
		return ImportOutcome{}, nil, err
	}
	return out, access, nil
}
