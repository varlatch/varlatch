// SPDX-License-Identifier: AGPL-3.0-or-later

// Package githubapps is an Organization's GitHub App (ADR-0047, the
// TypeScript domain/githubapps.ts; ADR-0059 step 4.10): its registration
// through GitHub's manifest flow, staged (ADR-0054 amendment D: start, the
// conversion in the callback, the attachment, discard, the hourly sweep),
// its import, its removal, and the App's own signed requests to GitHub
// (jwt.go).
package githubapps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// GitHubWeb is GITHUB_WEB.
const GitHubWeb = "https://github.com"

// RegistrationTTL is REGISTRATION_TTL_SECONDS: GitHub's code is valid for
// an hour, and so is the state.
const RegistrationTTL = time.Hour

// PendingTTL is PENDING_TTL_SECONDS: a pending conversion expires one hour
// after it was stored (amendment D).
const PendingTTL = time.Hour

// Permissions is GITHUB_APP_PERMISSIONS, in its order.
var Permissions = [][2]string{{"secrets", "write"}, {"environments", "write"}, {"metadata", "read"}}

const appNameMax = 34

var (
	loginPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
	slugPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,99}$`)
)

// Service is the GitHub App's operations.
type Service struct {
	Writer    *write.Writer
	Approvals *auth.Service
	RootKEK   []byte
	Policy    *outbound.Policy
	Now       func() time.Time
	Log       *slog.Logger
	client    *http.Client
}

// UseClient makes s send GitHub's requests through c instead of the
// outbound policy's client: tests, with a fake GitHub.
func UseClient(s *Service, c *http.Client) { s.client = c }

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Request is who asks, with which approval.
type Request struct {
	Principal *auth.Principal
	Approval  *string
	RequestID string
}

func (r Request) security(approvals *auth.Service) security.Request {
	out := security.Request{Principal: r.Principal, Approvals: approvals}
	if r.Approval != nil {
		if out.ApprovalID = auth.ParseApprovalID(*r.Approval); out.ApprovalID == "" {
			out.ApprovalMalformed = true
		}
	}
	return out
}

// ManageIn is actionIn's config.sync.manage, rechecked in a protected
// operation's job once its approval was consumed.
func ManageIn(p *auth.Principal, organizationID, requestID string) func(ctx context.Context, tx query.DBTX) error {
	return func(ctx context.Context, tx query.DBTX) error {
		ap := authz.Principal{IdentityID: p.Identity.ID, IdentityKind: p.Identity.Kind, CredentialID: p.Credential.ID}
		if p.Identity.OrganizationID != nil {
			ap.OrganizationID = *p.Identity.OrganizationID
		}
		d, err := authz.Decide(ctx, tx, ap, "config.sync.manage", authz.Resource{OrganizationID: organizationID},
			authz.Options{HideExistence: true, RequestID: requestID})
		if err != nil || d.Allowed {
			return err
		}
		if d.DenialEvent != nil {
			return &security.DeferredDenial{Err: d.Err, Event: *d.DenialEvent}
		}
		return d.Err
	}
}

// Account is a GitHub account: its login and type ("organization" or
// "user").
type Account struct {
	Login, Type string
}

func (a Account) js() jsvalue.Object {
	return jsvalue.Object{{Key: "login", Value: a.Login}, {Key: "type", Value: a.Type}}
}

func sameAccount(a, b Account) bool { return a.Type == b.Type && strings.EqualFold(a.Login, b.Login) }

// App is a github_apps row.
type App struct {
	ID, OrganizationID string
	GitHubAppID        int64
	Slug, ClientID     string
	OwnerLogin         string
	OwnerID            int64
	OwnerType          string
	CreatedBy          sql.NullString
	CreatedAt          int64
	Version            int64
	UpdatedAt          sql.NullInt64
	KeyEnvelope        sql.NullString
}

func appOf(r query.OrganizationGitHubAppRow) App {
	return App{ID: r.ID, OrganizationID: r.OrganizationID, GitHubAppID: r.GithubAppID, Slug: r.Slug, ClientID: r.ClientID,
		OwnerLogin: r.OwnerLogin, OwnerID: r.OwnerID, OwnerType: r.OwnerType, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt,
		Version: r.Version, UpdatedAt: r.UpdatedAt, KeyEnvelope: r.KeyEnvelope}
}

func insertedApp(r query.InsertGitHubAppRow) App {
	return App{ID: r.ID, OrganizationID: r.OrganizationID, GitHubAppID: r.GithubAppID, Slug: r.Slug, ClientID: r.ClientID,
		OwnerLogin: r.OwnerLogin, OwnerID: r.OwnerID, OwnerType: r.OwnerType, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt,
		Version: r.Version, UpdatedAt: r.UpdatedAt}
}

// JS is serializeGitHubApp.
func (a App) JS() jsvalue.Object {
	var updated any
	if a.UpdatedAt.Valid {
		updated = audit.ISOTime(a.UpdatedAt.Int64)
	}
	return jsvalue.Object{
		{Key: "id", Value: a.ID}, {Key: "organizationId", Value: a.OrganizationID}, {Key: "githubAppId", Value: a.GitHubAppID},
		{Key: "slug", Value: a.Slug}, {Key: "clientId", Value: a.ClientID},
		{Key: "owner", Value: jsvalue.Object{{Key: "login", Value: a.OwnerLogin}, {Key: "id", Value: a.OwnerID}, {Key: "type", Value: a.OwnerType}}},
		{Key: "htmlUrl", Value: GitHubWeb + "/apps/" + a.Slug}, {Key: "version", Value: a.Version},
		{Key: "createdAt", Value: audit.ISOTime(a.CreatedAt)}, {Key: "updatedAt", Value: updated},
	}
}

func noApp() error { return domainerr.New("RESOURCE_NOT_FOUND", "This Organization has no GitHub App") }

// liveApp is liveApp; nil for none.
func liveApp(ctx context.Context, db query.DBTX, organizationID string) (*App, error) {
	r, err := query.New(db).OrganizationGitHubApp(ctx, organizationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a := appOf(r)
	return &a, nil
}

// Get is getGitHubApp.
func Get(ctx context.Context, db query.DBTX, organizationID string) (App, error) {
	a, err := liveApp(ctx, db, organizationID)
	if err != nil {
		return App{}, err
	}
	if a == nil {
		return App{}, noApp()
	}
	return *a, nil
}

func appIDInUse(ctx context.Context, db query.DBTX, githubAppID int64) (bool, error) {
	n, err := query.New(db).GitHubAppIDInUse(ctx, githubAppID)
	return n > 0, err
}

// DeleteURL is githubAppDeleteUrl: where the owner of a GitHub App deletes it.
func DeleteURL(slug string, owner Account) string {
	if owner.Type == "organization" {
		return GitHubWeb + "/organizations/" + url.PathEscape(owner.Login) + "/settings/apps/" + url.PathEscape(slug) + "/advanced"
	}
	return GitHubWeb + "/settings/apps/" + url.PathEscape(slug) + "/advanced"
}

// ---------------------------------------------------------------------------
// The key.

// orgKEK is orgKekOf, read in db: a deleted Organization's KEK is
// destroyed, so it fails closed.
func (s *Service) orgKEK(ctx context.Context, db query.DBTX, organizationID string) ([]byte, error) {
	o, err := query.New(db).RetrievalOrganization(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	if !o.WrappedOrgKek.Valid {
		return nil, domainerr.New("ORGANIZATION_DELETED", "This Organization was deleted: its key is destroyed")
	}
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(o.WrappedOrgKek.String), &env); err != nil {
		return nil, err
	}
	return envelope.UnwrapOrgKEK(s.RootKEK, env, organizationID)
}

// SealKey is encryptGitHubAppKey: the PEM under the Organization KEK, bound
// to the App's row id (or the registration's id while it is pending).
func SealKey(orgKEK []byte, organizationID, appRowID, pemText string) (string, error) {
	sealed, err := envelope.Seal(orgKEK, []byte(pemText), envelope.GitHubAppKeyContext(organizationID, appRowID))
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(sealed)
	return string(b), err
}

// OpenKey is decryptGitHubAppKey.
func OpenKey(orgKEK []byte, organizationID, appRowID, sealed string) (string, error) {
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(sealed), &env); err != nil {
		return "", err
	}
	plain, err := envelope.Open(orgKEK, env, envelope.GitHubAppKeyContext(organizationID, appRowID))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// ---------------------------------------------------------------------------
// GitHub.

// clientFor is the client GitHub's requests go through: the outbound
// policy's for purpose github (or the test's), each request refused once
// the effect's deadline passed, each refusal noted for the effect, as the
// policy's fetch records it for the Organization.
func (s *Service) clientFor(organizationID string) *http.Client {
	base := s.client
	if base == nil {
		base = s.Policy.Client(outbound.GitHub)
	}
	next := base.Transport
	if next == nil {
		return base
	}
	c := *base
	c.Transport = roundTripper(func(r *http.Request) (*http.Response, error) {
		if err := write.EffectAlive(r.Context()); err != nil {
			return nil, err
		}
		res, err := next.RoundTrip(r)
		if refusal := outbound.RefusalOf(err); refusal != nil && s.Policy != nil {
			if e, ok := s.Policy.RefusalEvent(outbound.RefusalRecord{
				OrganizationID: organizationID, Purpose: outbound.GitHub, Phase: "connection", Refusal: refusal, Resource: jsvalue.Object{},
			}); ok {
				write.NoteRefusal(r.Context(), e)
			}
		}
		return res, err
	})
	return &c
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
