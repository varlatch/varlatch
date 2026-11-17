// SPDX-License-Identifier: AGPL-3.0-or-later

package githubapps

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/whatwg"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// Registration (ADR-0047 Decision 1 and its 2026-10-09 amendment, staged by
// ADR-0054 amendment D), as githubapps.ts runs it:
//
//  1. Start (not protected): a single-use state, bound to the person, the
//     Organization and the intended GitHub account, and the manifest.
//  2. Conversion (the callback, not protected): an external effect
//     holding the registration's gate across GitHub's code exchange
//     (feature-parity decision 4): the state claimed, GitHub's answer and
//     the owner checked, the conversion stored as pending (written once).
//  3. Attachment (github_app.register, protected): in the callback's final
//     job while it needs no approval; otherwise the conversion commits as
//     pending and the client attaches it on its own route.
//
// Attachment, discard and the sweep each take the registration's gate and
// check again under it that it is still pending; whichever commits first
// wins.

// registrationGate is a registration's resource gate (decision 4).
func registrationGate(id string) write.Gate { return write.Resource("github_app_registration", id) }

func nullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }
func nullInt(n int64) sql.NullInt64   { return sql.NullInt64{Int64: n, Valid: true} }

// encodeURIComponent is JavaScript's, for valid UTF-8.
func encodeURIComponent(s string) string {
	const keep = "-_.!~*'()"
	var b strings.Builder
	for _, r := range s {
		if r < utf8.RuneSelf && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(keep, r)) {
			b.WriteRune(r)
			continue
		}
		var enc [4]byte
		n := utf8.EncodeRune(enc[:], r)
		for _, c := range enc[:n] {
			b.WriteByte('%')
			b.WriteByte("0123456789ABCDEF"[c>>4])
			b.WriteByte("0123456789ABCDEF"[c&0xf])
		}
	}
	return b.String()
}

// sliceUTF16 is String.prototype.slice(0, n).
func sliceUTF16(s string, n int) string {
	u := utf16.Encode([]rune(s))
	if len(u) <= n {
		return s
	}
	return string(utf16.Decode(u[:n]))
}

// RedirectURL is registrationRedirectUrl: the dashboard's page for this
// Organization, where the browser goes back to after GitHub.
func RedirectURL(base *url.URL, orgSlug string) string {
	return base.Scheme + "://" + base.Host + strings.TrimRight(base.EscapedPath(), "/") + "/o/" + encodeURIComponent(orgSlug) + "/connections/github-app"
}

// Start is startRegistration: the registration's stable id (its target
// from then on), the state (returned once, only its SHA-256 stored), the
// manifest and where the browser posts it. Ended registrations a day past
// their expiry are deleted first.
func (s *Service) Start(ctx context.Context, p *auth.Principal, org authz.Organization, account Account, base *url.URL) (jsvalue.Object, error) {
	reader := s.Writer.Store.Reader()
	if err := write.RefuseIfDeleting(ctx, reader, org.ID); err != nil {
		return nil, err
	}
	if err := authz.RefuseIfIncidentFrozen(ctx, reader, org.ID, ""); err != nil {
		return nil, err
	}
	if !loginPattern.MatchString(account.Login) {
		return nil, domainerr.New("VALIDATION_FAILED", "account.login: not a GitHub account name")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	state := base64.RawURLEncoding.EncodeToString(raw)
	origin := base.Scheme + "://" + base.Host
	manifest := jsvalue.Object{
		{Key: "name", Value: strings.TrimRightFunc(sliceUTF16("Varlatch "+org.Slug, appNameMax), isJSSpace)},
		{Key: "url", Value: origin},
		{Key: "description", Value: "Varlatch writes GitHub Actions secrets for the " + org.Name + " Organization."},
		{Key: "redirect_url", Value: RedirectURL(base, org.Slug)},
		{Key: "public", Value: false},
		{Key: "default_permissions", Value: jsvalue.Object{{Key: "secrets", Value: "write"}, {Key: "environments", Value: "write"}, {Key: "metadata", Value: "read"}}},
		{Key: "default_events", Value: []any{}},
	}
	action := GitHubWeb + "/settings/apps/new?state=" + state
	if account.Type == "organization" {
		action = GitHubWeb + "/organizations/" + encodeURIComponent(account.Login) + "/settings/apps/new?state=" + state
	}
	actor := p.Identity.ID
	id := ids.New(ids.GitHubAppRegistration)
	var expires int64
	err := s.Writer.Job(ctx, []write.Gate{write.Organization(org.ID, write.Shared), write.Person(actor, write.Shared)}, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: org.ID}); err != nil {
			return err
		}
		if _, err := write.Checkpoint(ctx, tx, p, org.ID); err != nil {
			return err
		}
		now := s.now()
		q := query.New(tx)
		if err := q.DeleteOldGitHubAppRegistrations(ctx, now.Add(-24*time.Hour).UnixMicro()); err != nil {
			return err
		}
		a, err := liveApp(ctx, tx, org.ID)
		if err != nil {
			return err
		}
		if a != nil {
			return domainerr.New("STATE_CHANGED", "This Organization already has a GitHub App. Remove it from Varlatch before registering another.")
		}
		expires = now.Add(RegistrationTTL).UnixMicro()
		return q.InsertGitHubAppRegistration(ctx, query.InsertGitHubAppRegistrationParams{
			ID: id, StateHash: auth.HashToken(state), OrganizationID: org.ID, ActorIdentityID: actor,
			AccountLogin: account.Login, AccountType: account.Type, CreatedAt: now.UnixMicro(), ExpiresAt: expires,
		})
	})
	if err != nil {
		return nil, err
	}
	return jsvalue.Object{
		{Key: "id", Value: id}, {Key: "state", Value: state}, {Key: "action", Value: action}, {Key: "manifest", Value: manifest},
		{Key: "account", Value: account.js()}, {Key: "expiresAt", Value: audit.ISOTime(expires)},
	}, nil
}

// isJSSpace is what String.prototype.trimEnd removes.
func isJSSpace(r rune) bool { return whatwg.IsJSSpace(r) }

// ---------------------------------------------------------------------------
// Outcomes.

// Outcome is RegistrationOutcome.
type Outcome struct {
	// Kind is "registered", "refused" or "failed".
	Kind string
	App  App
	// Refused.
	Reason  string
	Refused struct {
		GitHubAppID int64
		Slug        string
		Owner       Account
	}
	Account   Account
	DeleteURL string
	Message   string
	// Failed.
	Retryable  bool
	HTTPStatus int
}

// JS is the answer's body (the route answers "registered" 201 with the App
// serialized, the rest 200).
func (o Outcome) JS() jsvalue.Object {
	switch o.Kind {
	case "registered":
		return jsvalue.Object{{Key: "outcome", Value: "registered"}, {Key: "app", Value: o.App.JS()}}
	case "refused":
		var del any
		if o.DeleteURL != "" {
			del = o.DeleteURL
		}
		return jsvalue.Object{
			{Key: "outcome", Value: "refused"}, {Key: "reason", Value: o.Reason},
			{Key: "app", Value: jsvalue.Object{{Key: "githubAppId", Value: o.Refused.GitHubAppID}, {Key: "slug", Value: o.Refused.Slug}, {Key: "owner", Value: o.Refused.Owner.js()}}},
			{Key: "account", Value: o.Account.js()}, {Key: "deleteUrl", Value: del}, {Key: "message", Value: o.Message},
		}
	}
	out := jsvalue.Object{{Key: "outcome", Value: "failed"}, {Key: "retryable", Value: o.Retryable}}
	if o.HTTPStatus != 0 {
		out = append(out, jsvalue.Member{Key: "httpStatus", Value: o.HTTPStatus})
	}
	return append(out, jsvalue.Member{Key: "message", Value: o.Message})
}

// conversion is GitHub's conversion answer (readConversion).
type conversion struct {
	id             int64
	slug, clientID string
	pem            string
	ownerLogin     string
	ownerID        int64
	ownerType      string
}

func (c conversion) owner() Account { return Account{Login: c.ownerLogin, Type: c.ownerType} }

// readConversion is readConversion: GitHub's answer, or nil when it is not
// GitHub's (or has no usable key).
func readConversion(v any) *conversion {
	b, ok := v.(jsvalue.Object)
	if !ok {
		return nil
	}
	get := func(k string) any { x, _ := b.Get(k); return x }
	id, ok := safeInt(get("id"))
	slug, _ := get("slug").(string)
	clientID, _ := get("client_id").(string)
	pemText, pemOK := get("pem").(string)
	owner, ownerOK := get("owner").(jsvalue.Object)
	if !ok || !slugPattern.MatchString(slug) || clientID == "" || len(utf16.Encode([]rune(clientID))) > 100 || !pemOK || !ownerOK {
		return nil
	}
	oget := func(k string) any { x, _ := owner.Get(k); return x }
	login, _ := oget("login").(string)
	ownerID, idOK := safeInt(oget("id"))
	typ, _ := oget("type").(string)
	if !loginPattern.MatchString(login) || !idOK || typ != "Organization" && typ != "User" {
		return nil
	}
	if !IsRSAKey(pemText) {
		return nil
	}
	c := &conversion{id: id, slug: slug, clientID: clientID, pem: pemText, ownerLogin: login, ownerID: ownerID, ownerType: "user"}
	if typ == "Organization" {
		c.ownerType = "organization"
	}
	return c
}

// pendingFrom is pendingFrom: a converted registration's pending conversion.
func pendingFrom(r query.GithubAppRegistration) Pending {
	return Pending{RegistrationID: r.ID, GitHubAppID: r.PendingGithubAppID.Int64, Slug: r.PendingSlug.String, ClientID: r.PendingClientID.String,
		OwnerLogin: r.PendingOwnerLogin.String, OwnerID: r.PendingOwnerID.Int64, OwnerType: r.PendingOwnerType.String}
}

func (p Pending) owner() Account { return Account{Login: p.OwnerLogin, Type: p.OwnerType} }

// refusedEvent is sync.github_app_registration_refused.
func refusedEvent(organizationID, actor, reason string, p Pending, account Account) audit.Event {
	action := "config.sync.manage"
	return audit.Event{
		Type: "sync.github_app_registration_refused", Decision: audit.Deny, ActorIdentityID: &actor, OrganizationID: &organizationID,
		Action: &action, Resource: jsvalue.Object{{Key: "organizationId", Value: organizationID}},
		Metadata: jsvalue.Object{
			{Key: "reason", Value: reason}, {Key: "appId", Value: p.GitHubAppID}, {Key: "slug", Value: p.Slug},
			{Key: "owner", Value: p.OwnerLogin}, {Key: "ownerType", Value: p.OwnerType},
			{Key: "account", Value: account.Login}, {Key: "accountType", Value: account.Type},
		},
	}
}

// abandonedEvent is sync.github_app_registration_abandoned: a pending key
// deleted. actor "" is null (the sweep).
func abandonedEvent(organizationID, actor, reason string, p Pending) audit.Event {
	action := "config.sync.manage"
	e := audit.Event{
		Type: "sync.github_app_registration_abandoned", Decision: audit.Info, OrganizationID: &organizationID,
		Action: &action, Resource: jsvalue.Object{{Key: "organizationId", Value: organizationID}},
		Metadata: jsvalue.Object{
			{Key: "reason", Value: reason}, {Key: "appId", Value: p.GitHubAppID}, {Key: "slug", Value: p.Slug},
			{Key: "owner", Value: p.OwnerLogin}, {Key: "ownerType", Value: p.OwnerType}, {Key: "registrationId", Value: p.RegistrationID},
		},
	}
	if actor != "" {
		e.ActorIdentityID = &actor
	}
	return e
}

// registeredEvent is sync.github_app_registered.
func registeredEvent(organizationID, actor, appRowID, via string, githubAppID int64, slug string, owner Account, extra string, used *auth.UsedApproval) audit.Event {
	action := "config.sync.manage"
	md := jsvalue.Object{
		{Key: "via", Value: via}, {Key: "appId", Value: githubAppID}, {Key: "slug", Value: slug},
		{Key: "owner", Value: owner.Login}, {Key: "ownerType", Value: owner.Type},
	}
	if extra != "" {
		md = append(md, jsvalue.Member{Key: "extraPermissions", Value: extra})
	}
	return audit.Event{
		Type: "sync.github_app_registered", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID,
		Action: &action, Resource: jsvalue.Object{{Key: "githubAppId", Value: appRowID}},
		Metadata: append(md, security.ApprovalMetadata(used)...),
	}
}

// ---------------------------------------------------------------------------
// Terminal refusals.

// TerminalRefusal is a terminal refusal of an attachment (amendment D): its
// job rolls back, then the registration is ended.
type TerminalRefusal struct {
	Reason string
	Row    query.GithubAppRegistration
}

func (e *TerminalRefusal) Error() string { return "GitHub App registration refused: " + e.Reason }

func notWaiting() error {
	return domainerr.New("RESOURCE_NOT_FOUND", "No GitHub App registration of yours in this Organization is waiting to be attached")
}

// lapsed is converted_at IS NOT NULL AND pending_expires_at <= now.
func lapsed(r query.GithubAppRegistration, now int64) bool {
	return r.ConvertedAt.Valid && r.PendingExpiresAt.Valid && r.PendingExpiresAt.Int64 <= now
}

// attachRefusal is attachRefusal: a terminal refusal when the converted
// registration cannot be attached now, nil when it can.
func attachRefusal(ctx context.Context, db query.DBTX, organizationID string, r *query.GithubAppRegistration, now int64) (*TerminalRefusal, error) {
	if r == nil || !r.ConvertedAt.Valid {
		return nil, notWaiting()
	}
	if r.EndedAt.Valid {
		return &TerminalRefusal{"registration-ended", *r}, nil
	}
	if lapsed(*r, now) {
		return &TerminalRefusal{"expired", *r}, nil
	}
	a, err := liveApp(ctx, db, organizationID)
	if err != nil {
		return nil, err
	}
	if a != nil {
		return &TerminalRefusal{"organization-has-app", *r}, nil
	}
	used, err := appIDInUse(ctx, db, r.PendingGithubAppID.Int64)
	if err != nil {
		return nil, err
	}
	if used {
		return &TerminalRefusal{"app-in-use", *r}, nil
	}
	return nil, nil
}

// registration is readRegistration: this person's registration, nil when
// there is none.
func registration(ctx context.Context, db query.DBTX, organizationID, id, actor string) (*query.GithubAppRegistration, error) {
	r, err := query.New(db).GitHubAppRegistrationByID(ctx, query.GitHubAppRegistrationByIDParams{ID: id, OrganizationID: organizationID, ActorIdentityID: actor})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// endPending is endPending: only while still pending, its key deleted.
func endPending(ctx context.Context, db query.DBTX, id, reason string, at int64) (bool, error) {
	n, err := query.New(db).EndPendingGitHubAppRegistration(ctx, query.EndPendingGitHubAppRegistrationParams{
		EndedAt: nullInt(at), EndReason: nullStr(reason), ID: id})
	return n > 0, err
}

var refusalMessages = map[string]func(slug string) string{
	"organization-has-app": func(slug string) string {
		return "This Organization got another GitHub App while this one was being created, so Varlatch did not keep " + slug + ". Delete it on GitHub."
	},
	"app-in-use": func(slug string) string {
		return "Another Organization on this Varlatch already uses the App " + slug + ", so Varlatch did not keep it here."
	},
	"expired": func(slug string) string {
		return "This registration was not attached within the hour, so Varlatch deleted its key and did not keep " + slug + ". Delete it on GitHub, then start again."
	},
	"registration-ended": func(slug string) string {
		return "This registration already ended: " + slug + " was attached, discarded or refused before."
	},
}

// endRefusedIn is endRefusedIn: a terminal refusal's end in db (which holds
// the Organization and the person): only if the registration is still
// pending, its key deleted and the audit event. The answer is the
// refusal, with GitHub's delete page for the App, except for a
// registration that already ended.
func endRefusedIn(ctx context.Context, db query.DBTX, organizationID string, refusal *TerminalRefusal, actor string, at int64) (Outcome, error) {
	p := pendingFrom(refusal.Row)
	account := Account{Login: refusal.Row.AccountLogin, Type: refusal.Row.AccountType}
	reason := "refused"
	if refusal.Reason == "expired" {
		reason = "expired"
	}
	ended, err := endPending(ctx, db, refusal.Row.ID, reason, at)
	if err != nil {
		return Outcome{}, err
	}
	if ended {
		switch refusal.Reason {
		case "expired":
			if _, err := audit.Record(ctx, db, abandonedEvent(organizationID, actor, "expired", p)); err != nil {
				return Outcome{}, err
			}
		case "organization-has-app", "app-in-use":
			if _, err := audit.Record(ctx, db, refusedEvent(organizationID, actor, refusal.Reason, p, account)); err != nil {
				return Outcome{}, err
			}
		}
	}
	o := Outcome{Kind: "refused", Reason: refusal.Reason, Account: account, Message: refusalMessages[refusal.Reason](p.Slug)}
	o.Refused.GitHubAppID, o.Refused.Slug, o.Refused.Owner = p.GitHubAppID, p.Slug, p.owner()
	if refusal.Reason != "registration-ended" {
		o.DeleteURL = DeleteURL(p.Slug, p.owner())
	}
	return o, nil
}

// ---------------------------------------------------------------------------
// Attachment.

// attachIn is attachInTx, in the caller's job: the protected operation's
// checks (github_app.register; refusals before an approval is asked for),
// then the registration's checks by the live clock, the key unwrapped and
// sealed again for the App row, the App inserted, the registration ended
// as attached, the count and the audit event. A *TerminalRefusal is the
// caller's to end.
func (s *Service) attachIn(ctx context.Context, tx query.DBTX, r security.Request, org authz.Organization, id string, authorizeIn func(context.Context, query.DBTX) error) (Outcome, error) {
	actor := r.Principal.Identity.ID
	p, err := security.Prepare(ctx, tx, r, security.Protected{
		Scope:  write.Scope{OrganizationID: org.ID},
		Checks: []security.Check{{Control: security.AdminStepUp, Operation: "github_app.register"}},
		Preflight: func(ctx context.Context, db query.DBTX) error {
			row, err := registration(ctx, db, org.ID, id, actor)
			if err != nil {
				return err
			}
			if row == nil || !row.ConvertedAt.Valid {
				return notWaiting()
			}
			return nil
		},
		Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
			row, err := registration(ctx, db, org.ID, id, actor)
			if err != nil {
				return nil, err
			}
			refusal, err := attachRefusal(ctx, db, org.ID, row, s.now().UnixMicro())
			if err != nil {
				return nil, err
			}
			if refusal != nil {
				return nil, refusal
			}
			return RegisterBinding(org.ID, org.Name, pendingFrom(*row)), nil
		},
		AuthorizeIn: authorizeIn,
	}, s.now)
	if err != nil {
		return Outcome{}, err
	}
	row, err := registration(ctx, tx, org.ID, id, actor)
	if err != nil {
		return Outcome{}, err
	}
	now := s.now().UnixMicro()
	refusal, err := attachRefusal(ctx, tx, org.ID, row, now)
	if err != nil {
		return Outcome{}, err
	}
	if refusal != nil {
		return Outcome{}, refusal
	}
	pending := pendingFrom(*row)
	kek, err := s.orgKEK(ctx, tx, org.ID)
	if err != nil {
		return Outcome{}, err
	}
	pemText, err := OpenKey(kek, org.ID, id, row.PendingKeyEnvelope.String)
	if err != nil {
		return Outcome{}, err
	}
	appID := ids.New(ids.GitHubApp)
	sealed, err := SealKey(kek, org.ID, appID, pemText)
	if err != nil {
		return Outcome{}, err
	}
	q := query.New(tx)
	inserted, err := q.InsertGitHubApp(ctx, query.InsertGitHubAppParams{
		ID: appID, OrganizationID: org.ID, GithubAppID: pending.GitHubAppID, Slug: pending.Slug, ClientID: pending.ClientID,
		OwnerLogin: pending.OwnerLogin, OwnerID: pending.OwnerID, OwnerType: pending.OwnerType, KeyEnvelope: nullStr(sealed),
		CreatedBy: nullStr(actor), CreatedAt: now,
	})
	if errors.Is(err, sql.ErrNoRows) {
		a, lerr := liveApp(ctx, tx, org.ID)
		if lerr != nil {
			return Outcome{}, lerr
		}
		reason := "app-in-use"
		if a != nil {
			reason = "organization-has-app"
		}
		return Outcome{}, &TerminalRefusal{reason, *row}
	}
	if err != nil {
		return Outcome{}, err
	}
	if _, err := q.EndPendingGitHubAppRegistration(ctx, query.EndPendingGitHubAppRegistrationParams{EndedAt: nullInt(now), EndReason: nullStr("attached"), ID: id}); err != nil {
		return Outcome{}, err
	}
	// Report mode (ADR-0054 Decision 9), before the audit insert.
	if err := p.Count(ctx, tx); err != nil {
		return Outcome{}, err
	}
	if _, err := audit.Record(ctx, tx, registeredEvent(org.ID, actor, appID, "manifest", pending.GitHubAppID, pending.Slug, pending.owner(), "", p.Approval)); err != nil {
		return Outcome{}, err
	}
	return Outcome{Kind: "registered", App: insertedApp(inserted)}, nil
}

// AttachResult is an attachment's outcome and the report counts.
type AttachResult struct {
	Outcome Outcome
	Reports []auth.PendingReport
}

// Attach is attachRegistration (amendment D step 3): github_app.register,
// protected, in a job of its own, under the registration's gate. Only the
// person who started it may attach it. A terminal refusal rolls the
// attempt back, consumption included, then ends the registration in a job
// of its own.
func (s *Service) Attach(ctx context.Context, req Request, org authz.Organization, id string) (AttachResult, error) {
	r := req.security(s.Approvals)
	actor := req.Principal.Identity.ID
	gates := r.Gates(org.ID, registrationGate(id))
	var out AttachResult
	err := s.Writer.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		o, err := s.attachIn(ctx, tx, r, org, id, ManageIn(req.Principal, org.ID, req.RequestID))
		out = AttachResult{Outcome: o}
		return err
	})
	var refusal *TerminalRefusal
	if !errors.As(err, &refusal) {
		if err != nil {
			return AttachResult{}, err
		}
		return out, nil
	}
	// The cleanup: the Organization and the person, the checkpoint, then the end.
	err = s.Writer.Job(ctx, []write.Gate{write.Organization(org.ID, write.Shared), write.Person(actor, write.Shared), registrationGate(id)},
		func(ctx context.Context, tx *storage.Tx) error {
			if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: org.ID}); err != nil {
				return err
			}
			reports, err := write.Checkpoint(ctx, tx, req.Principal, org.ID)
			if err != nil {
				return err
			}
			o, err := endRefusedIn(ctx, tx, org.ID, refusal, actor, s.now().UnixMicro())
			out = AttachResult{Outcome: o, Reports: reports}
			return err
		})
	if err != nil {
		return AttachResult{}, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// The callback.

// called is what GitHub's code exchange gave.
type called struct {
	noAnswer   bool
	refusal    *outbound.RefusedError
	status     int
	conversion *conversion
}

// CompleteResult is the callback's outcome, the report counts, and an
// error deferred until the conversion committed (an approval to ask for,
// or a machine credential's refusal).
type CompleteResult struct {
	Outcome  Outcome
	Reports  []auth.PendingReport
	Deferred error
}

// Complete is completeRegistration: the conversion, then the attachment in
// the same final job while it needs no approval, as one external effect
// holding the Organization's gate, the person's and the registration's
// across GitHub's code exchange (feature-parity decision 4). A second
// completion waits on the registration's gate and then reads the first
// one's outcome. The claim is written in the final job, with GitHub's
// answer: a call that got no answer leaves the state free for another
// attempt within the hour.
func (s *Service) Complete(ctx context.Context, req Request, org authz.Organization, state, code string) (CompleteResult, error) {
	actor := req.Principal.Identity.ID
	reader := s.Writer.Store.Reader()
	if err := write.RefuseIfDeleting(ctx, reader, org.ID); err != nil {
		return CompleteResult{}, err
	}
	if err := authz.RefuseIfIncidentFrozen(ctx, reader, org.ID, ""); err != nil {
		return CompleteResult{}, err
	}
	// A machine credential can never approve the attachment: under enforce
	// it is refused here, before the state is claimed or the code spent.
	if err := security.RefuseMachineUnderEnforce(ctx, reader, req.Principal, org.ID,
		[]security.Check{{Control: security.AdminStepUp, Operation: "github_app.register"}}); err != nil {
		return CompleteResult{}, err
	}
	stateHash := auth.HashToken(state)
	byState := func(ctx context.Context, db query.DBTX) (*query.GitHubAppRegistrationByStateRow, error) {
		r, err := query.New(db).GitHubAppRegistrationByState(ctx, query.GitHubAppRegistrationByStateParams{StateHash: stateHash, OrganizationID: org.ID, ActorIdentityID: actor})
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domainerr.New("RESOURCE_NOT_FOUND", "No GitHub App registration of yours in this Organization has this state")
		}
		if err != nil {
			return nil, err
		}
		return &r, nil
	}
	// The registration's id names its gate: read before the gates, read
	// again in the effect's snapshot.
	seen, err := byState(ctx, reader)
	if err != nil {
		return CompleteResult{}, err
	}
	// The attachment's request never carries an approval: the callback is
	// never repeated.
	attachReq := security.Request{Principal: req.Principal, Approvals: s.Approvals}
	var reg *query.GitHubAppRegistrationByStateRow
	var claimAt int64
	var deferred error
	out, reports, err := write.RunEffect(ctx, s.Writer, write.Effect[called, Outcome]{
		OrganizationID: org.ID, People: []write.Gate{write.Person(actor, write.Shared)}, Resources: []write.Gate{registrationGate(seen.ID)},
		Principal: req.Principal,
		Check: func(ctx context.Context, tx *sql.Tx) error {
			var err error
			reg, err = byState(ctx, tx)
			return err
		},
		Checked: func(ctx context.Context, tx *sql.Tx) error {
			now := s.now()
			if reg.ConsumedAt.Valid {
				full, err := query.New(tx).GitHubAppRegistrationByIDOnly(ctx, reg.ID)
				if err != nil {
					return err
				}
				if full.ConvertedAt.Valid && !full.EndedAt.Valid {
					return &domainerr.Error{Code: "CONSUMED", Message: "This GitHub App registration is waiting to be attached; attach it from Connections",
						Details: jsvalue.Object{{Key: "registrationId", Value: reg.ID}, {Key: "pending", Value: true}}}
				}
				return domainerr.New("CONSUMED", "This GitHub App registration was already completed")
			}
			if reg.ExpiresAt <= now.UnixMicro() {
				return domainerr.New("EXPIRED", "This GitHub App registration expired. Start again.")
			}
			// The claim's eligibility and its time, captured under the gate.
			claimAt = now.UnixMicro()
			return nil
		},
		Call: func(ctx context.Context) (called, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, GitHubAPI+"/app-manifests/"+encodeURIComponent(code)+"/conversions", nil)
			if err != nil {
				return called{}, err
			}
			setGitHubHeaders(req.Header)
			a, err := do(s.clientFor(org.ID), req)
			if err != nil {
				if derr := write.EffectAlive(ctx); derr != nil {
					return called{}, derr
				}
				return called{noAnswer: true, refusal: outbound.RefusalOf(err)}, nil
			}
			c := called{status: a.status}
			if a.status == http.StatusCreated {
				if v, ok := a.json(); ok {
					c.conversion = readConversion(v)
				}
			}
			return c, nil
		},
		Final: func(ctx context.Context, tx *storage.Tx, c called) (Outcome, error) {
			if c.noAnswer {
				// GitHub may not have seen the code: the state stays free.
				msg := "Varlatch could not reach api.github.com to finish the registration. Check that this server can reach it, then try again."
				if c.refusal != nil {
					msg = c.refusal.Error()
				}
				return Outcome{Kind: "failed", Retryable: true, Message: msg}, nil
			}
			q := query.New(tx)
			if err := q.ClaimGitHubAppRegistration(ctx, query.ClaimGitHubAppRegistrationParams{ConsumedAt: nullInt(claimAt), ID: reg.ID}); err != nil {
				return Outcome{}, err
			}
			if c.status != http.StatusCreated {
				return Outcome{Kind: "failed", HTTPStatus: c.status,
					Message: "GitHub did not hand over the App (HTTP " + itoa(int64(c.status)) + "): the code may have been used already, or be more than an hour old. If GitHub created the App, delete it on GitHub, then start again."}, nil
			}
			conv := c.conversion
			if conv == nil {
				return Outcome{Kind: "failed", HTTPStatus: c.status,
					Message: "The answer from api.github.com was not GitHub's, so Varlatch kept nothing. A proxy between this server and GitHub may be in the way."}, nil
			}
			account := Account{Login: reg.AccountLogin, Type: reg.AccountType}
			p := Pending{RegistrationID: reg.ID, GitHubAppID: conv.id, Slug: conv.slug, ClientID: conv.clientID,
				OwnerLogin: conv.ownerLogin, OwnerID: conv.ownerID, OwnerType: conv.ownerType}
			if !sameAccount(conv.owner(), account) {
				if _, err := audit.Record(ctx, tx, refusedEvent(org.ID, actor, "owner-mismatch", p, account)); err != nil {
					return Outcome{}, err
				}
				o := Outcome{Kind: "refused", Reason: "owner-mismatch", Account: account, DeleteURL: DeleteURL(conv.slug, conv.owner()),
					Message: "GitHub created the App " + conv.slug + " on " + conv.ownerLogin + "'s own account, not on " + account.Login +
						", because " + conv.ownerLogin + " cannot register Apps there. Varlatch did not keep it. " + conv.ownerLogin +
						" can delete it on GitHub. An owner or App manager of " + account.Login + " has to register the App, or register one and import it."}
				o.Refused.GitHubAppID, o.Refused.Slug, o.Refused.Owner = conv.id, conv.slug, conv.owner()
				return o, nil
			}
			// Stored as pending (step 2): the key under the Organization
			// KEK, bound to the registration id.
			kek, err := s.orgKEK(ctx, tx, org.ID)
			if err != nil {
				return Outcome{}, err
			}
			sealed, err := SealKey(kek, org.ID, reg.ID, conv.pem)
			if err != nil {
				return Outcome{}, err
			}
			now := s.now()
			if err := q.ConvertGitHubAppRegistrationByID(ctx, query.ConvertGitHubAppRegistrationByIDParams{
				ConvertedAt: nullInt(now.UnixMicro()), PendingExpiresAt: nullInt(now.Add(PendingTTL).UnixMicro()),
				PendingGithubAppID: nullInt(conv.id), PendingSlug: nullStr(conv.slug), PendingClientID: nullStr(conv.clientID),
				PendingOwnerLogin: nullStr(conv.ownerLogin), PendingOwnerID: nullInt(conv.ownerID), PendingOwnerType: nullStr(conv.ownerType),
				PendingKeyEnvelope: nullStr(sealed), ID: reg.ID,
			}); err != nil {
				return Outcome{}, err
			}
			// The attachment (step 3), in this job while it needs no approval.
			o, err := s.attachIn(ctx, tx, attachReq, org, reg.ID, ManageIn(req.Principal, org.ID, req.RequestID))
			var refusal *TerminalRefusal
			var needed *auth.ApprovalNeeded
			var de *domainerr.Error
			switch {
			case err == nil:
				return o, nil
			case errors.As(err, &refusal):
				return endRefusedIn(ctx, tx, org.ID, refusal, actor, s.now().UnixMicro())
			case errors.As(err, &needed):
				deferred = err
				return Outcome{}, nil
			case errors.As(err, &de) && machineCredential(de):
				// A machine credential that got past the early refusal: its
				// attachment can never be approved, so the pending key goes now.
				ended, eerr := endPending(ctx, tx, reg.ID, "refused", s.now().UnixMicro())
				if eerr != nil {
					return Outcome{}, eerr
				}
				if ended {
					if _, err := audit.Record(ctx, tx, abandonedEvent(org.ID, actor, "machine-credential", p)); err != nil {
						return Outcome{}, err
					}
				}
				deferred = err
				return Outcome{}, nil
			}
			return Outcome{}, err
		},
	})
	if err != nil {
		return CompleteResult{}, err
	}
	return CompleteResult{Outcome: out, Reports: reports, Deferred: deferred}, nil
}

func machineCredential(e *domainerr.Error) bool {
	r, _ := e.Details.Get("reason")
	return r == "machine-credential"
}

// ---------------------------------------------------------------------------
// Discard and the sweep.

// Discard is discardRegistration: the person's pending registration's key
// deleted and sync.github_app_registration_abandoned recorded; the App
// stays on GitHub. Decided under the registration's gate, after the
// existence read and the checkpoint: one no longer pending changes
// nothing, and one that was attached never gets a delete link. Not
// protected.
func (s *Service) Discard(ctx context.Context, p *auth.Principal, org authz.Organization, id string) (jsvalue.Object, []auth.PendingReport, error) {
	actor := p.Identity.ID
	gates := []write.Gate{write.Organization(org.ID, write.Shared), write.Person(actor, write.Shared), registrationGate(id)}
	var out jsvalue.Object
	var reports []auth.PendingReport
	err := s.Writer.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: org.ID}); err != nil {
			return err
		}
		row, err := registration(ctx, tx, org.ID, id, actor)
		if err != nil {
			return err
		}
		if row == nil {
			return domainerr.New("RESOURCE_NOT_FOUND", "No GitHub App registration of yours in this Organization has this id")
		}
		if reports, err = write.Checkpoint(ctx, tx, p, org.ID); err != nil {
			return err
		}
		answer := func(discarded bool, state string, deleteURL any, app any) {
			out = jsvalue.Object{{Key: "discarded", Value: discarded}, {Key: "state", Value: state}, {Key: "deleteUrl", Value: deleteURL}, {Key: "app", Value: app}}
		}
		if !row.ConvertedAt.Valid {
			answer(false, "waiting", nil, nil)
			return nil
		}
		pending := pendingFrom(*row)
		app := jsvalue.Object{{Key: "githubAppId", Value: pending.GitHubAppID}, {Key: "slug", Value: pending.Slug}}
		if row.EndReason.Valid && row.EndReason.String == "attached" {
			answer(false, "attached", nil, app)
			return nil
		}
		del := DeleteURL(pending.Slug, pending.owner())
		if row.EndedAt.Valid {
			answer(false, "ended", del, app)
			return nil
		}
		if _, err := endPending(ctx, tx, id, "discarded", s.now().UnixMicro()); err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, abandonedEvent(org.ID, actor, "discarded", pending)); err != nil {
			return err
		}
		answer(true, "discarded", del, app)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return out, reports, nil
}

// SweepLimit is sweepExpiredRegistrations' limit per pass.
const SweepLimit = 100

// Sweep is sweepExpiredRegistrations: pending conversions past their hour,
// in key order, each under its registration's gate, without the
// Organization's: each loses its key, and
// sync.github_app_registration_abandoned is recorded. Expiry is decided
// under the gate. It returns how many it ended. A registration a
// completion holds is never a candidate (a completion claims only
// unconverted ones), so the sweep never waits for GitHub's answer.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	ctx = audit.WithClock(ctx, s.now)
	candidates, err := query.New(s.Writer.Store.Reader()).ExpiredPendingGitHubAppRegistrations(ctx,
		query.ExpiredPendingGitHubAppRegistrationsParams{Now: nullInt(s.now().UnixMicro()), Lim: SweepLimit})
	if err != nil {
		return 0, err
	}
	ended := 0
	for _, id := range candidates {
		err := s.Writer.Job(ctx, []write.Gate{registrationGate(id)}, func(ctx context.Context, tx *storage.Tx) error {
			row, err := query.New(tx).GitHubAppRegistrationByIDOnly(ctx, id)
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			now := s.now().UnixMicro()
			if !lapsed(row, now) || row.EndedAt.Valid {
				return nil
			}
			if _, err := endPending(ctx, tx, id, "expired", now); err != nil {
				return err
			}
			ended++
			_, err = audit.Record(ctx, tx, abandonedEvent(row.OrganizationID, "", "expired", pendingFrom(row)))
			return err
		})
		if err != nil {
			return ended, err
		}
	}
	return ended, nil
}

// SweepInterval is the sweep loop's interval (startRegistrationSweepLoop).
const SweepInterval = time.Minute

// RunSweepLoop is startRegistrationSweepLoop: in every serving varlatchd, a
// pass at once and then every interval, inside the maintenance admission.
func (s *Service) RunSweepLoop(ctx context.Context, interval time.Duration, admit func() (leave func(), ok bool)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		func() {
			if admit != nil {
				leave, ok := admit()
				if !ok {
					return
				}
				defer leave()
			}
			if _, err := s.Sweep(ctx); err != nil && ctx.Err() == nil {
				s.log().Error("GitHub App registration sweep error", "error", err)
			}
		}()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
