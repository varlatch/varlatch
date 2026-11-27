// SPDX-License-Identifier: AGPL-3.0-or-later

// Package entry is entry links (ADR-0063): a short-lived link with which a
// person enters one Secret's value on Varlatch's own page, once, so that the
// application that needs the value never handles it.
//
// A link is a bearer secret that can do one thing: write one item of one
// environment, while that item is still what it was when the link was made.
// It reads nothing. Whose right it uses is its maker's, decided when it is
// made and again in the job that writes the value; who may use it is said
// when it is made (whoever holds it, a signed-in member, one person). It ends
// with the credential that made it (credentialEnded).
//
// The secret follows the # of the page's address, so no server, proxy or log
// on the way sees it; the page sends it in the body of a POST, and it is
// stored as its hash. Looking at a link, as a mail scanner or a link preview
// does, uses nothing up and records nothing.
package entry

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/totp"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// What a link accepts, and who may use it.
const (
	Value   = "value"
	OTPAuth = "otpauth"

	Anyone   = "anyone"
	Member   = "member"
	Identity = "identity"
)

// The bounds of a link's life, in seconds, and of how many there are.
const (
	MinTTLSeconds     = 60
	DefaultTTLSeconds = 15 * 60
	MaxTTLSeconds     = 60 * 60

	maxPending = 100
	maxPerHour = 300
	// maxRecorded is how many refusals of one link the audit log takes.
	maxRecorded = 20
	// Kept is how long a link's row is kept after it expired.
	Kept = 24 * time.Hour

	// MaxValue is how long a value may be, in bytes.
	MaxValue = 65_536

	tokenPrefix = "vlt_entry_"
	tokenLength = len(tokenPrefix) + 43
)

// Service makes, shows and takes entry links.
type Service struct {
	Writer  *write.Writer
	RootKEK []byte
	Now     func() time.Time
	limit   limiter
}

// Request is who asks, and the environment a link is of.
type Request struct {
	Principal *auth.Principal
	RequestID string
	Target    values.Target
}

func (r Request) scope(duringFreeze string) write.Scope {
	return write.Scope{OrganizationID: r.Target.OrganizationID, ProjectID: r.Target.Project.ID, EnvironmentIDs: []string{r.Target.Env.ID}, DuringFreeze: duringFreeze}
}

func (r Request) gates() []write.Gate {
	return []write.Gate{write.Organization(r.Target.OrganizationID, write.Shared), write.Person(r.Principal.Identity.ID, write.Shared)}
}

func principalOf(p *auth.Principal) authz.Principal {
	out := authz.Principal{IdentityID: p.Identity.ID, IdentityKind: p.Identity.Kind, CredentialID: p.Credential.ID}
	if p.Identity.OrganizationID != nil {
		out.OrganizationID = *p.Identity.OrganizationID
	}
	return out
}

func resourceOf(t values.Target) authz.Resource {
	root := t.Env.ID
	if t.Env.ParentEnvironmentID.Valid {
		root = t.Env.ParentEnvironmentID.String
	}
	return authz.Resource{OrganizationID: t.OrganizationID, ProjectID: t.Project.ID, Environment: &authz.Environment{ID: t.Env.ID, RootID: root, Tier: t.Env.Tier}}
}

// Input is what a link is asked for with.
type Input struct {
	Item, Accepts, RestrictedTo string
	Replace                     bool
	// IdentityID is the person, with RestrictedTo Identity.
	IdentityID string
	// Description is "" for none.
	Description string
	TTLSeconds  int64
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func newToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b[:])
}

func refuse(code, reason, message string) error {
	return &domainerr.Error{Code: code, Message: message, Details: jsvalue.Object{{Key: "reason", Value: reason}}}
}

// passkeyMode is passkey-verification's mode in the Organization, "" for
// off, and its version.
func passkeyMode(ctx context.Context, db query.DBTX, organizationID string) (string, int64, error) {
	active, err := query.New(db).ActivePasskeyVerificationControls(ctx, []string{organizationID})
	if err != nil || len(active) == 0 {
		return "", 0, err
	}
	return active[0].Mode, active[0].Version, nil
}

// Create makes a link: the maker's right (and config.value.write, to replace
// a value), the item as it is now, and the row. The address is in the answer
// and nowhere else.
func (s *Service) Create(ctx context.Context, req Request, in Input, base *url.URL) (jsvalue.Object, []auth.PendingReport, error) {
	if in.Accepts == "" {
		in.Accepts = Value
	}
	if in.RestrictedTo == "" {
		in.RestrictedTo = Member
	}
	if in.TTLSeconds == 0 {
		in.TTLSeconds = DefaultTTLSeconds
	}
	// The request's schema bounds it too; this is for every other caller.
	if in.TTLSeconds < MinTTLSeconds || in.TTLSeconds > MaxTTLSeconds {
		return nil, nil, domainerr.New("VALIDATION_FAILED", fmt.Sprintf("ttlSeconds: from %d to %d", MinTTLSeconds, MaxTTLSeconds))
	}
	if (in.RestrictedTo == Identity) != (in.IdentityID != "") {
		return nil, nil, domainerr.New("VALIDATION_FAILED", "identityId: the person the link is for, with restrictedTo identity and with nothing else")
	}
	var description sql.NullString
	if in.Description != "" {
		d, err := CheckDescription(in.Description)
		if err != nil {
			return nil, nil, err
		}
		description = sql.NullString{String: d, Valid: true}
	}
	if _, err := write.Text(in.IdentityID); err != nil {
		return nil, nil, err
	}
	token, id := newToken(), ids.New(ids.EntryLink)
	var row query.EntryLink
	var reports []auth.PendingReport
	err := s.Writer.Job(ctx, req.gates(), func(ctx context.Context, tx *storage.Tx) error {
		now, q := s.Now(), query.New(tx)
		at := now.UnixMicro()
		d, err := authz.DecideEntryLink(ctx, tx, principalOf(req.Principal), in.RestrictedTo == Anyone, resourceOf(req.Target), authz.Options{HideExistence: true, RequestID: req.RequestID})
		if err != nil {
			return err
		}
		if !d.Allowed {
			return denial(d)
		}
		// What it may be for, and whether it may replace: for who may write
		// values here.
		writes, err := authz.Decide(ctx, tx, principalOf(req.Principal), "config.value.write", resourceOf(req.Target), authz.Options{HideExistence: true, RequestID: req.RequestID})
		if err != nil {
			return err
		}
		if in.Replace && !writes.Allowed {
			return denial(writes)
		}
		if err := write.CheckLive(ctx, tx, req.scope("")); err != nil {
			return err
		}
		// What the link will end with, as it is in this job: it may have been
		// revoked since the request authenticated.
		made, err := q.EntryLinkCredential(ctx, req.Principal.Credential.ID)
		if err != nil {
			return err
		}
		if made.RevokedAt.Valid || made.Disabled || made.ExpiresAt.Valid && made.ExpiresAt.Int64 <= at {
			return domainerr.New("INVALID_CREDENTIAL", "Credential is invalid, revoked, or expired")
		}
		if how, _ := ofCredential(made, at); how != "" {
			return refuse("PERMISSION_DENIED", auth.EntryLinkCredentialEnded, "What this credential was exchanged under was revoked: exchange a token again")
		}
		expires := now.Add(time.Duration(in.TTLSeconds) * time.Second).UnixMicro()
		if endsWithExpiry(made) {
			expires = min(expires, made.ExpiresAt.Int64)
		}
		if reports, err = write.Checkpoint(ctx, tx, req.Principal, req.Target.OrganizationID); err != nil {
			return err
		}
		if in.RestrictedTo == Anyone {
			// Whoever enters a value there has no sign-in to verify.
			mode, version, err := passkeyMode(ctx, tx, req.Target.OrganizationID)
			if err != nil {
				return err
			}
			switch mode {
			case "enforce":
				return refuse("PERMISSION_DENIED", "passkey-verification", "This Organization requires a verified passkey of whoever writes a value: make the link for a member or for one person")
			case "report":
				if err := security.CountWouldBlock(ctx, tx, req.Target.OrganizationID, []security.WouldBlock{{
					Control: "passkey-verification", ConfigVersion: version, Operation: authz.EntryLinkCreateOpen, ActorIdentityID: req.Principal.Identity.ID, Reason: auth.GapNoEvidence,
				}}, at, s.Now); err != nil {
					return err
				}
			}
		}
		if in.RestrictedTo == Identity {
			n, err := q.EntryLinkPerson(ctx, query.EntryLinkPersonParams{ID: in.IdentityID, OrganizationID: req.Target.OrganizationID})
			if err != nil {
				return err
			}
			if n == 0 {
				return domainerr.New("VALIDATION_FAILED", "identityId: must name a person who is a member of this organization")
			}
		}
		current, err := values.Enterable(ctx, tx, req.Target, in.Item, in.Accepts == OTPAuth, writes.Allowed, at)
		if err != nil {
			return err
		}
		if current.VersionID != "" && !in.Replace {
			return refuse("VERSION_CONFLICT", "value-exists", in.Item+" has a value here already (its own, or an inherited one): ask to replace it")
		}
		if err := q.PruneEntryLinks(ctx, now.Add(-Kept).UnixMicro()); err != nil {
			return err
		}
		n, err := q.CountEntryLinks(ctx, query.CountEntryLinksParams{Now: at, Since: now.Add(-time.Hour).UnixMicro(), RequestedBy: req.Principal.Identity.ID})
		if err != nil {
			return err
		}
		if n.Pending >= maxPending || n.Recent >= maxPerHour {
			return domainerr.New("RATE_LIMITED", "Too many entry links: cancel some, or wait until they expire")
		}
		row = query.EntryLink{
			ID: id, TokenHash: hash(token), OrganizationID: req.Target.OrganizationID, ProjectID: req.Target.Project.ID, EnvironmentID: req.Target.Env.ID,
			ItemName: in.Item, Accepts: in.Accepts, RestrictedTo: in.RestrictedTo, IdentityID: sql.NullString{String: in.IdentityID, Valid: in.IdentityID != ""},
			Description: description, RequestedBy: req.Principal.Identity.ID, CredentialID: req.Principal.Credential.ID,
			Status: "pending", CreatedAt: at, ExpiresAt: expires,
		}
		if in.Replace {
			row.Replaces, row.BoundVersionID = 1, sql.NullString{String: current.VersionID, Valid: current.VersionID != ""}
		}
		if err := q.InsertEntryLink(ctx, query.InsertEntryLinkParams{
			ID: row.ID, TokenHash: row.TokenHash, OrganizationID: row.OrganizationID, ProjectID: row.ProjectID, EnvironmentID: row.EnvironmentID,
			ItemName: row.ItemName, Accepts: row.Accepts, Replaces: row.Replaces, BoundVersionID: row.BoundVersionID, RestrictedTo: row.RestrictedTo,
			IdentityID: row.IdentityID, Description: row.Description, RequestedBy: row.RequestedBy, CredentialID: row.CredentialID,
			CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt,
		}); err != nil {
			return err
		}
		md := jsvalue.Object{{Key: "entryLink", Value: row.RestrictedTo}, {Key: "accepts", Value: row.Accepts}, {Key: "replace", Value: in.Replace},
			{Key: "expiresAt", Value: audit.ISOTime(row.ExpiresAt)}}
		if row.IdentityID.Valid {
			md = append(md, jsvalue.Member{Key: "identityId", Value: row.IdentityID.String})
		}
		if row.Description.Valid {
			md = append(md, jsvalue.Member{Key: "description", Value: row.Description.String})
		}
		actor, action := req.Principal.Identity.ID, authz.EntryLinkAction(req.Principal.Identity.Kind, in.RestrictedTo == Anyone)
		_, err = audit.Record(ctx, tx, audit.Event{
			Type: "capability.issued", Decision: audit.Info, ActorIdentityID: &actor, CredentialID: audit.Value(row.CredentialID), OrganizationID: &row.OrganizationID, Action: &action,
			Resource: auth.EntryLinkResource(row), Authz: authz.AuditAuthz(d.Evaluation), RequestID: &req.RequestID, Metadata: md,
		})
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	// The secret after the #: a browser sends it to no server.
	page := *base
	page.Path, page.RawPath = strings.TrimRight(base.Path, "/")+"/entry", ""
	page.RawQuery, page.Fragment = "", ""
	return jsvalue.Object{{Key: "link", Value: js(row, row.CreatedAt)}, {Key: "url", Value: page.String() + "#" + token}}, reports, nil
}

// denial is a denied decision's error, its event recorded after the job.
func denial(d authz.Decision) error {
	if d.DenialEvent != nil {
		return &security.DeferredDenial{Err: d.Err, Event: *d.DenialEvent}
	}
	return d.Err
}

// How the credential a link was made with ended, for the audit log.
const (
	credentialRevoked = "revoked"
	credentialExpired = "expired"
	bindingRevoked    = "binding-revoked"
	identityRetired   = "identity-retired"
)

// endsWithExpiry is whether a link ends when the credential that made it
// expires: a service credential's expiry is the end somebody set to a
// machine's access. Every other expiry is how a credential of its kind ends
// in the ordinary way, and withdraws nothing: an exchanged OIDC credential
// lives minutes and the next one is as good, a browser's bearer is replaced
// every 15 minutes, a CLI login lasts some hours.
func endsWithExpiry(c query.EntryLinkCredentialRow) bool {
	return c.Kind == auth.KindService && c.IdentityKind != "human" && c.ExpiresAt.Valid
}

// ofCredential says how the credential a link was made with ended, "" while
// the link may go on, and when if that is known: revoked, however it was;
// expired, where that ends links; its identity retired; and for an exchanged
// credential one of the identity's OIDC bindings revoked since, as that is
// what stands behind it, and it may have expired before anyone could revoke
// it. A use limit used up is no withdrawal. A person's credentials end in
// the ordinary way all the time, so their links are ended by what takes a
// session away, in its own job (auth/entrylinks.go).
func ofCredential(c query.EntryLinkCredentialRow, now int64) (string, sql.NullInt64) {
	switch {
	case c.Disabled && c.IdentityKind == "human":
		return identityRetired, sql.NullInt64{}
	case c.IdentityKind == "human":
		return "", sql.NullInt64{}
	// Machines a deletion of their Organization suspended come back when it
	// is cancelled: until then it is the Organization that takes nothing.
	case c.Disabled && !c.SuspendedByDeletion.Valid:
		return identityRetired, c.RevokedAt
	case c.RevokedAt.Valid:
		return credentialRevoked, c.RevokedAt
	case endsWithExpiry(c) && c.ExpiresAt.Int64 <= now:
		return credentialExpired, c.ExpiresAt
	case c.Kind == auth.KindOIDC && c.BindingRevokedAt != 0:
		return bindingRevoked, sql.NullInt64{Int64: c.BindingRevokedAt, Valid: true}
	}
	return "", sql.NullInt64{}
}

// credentialEnded is ofCredential of a pending link, in db and at now.
func credentialEnded(ctx context.Context, db query.DBTX, l query.EntryLink, now int64) (string, sql.NullInt64, error) {
	if statusOf(l, now) != "pending" {
		return "", sql.NullInt64{}, nil
	}
	c, err := query.New(db).EntryLinkCredential(ctx, l.CredentialID)
	if err != nil {
		return "", sql.NullInt64{}, err
	}
	how, at := ofCredential(c, now)
	return how, at, nil
}

// statusOf is a link's status now.
func statusOf(l query.EntryLink, now int64) string {
	if l.Status == "pending" && l.ExpiresAt <= now {
		return "expired"
	}
	return l.Status
}

func text(s sql.NullString) any {
	if s.Valid {
		return s.String
	}
	return nil
}

// shown is a link as its maker sees it, in db: one whose credential ended is
// ended, whether or not anybody has tried to use it since.
func (s *Service) shown(ctx context.Context, db query.DBTX, l query.EntryLink) (jsvalue.Object, error) {
	now := s.Now().UnixMicro()
	how, at, err := credentialEnded(ctx, db, l, now)
	if err != nil {
		return nil, err
	}
	if how != "" {
		l.Status, l.Reason, l.EndedAt = "cancelled", sql.NullString{String: auth.EntryLinkCredentialEnded, Valid: true}, at
	}
	return js(l, now), nil
}

func js(l query.EntryLink, now int64) jsvalue.Object {
	o := jsvalue.Object{{Key: "id", Value: l.ID}, {Key: "environmentId", Value: l.EnvironmentID}, {Key: "item", Value: l.ItemName},
		{Key: "accepts", Value: l.Accepts}, {Key: "replace", Value: l.Replaces == 1}, {Key: "restrictedTo", Value: l.RestrictedTo}}
	if l.IdentityID.Valid {
		o = append(o, jsvalue.Member{Key: "identityId", Value: l.IdentityID.String})
	}
	o = append(o, jsvalue.Member{Key: "description", Value: text(l.Description)}, jsvalue.Member{Key: "requestedByIdentityId", Value: l.RequestedBy},
		jsvalue.Member{Key: "status", Value: statusOf(l, now)})
	if l.Reason.Valid {
		o = append(o, jsvalue.Member{Key: "reason", Value: l.Reason.String})
	}
	var ended any
	if l.EndedAt.Valid {
		ended = audit.ISOTime(l.EndedAt.Int64)
	}
	return append(o, jsvalue.Member{Key: "createdAt", Value: audit.ISOTime(l.CreatedAt)}, jsvalue.Member{Key: "expiresAt", Value: audit.ISOTime(l.ExpiresAt)},
		jsvalue.Member{Key: "endedAt", Value: ended})
}

// requester filters links by who asked for them; "" is everybody.
func requester(id string) sql.NullString { return sql.NullString{String: id, Valid: id != ""} }

// List is an environment's links, those owner asked for when it is set.
func (s *Service) List(ctx context.Context, db query.DBTX, environmentID, owner string) (jsvalue.Object, error) {
	rows, err := query.New(db).ListEntryLinks(ctx, query.ListEntryLinksParams{EnvironmentID: environmentID, Requester: requester(owner)})
	if err != nil {
		return nil, err
	}
	items := make([]any, len(rows))
	for i, r := range rows {
		if items[i], err = s.shown(ctx, db, r); err != nil {
			return nil, err
		}
	}
	return jsvalue.Object{{Key: "items", Value: items}, {Key: "nextCursor", Value: nil}}, nil
}

func of(ctx context.Context, db query.DBTX, environmentID, id, owner string) (query.EntryLink, error) {
	if _, err := write.Text(id); err != nil {
		return query.EntryLink{}, err
	}
	l, err := query.New(db).EntryLinkOf(ctx, query.EntryLinkOfParams{ID: id, EnvironmentID: environmentID, Requester: requester(owner)})
	if errors.Is(err, sql.ErrNoRows) {
		return query.EntryLink{}, domainerr.NotFound("Entry link")
	}
	return l, err
}

// Get is one link.
func (s *Service) Get(ctx context.Context, db query.DBTX, environmentID, id, owner string) (jsvalue.Object, error) {
	l, err := of(ctx, db, environmentID, id, owner)
	if err != nil {
		return nil, err
	}
	return s.shown(ctx, db, l)
}

// Cancel ends a pending link: recovery while frozen.
func (s *Service) Cancel(ctx context.Context, req Request, id, owner string) ([]auth.PendingReport, error) {
	var reports []auth.PendingReport
	err := s.Writer.Job(ctx, req.gates(), func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, req.scope(authz.DuringFreezeRecovery)); err != nil {
			return err
		}
		l, err := of(ctx, tx, req.Target.Env.ID, id, owner)
		if err != nil {
			return err
		}
		if reports, err = write.Checkpoint(ctx, tx, req.Principal, req.Target.OrganizationID); err != nil {
			return err
		}
		n, err := query.New(tx).EndEntryLink(ctx, query.EndEntryLinkParams{Status: "cancelled", Reason: sql.NullString{String: "cancelled", Valid: true}, Now: s.Now().UnixMicro(), ID: l.ID})
		if err != nil {
			return err
		}
		if n == 0 {
			return domainerr.NotFound("Entry link")
		}
		actor, action := req.Principal.Identity.ID, authz.EntryLinkAction(req.Principal.Identity.Kind, l.RestrictedTo == Anyone)
		_, err = audit.Record(ctx, tx, audit.Event{
			Type: "capability.revoked", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &l.OrganizationID, Action: &action,
			Resource: append(auth.EntryLinkResource(l), jsvalue.Member{Key: "issuedByIdentityId", Value: l.RequestedBy}), RequestID: &req.RequestID,
			Metadata: jsvalue.Object{{Key: "entryLink", Value: l.RestrictedTo}},
		})
		return err
	})
	return reports, err
}

// refusal is why a link is not taken: its reason in the audit log, and what
// is answered.
type refusal struct {
	reason string
	err    error
	// credential is how the link's credential ended, when that is why.
	credential string
}

func no(code, reason, message string) *refusal {
	return &refusal{reason: reason, err: refuse(code, reason, message)}
}

var errNoLink = domainerr.New("RESOURCE_NOT_FOUND", "There is no such entry link: it may be old, or not copied whole")

// byToken is the link of a token, whoever asks. An unknown one is counted by
// the client's address, and beyond so many of them refused as such.
func (s *Service) byToken(ctx context.Context, db query.DBTX, token, client string) (query.EntryLink, error) {
	if strings.HasPrefix(token, tokenPrefix) && len(token) == tokenLength {
		l, err := query.New(db).EntryLinkByToken(ctx, hash(token))
		if !errors.Is(err, sql.ErrNoRows) {
			return l, err
		}
	}
	if retry := s.limit.blocked(client, s.Now()); retry > 0 {
		return query.EntryLink{}, &domainerr.Error{Code: "RATE_LIMITED", Message: "Too many unknown entry links from this address",
			Details: jsvalue.Object{{Key: "retryAfterSeconds", Value: int64(retry/time.Second) + 1}}}
	}
	s.limit.unknown(client, s.Now())
	return query.EntryLink{}, errNoLink
}

// ended is the refusal, in db and at now, of a link that has ended, its
// credential included; nil for a pending one. Its holder is not told whether
// it was cancelled or ended with its credential, nor how.
func ended(ctx context.Context, db query.DBTX, l query.EntryLink, now int64) (*refusal, error) {
	status := statusOf(l, now)
	if status == "pending" {
		how, _, err := credentialEnded(ctx, db, l, now)
		if err != nil || how == "" {
			return nil, err
		}
		return &refusal{reason: auth.EntryLinkCredentialEnded, credential: how, err: hasEnded("EXPIRED", "cancelled", linkEnded)}, nil
	}
	code, reason, message := "EXPIRED", status, "This link has expired: ask for another one"
	switch status {
	case "entered":
		code, reason, message = "CONSUMED", "already-entered", "A value was entered with this link already: it works once"
	case "cancelled":
		message = linkEnded
		switch l.Reason.String {
		case "value-changed":
			message = "The value changed after this link was made: ask for another one"
		case auth.EntryLinkCredentialEnded:
			reason = auth.EntryLinkCredentialEnded
		}
	}
	return &refusal{reason: reason, err: hasEnded(code, status, message)}, nil
}

const linkEnded = "This link has ended: ask for another one"

func hasEnded(code, status, message string) error {
	return &domainerr.Error{Code: code, Message: message, Details: jsvalue.Object{{Key: "status", Value: status}}}
}

var (
	frozen      = no("PERMISSION_DENIED", "organization-unavailable", "This organization takes no values now: try again later, or ask whoever sent you the link")
	gone        = no("EXPIRED", "gone", "What this link was for is not there any more")
	notAllowed  = no("PERMISSION_DENIED", "requester-not-allowed", "Whoever made this link may not ask for this value any more")
	notForYou   = no("PERMISSION_DENIED", "not-for-you", "This link is for somebody else: sign in as the person it was made for")
	noAnonymous = no("PERMISSION_DENIED", "passkey-verification", "This organization now requires a verified passkey of whoever writes a value: ask for a link made for you")
	changed     = no("STATE_CHANGED", "value-changed", "The value changed after this link was made, so nothing was entered and the link has ended: ask for another one")
)

// link is where a link writes, and whether its maker may write there anyway.
type link struct {
	values.Target
	writes bool
}

// usable decides, in db and at now, that a pending link may still be used
// and by p: the Organization, the Project and the environment are live and
// not frozen, its maker may still make it, and p is who it was made for.
func (s *Service) usable(ctx context.Context, db query.DBTX, l query.EntryLink, p *auth.Principal, now int64) (link, *refusal, error) {
	t := link{Target: values.Target{OrganizationID: l.OrganizationID}}
	if l.RestrictedTo != Anyone {
		// Who asks first: somebody else learns nothing more.
		if p == nil || p.Identity.Kind != "human" || l.RestrictedTo == Identity && p.Identity.ID != l.IdentityID.String {
			return t, notForYou, nil
		}
		role, err := authz.OrgRole(ctx, db, l.OrganizationID, p.Identity.ID)
		if err != nil {
			return t, nil, err
		}
		if role == "" {
			return t, notForYou, nil
		}
	}
	err := write.CheckLive(ctx, db, write.Scope{OrganizationID: l.OrganizationID, ProjectID: l.ProjectID, EnvironmentIDs: []string{l.EnvironmentID}})
	var fe *authz.FrozenError
	var de *domainerr.Error
	switch {
	case errors.As(err, &fe):
		return t, frozen, nil
	case errors.As(err, &de) && de.Code == "ORGANIZATION_DELETING":
		return t, frozen, nil
	case errors.As(err, &de) && de.Code == "RESOURCE_NOT_FOUND":
		return t, gone, nil
	case err != nil:
		return t, nil, err
	}
	q := query.New(db)
	if t.Project, err = q.LiveProject(ctx, query.LiveProjectParams{OrganizationID: l.OrganizationID, SlugOrID: l.ProjectID}); err != nil {
		return t, nil, err
	}
	if t.Env, err = q.LiveEnvironment(ctx, query.LiveEnvironmentParams{ProjectID: l.ProjectID, NameOrID: l.EnvironmentID}); err != nil {
		return t, nil, err
	}
	if t.Project.ID != l.ProjectID || t.Env.ID != l.EnvironmentID {
		return t, gone, nil
	}
	if t.Env.ExpiresAt.Valid && t.Env.ExpiresAt.Int64 <= now {
		return t, gone, nil
	}
	may, writes, err := s.maker(ctx, db, l, t.Target)
	if err != nil {
		return t, nil, err
	}
	if !may || l.Replaces == 1 && !writes {
		return t, notAllowed, nil
	}
	t.writes = writes
	if l.RestrictedTo == Anyone {
		mode, _, err := passkeyMode(ctx, db, l.OrganizationID)
		if err != nil {
			return t, nil, err
		}
		if mode == "enforce" {
			return t, noAnonymous, nil
		}
	}
	return t, nil, nil
}

// maker reports whether whoever made the link is live and may still make it,
// and whether they may write values there, as of now: a removed Grant takes
// its links away. Their credential is ended's (a retired machine is too).
func (s *Service) maker(ctx context.Context, db query.DBTX, l query.EntryLink, t values.Target) (may, writes bool, err error) {
	id, err := query.New(db).GetIdentity(ctx, l.RequestedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil || id.Disabled {
		return false, false, err
	}
	p := authz.Principal{IdentityID: id.ID, IdentityKind: id.Kind, OrganizationID: id.OrganizationID.String}
	made, err := authz.DecideEntryLink(ctx, db, p, l.RestrictedTo == Anyone, resourceOf(t), authz.Options{})
	if err != nil {
		return false, false, err
	}
	written, err := authz.Decide(ctx, db, p, "config.value.write", resourceOf(t), authz.Options{})
	return made.Allowed, written.Allowed, err
}

// Lookup is what a link's page shows. It writes nothing.
func (s *Service) Lookup(ctx context.Context, p *auth.Principal, token, client string) (jsvalue.Object, error) {
	db := s.Writer.Store.Reader()
	l, err := s.byToken(ctx, db, token, client)
	if err != nil {
		return nil, err
	}
	now := s.Now().UnixMicro()
	if r, err := ended(ctx, db, l, now); err != nil {
		return nil, err
	} else if r != nil {
		return nil, r.err
	}
	if l.RestrictedTo != Anyone && p == nil {
		return jsvalue.Object{{Key: "restrictedTo", Value: l.RestrictedTo}, {Key: "signInRequired", Value: true}}, nil
	}
	t, r, err := s.usable(ctx, db, l, p, now)
	if err != nil {
		return nil, err
	}
	if r != nil {
		return nil, r.err
	}
	place, err := query.New(db).EntryLinkPlace(ctx, query.EntryLinkPlaceParams{OrganizationID: l.OrganizationID, ProjectID: l.ProjectID, EnvironmentID: t.Env.ID, RequestedBy: l.RequestedBy})
	if err != nil {
		return nil, err
	}
	return jsvalue.Object{{Key: "restrictedTo", Value: l.RestrictedTo}, {Key: "signInRequired", Value: false},
		{Key: "organization", Value: place.Organization}, {Key: "project", Value: place.Project}, {Key: "environment", Value: place.Environment},
		{Key: "item", Value: l.ItemName}, {Key: "accepts", Value: l.Accepts}, {Key: "replace", Value: l.Replaces == 1}, {Key: "description", Value: text(l.Description)},
		{Key: "requestedBy", Value: jsvalue.Object{{Key: "name", Value: place.Requester}, {Key: "kind", Value: place.RequesterKind}}},
		{Key: "expiresAt", Value: audit.ISOTime(l.ExpiresAt)},
		{Key: "expiresInSeconds", Value: max(0, (l.ExpiresAt-now)/1_000_000)}}, nil
}

// Entered is what is entered: a value, or the seed of a one-time code.
type Entered struct {
	Value string
	Seed  *totp.Seed
}

// Submit enters a value, once. Everything is decided in the job that writes
// it and uses the link up: of several at once, one does. A refusal is
// recorded (the first ones of a link), and uses the link up only when the
// item is not what it was.
func (s *Service) Submit(ctx context.Context, p *auth.Principal, token, client, requestID string, in Entered) ([]auth.PendingReport, error) {
	l, err := s.byToken(ctx, s.Writer.Store.Reader(), token, client)
	if err != nil {
		return nil, err
	}
	// What the link accepts, before anything is decided: nothing is recorded.
	if (l.Accepts == OTPAuth) != (in.Seed != nil) {
		if l.Accepts == OTPAuth {
			return nil, domainerr.New("VALIDATION_FAILED", "otpauth: this link takes the seed of a one-time code")
		}
		return nil, domainerr.New("VALIDATION_FAILED", "value: this link takes a value")
	}
	if l.RestrictedTo == Anyone {
		// Nobody in particular, whoever's browser it is.
		p = nil
	} else if p == nil {
		return nil, domainerr.New("AUTHENTICATION_REQUIRED", "This link is for a signed-in person: sign in first")
	}
	if err := values.CheckEntered(in.Value); in.Seed == nil && err != nil {
		return nil, err
	}
	gates := []write.Gate{write.Organization(l.OrganizationID, write.Shared), write.Person(l.RequestedBy, write.Shared)}
	if p != nil && p.Identity.ID != l.RequestedBy {
		gates = append(gates, write.Person(p.Identity.ID, write.Shared))
	}
	var refused *refusal
	var reports []auth.PendingReport
	err = s.Writer.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		refused, reports = nil, nil
		q, at := query.New(tx), s.Now().UnixMicro()
		var err error
		if l, err = q.EntryLinkByToken(ctx, l.TokenHash); errors.Is(err, sql.ErrNoRows) {
			return errNoLink
		} else if err != nil {
			return err
		}
		t, why, err := s.take(ctx, tx, l, p, at, &reports)
		if err != nil {
			return err
		}
		if why != nil {
			refused = why
			return s.refuse(ctx, tx, l, p, requestID, why, at)
		}
		n, err := q.EndEntryLink(ctx, query.EndEntryLinkParams{Status: "entered", Now: at, ID: l.ID})
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("entry: a pending link did not end")
		}
		actor := ""
		if p != nil {
			actor = p.Identity.ID
		}
		return values.Enter(ctx, tx, s.RootKEK, t.Target, l.ItemName, in.Value, in.Seed, actor, requestID, jsvalue.Object{
			{Key: "entryLinkId", Value: l.ID}, {Key: "entryLink", Value: l.RestrictedTo}, {Key: "requestedByIdentityId", Value: l.RequestedBy}}, at)
	})
	if err != nil {
		return nil, err
	}
	if refused != nil {
		return nil, refused.err
	}
	return reports, nil
}

// take decides, in the job, whether the link is taken.
func (s *Service) take(ctx context.Context, tx *storage.Tx, l query.EntryLink, p *auth.Principal, at int64, reports *[]auth.PendingReport) (link, *refusal, error) {
	if r, err := ended(ctx, tx, l, at); err != nil || r != nil {
		return link{}, r, err
	}
	t, r, err := s.usable(ctx, tx, l, p, at)
	if err != nil || r != nil {
		return t, r, err
	}
	if p != nil {
		var refused *auth.VerificationRefusal
		if *reports, err = write.Checkpoint(ctx, tx, p, l.OrganizationID); errors.As(err, &refused) {
			return t, &refusal{reason: "passkey-verification", err: err}, nil
		} else if err != nil {
			return t, nil, err
		}
	}
	current, err := values.Enterable(ctx, tx, t.Target, l.ItemName, l.Accepts == OTPAuth, t.writes, at)
	var de *domainerr.Error
	if errors.As(err, &de) {
		// Rotating, of another kind, no Secret any more, or not for its maker
		// to ask for any more.
		return t, changed, nil
	}
	if err != nil {
		return t, nil, err
	}
	if current.VersionID != l.BoundVersionID.String {
		return t, changed, nil
	}
	return t, nil, nil
}

// refuse records a refusal, the first ones of a link, and ends a link whose
// item is not what it was, or whose credential ended.
func (s *Service) refuse(ctx context.Context, tx *storage.Tx, l query.EntryLink, p *auth.Principal, requestID string, why *refusal, at int64) error {
	q := query.New(tx)
	if why == changed || why.credential != "" {
		if _, err := q.EndEntryLink(ctx, query.EndEntryLinkParams{Status: "cancelled", Reason: sql.NullString{String: why.reason, Valid: true}, Now: at, ID: l.ID}); err != nil {
			return err
		}
	}
	n, err := q.RefuseEntryLink(ctx, l.ID)
	if err != nil || n > maxRecorded {
		return err
	}
	action := "config.value.write"
	md := jsvalue.Object{{Key: "reason", Value: why.reason}, {Key: "entryLink", Value: l.RestrictedTo}}
	if why.credential != "" {
		md = append(md, jsvalue.Member{Key: "credential", Value: why.credential})
	}
	event := audit.Event{
		Type: "capability.denied", Decision: audit.Deny, OrganizationID: &l.OrganizationID, Action: &action, RequestID: &requestID,
		Resource: append(auth.EntryLinkResource(l), jsvalue.Member{Key: "issuedByIdentityId", Value: l.RequestedBy}),
		Metadata: md,
	}
	if p != nil {
		id := p.Identity.ID
		event.ActorIdentityID, event.CredentialID = &id, audit.Value(p.Credential.ID)
	}
	_, err = audit.Record(ctx, tx, event)
	return err
}

// Prune forgets links that expired a day ago.
func Prune(ctx context.Context, store *storage.DB, now time.Time) error {
	before := now.Add(-Kept).UnixMicro()
	var n int
	if err := store.Reader().QueryRowContext(ctx, "SELECT count(*) FROM (SELECT 1 FROM entry_links WHERE expires_at < ? LIMIT 1)", before).Scan(&n); err != nil || n == 0 {
		return err
	}
	return store.Write(ctx, func(tx *storage.Tx) error { return query.New(tx).PruneEntryLinks(ctx, before) })
}

// PruneInterval is how often PruneLoop looks.
const PruneInterval = 10 * time.Minute

// PruneLoop prunes at once and then every PruneInterval, until ctx ends;
// not while maintenance admits nothing.
func PruneLoop(ctx context.Context, store *storage.DB, log *slog.Logger, admit func() (func(), bool)) {
	t := time.NewTicker(PruneInterval)
	defer t.Stop()
	for {
		if leave, ok := admit(); ok {
			if err := Prune(ctx, store, time.Now()); err != nil && ctx.Err() == nil {
				log.Error("forgetting entry links failed", "error", err)
			}
			leave()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
