// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Step-up approvals (ADR-0054 Decision 3; domain/approvals.ts): a fresh
// WebAuthn assertion, with user verification required, by a trusted
// passkey of the person who asked, for one exact operation.
//
//  1. An operation that needs an approval and arrives without one stores an
//     Approval Intent for the requesting credential and its person, bound
//     to the operation, its Organization (none for an account operation),
//     its target, keyed hashes of its body and query, and its expected
//     version, and answers STEP_UP_REQUIRED with it.
//  2. Only that person sees the intent, and approves it in the dashboard
//     with a challenge bound to the intent, the person and their session,
//     by a trusted passkey with user verification.
//  3. The client repeats the operation with the intent's id (the
//     Varlatch-Approval header); the operation's write job consumes it,
//     when it fits exactly, and revalidates the requesting credential.
//     Consumption and the operation commit or roll back together.
//
// The operations that ask for one: removing a trusted passkey while the
// person belongs to an Organization with a Security Control at enforce
// (passkey.remove, here), and an Organization's protected operations
// (go/server/security), which consume one with ConsumeApproval in their
// own write job and answer StepUpRequired when they were given none.

// Approval limits (APPROVALS).
const (
	approvalDashboardLifetime = 120 * time.Second
	approvalCLILifetime       = 600 * time.Second
	approvalInterval          = 5
	approvalSlowDown          = 5
	approvalsOpenPerCred      = 5
	approvalsPerPerson        = 30
	approvalWindow            = 600 * time.Second
	approvalChallengeLife     = 120 * time.Second
	approvalChallengesPerPers = 20
	approvalRetention         = 86_400 * time.Second
)

// Requester is the credential that asks for an operation, and its person.
type Requester struct {
	IdentityID     string
	IdentityKind   string
	CredentialID   string
	CredentialKind string
	// AuthSessionID is a browser bearer's session.
	AuthSessionID *string
}

// RequesterOf is a principal as a requester.
func RequesterOf(p *Principal) Requester {
	return Requester{
		IdentityID: p.Identity.ID, IdentityKind: p.Identity.Kind,
		CredentialID: p.Credential.ID, CredentialKind: p.Credential.Kind, AuthSessionID: p.Credential.AuthSessionID,
	}
}

// ApprovalChange is one change an approver reads.
type ApprovalChange struct {
	Field   string
	From    *string
	To      *string
	Loosens bool
}

// ApprovalSummary is what the approver reads.
type ApprovalSummary struct {
	Title   string
	Changes []ApprovalChange
}

func (s ApprovalSummary) value() jsvalue.Object {
	changes := make([]any, 0, len(s.Changes))
	for _, c := range s.Changes {
		var from, to any
		if c.From != nil {
			from = *c.From
		}
		if c.To != nil {
			to = *c.To
		}
		changes = append(changes, jsvalue.Object{{Key: "field", Value: c.Field}, {Key: "from", Value: from}, {Key: "to", Value: to}, {Key: "loosens", Value: c.Loosens}})
	}
	return jsvalue.Object{{Key: "title", Value: s.Title}, {Key: "changes", Value: changes}}
}

// Binding is the one exact operation an approval is for (ApprovalBinding).
type Binding struct {
	Operation      string
	OrganizationID *string
	// Target holds stable target ids.
	Target map[string]string
	// Body is the normalized request body (a jsvalue value; nil is null).
	Body any
	// Query is the query parameters the operation reads.
	Query           map[string]string
	ExpectedVersion *int64
	Summary         ApprovalSummary
}

// canonicalJSON is canonicalJson: JSON with object keys sorted, so equal
// values hash equally whatever their key order.
func canonicalJSON(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case map[string]string:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = string(jsvalue.Stringify(k)) + ":" + string(jsvalue.Stringify(x[k]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	case jsvalue.Object:
		sorted := slices.Clone(x)
		slices.SortStableFunc(sorted, func(a, b jsvalue.Member) int { return strings.Compare(a.Key, b.Key) })
		parts := make([]string, 0, len(sorted))
		for _, m := range sorted {
			parts = append(parts, string(jsvalue.Stringify(m.Key))+":"+canonicalJSON(m.Value))
		}
		return "{" + strings.Join(parts, ",") + "}"
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = canonicalJSON(e)
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	return string(jsvalue.Stringify(v))
}

// approvalHash is a keyed hash of a normalized body or query: an HMAC under
// the Root KEK, so a stored hash says nothing about a low-entropy value it
// covers.
func approvalHash(key []byte, kind string, value any) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("varlatch:approval:" + kind + ":v1\x00"))
	m.Write([]byte(canonicalJSON(value)))
	return "hmac-v1:" + hex.EncodeToString(m.Sum(nil))
}

var approvalIDPattern = regexp.MustCompile(`^apr_[a-z2-7]{26}$`)

// ParseApprovalID is an approval id from a header or route; "" when it
// cannot be one.
func ParseApprovalID(value string) string {
	id := strings.TrimSpace(value)
	if !approvalIDPattern.MatchString(id) {
		return ""
	}
	return id
}

// approvalURL is where a person approves: the dashboard's /approve/<id>
// under the public URL.
func (s *Service) approvalURL(id string) any {
	if s.publicURL == nil {
		return nil
	}
	return s.rp.Origin + strings.TrimRight(s.publicURL.Path, "/") + "/approve/" + id
}

var approvalRefusalMessages = map[string]string{
	"not-found":     "No approval of yours has this id",
	"pending":       "This approval has not been approved yet",
	"approved":      "This approval was already approved",
	"expired":       "This approval expired; ask for a new one",
	"consumed":      "This approval was already used; ask for a new one",
	"closed":        "This approval was cancelled or reset; ask for a new one",
	"mismatch":      "This approval was given for another request: another operation, target, body or credential",
	"stale":         "This approval was given for another version of the target; ask for a new one",
	"session-ended": "The dashboard session this approval was asked from has ended (signed out or expired); ask for a new one",
}

// ApprovalInvalid is approvalInvalid: APPROVAL_INVALID with the reason and
// the approval's id (null when the request named none that can be one).
func ApprovalInvalid(reason string, approvalID *string) error {
	var id any
	if approvalID != nil {
		id = *approvalID
	}
	return &domainerr.Error{Code: "APPROVAL_INVALID", Message: approvalRefusalMessages[reason],
		Details: jsvalue.Object{{Key: "reason", Value: reason}, {Key: "approvalId", Value: id}}}
}

var errApprovalNotFound = domainerr.New("RESOURCE_NOT_FOUND", "Approval not found")

type intent = query.ApprovalIntentOfRow

func lapsed(r intent, now int64) bool { return r.ExpiresAt <= now }

// stateOf is an intent's state.
func stateOf(r intent, now int64) string {
	switch {
	case r.ClosedAt.Valid:
		return "closed"
	case r.ConsumedAt.Valid:
		return "consumed"
	case lapsed(r, now):
		return "expired"
	case r.ApprovedAt.Valid:
		return "approved"
	}
	return "pending"
}

func (s *Service) intentOf(ctx context.Context, db query.DBTX, id, identityID string) (*intent, error) {
	r, err := query.New(db).ApprovalIntentOf(ctx, query.ApprovalIntentOfParams{ID: id, IdentityID: identityID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ApprovalView is an approval as its person sees it (protocol Approval),
// in the TypeScript server's member order.
func (s *Service) approvalView(r intent, now int64) (jsvalue.Object, error) {
	parsed, err := jsvalue.Parse([]byte(r.Summary))
	if err != nil {
		return nil, fmt.Errorf("approval %s: summary: %w", r.ID, err)
	}
	var org any
	if r.OrganizationID.Valid && r.OrgSlug != "" {
		org = jsvalue.Object{{Key: "id", Value: r.OrganizationID.String}, {Key: "slug", Value: r.OrgSlug}, {Key: "name", Value: r.OrgName}}
	}
	opt := func(n sql.NullInt64) any {
		if !n.Valid {
			return nil
		}
		return ISO(n.Int64)
	}
	var closeReason, client any
	if r.CloseReason.Valid {
		closeReason = r.CloseReason.String
	}
	if r.Client.Valid {
		client = r.Client.String
	}
	return jsvalue.Object{
		{Key: "id", Value: r.ID},
		{Key: "operation", Value: r.Operation},
		{Key: "organization", Value: org},
		// The summary as jsonb gives it back.
		{Key: "summary", Value: jsvalue.Jsonb(parsed)},
		{Key: "state", Value: stateOf(r, now)},
		{Key: "closeReason", Value: closeReason},
		{Key: "requestedBy", Value: jsvalue.Object{{Key: "credentialKind", Value: r.CredentialKind}, {Key: "client", Value: client}}},
		{Key: "url", Value: s.approvalURL(r.ID)},
		{Key: "interval", Value: r.PollInterval},
		{Key: "createdAt", Value: ISO(r.CreatedAt)},
		{Key: "expiresAt", Value: ISO(r.ExpiresAt)},
		{Key: "approvedAt", Value: opt(r.ApprovedAt)},
		{Key: "consumedAt", Value: opt(r.ConsumedAt)},
		{Key: "closedAt", Value: opt(r.ClosedAt)},
	}, nil
}

// ApprovalNeeded is an operation's need of an approval it was not given
// (ApprovalNeeded): returned from its write job, it rolls the job back,
// and the caller answers StepUpRequired with the binding.
type ApprovalNeeded struct{ Binding Binding }

func (e *ApprovalNeeded) Error() string { return e.Binding.Operation + " needs a step-up approval" }

// UsedApproval is the approval a consumption used, for the operation's
// audit record (UsedApproval).
type UsedApproval struct {
	ID           string
	PasskeyID    string
	UserVerified bool
}

// OperationsDuringFreeze are the Organization-bound operations an intent
// may be created for while the Organization is frozen for an incident
// (OPERATIONS_DURING_FREEZE, ADR-0055 Decisions 3 and 6).
var OperationsDuringFreeze = map[string]bool{
	"organization.unfreeze":   true,
	"security_control.change": true,
	"oidc_binding.delete":     true,
	"grant.revoke":            true,
	"member.remove":           true,
	"member.demote":           true,
	"connection.delete":       true,
}

// createApproval stores a pending intent for the binding, requested by this
// credential, within the bounds (createApproval). Only a person's
// dashboard or CLI credential can be approved.
func (s *Service) createApproval(ctx context.Context, req Requester, b Binding) (jsvalue.Object, error) {
	if req.IdentityKind != "human" || (req.CredentialKind != KindBrowser && req.CredentialKind != KindCLI) {
		return nil, &domainerr.Error{Code: "PERMISSION_DENIED", Message: "This needs a person's approval with a passkey, which a machine credential cannot give",
			Details: jsvalue.Object{{Key: "reason", Value: "machine-credential"}}}
	}
	if s.publicURL == nil {
		return nil, &domainerr.Error{Code: "PERMISSION_DENIED", Message: "This needs an approval with a passkey, and this server has no public URL to approve it at",
			Details: jsvalue.Object{{Key: "reason", Value: "approvals-unavailable"}}}
	}
	origin := "cli"
	if req.CredentialKind == KindBrowser {
		origin = "dashboard"
		if req.AuthSessionID == nil {
			return nil, &domainerr.Error{Code: "PERMISSION_DENIED", Message: "This dashboard sign-in has no session to bind an approval to; reload the page and sign in again",
				Details: jsvalue.Object{{Key: "reason", Value: "no-session"}}}
		}
	}
	lifetime := approvalCLILifetime
	if origin == "dashboard" {
		lifetime = approvalDashboardLifetime
	}
	var view jsvalue.Object
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		now := s.micros()
		// Intents ended a day ago, and their challenges by cascade.
		if err := q.SweepApprovalIntents(ctx, now-approvalRetention.Microseconds()); err != nil {
			return err
		}
		if b.OrganizationID != nil {
			if err := intentOrganization(ctx, tx, req, b); err != nil {
				return err
			}
		}
		open, err := q.OpenApprovalsOfCredential(ctx, query.OpenApprovalsOfCredentialParams{CredentialID: req.CredentialID, Now: now})
		if err != nil {
			return err
		}
		if open >= approvalsOpenPerCred {
			return &domainerr.Error{Code: "RATE_LIMITED",
				Message: fmt.Sprintf("At most %d approvals may be open for one credential; approve, cancel or let one expire", approvalsOpenPerCred),
				Details: jsvalue.Object{{Key: "cap", Value: "open-per-credential"}}}
		}
		w, err := q.ApprovalsCreatedSince(ctx, query.ApprovalsCreatedSinceParams{IdentityID: req.IdentityID, Since: now - approvalWindow.Microseconds()})
		if err != nil {
			return err
		}
		if w.N >= approvalsPerPerson {
			retryAt := ISO(w.Oldest + approvalWindow.Microseconds())
			return &domainerr.Error{Code: "RATE_LIMITED", Message: "Too many approvals asked for; try again after " + retryAt,
				Details: jsvalue.Object{{Key: "cap", Value: "per-person"}, {Key: "retryAt", Value: retryAt}}}
		}
		id := ids.New(ids.ApprovalIntent)
		var session sql.NullString
		if origin == "dashboard" {
			session = sql.NullString{String: *req.AuthSessionID, Valid: true}
		}
		if err := q.InsertApprovalIntent(ctx, query.InsertApprovalIntentParams{
			ID: id, CredentialID: req.CredentialID, IdentityID: req.IdentityID, OrganizationID: nullStr(b.OrganizationID),
			Operation: b.Operation, Target: canonicalJSON(b.Target), BodyHash: approvalHash(s.rootKEK, "body", b.Body),
			QueryHash: approvalHash(s.rootKEK, "query", b.Query), ExpectedVersion: nullInt(b.ExpectedVersion),
			Summary: string(jsvalue.Stringify(b.Summary.value())), Origin: origin, CreatedAt: now,
			ExpiresAt: now + lifetime.Microseconds(), PollInterval: approvalInterval, AuthSessionID: session,
		}); err != nil {
			return err
		}
		r, err := s.intentOf(ctx, tx, id, req.IdentityID)
		if err != nil {
			return err
		}
		view, err = s.approvalView(*r, now)
		return err
	})
	return view, err
}

// intentOrganization is createApproval's checks of an Organization-bound
// intent, in its job: the Organization live, not frozen for an incident
// unless the operation runs during one, and the requester's
// passkey-verification checkpoint, so a refused sign-in creates no intent.
func intentOrganization(ctx context.Context, tx query.DBTX, req Requester, b Binding) error {
	live, err := query.New(tx).LiveOrganizationExists(ctx, *b.OrganizationID)
	if err != nil {
		return err
	}
	if live == 0 {
		return domainerr.New("RESOURCE_NOT_FOUND", "Organization not found")
	}
	if !OperationsDuringFreeze[b.Operation] {
		if err := authz.RefuseIfIncidentFrozen(ctx, tx, *b.OrganizationID, ""); err != nil {
			return err
		}
	}
	p := &Principal{
		Identity:   Identity{ID: req.IdentityID, Kind: req.IdentityKind},
		Credential: Credential{ID: req.CredentialID, Kind: req.CredentialKind},
	}
	out, err := PasskeyVerification(ctx, tx, p, []string{*b.OrganizationID})
	if err != nil {
		return err
	}
	if reason, ok := out.Blocked[*b.OrganizationID]; ok {
		return PasskeyVerificationRequired(*b.OrganizationID, reason)
	}
	return nil
}

// StepUpRequired is the answer to an operation that needs an approval it
// was not given (withApproval): the intent created for the binding, in
// details.approval, or why none could be created.
func (s *Service) StepUpRequired(ctx context.Context, req Requester, b Binding) error {
	return s.stepUpRequired(ctx, req, b)
}

// stepUpRequired is the answer to an operation that needs an approval: the
// intent created for it, in details.approval.
func (s *Service) stepUpRequired(ctx context.Context, req Requester, b Binding) error {
	view, err := s.createApproval(ctx, req, b)
	if err != nil {
		return err
	}
	msg := "This needs your approval with a trusted passkey in the dashboard, then the request repeated with the Varlatch-Approval header"
	if u, ok := s.approvalURL(view[0].Value.(string)).(string); ok {
		msg = "This needs your approval with a trusted passkey: open " + u + " and approve, then repeat the request with the Varlatch-Approval header"
	}
	return &domainerr.Error{Code: "STEP_UP_REQUIRED", Message: msg, Details: jsvalue.Object{{Key: "approval", Value: view}}}
}

// consumeApproval consumes an approved intent for exactly this request, in
// the operation's write job, then revalidates the requesting credential
// (consumeApproval). It refuses with APPROVAL_INVALID and a reason, or
// INVALID_CREDENTIAL when the credential ended meanwhile; the job then
// rolls back, the consumption with it.
func (s *Service) consumeApproval(ctx context.Context, tx query.DBTX, req Requester, approvalID string, b Binding) error {
	_, err := s.ConsumeApproval(ctx, tx, req, approvalID, b)
	return err
}

// ConsumeApproval is consumeApproval for an operation's write job: the
// approval it used, or the refusal (the job then rolls back).
func (s *Service) ConsumeApproval(ctx context.Context, tx query.DBTX, req Requester, approvalID string, b Binding) (UsedApproval, error) {
	q := query.New(tx)
	now := s.micros()
	bodyHash, queryHash := approvalHash(s.rootKEK, "body", b.Body), approvalHash(s.rootKEK, "query", b.Query)
	var kind any = req.CredentialKind
	consumed, err := q.ConsumeApprovalIntent(ctx, query.ConsumeApprovalIntentParams{
		Now: sql.NullInt64{Int64: now, Valid: true}, ID: approvalID, IdentityID: req.IdentityID, Operation: b.Operation,
		CredentialID: req.CredentialID, CredentialKind: kind, AuthSessionID: nullStr(req.AuthSessionID),
		OrganizationID: nullStr(b.OrganizationID), Target: canonicalJSON(b.Target), BodyHash: bodyHash, QueryHash: queryHash,
		ExpectedVersion: nullInt(b.ExpectedVersion),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return UsedApproval{}, s.refusalOf(ctx, tx, req, approvalID, b, bodyHash, queryHash, now)
	}
	if err != nil {
		return UsedApproval{}, err
	}
	// A dashboard intent needs its session alive, and the requester's.
	if consumed.AuthSessionID.Valid {
		if _, err := q.LiveSessionOfIdentity(ctx, query.LiveSessionOfIdentityParams{ID: consumed.AuthSessionID.String, IdentityID: req.IdentityID, Now: now}); errors.Is(err, sql.ErrNoRows) {
			return UsedApproval{}, ApprovalInvalid("session-ended", &approvalID)
		} else if err != nil {
			return UsedApproval{}, err
		}
	}
	// Revalidate: the requesting credential is live and its person enabled;
	// for a dashboard intent, it is a browser bearer of the intent's session.
	var session any
	if consumed.AuthSessionID.Valid {
		session = consumed.AuthSessionID.String
	}
	n, err := q.LiveRequesterCredential(ctx, query.LiveRequesterCredentialParams{
		ID: req.CredentialID, IdentityID: req.IdentityID, Now: sql.NullInt64{Int64: now, Valid: true}, AuthSessionID: session,
	})
	if err != nil {
		return UsedApproval{}, err
	}
	if n == 0 {
		return UsedApproval{}, domainerr.New("INVALID_CREDENTIAL", "Credential is invalid, revoked, or expired")
	}
	return UsedApproval{ID: consumed.ID, PasskeyID: consumed.ApprovedWithPasskeyID.String, UserVerified: consumed.ApprovalUserVerified.Bool}, nil
}

// refusalOf is why an approval does not fit this request now.
func (s *Service) refusalOf(ctx context.Context, tx query.DBTX, req Requester, approvalID string, b Binding, bodyHash, queryHash string, now int64) error {
	r, err := s.intentOf(ctx, tx, approvalID, req.IdentityID)
	if err != nil {
		return err
	}
	if r == nil {
		return ApprovalInvalid("not-found", &approvalID)
	}
	if st := stateOf(*r, now); st != "approved" {
		return ApprovalInvalid(st, &approvalID)
	}
	sameRequester := r.Origin == "cli" && r.CredentialID == req.CredentialID ||
		r.Origin == "dashboard" && req.CredentialKind == KindBrowser && req.AuthSessionID != nil && r.AuthSessionID.Valid && r.AuthSessionID.String == *req.AuthSessionID
	sameOrg := r.OrganizationID.Valid == (b.OrganizationID != nil) && (b.OrganizationID == nil || r.OrganizationID.String == *b.OrganizationID)
	sameTarget := false
	var stored any
	if v, err := jsvalue.Parse([]byte(r.Target)); err == nil {
		stored = v
		sameTarget = canonicalJSON(stored) == canonicalJSON(b.Target)
	}
	sameRequest := sameRequester && r.Operation == b.Operation && sameOrg && sameTarget && r.BodyHash == bodyHash && r.QueryHash == queryHash
	sameVersion := r.ExpectedVersion.Valid == (b.ExpectedVersion != nil) && (b.ExpectedVersion == nil || r.ExpectedVersion.Int64 == *b.ExpectedVersion)
	if sameRequest && !sameVersion {
		return ApprovalInvalid("stale", &approvalID)
	}
	return ApprovalInvalid("mismatch", &approvalID)
}

// ErrSlowDown is a poll of one's own approval sooner than its interval: the
// interval grew to Interval seconds.
type ErrSlowDown struct{ Interval int64 }

func (e *ErrSlowDown) Error() string {
	return fmt.Sprintf("Polled too soon; wait %d seconds between polls", e.Interval)
}

// GetApproval is GET /v1/me/approvals/{approval} (getApproval): the
// person's own approval. Polls by the requesting credential closer together
// than its interval answer SLOW_DOWN and lengthen it; another credential of
// the same person (the dashboard) reads it without counting.
func (s *Service) GetApproval(ctx context.Context, req Requester, approvalID string) (jsvalue.Object, error) {
	var view jsvalue.Object
	var slow *ErrSlowDown
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		view, slow = nil, nil
		q := query.New(tx)
		now := s.micros()
		r, err := s.intentOf(ctx, tx, approvalID, req.IdentityID)
		if err != nil {
			return err
		}
		if r == nil {
			return errApprovalNotFound
		}
		if r.CredentialID == req.CredentialID {
			if r.LastPolledAt.Valid && r.LastPolledAt.Int64 > now-r.PollInterval*int64(time.Second/time.Microsecond) {
				interval, err := q.SlowDownApproval(ctx, query.SlowDownApprovalParams{SlowDown: approvalSlowDown, Now: sql.NullInt64{Int64: now, Valid: true}, ID: approvalID})
				if err != nil {
					return err
				}
				slow = &ErrSlowDown{Interval: interval}
				return nil
			}
			if err := q.MarkApprovalPolled(ctx, query.MarkApprovalPolledParams{LastPolledAt: sql.NullInt64{Int64: now, Valid: true}, ID: approvalID}); err != nil {
				return err
			}
			if r, err = s.intentOf(ctx, tx, approvalID, req.IdentityID); err != nil {
				return err
			}
		}
		view, err = s.approvalView(*r, now)
		return err
	})
	if err == nil && slow != nil {
		return nil, slow
	}
	return view, err
}

// StartApproval is POST /v1/me/approvals/{approval}/options
// (startApproval): a fresh challenge for one of the person's pending
// intents, listing only their trusted passkeys, user verification required,
// bound to the intent, the person and their session; it expires with the
// intent at the latest. At most 20 per person per 10 minutes.
func (s *Service) StartApproval(ctx context.Context, identityID, sessionID, approvalID string) (RequestOptions, error) {
	if s.rp == nil {
		return RequestOptions{}, errNoPublicURL
	}
	var out RequestOptions
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		now := s.micros()
		r, err := s.intentOf(ctx, tx, approvalID, identityID)
		if err != nil {
			return err
		}
		if r == nil {
			return errApprovalNotFound
		}
		if st := stateOf(*r, now); st != "pending" {
			return ApprovalInvalid(st, &approvalID)
		}
		w, err := q.ApprovalChallengesSince(ctx, query.ApprovalChallengesSinceParams{IdentityID: identityID, Since: now - approvalWindow.Microseconds()})
		if err != nil {
			return err
		}
		if w.Issued >= approvalChallengesPerPers {
			retryAt := ISO(w.Oldest + approvalWindow.Microseconds())
			return &domainerr.Error{Code: "RATE_LIMITED", Message: "Too many approvals started; try again after " + retryAt,
				Details: jsvalue.Object{{Key: "retryAt", Value: retryAt}}}
		}
		list, err := ownPasskeys(ctx, tx, identityID)
		if err != nil {
			return err
		}
		trusted := []string{}
		for _, p := range list {
			if p.Trust == "trusted" {
				trusted = append(trusted, p.ID)
			}
		}
		options, err := s.assertionOptions(ctx, tx, identityID, "required", trusted)
		if err != nil {
			return err
		}
		if options == nil {
			return &domainerr.Error{Code: "PERMISSION_DENIED",
				Message: "You have no trusted passkey to approve with. Confirm a passkey with a trusted one under Account, Security, or ask whoever runs this Varlatch server for a link that enrolls a trusted one (varlatch admin reenroll)",
				Details: jsvalue.Object{{Key: "reason", Value: "no-trusted-passkey"}}}
		}
		remaining := max(time.Second.Microseconds(), r.ExpiresAt-now)
		options.Timeout = min(approvalChallengeLife.Microseconds(), remaining) / 1000
		if err := q.SupersedeApprovalChallenges(ctx, query.SupersedeApprovalChallengesParams{
			Now: sql.NullInt64{Int64: now, Valid: true}, IntentID: approvalID, IdentityID: identityID, AuthSessionID: sessionID,
		}); err != nil {
			return err
		}
		if err := q.InsertApprovalChallenge(ctx, query.InsertApprovalChallengeParams{
			ID: ids.New(ids.ApprovalIntentChallenge), IntentID: approvalID, IdentityID: identityID, AuthSessionID: sessionID,
			Challenge: options.Challenge, CreatedAt: now, ExpiresAt: min(now+approvalChallengeLife.Microseconds(), r.ExpiresAt),
		}); err != nil {
			return err
		}
		out = *options
		return nil
	})
	return out, err
}

// ApproveApproval is POST /v1/me/approvals/{approval}/approve
// (approveApproval): in one write job, check the intent is still pending,
// consume the challenge (issued for this intent, person and session;
// unused; unexpired), verify the assertion with one of the person's trusted
// passkeys, user verification required, and mark the intent approved with
// the passkey that asserted. A refused challenge or assertion stays
// consumed and is audited as authentication.failed.
func (s *Service) ApproveApproval(ctx context.Context, identityID, sessionID, approvalID string, response json.RawMessage, requestID string) (jsvalue.Object, error) {
	if s.rp == nil {
		return nil, errNoPublicURL
	}
	challenge := AssertionChallenge(response)
	var view jsvalue.Object
	refusal := ""
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		view, refusal = nil, ""
		q := query.New(tx)
		now := s.micros()
		r, err := s.intentOf(ctx, tx, approvalID, identityID)
		if err != nil {
			return err
		}
		if r == nil {
			return errApprovalNotFound
		}
		if st := stateOf(*r, now); st != "pending" {
			return ApprovalInvalid(st, &approvalID)
		}
		consumed := false
		if challenge != "" {
			id, err := q.BoundApprovalChallenge(ctx, query.BoundApprovalChallengeParams{Challenge: challenge, IntentID: approvalID, IdentityID: identityID, AuthSessionID: sessionID})
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if err == nil {
				n, err := q.ConsumeApprovalChallenge(ctx, query.ConsumeApprovalChallengeParams{Now: sql.NullInt64{Int64: now, Valid: true}, ID: id})
				if err != nil {
					return err
				}
				consumed = n > 0
			}
		}
		list, err := ownPasskeys(ctx, tx, identityID)
		if err != nil {
			return err
		}
		trusted := []string{}
		for _, p := range list {
			if p.Trust == "trusted" {
				trusted = append(trusted, p.ID)
			}
		}
		var evidence *Evidence
		reason := refusalChallenge
		if consumed {
			if evidence, reason, err = s.verifyAssertion(ctx, tx, identityID, response, challenge, true, trusted); err != nil {
				return err
			}
		}
		if evidence == nil {
			refusal = reason
			return record(ctx, tx, audit.Event{
				Type: "authentication.failed", Decision: audit.Deny, ActorIdentityID: &identityID,
				OrganizationID: ptrStr(r.OrganizationID), RequestID: &requestID,
				Resource: jsvalue.Object{{Key: "approvalId", Value: approvalID}},
				Metadata: jsvalue.Object{{Key: "method", Value: "step-up-approval"}, {Key: "operation", Value: r.Operation}, {Key: "reason", Value: reason}},
			})
		}
		n, err := q.MarkApprovalApproved(ctx, query.MarkApprovalApprovedParams{
			Now: sql.NullInt64{Int64: now, Valid: true}, PasskeyID: sql.NullString{String: evidence.PasskeyID, Valid: true},
			UserVerified: sql.NullBool{Bool: evidence.UserVerified, Valid: true}, ID: approvalID,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ApprovalInvalid("expired", &approvalID)
		}
		if r, err = s.intentOf(ctx, tx, approvalID, identityID); err != nil {
			return err
		}
		view, err = s.approvalView(*r, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	if refusal != "" {
		msg := "The approval could not be verified with one of your trusted passkeys"
		switch refusal {
		case refusalChallenge:
			msg = "This approval challenge was not issued for this approval and session, or it was used or expired; start again"
		case refusalUserVerification:
			msg = "The passkey did not verify you with a PIN, fingerprint or face; approve with a passkey that does"
		}
		return nil, &domainerr.Error{Code: "PERMISSION_DENIED", Message: msg, Details: jsvalue.Object{{Key: "reason", Value: refusal}}}
	}
	return view, nil
}

// CancelApproval is POST /v1/me/approvals/{approval}/cancel
// (cancelApproval): one of the person's approvals that is pending, or
// approved and not used yet.
func (s *Service) CancelApproval(ctx context.Context, identityID, approvalID string) (jsvalue.Object, error) {
	var view jsvalue.Object
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		now := s.micros()
		r, err := s.intentOf(ctx, tx, approvalID, identityID)
		if err != nil {
			return err
		}
		if r == nil {
			return errApprovalNotFound
		}
		if st := stateOf(*r, now); st != "pending" && st != "approved" {
			return ApprovalInvalid(st, &approvalID)
		}
		if err := query.New(tx).CancelApprovalIntent(ctx, query.CancelApprovalIntentParams{ClosedAt: sql.NullInt64{Int64: now, Valid: true}, ID: approvalID}); err != nil {
			return err
		}
		if r, err = s.intentOf(ctx, tx, approvalID, identityID); err != nil {
			return err
		}
		view, err = s.approvalView(*r, now)
		return err
	})
	return view, err
}
