// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// A person's passkeys as approval keys (ADR-0054 Decision 4) and the
// evidence a sign-in leaves (Decision 6), as domain/passkeys.ts records
// them:
//
//   - provenance: trusted when it existed at the upgrade, came from a setup
//     grant, or was confirmed; unconfirmed when a signed-in session added
//     it, until a trusted passkey confirms it with user verification. A
//     passkey without a provenance row counts as unconfirmed;
//   - evidence: whether the authenticator verified the user, and which
//     passkey asserted. Sessions carry it (auth_session_evidence), browser
//     and browser-handoff CLI credentials through their session, device
//     sign-in CLI credentials on the credential itself.

// Passkey confirmation limits (PASSKEY_CONFIRMATION).
const (
	confirmationChallengeLifetime = 300 * time.Second
	confirmationsPerWindow        = 10
	confirmationWindow            = 600 * time.Second
)

// OwnPasskey is one of a person's passkeys with its provenance.
type OwnPasskey struct {
	ID                   string
	Name                 *string
	DeviceType           string
	BackedUp             bool
	CreatedAt            *int64
	Trust                string
	TrustedVia           *string
	TrustedAt            *int64
	SetupGrantKind       *string
	ConfirmedByPasskeyID *string
}

func ownPasskey(r query.OwnPasskeysRow) OwnPasskey {
	return OwnPasskey{
		ID: r.ID, Name: ptrStr(r.Name), DeviceType: r.DeviceType, BackedUp: r.BackedUp, CreatedAt: ptrInt(r.CreatedAt),
		Trust: r.Trust, TrustedVia: ptrStr(r.TrustedVia), TrustedAt: ptrInt(r.TrustedAt),
		SetupGrantKind: ptrStr(r.SetupGrantKind), ConfirmedByPasskeyID: ptrStr(r.ConfirmedByPasskeyID),
	}
}

// ownPasskeys lists an identity's passkeys, oldest first (a passkey without
// a creation time first).
func ownPasskeys(ctx context.Context, db query.DBTX, identityID string) ([]OwnPasskey, error) {
	rows, err := query.New(db).OwnPasskeys(ctx, identityID)
	if err != nil {
		return nil, err
	}
	out := make([]OwnPasskey, 0, len(rows))
	for _, r := range rows {
		out = append(out, ownPasskey(r))
	}
	return out, nil
}

func findPasskey(list []OwnPasskey, id string) *OwnPasskey {
	for i := range list {
		if list[i].ID == id {
			return &list[i]
		}
	}
	return nil
}

// ListOwnPasskeys is GET /v1/me/passkeys.
func (s *Service) ListOwnPasskeys(ctx context.Context, identityID string) ([]OwnPasskey, error) {
	return ownPasskeys(ctx, s.store.Reader(), identityID)
}

// Evidence is what a passkey ceremony proved: whether the authenticator
// verified the user, and which passkey asserted.
type Evidence struct {
	UserVerified bool
	PasskeyID    string
}

// CredentialEvidence is a credential's evidence as it counts when used:
// with the asserting passkey's trust now.
type CredentialEvidence struct {
	Evidence
	// Source is "session" or "credential" (device sign-in).
	Source         string
	PasskeyTrusted bool
}

// EvidenceOf is credentialEvidence: the sign-in evidence a credential
// carries, or nil when it has none.
func EvidenceOf(ctx context.Context, db query.DBTX, credentialID string) (*CredentialEvidence, error) {
	row, err := query.New(db).CredentialEvidence(ctx, credentialID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var e CredentialEvidence
	switch {
	case row.EvidencePasskeyID.Valid && row.EvidenceUserVerified.Valid:
		e = CredentialEvidence{Evidence: Evidence{UserVerified: row.EvidenceUserVerified.Bool, PasskeyID: row.EvidencePasskeyID.String}, Source: "credential"}
	case row.HasSessionEvidence && row.SessionPasskeyID.Valid:
		e = CredentialEvidence{Evidence: Evidence{UserVerified: row.SessionUserVerified, PasskeyID: row.SessionPasskeyID.String}, Source: "session"}
	default:
		return nil, nil
	}
	list, err := ownPasskeys(ctx, db, row.IdentityID)
	if err != nil {
		return nil, err
	}
	if p := findPasskey(list, e.PasskeyID); p != nil && p.Trust == "trusted" {
		e.PasskeyTrusted = true
	}
	return &e, nil
}

// approvalPasskeys are an identity's passkeys that may assert, with their
// keys and counters as committed now; all of them when scope is nil.
func approvalPasskeys(ctx context.Context, db query.DBTX, identityID string, scope []string) ([]query.PasskeysOfIdentityRow, error) {
	rows, err := query.New(db).PasskeysOfIdentity(ctx, identityID)
	if err != nil || scope == nil {
		return rows, err
	}
	allowed := map[string]bool{}
	for _, id := range scope {
		allowed[id] = true
	}
	out := rows[:0:0]
	for _, r := range rows {
		if allowed[r.ID] {
			out = append(out, r)
		}
	}
	return out, nil
}

// assertionOptions is approval-assertion.ts's: request options for the
// identity's own passkeys in scope, with a new challenge; nil when it has
// none.
func (s *Service) assertionOptions(ctx context.Context, db query.DBTX, identityID, userVerification string, scope []string) (*RequestOptions, error) {
	rows, err := approvalPasskeys(ctx, db, identityID, scope)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	allow := make([]CredentialDescriptor, 0, len(rows))
	for _, r := range rows {
		allow = append(allow, CredentialDescriptor{ID: r.CredentialID, Type: "public-key", Transports: transportList(r.Transports.String)})
	}
	o := s.rp.requestOptions(newChallenge(), userVerification, allow)
	return &o, nil
}

// Assertion refusals (AssertionRefusal), and "challenge" for a challenge
// that was not issued for this operation, or was used or expired.
const (
	refusalChallenge        = "challenge"
	refusalUnknownPasskey   = "unknown-passkey"
	refusalInvalidAssertion = "invalid-assertion"
	refusalUserVerification = "user-verification-required"
)

// verifyAssertion verifies an assertion with one of the identity's passkeys
// in scope over challenge and advances that passkey's counter, in the
// caller's write job (verifyAssertion): the single writer runs two
// assertions of one passkey one after the other, so the second is verified
// against the counter the first wrote and refused like a replay. It returns
// the evidence, or the refusal's reason.
func (s *Service) verifyAssertion(ctx context.Context, tx query.DBTX, identityID string, response json.RawMessage, challenge string, requireUV bool, scope []string) (*Evidence, string, error) {
	a, err := parseAssertion(response)
	if err != nil {
		return nil, refusalUnknownPasskey, nil
	}
	rows, err := approvalPasskeys(ctx, tx, identityID, scope)
	if err != nil {
		return nil, "", err
	}
	var pk *query.PasskeysOfIdentityRow
	for i := range rows {
		if rows[i].CredentialID == a.CredentialID() {
			pk = &rows[i]
		}
	}
	// A passkey of another identity, one out of scope, or none at all,
	// never approves for this one.
	if pk == nil {
		return nil, refusalUnknownPasskey, nil
	}
	counter, verified, err := s.rp.verify(a, challenge, pk.PublicKey, pk.Counter, false)
	if err != nil {
		return nil, refusalInvalidAssertion, nil
	}
	if requireUV && !verified {
		return nil, refusalUserVerification, nil
	}
	if err := query.New(tx).AdvancePasskeyCounter(ctx, query.AdvancePasskeyCounterParams{Counter: int64(counter), ID: pk.ID}); err != nil {
		return nil, "", err
	}
	return &Evidence{UserVerified: verified, PasskeyID: pk.ID}, "", nil
}

// StartConfirmation is POST /v1/me/passkeys/{passkey}/confirmation/options
// (issueConfirmationChallenge): a challenge for confirming one unconfirmed
// passkey, listing only the person's trusted passkeys, user verification
// required, bound to the person, their session and the passkey; an earlier
// unused challenge of the same three is superseded. At most 10 per person
// per 10 minutes.
func (s *Service) StartConfirmation(ctx context.Context, identityID, sessionID, passkeyID string) (RequestOptions, error) {
	release, gateErr := s.personGate(ctx, identityID, true)
	if gateErr != nil {
		return RequestOptions{}, gateErr
	}
	defer release()
	if s.rp == nil {
		return RequestOptions{}, errNoPublicURL
	}
	var out RequestOptions
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		list, err := ownPasskeys(ctx, tx, identityID)
		if err != nil {
			return err
		}
		target := findPasskey(list, passkeyID)
		if target == nil {
			return domainerr.New("RESOURCE_NOT_FOUND", "Passkey not found")
		}
		if target.Trust == "trusted" {
			return domainerr.New("STATE_CHANGED", "This passkey is already trusted")
		}
		now := s.micros()
		window, err := q.ConfirmationChallengeWindow(ctx, query.ConfirmationChallengeWindowParams{IdentityID: identityID, Since: now - confirmationWindow.Microseconds()})
		if err != nil {
			return err
		}
		if window.Issued >= confirmationsPerWindow {
			retryAt := ISO(window.Oldest + confirmationWindow.Microseconds())
			return &domainerr.Error{Code: "RATE_LIMITED", Message: "Too many passkey confirmations started; try again after " + retryAt,
				Details: jsvalue.Object{{Key: "retryAt", Value: retryAt}}}
		}
		var trusted []string
		for _, p := range list {
			if p.Trust == "trusted" {
				trusted = append(trusted, p.ID)
			}
		}
		if trusted == nil {
			trusted = []string{}
		}
		options, err := s.assertionOptions(ctx, tx, identityID, "required", trusted)
		if err != nil {
			return err
		}
		if options == nil {
			return &domainerr.Error{Code: "PERMISSION_DENIED",
				Message: "You have no trusted passkey to confirm it with. Whoever runs this Varlatch server can send you a link that enrolls a trusted one (varlatch admin reenroll)",
				Details: jsvalue.Object{{Key: "reason", Value: "no-trusted-passkey"}}}
		}
		if err := q.SupersedeConfirmationChallenges(ctx, query.SupersedeConfirmationChallengesParams{
			Now: sql.NullInt64{Int64: now, Valid: true}, IdentityID: identityID, AuthSessionID: sessionID, TargetPasskeyID: passkeyID,
		}); err != nil {
			return err
		}
		if err := q.InsertConfirmationChallenge(ctx, query.InsertConfirmationChallengeParams{
			ID: ids.New(ids.PasskeyConfirmationChallenge), IdentityID: identityID, AuthSessionID: sessionID, TargetPasskeyID: passkeyID,
			Challenge: options.Challenge, CreatedAt: now, ExpiresAt: now + confirmationChallengeLifetime.Microseconds(),
		}); err != nil {
			return err
		}
		out = *options
		return nil
	})
	return out, err
}

// Confirm is POST /v1/me/passkeys/{passkey}/confirmation (confirmPasskey):
// in one write job, consume the challenge (issued for this person, session
// and passkey; unused; unexpired), verify the assertion with one of the
// person's other trusted passkeys, user verification required, and mark the
// passkey trusted, with authentication.passkey_confirmed. A refused
// challenge or assertion stays consumed and is audited as
// authentication.failed; the refusal names the reason (details.reason).
func (s *Service) Confirm(ctx context.Context, identityID, sessionID, passkeyID string, response json.RawMessage, requestID string) (OwnPasskey, error) {
	release, gateErr := s.personGate(ctx, identityID, true)
	if gateErr != nil {
		return OwnPasskey{}, gateErr
	}
	defer release()
	if s.rp == nil {
		return OwnPasskey{}, errNoPublicURL
	}
	challenge := AssertionChallenge(response)
	var refusal string
	var confirmed OwnPasskey
	alreadyTrusted := false
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		refusal, alreadyTrusted = "", false
		q := query.New(tx)
		now := s.micros()
		consumed := false
		if challenge != "" {
			id, err := q.BoundConfirmationChallenge(ctx, query.BoundConfirmationChallengeParams{
				Challenge: challenge, IdentityID: identityID, AuthSessionID: sessionID, TargetPasskeyID: passkeyID,
			})
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if err == nil {
				n, err := q.ConsumeConfirmationChallenge(ctx, query.ConsumeConfirmationChallengeParams{Now: sql.NullInt64{Int64: now, Valid: true}, ID: id})
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
		target := findPasskey(list, passkeyID)
		if target == nil {
			return domainerr.New("RESOURCE_NOT_FOUND", "Passkey not found")
		}
		if consumed && target.Trust == "trusted" {
			alreadyTrusted = true
			return nil
		}
		trusted := []string{}
		for _, p := range list {
			if p.Trust == "trusted" && p.ID != passkeyID {
				trusted = append(trusted, p.ID)
			}
		}
		var evidence *Evidence
		reason := refusalChallenge
		if consumed {
			evidence, reason, err = s.verifyAssertion(ctx, tx, identityID, response, challenge, true, trusted)
			if err != nil {
				return err
			}
		}
		if evidence == nil {
			refusal = reason
			return record(ctx, tx, audit.Event{
				Type: "authentication.failed", Decision: audit.Deny, ActorIdentityID: &identityID, RequestID: &requestID,
				Resource: jsvalue.Object{{Key: "passkeyId", Value: passkeyID}},
				Metadata: jsvalue.Object{{Key: "method", Value: "passkey-confirmation"}, {Key: "reason", Value: reason}},
			})
		}
		if err := q.ConfirmProvenance(ctx, query.ConfirmProvenanceParams{
			PasskeyID: passkeyID, Now: sql.NullInt64{Int64: now, Valid: true}, ConfirmedBy: sql.NullString{String: evidence.PasskeyID, Valid: true},
		}); err != nil {
			return err
		}
		if err := record(ctx, tx, audit.Event{
			Type: "authentication.passkey_confirmed", Decision: audit.Info, ActorIdentityID: &identityID,
			AuthenticationMethodID: str("passkey"), RequestID: &requestID,
			Resource: jsvalue.Object{{Key: "passkeyId", Value: passkeyID}},
			Metadata: jsvalue.Object{{Key: "confirmedByPasskeyId", Value: evidence.PasskeyID}, {Key: "userVerified", Value: evidence.UserVerified}},
		}); err != nil {
			return err
		}
		after, err := ownPasskeys(ctx, tx, identityID)
		if err != nil {
			return err
		}
		confirmed = *findPasskey(after, passkeyID)
		return nil
	})
	if err != nil {
		return OwnPasskey{}, err
	}
	if alreadyTrusted {
		return OwnPasskey{}, domainerr.New("STATE_CHANGED", "This passkey is already trusted")
	}
	if refusal != "" {
		msg := "The confirmation could not be verified with one of your trusted passkeys"
		switch refusal {
		case refusalChallenge:
			msg = "This confirmation was not started for this passkey and session, or it was used or expired; start it again"
		case refusalUserVerification:
			msg = "The passkey did not verify you with a PIN, fingerprint or face; confirm with a passkey that does"
		}
		return OwnPasskey{}, &domainerr.Error{Code: "PERMISSION_DENIED", Message: msg, Details: jsvalue.Object{{Key: "reason", Value: refusal}}}
	}
	return confirmed, nil
}

// RemoveOwnPasskey is DELETE /v1/me/passkeys/{passkey} (removeOwnPasskey):
// another person's passkey, or an unknown id, is not found. Removing a
// trusted passkey while the person belongs to a live Organization with a
// Security Control at enforce needs a step-up approval (ADR-0054 Decision
// 4) for passkey.remove of this passkey: approvalID is the request's
// Varlatch-Approval header ("" for none), consumed in the removal's job.
// Without one the intent is created and the answer is STEP_UP_REQUIRED.
func (s *Service) RemoveOwnPasskey(ctx context.Context, req Requester, passkeyID, approvalID string) error {
	release, gateErr := s.personGate(ctx, req.IdentityID, true)
	if gateErr != nil {
		return gateErr
	}
	defer release()
	var needed *ApprovalNeeded
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		needed = nil
		q := query.New(tx)
		list, err := ownPasskeys(ctx, tx, req.IdentityID)
		if err != nil {
			return err
		}
		p := findPasskey(list, passkeyID)
		if p == nil {
			return domainerr.New("RESOURCE_NOT_FOUND", "Passkey not found")
		}
		if p.Trust == "trusted" {
			orgs, err := q.PasskeyRemovalRestriction(ctx, req.IdentityID)
			if err != nil {
				return err
			}
			if len(orgs) > 0 {
				name := p.ID
				if p.Name != nil {
					name = `"` + *p.Name + `"`
				}
				b := Binding{
					Operation: "passkey.remove", Target: map[string]string{"passkeyId": p.ID}, Body: nil, Query: map[string]string{},
					Summary: ApprovalSummary{Title: "Remove your trusted passkey " + name},
				}
				if approvalID == "" {
					needed = &ApprovalNeeded{Binding: b}
					return needed
				}
				if err := s.consumeApproval(ctx, tx, req, approvalID, b); err != nil {
					return err
				}
			}
		}
		_, err = q.DeletePasskey(ctx, passkeyID)
		return err
	})
	if needed != nil && errors.Is(err, needed) {
		// The intent is created after the removal's gate is released, in
		// createApproval's own job, as withApproval creates it after the
		// operation's transaction ended.
		release()
		return s.stepUpRequired(ctx, req, needed.Binding)
	}
	return err
}

// passkey-verification (ADR-0054 Decision 7; domain/passkeyverification.ts):
// an Organization access by a person's credential whose sign-in evidence
// lacks user verification, or comes from a passkey not trusted now, is
// counted under report and refused under enforce. Machine credentials are
// exempt by kind.

// Verification gaps (VerificationGap): what a credential's evidence lacks.
const (
	GapNoEvidence      = "no-evidence"
	GapNotUserVerified = "not-user-verified"
	GapUntrusted       = "untrusted-passkey"
)

// VerificationGap is verificationGap: what a person's credential lacks, or
// "" when its evidence is user-verified and from a passkey trusted now. A
// kind that cannot carry a sign-in's evidence (only browser and cli can)
// has none.
func VerificationGap(ctx context.Context, db query.DBTX, credentialID, credentialKind string) (string, error) {
	if credentialKind != KindBrowser && credentialKind != KindCLI {
		return GapNoEvidence, nil
	}
	e, err := EvidenceOf(ctx, db, credentialID)
	if err != nil {
		return "", err
	}
	switch {
	case e == nil:
		return GapNoEvidence, nil
	case !e.UserVerified:
		return GapNotUserVerified, nil
	case !e.PasskeyTrusted:
		return GapUntrusted, nil
	}
	return "", nil
}

// SessionVerificationGap is VerificationGap of what a browser session's own
// credentials carry: the evidence of the session's sign-in.
func SessionVerificationGap(ctx context.Context, db query.DBTX, sessionID, identityID string) (string, error) {
	row, err := query.New(db).SessionEvidence(ctx, sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return GapNoEvidence, nil
	}
	if err != nil {
		return "", err
	}
	if !row.UserVerified {
		return GapNotUserVerified, nil
	}
	list, err := ownPasskeys(ctx, db, identityID)
	if err != nil {
		return "", err
	}
	if p := findPasskey(list, row.PasskeyID); p == nil || p.Trust != "trusted" {
		return GapUntrusted, nil
	}
	return "", nil
}

// PendingReport is a report-mode count the request makes once it
// succeeded (PendingAccessReport).
type PendingReport struct {
	OrganizationID  string
	ActorIdentityID string
	ConfigVersion   int64
	Reason          string
}

// VerificationOutcome is passkeyVerification's outcome for a request.
type VerificationOutcome struct {
	Reports []PendingReport
	// Blocked maps an Organization at enforce to the gap.
	Blocked map[string]string
}

// PasskeyVerification decides passkey-verification for a requester entering
// these Organizations, reading through db: nothing for a machine, or when
// every control is off.
func PasskeyVerification(ctx context.Context, db query.DBTX, p *Principal, organizationIDs []string) (VerificationOutcome, error) {
	out := VerificationOutcome{Blocked: map[string]string{}}
	if p.Identity.Kind != "human" || len(organizationIDs) == 0 {
		return out, nil
	}
	active, err := query.New(db).ActivePasskeyVerificationControls(ctx, organizationIDs)
	if err != nil || len(active) == 0 {
		return out, err
	}
	gap, err := VerificationGap(ctx, db, p.Credential.ID, p.Credential.Kind)
	if err != nil || gap == "" {
		return out, err
	}
	for _, r := range active {
		if r.Mode == "enforce" {
			out.Blocked[r.OrganizationID] = gap
		} else {
			out.Reports = append(out.Reports, PendingReport{OrganizationID: r.OrganizationID, ActorIdentityID: p.Identity.ID, ConfigVersion: r.Version, Reason: gap})
		}
	}
	return out, nil
}

var gapMessages = map[string]string{
	GapNoEvidence:      "your sign-in carries no passkey evidence (it may predate this check)",
	GapNotUserVerified: "the passkey you signed in with did not verify you with a PIN or biometric",
	GapUntrusted:       "you signed in with a passkey that is not trusted (confirm it on your account's Security page first)",
}

// VerificationRefusal is PasskeyVerificationRefusal: PASSKEY_VERIFICATION_REQUIRED
// (403), naming what the person's sign-in lacks in details.reason. The
// Organization is not in the response; the HTTP layer audits a refusal of
// access with it. SelfLockout is turning the control to enforce from a
// sign-in it would refuse, which records nothing.
type VerificationRefusal struct {
	Domain         *domainerr.Error
	OrganizationID string
	Reason         string
	SelfLockout    bool
}

func (e *VerificationRefusal) Error() string { return e.Domain.Error() }
func (e *VerificationRefusal) Unwrap() error { return e.Domain }

// PasskeyVerificationRequired is the refusal of an access by a blocked
// person's request.
func PasskeyVerificationRequired(organizationID, reason string) *VerificationRefusal {
	return &VerificationRefusal{
		Domain: &domainerr.Error{Code: "PASSKEY_VERIFICATION_REQUIRED",
			Message: "This Organization requires a sign-in with a trusted passkey that verifies you with a PIN or biometric, and " + gapMessages[reason] + ". " +
				"Sign in again with such a passkey: in the dashboard, sign out and sign in; for the CLI, run varlatch login and approve it with that passkey.",
			Details: jsvalue.Object{{Key: "control", Value: "passkey-verification"}, {Key: "reason", Value: reason}}},
		OrganizationID: organizationID, Reason: reason,
	}
}

// EnforceWouldRefuseYou is the refusal to turn the control to enforce from
// a sign-in it would refuse.
func EnforceWouldRefuseYou(organizationID, reason string) *VerificationRefusal {
	return &VerificationRefusal{
		Domain: &domainerr.Error{Code: "PASSKEY_VERIFICATION_REQUIRED",
			Message: "Enforcing passkey-verification would refuse your own sign-in: " + gapMessages[reason] + ". " +
				"Sign in again with a trusted passkey that verifies you with a PIN or biometric, then turn it on. Nothing was changed.",
			Details: jsvalue.Object{{Key: "control", Value: "passkey-verification"}, {Key: "reason", Value: reason}, {Key: "change", Value: "refused"}}},
		OrganizationID: organizationID, Reason: reason, SelfLockout: true,
	}
}
