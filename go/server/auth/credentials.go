// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Identity is the identity a credential belongs to (IdentityRow).
type Identity struct {
	ID                string
	Kind              string
	Name              string
	Disabled          bool
	InstallationAdmin bool
	OrganizationID    *string
}

// Credential is an authenticated credential (CredentialRow).
type Credential struct {
	ID         string
	IdentityID string
	Kind       string
	Name       *string
	ExpiresAt  *int64
	MaxUses    *int64
	UseCount   int64
	// AuthSessionID is the browser session a browser bearer was minted
	// from, or a browser-handoff CLI credential came from.
	AuthSessionID *string
	// ExerciseOnly is set for an exercise-only credential (ADR-0060): it
	// exercises Capabilities of its Broker and nothing else.
	ExerciseOnly *ExerciseOnly
}

// ExerciseOnly is what limits an exercise-only credential.
type ExerciseOnly struct {
	// OIDCBindingID is the binding its token was exchanged under.
	OIDCBindingID string
	// RunID, when set, is the one run whose Capabilities it exercises.
	RunID *string
}

// Principal is who a /v1 request authenticated as.
type Principal struct {
	Identity   Identity
	Credential Credential
}

// Reasons a bearer does not authenticate, for the audit log only: callers
// answer every one as INVALID_CREDENTIAL.
const (
	ReasonInvalid          = "invalid"
	ReasonRevoked          = "revoked"
	ReasonExpired          = "expired"
	ReasonExhausted        = "exhausted"
	ReasonIdentityDisabled = "identity-disabled"
)

// ReasonExerciseOnly is Authenticate's for a live exercise-only credential:
// it authenticates, but only for an exercise (AuthenticateExercise).
const ReasonExerciseOnly = "exercise-only"

// lastUsedEvery throttles the last-used write (ADR-0034): at most one per
// credential per 60 seconds.
const lastUsedEvery = 60 * time.Second

func nullStr(p *string) sql.NullString {
	if p == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *p, Valid: true}
}

func nullInt(p *int64) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *p, Valid: true}
}

func ptrStr(n sql.NullString) *string {
	if !n.Valid {
		return nil
	}
	return &n.String
}

func ptrInt(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	return &n.Int64
}

// Authenticate resolves a bearer token, as authenticateBearer does: the
// credential and its identity, or the reason it does not authenticate. A
// credential with a use limit spends one use, in a write job that refuses
// the use past the limit; a credential not used for a minute records that
// it was, with its identity's last-seen time.
//
// An exercise-only credential (ADR-0060) is refused here, whatever the
// caller serves: ReasonExerciseOnly, and no principal. Only
// AuthenticateExercise accepts one.
func (s *Service) Authenticate(ctx context.Context, token string) (*Principal, string, error) {
	p, reason, err := s.AuthenticateExercise(ctx, token)
	if err == nil && p != nil && p.Credential.ExerciseOnly != nil {
		return nil, ReasonExerciseOnly, nil
	}
	return p, reason, err
}

// AuthenticateExercise is Authenticate for the one operation an
// exercise-only credential may be used for, the exercise of a Capability;
// every other credential is resolved as Authenticate resolves it.
func (s *Service) AuthenticateExercise(ctx context.Context, token string) (*Principal, string, error) {
	digest := HashToken(token)
	q := query.New(s.store.Reader())
	row, err := q.CredentialByTokenHash(ctx, digest)
	prefix := ""
	if errors.Is(err, sql.ErrNoRows) {
		prefix = ExercisePrefix
		row, err = q.CredentialByTokenHash(ctx, ExercisePrefix+digest)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ReasonInvalid, nil
	}
	if err != nil {
		return nil, "", err
	}
	var only *ExerciseOnly
	if prefix != "" {
		limit, err := q.ExerciseCredential(ctx, row.ID)
		if errors.Is(err, sql.ErrNoRows) {
			// Its limits are gone (a migration there and back): not usable.
			return nil, ReasonInvalid, nil
		}
		if err != nil {
			return nil, "", err
		}
		only = &ExerciseOnly{OIDCBindingID: limit.OidcBindingID, RunID: ptrStr(limit.RunID)}
	}
	// Defense in depth against lookup-layer surprises.
	stored, err1 := hex.DecodeString(strings.TrimPrefix(row.TokenHash, prefix))
	want, _ := hex.DecodeString(digest)
	if err1 != nil || subtle.ConstantTimeCompare(stored, want) != 1 {
		return nil, ReasonInvalid, nil
	}
	now := s.micros()
	if row.RevokedAt.Valid {
		return nil, ReasonRevoked, nil
	}
	if row.ExpiresAt.Valid && row.ExpiresAt.Int64 <= now {
		return nil, ReasonExpired, nil
	}
	if row.Disabled {
		return nil, ReasonIdentityDisabled, nil
	}
	touch := !row.LastUsedAt.Valid || row.LastUsedAt.Int64 < now-lastUsedEvery.Microseconds()
	if row.MaxUses.Valid || touch {
		exhausted := false
		err := s.store.Write(ctx, func(tx *storage.Tx) error {
			exhausted = false
			q := query.New(tx)
			now := s.micros()
			if row.MaxUses.Valid {
				// The single writer runs this check and the increment with
				// nothing between: concurrent requests never overspend.
				n, err := q.ConsumeCredentialUse(ctx, row.ID)
				if err != nil {
					return err
				}
				if n == 0 {
					exhausted = true
					return nil
				}
			}
			n, err := q.TouchCredential(ctx, query.TouchCredentialParams{
				Now: sql.NullInt64{Int64: now, Valid: true}, ID: row.ID,
				Before: sql.NullInt64{Int64: now - lastUsedEvery.Microseconds(), Valid: true},
			})
			if err != nil {
				return err
			}
			if n > 0 {
				return q.TouchIdentity(ctx, query.TouchIdentityParams{LastSeenAt: sql.NullInt64{Int64: now, Valid: true}, ID: row.IdentityID})
			}
			return nil
		})
		if err != nil {
			return nil, "", err
		}
		if exhausted {
			return nil, ReasonExhausted, nil
		}
	}
	return &Principal{
		Identity: Identity{
			ID: row.IdentityID, Kind: row.IdentityKind, Name: row.IdentityName, Disabled: row.Disabled,
			InstallationAdmin: row.InstallationAdmin, OrganizationID: ptrStr(row.OrganizationID),
		},
		Credential: Credential{
			ID: row.ID, IdentityID: row.IdentityID, Kind: row.Kind, Name: ptrStr(row.Name),
			ExpiresAt: ptrInt(row.ExpiresAt), MaxUses: ptrInt(row.MaxUses), UseCount: row.UseCount,
			AuthSessionID: ptrStr(row.AuthSessionID), ExerciseOnly: only,
		},
	}, "", nil
}

// RecordAuthenticationFailed records the refusal of a bearer: the /v1
// middleware's authentication.failed, with the reason.
func (s *Service) RecordAuthenticationFailed(ctx context.Context, requestID, reason string) error {
	return s.store.Write(ctx, func(tx *storage.Tx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Type: "authentication.failed", Decision: audit.Deny, RequestID: &requestID,
			Metadata: jsvalue.Object{{Key: "reason", Value: reason}},
		})
		return err
	})
}

// CredentialExpiresWarning is how close to its expiry a machine credential
// names it on every response (ADR-0054 Decision 8).
const CredentialExpiresWarning = 7 * 24 * time.Hour

// ExpiresNotice is the Varlatch-Credential-Expires header's value for a
// principal, or "": only for a service credential of a non-human identity
// that expires within 7 days (credentialExpiresNotice).
func (s *Service) ExpiresNotice(p *Principal) string {
	c := p.Credential
	if c.Kind != KindService || p.Identity.Kind == "human" || c.ExpiresAt == nil {
		return ""
	}
	if *c.ExpiresAt-s.micros() > CredentialExpiresWarning.Microseconds() {
		return ""
	}
	return ISO(*c.ExpiresAt)
}

// Issue is what issueCredential takes.
type Issue struct {
	IdentityID string
	Kind       string
	Name       *string
	// ExpiresAt in microseconds; nil for none.
	ExpiresAt *int64
	MaxUses   *int64
	// ActorIdentityID is who was shown the token (issued_by and the event's
	// actor); the identity itself when nil.
	ActorIdentityID *string
	OrganizationID  *string
	Metadata        jsvalue.Object
	// Client is the readable client label (ClientLabel), never a raw
	// User-Agent.
	Client *string
	// AuthSessionID: browser bearers and browser-handoff CLI credentials.
	AuthSessionID *string
	// Evidence: CLI credentials from device sign-in.
	Evidence *Evidence
	// ExerciseOnly limits the credential to exercising Capabilities
	// (ADR-0060).
	ExerciseOnly *ExerciseOnly
}

// Issued is a credential issued: the token is returned once and never
// stored.
type Issued struct {
	CredentialID string
	Token        string
}

// IssueCredential issues a credential in the caller's write job, with its
// credential.issued event (issueCredential).
func IssueCredential(ctx context.Context, tx query.DBTX, now int64, in Issue) (Issued, error) {
	token := GenerateToken(in.Kind)
	id := ids.New(ids.Credential)
	actor := in.IdentityID
	if in.ActorIdentityID != nil {
		actor = *in.ActorIdentityID
	}
	params := query.InsertCredentialParams{
		ID: id, IdentityID: in.IdentityID, Kind: in.Kind, Name: nullStr(in.Name), TokenHash: HashToken(token),
		CreatedAt: now, ExpiresAt: nullInt(in.ExpiresAt), MaxUses: nullInt(in.MaxUses), Client: nullStr(in.Client),
		AuthSessionID: nullStr(in.AuthSessionID), IssuedBy: sql.NullString{String: actor, Valid: true},
	}
	if in.Evidence != nil {
		params.EvidenceUserVerified = sql.NullBool{Bool: in.Evidence.UserVerified, Valid: true}
		params.EvidencePasskeyID = sql.NullString{String: in.Evidence.PasskeyID, Valid: true}
	}
	if in.ExerciseOnly != nil {
		params.TokenHash = ExercisePrefix + params.TokenHash
	}
	if err := query.New(tx).InsertCredential(ctx, params); err != nil {
		return Issued{}, err
	}
	metadata := jsvalue.Object{{Key: "kind", Value: in.Kind}}
	if x := in.ExerciseOnly; x != nil {
		if err := query.New(tx).InsertExerciseCredential(ctx, query.InsertExerciseCredentialParams{
			CredentialID: id, OidcBindingID: x.OIDCBindingID, RunID: nullStr(x.RunID),
		}); err != nil {
			return Issued{}, err
		}
		metadata = append(metadata, jsvalue.Member{Key: "exerciseOnly", Value: true})
		if x.RunID != nil {
			metadata = append(metadata, jsvalue.Member{Key: "runId", Value: *x.RunID})
		}
	}
	if in.ExpiresAt != nil {
		metadata = append(metadata, jsvalue.Member{Key: "expiresAt", Value: ISO(*in.ExpiresAt)})
	}
	if in.MaxUses != nil && *in.MaxUses != 0 {
		metadata = append(metadata, jsvalue.Member{Key: "maxUses", Value: *in.MaxUses})
	}
	for _, m := range in.Metadata {
		metadata = metadata.Set(m.Key, m.Value)
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Type: "credential.issued", Decision: audit.Info, ActorIdentityID: &actor,
		CredentialID: audit.Value(id), OrganizationID: in.OrganizationID,
		Resource: jsvalue.Object{{Key: "identityId", Value: in.IdentityID}},
		Metadata: metadata,
	})
	if err != nil {
		return Issued{}, err
	}
	return Issued{CredentialID: id, Token: token}, nil
}

// RevokeCredential revokes a credential in the caller's write job, with its
// credential.revoked event naming its kind and identity (revokeCredential).
// Revoking one already revoked records the event without them.
func RevokeCredential(ctx context.Context, tx query.DBTX, now int64, credentialID, actorIdentityID string, organizationID *string) error {
	row, err := query.New(tx).RevokeCredential(ctx, query.RevokeCredentialParams{Now: sql.NullInt64{Int64: now, Valid: true}, ID: credentialID})
	found := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	e := audit.Event{
		Type: "credential.revoked", Decision: audit.Info, ActorIdentityID: &actorIdentityID,
		CredentialID: audit.Value(credentialID), OrganizationID: organizationID,
	}
	if found {
		e.Resource = jsvalue.Object{{Key: "identityId", Value: row.IdentityID}}
		e.Metadata = jsvalue.Object{{Key: "kind", Value: row.Kind}}
	}
	_, err = audit.Record(ctx, tx, e)
	return err
}

// OwnCredential is one of the caller's credentials, as GET
// /v1/me/credentials lists it.
type OwnCredential struct {
	ID        string
	Kind      string
	Name      *string
	CreatedAt int64
	ExpiresAt *int64
	RevokedAt *int64
	MaxUses   *int64
	UseCount  int64
	Client    *string
}

// ListOwnCredentials lists an identity's credentials, newest first.
func (s *Service) ListOwnCredentials(ctx context.Context, identityID string) ([]OwnCredential, error) {
	rows, err := query.New(s.store.Reader()).ListCredentialsOfIdentity(ctx, identityID)
	if err != nil {
		return nil, err
	}
	out := make([]OwnCredential, 0, len(rows))
	for _, r := range rows {
		out = append(out, OwnCredential{
			ID: r.ID, Kind: r.Kind, Name: ptrStr(r.Name), CreatedAt: r.CreatedAt, ExpiresAt: ptrInt(r.ExpiresAt),
			RevokedAt: ptrInt(r.RevokedAt), MaxUses: ptrInt(r.MaxUses), UseCount: r.UseCount, Client: ptrStr(r.Client),
		})
	}
	return out, nil
}

// RevokeOwnCredential revokes one of the caller's credentials (DELETE
// /v1/me/credentials/{credential}); another's, or an unknown one, is not
// found. A browser credential's session ends with it (endsSession). A machine identity's Organization must be live: its credentials
// belong to the Organization (lockLiveScope with the recovery exception).
func (s *Service) RevokeOwnCredential(ctx context.Context, p *Principal, credentialID string) error {
	return s.store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		if p.Identity.OrganizationID != nil {
			if _, err := q.LiveOrganization(ctx, *p.Identity.OrganizationID); errors.Is(err, sql.ErrNoRows) {
				return domainerr.NotFound("Organization")
			} else if err != nil {
				return err
			}
		}
		row, err := q.CredentialOfIdentity(ctx, query.CredentialOfIdentityParams{ID: credentialID, IdentityID: p.Identity.ID})
		if errors.Is(err, sql.ErrNoRows) {
			return domainerr.New("RESOURCE_NOT_FOUND", "Credential not found")
		} else if err != nil {
			return err
		}
		now := s.micros()
		if err := RevokeCredential(ctx, tx, now, credentialID, p.Identity.ID, nil); err != nil {
			return err
		}
		if err := endEntryLinksOfPerson(ctx, tx, now, p, credentialID); err != nil {
			return err
		}
		if !endsSession(p, credentialID, row.Kind, row.AuthSessionID) {
			return nil
		}
		// Deleting the session revokes its other browser bearers (the
		// trigger), so the browser cannot mint another from its cookie.
		_, err = q.DeleteAuthSession(ctx, row.AuthSessionID.String)
		return err
	})
}

// SignOutOtherSessions ends every browser session of the caller but the
// one its browser bearer comes from (POST /v1/me/sessions/sign-out-others)
// and returns how many: the session-end trigger revokes each session's
// browser bearers, each a credential.revoked event, so the browser cannot
// mint another. CLI credentials, the hand-off's included, stay. Only a
// browser bearer may: it names the session that stays.
func (s *Service) SignOutOtherSessions(ctx context.Context, p *Principal) (int64, error) {
	if p.Identity.Kind != "human" || p.Credential.Kind != KindBrowser || p.Credential.AuthSessionID == nil {
		return 0, domainerr.New("PERMISSION_DENIED", "Only a browser session bearer may sign out the other browsers")
	}
	var ended int64
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		// The request authenticated before this write: a browser that
		// another one signed out meanwhile (the single writer ran that
		// first) signs out nobody. Its bearer and its session must still be
		// live now.
		q := query.New(tx)
		live, err := q.BrowserBearerSessionLive(ctx, query.BrowserBearerSessionLiveParams{
			CredentialID: p.Credential.ID, IdentityID: p.Identity.ID, Now: sql.NullInt64{Int64: s.micros(), Valid: true},
		})
		if err != nil {
			return err
		}
		if live == 0 {
			return domainerr.New("INVALID_CREDENTIAL", "Credential is invalid, revoked, or expired")
		}
		ended, err = q.DeleteOtherAuthSessionsOfIdentity(ctx, query.DeleteOtherAuthSessionsOfIdentityParams{
			Keep: *p.Credential.AuthSessionID, IdentityID: p.Identity.ID,
		})
		return err
	})
	return ended, err
}

// endsSession reports whether revoking a browser credential ends the
// browser session it was minted from: a revoked bearer would otherwise be
// replaced by the next POST /auth/varlatch-token of the same browser, for
// as long as its session lasts. An older bearer of the caller's own
// session is only revoked ("Sign out everywhere else" leaves this browser
// signed in); the presenting bearer ends it ("Sign out this browser"). Only
// a browser bearer is of its own session: a CLI credential from the browser
// hand-off carries the session too, but revoking a browser bearer with it
// ends the session; revoking that CLI credential leaves the session alone
// (ADR-0024).
func endsSession(p *Principal, credentialID, kind string, session sql.NullString) bool {
	if kind != KindBrowser || !session.Valid {
		return false
	}
	own := p.Credential.Kind == KindBrowser && p.Credential.AuthSessionID != nil && *p.Credential.AuthSessionID == session.String
	return !own || credentialID == p.Credential.ID
}

// CLI credential lifetimes for the browser hand-off exchange (ADR-0024).
const (
	CLIDefaultTTL = 43_200
	CLIMinTTL     = 60
	CLIMaxTTL     = 86_400
)

// ExchangeCLI trades the dashboard's browser bearer for a CLI credential,
// revoking the bearer: one exchange per bearer (POST
// /v1/me/credentials/cli). Only a person's browser bearer may be exchanged.
// The new credential carries the bearer's session, and so its sign-in
// evidence (ADR-0054 Decision 6).
func (s *Service) ExchangeCLI(ctx context.Context, p *Principal, ttlSeconds int64, name *string, client *string) (Issued, int64, error) {
	if p.Identity.Kind != "human" || p.Credential.Kind != KindBrowser {
		return Issued{}, 0, domainerr.New("PERMISSION_DENIED", "Only a browser session bearer may be exchanged for a CLI credential")
	}
	var issued Issued
	var expiresAt int64
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		now := s.micros()
		expiresAt = (now/1000 + ttlSeconds*1000) * 1000
		n, err := q.ConsumeBrowserCredential(ctx, query.ConsumeBrowserCredentialParams{Now: sql.NullInt64{Int64: now, Valid: true}, ID: p.Credential.ID})
		if err != nil {
			return err
		}
		if n == 0 {
			return domainerr.New("INVALID_CREDENTIAL", "Browser credential was already consumed or expired")
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "credential.revoked", Decision: audit.Info, ActorIdentityID: &p.Identity.ID,
			CredentialID: audit.Value(p.Credential.ID),
		}); err != nil {
			return err
		}
		if name == nil {
			name = str("browser-handoff login")
		}
		issued, err = IssueCredential(ctx, tx, now, Issue{
			IdentityID: p.Identity.ID, Kind: KindCLI, Name: name, ExpiresAt: &expiresAt, ActorIdentityID: &p.Identity.ID,
			Metadata: jsvalue.Object{{Key: "exchangedFromCredentialId", Value: p.Credential.ID}, {Key: "ttlSeconds", Value: ttlSeconds}},
			Client:   client, AuthSessionID: p.Credential.AuthSessionID,
		})
		return err
	})
	return issued, expiresAt, err
}
