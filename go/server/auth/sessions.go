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
)

// Browser sessions (ADR-0059 Decision 6), replacing Better Auth's: a
// session's token is 32 random bytes the browser keeps in an HttpOnly
// cookie, stored only as its SHA-256 (auth_sessions.token_hash). A session
// lasts SessionLifetime and is extended, as Better Auth did, when it is
// used a day or more after its last extension. It ends when its row is
// deleted (sign-out, expiry): the schema's trigger
// session_end_revokes_browser_credentials then revokes its live browser
// bearers in the same statement, with their audit events, and leaves the
// CLI credentials of a browser hand-off alone.
const (
	SessionLifetime = 7 * 24 * time.Hour
	sessionRefresh  = 24 * time.Hour
	// BearerLifetime is the dashboard bearer's: 15 minutes, never past its
	// session's end.
	BearerLifetime = 15 * time.Minute
)

// Session is a live browser session.
type Session struct {
	ID         string
	IdentityID string
	ExpiresAt  int64
}

// SessionOf resolves a session token from the cookie: the live session, or
// nil. A session last extended a day or more ago is extended now.
func (s *Service) SessionOf(ctx context.Context, token string) (*Session, error) {
	if token == "" {
		return nil, nil
	}
	row, err := query.New(s.store.Reader()).SessionByTokenHash(ctx, HashToken(token))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := s.micros()
	if row.ExpiresAt <= now {
		// Ended: deleting the row runs the trigger (its bearers expired
		// with it already; they are never minted past its end).
		err := s.store.Write(ctx, func(tx *storage.Tx) error {
			_, err := query.New(tx).DeleteExpiredAuthSessions(ctx, s.micros())
			return err
		})
		return nil, err
	}
	session := &Session{ID: row.ID, IdentityID: row.IdentityID, ExpiresAt: row.ExpiresAt}
	if now-row.UpdatedAt >= sessionRefresh.Microseconds() {
		expires := now + SessionLifetime.Microseconds()
		if err := s.store.Write(ctx, func(tx *storage.Tx) error {
			return query.New(tx).ExtendAuthSession(ctx, query.ExtendAuthSessionParams{ExpiresAt: expires, UpdatedAt: now, ID: row.ID})
		}); err != nil {
			return nil, err
		}
		session.ExpiresAt = expires
	}
	return session, nil
}

// createSession starts a session for an identity's auth user in the
// caller's write job, with the evidence of the ceremony that created it
// (ADR-0054 Decision 6). It returns the session and its token.
func createSession(ctx context.Context, tx query.DBTX, now int64, userID, ip, userAgent string, evidence sessionEvidence) (string, string, int64, error) {
	q := query.New(tx)
	token := randomBase64URL(32)
	id := ids.New(ids.AuthSession)
	expires := now + SessionLifetime.Microseconds()
	if len(userAgent) > 512 {
		userAgent = userAgent[:512]
	}
	if err := q.InsertAuthSession(ctx, query.InsertAuthSessionParams{
		ID: id, ExpiresAt: expires, TokenHash: HashToken(token), CreatedAt: now, UpdatedAt: now,
		IpAddress: sql.NullString{String: ip, Valid: ip != ""}, UserAgent: sql.NullString{String: userAgent, Valid: userAgent != ""},
		UserID: userID,
	}); err != nil {
		return "", "", 0, err
	}
	if err := q.InsertSessionEvidence(ctx, query.InsertSessionEvidenceParams{
		SessionID: id, Ceremony: evidence.ceremony, UserVerified: evidence.userVerified, PasskeyID: evidence.passkeyID, RecordedAt: now,
	}); err != nil {
		return "", "", 0, err
	}
	// Evidence nothing can use any more: its session ended and no live
	// credential links it (recordSessionEvidence's sweep).
	if err := q.SweepSessionEvidence(ctx, sql.NullInt64{Int64: now, Valid: true}); err != nil {
		return "", "", 0, err
	}
	return id, token, expires, nil
}

type sessionEvidence struct {
	ceremony     string // "sign-in" or "enrollment"
	userVerified bool
	passkeyID    string
}

// EndSession signs a browser out: its session row is deleted, which revokes
// its browser bearers (the trigger). A token with no session does nothing.
func (s *Service) EndSession(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	hash := HashToken(token)
	return s.store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		row, err := q.SessionByTokenHash(ctx, hash)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = q.DeleteAuthSession(ctx, row.ID)
		return err
	})
}

// Bearer is the dashboard's /v1 bearer, minted from its session.
type Bearer struct {
	Token      string
	IdentityID string
	ExpiresAt  int64
}

// MintBearer exchanges a live session for a short-lived opaque browser
// credential (POST /auth/varlatch-token, ADR-0018 §6): 15 minutes, never
// past the session's end, bound to the session so the session's end revokes
// it. The session is checked again in the job that issues it, so a sign-out
// committed before it refuses it, and one after revokes it.
func (s *Service) MintBearer(ctx context.Context, session *Session, client *string) (Bearer, error) {
	var b Bearer
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		now := s.micros()
		end, err := q.LiveSessionOfIdentity(ctx, query.LiveSessionOfIdentityParams{ID: session.ID, IdentityID: session.IdentityID, Now: now})
		if errors.Is(err, sql.ErrNoRows) {
			return domainerr.New("AUTHENTICATION_REQUIRED", "No authenticated session")
		}
		if err != nil {
			return err
		}
		expires := min((now/1000)*1000+BearerLifetime.Microseconds(), (end/1000)*1000)
		issued, err := IssueCredential(ctx, tx, now, Issue{
			IdentityID: session.IdentityID, Kind: KindBrowser, Name: str("dashboard session bearer"), ExpiresAt: &expires,
			ActorIdentityID: &session.IdentityID, Client: client, AuthSessionID: &session.ID,
		})
		if err != nil {
			return err
		}
		b = Bearer{Token: issued.Token, IdentityID: session.IdentityID, ExpiresAt: expires}
		return nil
	})
	return b, err
}

// SignInOptions starts a passkey sign-in with a discoverable credential: no
// credential is named, user verification preferred. The challenge is bound
// to the browser's CSRF cookie (binding).
func (s *Service) SignInOptions(binding string) (RequestOptions, error) {
	if s.rp == nil {
		return RequestOptions{}, errNoPublicURL
	}
	challenge := newChallenge()
	if err := s.ceremonies.put(s.now(), challenge, ceremony{kind: ceremonySignIn, binding: binding}); err != nil {
		return RequestOptions{}, domainerr.New("RATE_LIMITED", "Too many passkey sign-ins are in progress; try again in a minute")
	}
	return s.rp.requestOptions(challenge, "preferred", nil), nil
}

var errNoPublicURL = domainerr.New("RESOURCE_NOT_FOUND", "Passkeys are not available: this server has no public URL")

// ErrPasskeyNotFound is a sign-in with a passkey the server does not hold:
// the browser may forget it (the clients' stale-passkey clean-up).
var ErrPasskeyNotFound = &domainerr.Error{Code: "PASSKEY_NOT_FOUND", Message: "Passkey not found"}

// Started is a session a ceremony started.
type Started struct {
	SessionToken string
	SessionID    string
	IdentityID   string
	ExpiresAt    int64
}

// SignIn verifies a sign-in assertion and starts a session: the challenge
// must be this browser's, unused and unexpired; the passkey is found by its
// credential id; its counter moves forward in the same job (the single
// writer runs concurrent sign-ins of one passkey one after the other, so
// the second is verified against the first's counter and refused).
func (s *Service) SignIn(ctx context.Context, binding string, response json.RawMessage, ip, userAgent string) (Started, error) {
	if s.rp == nil {
		return Started{}, errNoPublicURL
	}
	failed := domainerr.New("INVALID_CREDENTIAL", "The passkey sign-in could not be verified")
	a, err := parseAssertion(response)
	if err != nil {
		return Started{}, failed
	}
	challenge := string(a.parsed.Response.CollectedClientData.Challenge)
	if _, ok := s.ceremonies.take(s.now(), challenge, ceremonySignIn, binding); !ok {
		return Started{}, domainerr.New("INVALID_CREDENTIAL", "This sign-in was not started in this browser, or it was used or expired; start it again")
	}
	var started Started
	err = s.store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		rows, err := q.PasskeyByCredentialID(ctx, a.CredentialID())
		if err != nil {
			return err
		}
		// None, or a credential id two rows share (only from before such
		// registrations were refused): no sign-in.
		if len(rows) != 1 || !rows[0].IdentityID.Valid {
			return ErrPasskeyNotFound
		}
		pk := rows[0]
		counter, verified, err := s.rp.verify(a, challenge, pk.PublicKey, pk.Counter, false)
		if err != nil {
			return failed
		}
		if err := q.AdvancePasskeyCounter(ctx, query.AdvancePasskeyCounterParams{Counter: int64(counter), ID: pk.ID}); err != nil {
			return err
		}
		identity, err := q.GetIdentity(ctx, pk.IdentityID.String)
		if err != nil {
			return err
		}
		if identity.Disabled {
			return domainerr.New("INVALID_CREDENTIAL", "This identity is disabled")
		}
		now := s.micros()
		id, token, expires, err := createSession(ctx, tx, now, pk.UserID, ip, userAgent, sessionEvidence{ceremony: "sign-in", userVerified: verified, passkeyID: pk.ID})
		if err != nil {
			return err
		}
		started = Started{SessionToken: token, SessionID: id, IdentityID: identity.ID, ExpiresAt: expires}
		return nil
	})
	return started, err
}

// RegistrationOptions starts a passkey registration. With a setup token it
// is an enrollment: the grant is checked, not consumed (issue #23), and the
// challenge is bound to the browser's CSRF cookie. Without one it adds a
// passkey to the signed-in person: the challenge is bound to the session.
// The person's passkeys are excluded, so an authenticator holding one is
// not registered twice.
func (s *Service) RegistrationOptions(ctx context.Context, binding string, setupToken string, session *Session) (CreationOptions, error) {
	if s.rp == nil {
		return CreationOptions{}, errNoPublicURL
	}
	c := ceremony{kind: ceremonyRegister, binding: binding}
	var displayName, identityID string
	switch {
	case setupToken != "":
		g, err := s.PeekSetupGrant(ctx, setupToken)
		if err != nil {
			return CreationOptions{}, err
		}
		c.grantToken, c.grantID, displayName = setupToken, g.ID, g.DisplayName
		// The user handle carries the grant id, as Better Auth's provisional
		// user did; a passkey is found by its credential id, never by it.
		c.userHandle = []byte("setup:" + g.ID)
	case session != nil:
		identity, err := query.New(s.store.Reader()).GetIdentity(ctx, session.IdentityID)
		if err != nil {
			return CreationOptions{}, err
		}
		user, err := query.New(s.store.Reader()).AuthUserOfIdentity(ctx, session.IdentityID)
		if err != nil {
			return CreationOptions{}, err
		}
		identityID, displayName = identity.ID, identity.Name
		c.identityID, c.sessionID, c.userHandle = identity.ID, session.ID, []byte(user)
		c.binding = SessionBinding(session.ID)
	default:
		return CreationOptions{}, domainerr.New("AUTHENTICATION_REQUIRED", "Enrollment requires a setup token")
	}
	var exclude []CredentialDescriptor
	if identityID != "" {
		rows, err := query.New(s.store.Reader()).PasskeysOfIdentity(ctx, identityID)
		if err != nil {
			return CreationOptions{}, err
		}
		for _, r := range rows {
			exclude = append(exclude, CredentialDescriptor{ID: r.CredentialID, Type: "public-key", Transports: transportList(r.Transports.String)})
		}
	}
	challenge := newChallenge()
	if err := s.ceremonies.put(s.now(), challenge, c); err != nil {
		return CreationOptions{}, domainerr.New("RATE_LIMITED", "Too many passkey ceremonies are in progress; try again in a minute")
	}
	return s.rp.creationOptions(challenge, c.userHandle, displayName, displayName, exclude), nil
}

// ErrAlreadyRegistered is a registration of a credential id already
// registered, for anyone (WebAuthn §7.1 step 22).
var ErrAlreadyRegistered = &domainerr.Error{Code: "PASSKEY_ALREADY_REGISTERED", Message: "This passkey is already registered"}

// Registration is a passkey registered.
type Registration struct {
	PasskeyID  string
	IdentityID string
	// Session is the session an enrollment started; nil when a signed-in
	// person added the passkey.
	Session *Started
}

// Register verifies a registration and stores the passkey. An enrollment
// consumes its setup grant in the same job, links (or, the first time,
// creates) the person's auth user, records the passkey as trusted by the
// grant's kind, and starts a session with the enrollment's evidence. A
// passkey a signed-in person adds is unconfirmed (ADR-0054 Decision 4).
// A credential id already registered is refused before the grant is
// consumed, and checked again in the job that inserts it.
func (s *Service) Register(ctx context.Context, binding string, session *Session, response json.RawMessage, name, ip, userAgent string) (Registration, error) {
	if s.rp == nil {
		return Registration{}, errNoPublicURL
	}
	failed := domainerr.New("VALIDATION_FAILED", "Registration could not be verified")
	challenge := AssertionChallenge(response)
	if challenge == "" {
		return Registration{}, failed
	}
	// An enrollment's options were bound to the browser's CSRF cookie, an
	// added passkey's to its session.
	bindings := []string{binding}
	if session != nil {
		bindings = append(bindings, SessionBinding(session.ID))
	}
	c, ok := s.ceremonies.take(s.now(), challenge, ceremonyRegister, bindings...)
	if !ok {
		return Registration{}, domainerr.New("VALIDATION_FAILED", "This registration was not started in this browser, or it was used or expired; start it again")
	}
	if c.sessionID != "" && (session == nil || session.ID != c.sessionID) {
		return Registration{}, domainerr.New("AUTHENTICATION_REQUIRED", "No authenticated session")
	}
	reg, err := s.rp.verifyRegistration(response, challenge)
	if err != nil {
		return Registration{}, failed
	}
	if n, err := query.New(s.store.Reader()).CountPasskeysWithCredentialID(ctx, reg.CredentialID); err != nil {
		return Registration{}, err
	} else if n > 0 {
		return Registration{}, ErrAlreadyRegistered
	}
	var out Registration
	rejected := false
	err = s.store.Write(ctx, func(tx *storage.Tx) error {
		rejected = false
		q := query.New(tx)
		now := s.micros()
		// Settled at the insert: a concurrent registration of the same
		// credential id committed first.
		if n, err := q.CountPasskeysWithCredentialID(ctx, reg.CredentialID); err != nil {
			return err
		} else if n > 0 {
			return ErrAlreadyRegistered
		}
		var identityID, userID, grantKind string
		if c.grantToken != "" {
			consumed, ok, err := consumeSetupGrant(ctx, tx, now, c.grantToken, "")
			if err != nil {
				return err
			}
			if !ok {
				rejected = true
				return nil
			}
			if consumed.GrantID != c.grantID {
				return domainerr.New("VALIDATION_FAILED", "Setup token does not match this enrollment")
			}
			identityID, grantKind = consumed.IdentityID, consumed.Kind
			existing, err := q.AuthUserOfIdentity(ctx, identityID)
			switch {
			case err == nil:
				userID = existing
			case errors.Is(err, sql.ErrNoRows):
				// First enrollment: the person's auth user, with a
				// non-routable placeholder email (no SMTP, ever; ADR-0006).
				identity, err := q.GetIdentity(ctx, identityID)
				if err != nil {
					return err
				}
				userID = "bau_" + identityID
				if err := q.InsertAuthUser(ctx, query.InsertAuthUserParams{
					ID: userID, Name: identity.Name, Email: identityID + "@varlatch.placeholder.invalid", CreatedAt: now, UpdatedAt: now,
				}); err != nil {
					return err
				}
				if err := q.LinkAuthUser(ctx, query.LinkAuthUserParams{BetterAuthUserID: userID, IdentityID: identityID}); err != nil {
					return err
				}
				if _, err := audit.Record(ctx, tx, audit.Event{
					Type: "authentication.passkey_enrollment_started", Decision: audit.Info,
					ActorIdentityID: &identityID, AuthenticationMethodID: str("passkey"),
				}); err != nil {
					return err
				}
			default:
				return err
			}
		} else {
			identityID = c.identityID
			u, err := q.AuthUserOfIdentity(ctx, identityID)
			if err != nil {
				return err
			}
			userID = u
		}
		passkeyID := ids.New(ids.Passkey)
		var pkName *string
		if name != "" {
			pkName = &name
		}
		if err := q.InsertPasskey(ctx, query.InsertPasskeyParams{
			ID: passkeyID, Name: nullStr(pkName), PublicKey: reg.PublicKey, UserID: userID, CredentialID: reg.CredentialID,
			Counter: int64(reg.Counter), DeviceType: reg.DeviceType, BackedUp: reg.BackedUp,
			Transports: sql.NullString{String: reg.Transports, Valid: reg.Transports != ""},
			CreatedAt:  sql.NullInt64{Int64: now, Valid: true}, Aaguid: sql.NullString{String: reg.AAGUID, Valid: reg.AAGUID != ""},
		}); err != nil {
			return err
		}
		out = Registration{PasskeyID: passkeyID, IdentityID: identityID}
		if grantKind != "" {
			if err := q.InsertProvenanceTrusted(ctx, query.InsertProvenanceTrustedParams{
				PasskeyID: passkeyID, Now: sql.NullInt64{Int64: now, Valid: true}, SetupGrantKind: sql.NullString{String: grantKind, Valid: true},
			}); err != nil {
				return err
			}
			id, token, expires, err := createSession(ctx, tx, now, userID, ip, userAgent, sessionEvidence{ceremony: "enrollment", userVerified: reg.UserVerified, passkeyID: passkeyID})
			if err != nil {
				return err
			}
			out.Session = &Started{SessionToken: token, SessionID: id, IdentityID: identityID, ExpiresAt: expires}
			return nil
		}
		return q.InsertProvenanceUnconfirmed(ctx, query.InsertProvenanceUnconfirmedParams{PasskeyID: passkeyID, RecordedAt: now})
	})
	if err == nil && rejected {
		return Registration{}, s.rejectSetupGrant(ctx)
	}
	return out, err
}

// auditEvent is a small helper for the jobs here.
func record(ctx context.Context, tx query.DBTX, e audit.Event) error {
	_, err := audit.Record(ctx, tx, e)
	return err
}
