// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Device-authorization sign-in (ADR-0043 Decision 2; domain/
// device-sign-in.ts): RFC 8628 adapted to Varlatch's credentials. A CLI
// requests a pending sign-in and keeps the device code private; a person
// types the user code in the dashboard and approves with a fresh passkey
// assertion; the CLI collects one cli credential for that person. Every
// state change runs in a write job, so decisions and collection are single
// under concurrency.

// Device sign-in limits (DEVICE_SIGN_IN).
const (
	deviceLifetime        = 600 * time.Second
	deviceInterval        = 5
	deviceSlowDown        = 5
	deviceChallengeLife   = 300 * time.Second
	devicePendingPerPeer  = 10
	devicePendingTotal    = 1000
	deviceAttemptWindow   = 600 * time.Second
	DeviceDefaultTTL      = 43_200
	userCodeAlphabet      = "BCDFGHJKLMNPQRSTVWXZ"
	deviceHousekeepingAge = 24 * time.Hour
)

var wrongCodeLimits = map[string]int64{"identity": 5, "peer": 20, "global": 100}

var (
	userCodePattern   = regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{8}$`)
	deviceCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func generateUserCode() string {
	var b strings.Builder
	for range 8 {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(userCodeAlphabet))))
		if err != nil {
			panic(err)
		}
		b.WriteByte(userCodeAlphabet[n.Int64()])
	}
	return b.String()
}

// NormalizeUserCode compares a typed code case-insensitively, the dash and
// spaces optional; "" when it cannot be a code.
func NormalizeUserCode(input string) string {
	code := strings.ToUpper(strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f' || r == '\v' {
			return -1
		}
		return r
	}, input))
	if !userCodePattern.MatchString(code) {
		return ""
	}
	return code
}

// FormatUserCode is a code as shown to people: WDJB-MJHT.
func FormatUserCode(code string) string { return code[:4] + "-" + code[4:] }

// sweepDeviceSignIns is the housekeeping each new request runs: lapsed
// sign-ins become expired (which frees their user codes), and rows a day
// past their expiry go.
func sweepDeviceSignIns(ctx context.Context, q *query.Queries, now int64) error {
	before := now - deviceHousekeepingAge.Microseconds()
	if err := q.ExpireLapsedDeviceSignIns(ctx, now); err != nil {
		return err
	}
	if err := q.DeleteOldDeviceSignInChallenges(ctx, before); err != nil {
		return err
	}
	if err := q.DeleteOldDeviceSignIns(ctx, before); err != nil {
		return err
	}
	return q.DeleteOldDeviceCodeWindows(ctx, before)
}

// DeviceRequest is a started sign-in, for the requesting CLI only.
type DeviceRequest struct {
	ID         string
	DeviceCode string
	UserCode   string
	ExpiresIn  int64
	Interval   int64
}

// RequestDeviceSignIn is POST /v1/auth/device (requestDeviceSignIn): at most
// 10 pending sign-ins per client address and 1000 in all.
func (s *Service) RequestDeviceSignIn(ctx context.Context, ttlSeconds int64, name *string, peer string, userAgent *string, requestID string) (DeviceRequest, error) {
	var out DeviceRequest
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		now := s.micros()
		if err := sweepDeviceSignIns(ctx, q, now); err != nil {
			return err
		}
		counts, err := q.PendingDeviceSignInCounts(ctx, query.PendingDeviceSignInCountsParams{Peer: sql.NullString{String: peer, Valid: true}, Now: now})
		if err != nil {
			return err
		}
		if counts.Peer >= devicePendingPerPeer {
			return &domainerr.Error{Code: "RATE_LIMITED",
				Message: fmt.Sprintf("At most %d sign-ins may be pending from one address; let one complete or expire", devicePendingPerPeer),
				Details: jsvalue.Object{{Key: "cap", Value: "pending-per-client"}}}
		}
		if counts.Total >= devicePendingTotal {
			return &domainerr.Error{Code: "RATE_LIMITED", Message: "Too many sign-ins are pending; try again in a few minutes",
				Details: jsvalue.Object{{Key: "cap", Value: "pending-total"}}}
		}
		id := ids.New(ids.DeviceSignIn)
		deviceCode := randomBase64URL(32)
		var ua sql.NullString
		if userAgent != nil {
			v := *userAgent
			if len(v) > 512 {
				v = truncateUTF16(v, 512)
			}
			ua = sql.NullString{String: v, Valid: true}
		}
		// The user code is unique among pending sign-ins; a collision draws again.
		for range 8 {
			code := generateUserCode()
			taken, err := q.PendingUserCodeTaken(ctx, code)
			if err != nil {
				return err
			}
			if taken > 0 {
				continue
			}
			if err := q.InsertDeviceSignIn(ctx, query.InsertDeviceSignInParams{
				ID: id, DeviceCodeHash: sha256Hex(deviceCode), UserCode: code, RequestedTtl: ttlSeconds, RequestedName: nullStr(name),
				RequesterIp: sql.NullString{String: peer, Valid: true}, RequesterUserAgent: ua, CreatedAt: now,
				ExpiresAt: now + deviceLifetime.Microseconds(), PollInterval: deviceInterval,
			}); err != nil {
				return err
			}
			if err := record(ctx, tx, audit.Event{
				Type: "authentication.device_requested", Decision: audit.Info, RequestID: &requestID,
				Resource: jsvalue.Object{{Key: "deviceSignInId", Value: id}},
				Metadata: jsvalue.Object{{Key: "ttlSeconds", Value: ttlSeconds}},
			}); err != nil {
				return err
			}
			out = DeviceRequest{ID: id, DeviceCode: deviceCode, UserCode: FormatUserCode(code), ExpiresIn: int64(deviceLifetime.Seconds()), Interval: deviceInterval}
			return nil
		}
		return domainerr.New("INTERNAL", "Could not allocate a user code")
	})
	return out, err
}

// truncateUTF16 is JavaScript's slice(0, n) of a string, by UTF-16 units,
// never splitting a character.
func truncateUTF16(s string, n int) string {
	units := 0
	for i, r := range s {
		w := 1
		if r > 0xFFFF {
			w = 2
		}
		if units+w > n {
			return s[:i]
		}
		units += w
	}
	return s
}

// Poll outcomes (PollOutcome).
const (
	PollPending  = "pending"
	PollSlowDown = "slow_down"
	PollDenied   = "denied"
	PollExpired  = "expired"
	PollUnknown  = "unknown"
	PollConsumed = "consumed"
	PollIssued   = "issued"
)

// PollOutcome is a CLI's poll's answer.
type PollOutcome struct {
	Kind         string
	Interval     int64
	CredentialID *string
	Issued       Issued
	ExpiresAt    int64
}

// PollDeviceSignIn is POST /v1/auth/device/token (pollDeviceSignIn):
// collection marks the sign-in consumed and issues the credential in one
// job, so of two concurrent collectors the second sees consumed and gets
// the issued credential's id, never a second credential.
func (s *Service) PollDeviceSignIn(ctx context.Context, deviceCode string, userAgent *string, requestID string) (PollOutcome, error) {
	if !deviceCodePattern.MatchString(deviceCode) {
		return PollOutcome{Kind: PollUnknown}, nil
	}
	var out PollOutcome
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		now := s.micros()
		row, err := q.DeviceSignInByCodeHash(ctx, sha256Hex(deviceCode))
		if errors.Is(err, sql.ErrNoRows) {
			out = PollOutcome{Kind: PollUnknown}
			return nil
		}
		if err != nil {
			return err
		}
		switch row.Status {
		case "consumed":
			out = PollOutcome{Kind: PollConsumed, CredentialID: ptrStr(row.IssuedCredentialID)}
			return nil
		case "denied":
			out = PollOutcome{Kind: PollDenied}
			return nil
		case "expired":
			out = PollOutcome{Kind: PollExpired}
			return nil
		}
		if row.ExpiresAt <= now {
			// Approved but not collected in time yields no credential.
			out = PollOutcome{Kind: PollExpired}
			return q.SetDeviceSignInStatus(ctx, query.SetDeviceSignInStatusParams{Status: "expired", ID: row.ID})
		}
		if row.Status == "pending" {
			if row.LastPolledAt.Valid && row.LastPolledAt.Int64 > now-row.PollInterval*int64(time.Second/time.Microsecond) {
				interval, err := q.SlowDownDeviceSignIn(ctx, query.SlowDownDeviceSignInParams{SlowDown: deviceSlowDown, Now: sql.NullInt64{Int64: now, Valid: true}, ID: row.ID})
				if err != nil {
					return err
				}
				out = PollOutcome{Kind: PollSlowDown, Interval: interval}
				return nil
			}
			out = PollOutcome{Kind: PollPending, Interval: row.PollInterval}
			return q.MarkDeviceSignInPolled(ctx, query.MarkDeviceSignInPolledParams{LastPolledAt: sql.NullInt64{Int64: now, Valid: true}, ID: row.ID})
		}
		// Approved: collect.
		identityID := row.ApprovedByIdentityID.String
		expiresAt := (now/1000 + row.RequestedTtl*1000) * 1000
		name := "device sign-in"
		if row.RequestedName.Valid {
			name = row.RequestedName.String
		}
		var evidence *Evidence
		if row.ApprovalPasskeyID.Valid && row.ApprovalUserVerified.Valid {
			evidence = &Evidence{UserVerified: row.ApprovalUserVerified.Bool, PasskeyID: row.ApprovalPasskeyID.String}
		}
		issued, err := IssueCredential(ctx, tx, now, Issue{
			IdentityID: identityID, Kind: KindCLI, Name: &name, ExpiresAt: &expiresAt, ActorIdentityID: &identityID,
			Metadata: jsvalue.Object{{Key: "deviceSignInId", Value: row.ID}, {Key: "ttlSeconds", Value: row.RequestedTtl}},
			Client:   ClientLabel(userAgent), Evidence: evidence,
		})
		if err != nil {
			return err
		}
		if err := q.ConsumeDeviceSignIn(ctx, query.ConsumeDeviceSignInParams{
			Now: sql.NullInt64{Int64: now, Valid: true}, CredentialID: sql.NullString{String: issued.CredentialID, Valid: true}, ID: row.ID,
		}); err != nil {
			return err
		}
		if err := record(ctx, tx, audit.Event{
			Type: "authentication.device_collected", Decision: audit.Info, ActorIdentityID: &identityID,
			CredentialID: audit.Value(issued.CredentialID), RequestID: &requestID,
			Resource: jsvalue.Object{{Key: "deviceSignInId", Value: row.ID}, {Key: "identityId", Value: identityID}},
		}); err != nil {
			return err
		}
		out = PollOutcome{Kind: PollIssued, Issued: issued, ExpiresAt: expiresAt}
		return nil
	})
	return out, err
}

// PendingSignIn is a pending sign-in as its confirmation shows it.
type PendingSignIn struct {
	ID                 string
	UserCode           string
	RequestedTTL       int64
	RequestedName      *string
	RequesterIP        *string
	RequesterUserAgent *string
	CreatedAt          int64
	ExpiresAt          int64
}

// ErrWrongCode is a code no pending sign-in has.
var ErrWrongCode = domainerr.New("RESOURCE_NOT_FOUND", "No pending sign-in has this code: check the code the CLI shows (it expires after 10 minutes)")

// FindSignInByCode finds the pending sign-in a person typed the code of,
// under the persistent attempt limits: wrong codes count per approving
// identity, per client address and in total; a locked scope refuses even a
// correct code until its window ends (findSignInByCode). A wrong code is
// counted and audited, and committed, before it is refused.
func (s *Service) FindSignInByCode(ctx context.Context, identityID, peer, userCode, requestID string) (PendingSignIn, error) {
	type scoped struct{ scope, key string }
	keys := []scoped{{"global", "all"}, {"identity", identityID}, {"peer", peer}}
	var found *PendingSignIn
	var lockedUntil int64
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		found, lockedUntil = nil, 0
		q := query.New(tx)
		now := s.micros()
		window := deviceAttemptWindow.Microseconds()
		type state struct {
			failures, started int64
		}
		current := map[string]state{}
		for _, k := range keys {
			if err := q.EnsureDeviceCodeWindow(ctx, query.EnsureDeviceCodeWindowParams{Scope: k.scope, Key: k.key, WindowStartedAt: now}); err != nil {
				return err
			}
			w, err := q.DeviceCodeWindow(ctx, query.DeviceCodeWindowParams{Scope: k.scope, Key: k.key})
			if err != nil {
				return err
			}
			current[k.scope] = state{w.Failures, w.WindowStartedAt}
			if w.WindowStartedAt > now-window && w.Failures >= wrongCodeLimits[k.scope] {
				lockedUntil = max(lockedUntil, w.WindowStartedAt+window)
			}
		}
		if lockedUntil > 0 {
			return nil
		}
		if code := NormalizeUserCode(userCode); code != "" {
			row, err := q.PendingDeviceSignInByUserCode(ctx, query.PendingDeviceSignInByUserCodeParams{UserCode: code, Now: now})
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if err == nil {
				found = &PendingSignIn{
					ID: row.ID, UserCode: FormatUserCode(row.UserCode), RequestedTTL: row.RequestedTtl, RequestedName: ptrStr(row.RequestedName),
					RequesterIP: ptrStr(row.RequesterIp), RequesterUserAgent: ptrStr(row.RequesterUserAgent),
					CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt,
				}
				return nil
			}
		}
		// Never the typed code: a near miss of a live code must not reach
		// the audit log.
		if err := record(ctx, tx, audit.Event{
			Type: "authentication.device_code_rejected", Decision: audit.Deny, ActorIdentityID: &identityID, RequestID: &requestID,
		}); err != nil {
			return err
		}
		for _, k := range keys {
			st := current[k.scope]
			failures, started := int64(1), now
			if st.started > now-window {
				failures, started = st.failures+1, st.started
			}
			if err := q.SetDeviceCodeWindow(ctx, query.SetDeviceCodeWindowParams{Failures: failures, WindowStartedAt: started, Scope: k.scope, Key: k.key}); err != nil {
				return err
			}
			if failures == wrongCodeLimits[k.scope] {
				if err := record(ctx, tx, audit.Event{
					Type: "authentication.device_code_locked", Decision: audit.Deny, ActorIdentityID: &identityID, RequestID: &requestID,
					Metadata: jsvalue.Object{{Key: "scope", Value: k.scope}, {Key: "until", Value: ISO(started + window)}},
				}); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return PendingSignIn{}, err
	}
	if lockedUntil > 0 {
		retryAt := ISO(lockedUntil)
		return PendingSignIn{}, &domainerr.Error{Code: "RATE_LIMITED", Message: "Too many wrong codes; code entry is paused until " + retryAt,
			Details: jsvalue.Object{{Key: "retryAt", Value: retryAt}}}
	}
	if found == nil {
		return PendingSignIn{}, ErrWrongCode
	}
	return *found, nil
}

// ApprovalChallenge is issueApprovalChallenge: a fresh challenge for this
// sign-in, person and session, kept server-side; nil when the person has
// no passkey. An earlier unused challenge of the same three is replaced.
// User verification is preferred, as at sign-in: approval records what the
// authenticator did (ADR-0054 Decision 6).
func (s *Service) ApprovalChallenge(ctx context.Context, signInID, identityID, sessionID string) (*RequestOptions, error) {
	if s.rp == nil {
		return nil, errNoPublicURL
	}
	var out *RequestOptions
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		options, err := s.assertionOptions(ctx, tx, identityID, "preferred", nil)
		if err != nil || options == nil {
			out = nil
			return err
		}
		if err := q.DeleteUnusedDeviceSignInChallenges(ctx, query.DeleteUnusedDeviceSignInChallengesParams{
			DeviceSignInID: signInID, IdentityID: identityID, AuthSessionID: sessionID,
		}); err != nil {
			return err
		}
		now := s.micros()
		if err := q.InsertDeviceSignInChallenge(ctx, query.InsertDeviceSignInChallengeParams{
			ID: ids.New(ids.DeviceSignInChallenge), DeviceSignInID: signInID, IdentityID: identityID, AuthSessionID: sessionID,
			Challenge: options.Challenge, CreatedAt: now, ExpiresAt: now + deviceChallengeLife.Microseconds(),
		}); err != nil {
			return err
		}
		out = options
		return nil
	})
	return out, err
}

var errNoLongerPending = domainerr.New("STATE_CHANGED", "This sign-in is no longer pending: it was decided or it expired")

func stillPending(ctx context.Context, q *query.Queries, signInID string, now int64) error {
	row, err := q.DeviceSignIn(ctx, signInID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (row.Status != "pending" || row.ExpiresAt <= now) {
		return errNoLongerPending
	}
	return err
}

// DenyDeviceSignIn is a person's denial (denyDeviceSignIn).
func (s *Service) DenyDeviceSignIn(ctx context.Context, signInID, identityID, requestID string) error {
	return s.store.Write(ctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		now := s.micros()
		if err := stillPending(ctx, q, signInID, now); err != nil {
			return err
		}
		n, err := q.DenyDeviceSignIn(ctx, query.DenyDeviceSignInParams{Now: sql.NullInt64{Int64: now, Valid: true}, ID: signInID})
		if err != nil {
			return err
		}
		if n == 0 {
			return errNoLongerPending
		}
		if err := q.DeleteDeviceSignInChallenges(ctx, signInID); err != nil {
			return err
		}
		return record(ctx, tx, audit.Event{
			Type: "authentication.device_denied", Decision: audit.Info, ActorIdentityID: &identityID, RequestID: &requestID,
			Resource: jsvalue.Object{{Key: "deviceSignInId", Value: signInID}},
		})
	})
}

// ApproveDeviceSignIn is approveDeviceSignIn: in one write job, check the
// sign-in is still pending, consume the challenge (only one issued for this
// sign-in, person and session; unused; unexpired), verify the assertion
// with one of the person's passkeys, and move the sign-in to approved with
// the assertion's evidence for collection to copy onto the credential. A
// refused challenge or assertion stays consumed and is audited.
func (s *Service) ApproveDeviceSignIn(ctx context.Context, signInID, identityID, sessionID string, response json.RawMessage, requestID string) error {
	if s.rp == nil {
		return errNoPublicURL
	}
	challenge := AssertionChallenge(response)
	refusal := ""
	err := s.store.Write(ctx, func(tx *storage.Tx) error {
		refusal = ""
		q := query.New(tx)
		now := s.micros()
		// Decided or expired meanwhile: say so, and leave the challenge and
		// the audit log alone.
		if err := stillPending(ctx, q, signInID, now); err != nil {
			return err
		}
		consumed := false
		if challenge != "" {
			id, err := q.BoundDeviceSignInChallenge(ctx, query.BoundDeviceSignInChallengeParams{
				Challenge: challenge, DeviceSignInID: signInID, IdentityID: identityID, AuthSessionID: sessionID,
			})
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if err == nil {
				n, err := q.ConsumeDeviceSignInChallenge(ctx, query.ConsumeDeviceSignInChallengeParams{Now: sql.NullInt64{Int64: now, Valid: true}, ID: id})
				if err != nil {
					return err
				}
				consumed = n > 0
			}
		}
		var evidence *Evidence
		reason := refusalChallenge
		if consumed {
			var err error
			evidence, reason, err = s.verifyAssertion(ctx, tx, identityID, response, challenge, false, nil)
			if err != nil {
				return err
			}
		}
		if evidence == nil {
			refusal = reason
			return record(ctx, tx, audit.Event{
				Type: "authentication.failed", Decision: audit.Deny, ActorIdentityID: &identityID, RequestID: &requestID,
				Resource: jsvalue.Object{{Key: "deviceSignInId", Value: signInID}},
				Metadata: jsvalue.Object{{Key: "method", Value: "device-approval"}, {Key: "reason", Value: reason}},
			})
		}
		n, err := q.ApproveDeviceSignIn(ctx, query.ApproveDeviceSignInParams{
			IdentityID: sql.NullString{String: identityID, Valid: true}, Now: sql.NullInt64{Int64: now, Valid: true},
			UserVerified: sql.NullBool{Bool: evidence.UserVerified, Valid: true}, PasskeyID: sql.NullString{String: evidence.PasskeyID, Valid: true},
			ID: signInID,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return errNoLongerPending
		}
		return record(ctx, tx, audit.Event{
			Type: "authentication.device_approved", Decision: audit.Info, ActorIdentityID: &identityID,
			AuthenticationMethodID: str("passkey"), RequestID: &requestID,
			Resource: jsvalue.Object{{Key: "deviceSignInId", Value: signInID}},
		})
	})
	if err != nil {
		return err
	}
	switch refusal {
	case "":
		return nil
	case refusalChallenge:
		return domainerr.New("PERMISSION_DENIED", "This passkey confirmation was not issued for this sign-in and session, or it was used or expired; enter the code again")
	default:
		return domainerr.New("PERMISSION_DENIED", "The passkey confirmation could not be verified with one of your passkeys")
	}
}
