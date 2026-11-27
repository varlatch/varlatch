// SPDX-License-Identifier: AGPL-3.0-or-later

// Package oidc is OIDC workload identity (domain/oidc.ts, auth/oidc.ts;
// ADR-0059 step 4.8): a workload exchanges a token its platform issued
// for a short-lived oidc credential of the machine identity a binding
// names (identities.CreateOIDCBinding). The token is verified against the
// issuer's published keys, fetched through the outbound policy within the
// verifier's bounds; every failure answers alike (INVALID_CREDENTIAL), and
// only the audit event tells them apart.
package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/oidc/limits"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/write"
)

// The exchanged credential's lifetime, in seconds.
const (
	DefaultTTL = 600
	MaxTTL     = 3600
)

// MaxSingleExchangeLifetime bounds, in seconds, how long a token exchanged
// once may still be valid: its use is kept until the token itself is no
// longer accepted, so this bounds what is kept.
const MaxSingleExchangeLifetime = 24 * 60 * 60

// useKept is how much longer than the token's acceptance (its exp and
// ClockSkew) its use is kept, in seconds: while the host's clock is ahead,
// exchanges prune what is still needed once it is set back.
const useKept = 26 * 60 * 60

// PolicyFetcher is the verifier's fetch through the outbound policy's oidc
// client (ADR-0057): every connection checked as it opens, no redirect
// followed, the request and its body within FetchTimeout.
func PolicyFetcher(policy *outbound.Policy) Fetcher {
	client := policy.Client(outbound.OIDC)
	return func(ctx context.Context, raw string) (*Response, error) {
		ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
		defer cancel()
		u, ok := outbound.RequestURL(raw)
		if !ok {
			return nil, fmt.Errorf("fetch: %s cannot be requested", raw)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.URL = u
		req.Header.Set("Accept", "application/json")
		res, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		body, bodyErr := io.ReadAll(res.Body)
		return &Response{Status: res.StatusCode, Body: body, BodyErr: bodyErr}, nil
	}
}

// Service is the exchange.
type Service struct {
	Writer   *write.Writer
	Policy   *outbound.Policy
	Verifier *Verifier
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	Log *slog.Logger
}

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

// Issued is the exchange's answer.
type Issued struct {
	CredentialID, Token, IdentityID string
	// ExpiresAt in microseconds (a millisecond time).
	ExpiresAt int64
	// ExerciseOnly is what limits the credential, nil for nothing.
	ExerciseOnly *auth.ExerciseOnly
}

// JS is the answer as the API gives it.
func (i Issued) JS() jsvalue.Object {
	o := jsvalue.Object{
		{Key: "id", Value: i.CredentialID}, {Key: "token", Value: i.Token}, {Key: "expiresAt", Value: audit.ISOTime(i.ExpiresAt)},
		{Key: "identityId", Value: i.IdentityID},
	}
	if x := i.ExerciseOnly; x != nil {
		o = append(o, jsvalue.Member{Key: "exerciseOnly", Value: true})
		if x.RunID != nil {
			o = append(o, jsvalue.Member{Key: "runId", Value: *x.RunID})
		}
	}
	return o
}

// reject is reject: every failure answers alike; the audit event has the
// reason.
func (s *Service) reject(ctx context.Context, reason, requestID string) error {
	return s.rejectFor(ctx, nil, reason, requestID)
}

// rejectFor is reject of a verified token that matched binding b: the event
// names b and its identity, in its Organization, so the people who read
// that Organization's log see a token exchanged again.
func (s *Service) rejectFor(ctx context.Context, b *query.OidcBinding, reason, requestID string) error {
	var rid *string
	if requestID != "" {
		rid = &requestID
	}
	if err := s.Writer.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
		e := audit.Event{
			Type: "authentication.failed", Decision: audit.Deny, RequestID: rid,
			Metadata: jsvalue.Object{{Key: "method", Value: "oidc"}, {Key: "reason", Value: reason}},
		}
		if b != nil {
			org := b.OrganizationID
			e.OrganizationID = &org
			e.Resource = jsvalue.Object{{Key: "identityId", Value: b.IdentityID}, {Key: "oidcBindingId", Value: b.ID}}
		}
		_, err := audit.Record(ctx, tx, e)
		return err
	}); err != nil {
		return err
	}
	return domainerr.New("INVALID_CREDENTIAL", "OIDC token was not accepted")
}

// subjectMatches is subjectMatches: exact, or a prefix when the binding's
// subject ends with "*".
func subjectMatches(pattern, sub string) bool {
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(sub) >= len(prefix) && sub[:len(prefix)] == prefix
	}
	return pattern == sub
}

// audienceMatches is audienceMatches: one of an array's members, or the
// value itself.
func audienceMatches(aud any, expected string) bool {
	if list, ok := aud.([]any); ok {
		for _, a := range list {
			if s, ok := a.(string); ok && s == expected {
				return true
			}
		}
		return false
	}
	s, ok := aud.(string)
	return ok && s == expected
}

// Matches is the exchange's filter of one binding: its audience, its
// subject and each of its extra claims, exactly.
func Matches(claims jsvalue.Object, audience, subject string, extra jsvalue.Object) bool {
	aud, _ := claims.Get("aud")
	sub, _ := claims.Get("sub")
	s, _ := sub.(string)
	if !audienceMatches(aud, audience) || !subjectMatches(subject, s) {
		return false
	}
	for _, m := range extra {
		got, ok := claims.Get(m.Key)
		gs, isString := got.(string)
		want, _ := m.Value.(string)
		if !ok || !isString || gs != want {
			return false
		}
	}
	return true
}

// errTokenUsed is a token exchanged before under a binding that takes each
// once.
var errTokenUsed = errors.New("oidc: the token was exchanged before")

// errBindingGone is a binding the token matched, no longer live when the
// credential is issued.
var errBindingGone = errors.New("oidc: a matched binding is no longer live")

// tokenKey names a verified token among the uses: its issuer and jti, or,
// for one without a jti, its signed part (its signature can be written more
// than one way; what it signs cannot).
func tokenKey(token string, claims jsvalue.Object, issuer string) string {
	h := sha256.New()
	v, _ := claims.Get("jti")
	if jti, ok := v.(string); ok && jti != "" {
		_, _ = io.WriteString(h, "jti\x00"+issuer+"\x00"+jti)
	} else {
		_, _ = io.WriteString(h, "token\x00"+token[:strings.LastIndexByte(token, '.')])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// runIDOf is the run a token is for: the named claim, a string a
// Capability's runId can equal.
func runIDOf(claims jsvalue.Object, name string) (string, bool) {
	v, _ := claims.Get(name)
	s, ok := v.(string)
	if !ok || s == "" || utf16Prefix(s, limits.MaxRunID) != s {
		return "", false
	}
	stored, err := write.Text(s)
	return s, err == nil && stored == s
}

// utf16Prefix is s.slice(0, n): the first n UTF-16 code units of a string
// held as WTF-8 (a surrogate the slice splits stays lone, and the stored
// text makes it U+FFFD, as Node writes it).
func utf16Prefix(s string, n int) string {
	units := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		w := 1
		if r == utf8.RuneError && size == 1 && i+2 < len(s) && s[i] == 0xed && s[i+1] >= 0xa0 && s[i+1] <= 0xbf {
			size = 3 // a lone surrogate's WTF-8 bytes: one unit
		} else if r >= 0x10000 {
			w = 2
		}
		if units+w > n {
			if w == 2 && units < n {
				// The slice keeps the high surrogate alone.
				hi, _ := utf16.EncodeRune(r)
				return s[:i] + string([]byte{0xed, byte(0xa0 | (hi>>6)&0x0f), byte(0x80 | hi&0x3f)})
			}
			return s[:i]
		}
		units += w
		i += size
	}
	return s
}

// Exchange is exchangeOidcToken: the issuer's live bindings in the
// Organization (by id or slug), the token verified against the issuer's
// keys, the bindings it matches, all of one identity; then an oidc
// credential of that identity, issued under its live, held Organization.
// Existence stays hidden: an unknown issuer, no binding and a failed
// verification all answer INVALID_CREDENTIAL. ttl is in seconds, nil for
// the default.
//
// The limits of the bindings matched, all together (ADR-0060): a token
// taken once is recorded in the credential's own job, so an exchange that
// was refused spends nothing and two at once issue one credential; an
// exercise-only credential carries its run.
func (s *Service) Exchange(ctx context.Context, token, organization string, ttl *int64, requestID string) (Issued, error) {
	t := int64(DefaultTTL)
	if ttl != nil {
		t = *ttl
	}
	if t < 1 || t > MaxTTL {
		return Issued{}, domainerr.New("VALIDATION_FAILED", fmt.Sprintf("ttlSeconds must be 1..%d", MaxTTL))
	}
	peek, err := DecodeUnverified(token)
	if err != nil {
		return Issued{}, s.reject(ctx, "malformed", requestID)
	}
	iss, _, err := prop(peek, "iss")
	if err != nil {
		// peek.iss of a null payload: the TypeScript server's TypeError,
		// answered 500 INTERNAL.
		return Issued{}, err
	}
	issuer, _ := iss.(string)
	if err := pgText(issuer, organization); err != nil {
		return Issued{}, err
	}
	bindings, err := query.New(s.Writer.Store.Reader()).ExchangeOidcBindings(ctx, query.ExchangeOidcBindingsParams{Organization: organization, Issuer: issuer})
	if err != nil {
		return Issued{}, err
	}
	if len(bindings) == 0 {
		return Issued{}, s.reject(ctx, "no-binding", requestID)
	}
	first := bindings[0]
	claims, err := s.Verifier.Verify(token, first.Issuer)
	if err != nil {
		// A refused discovery or JWKS fetch is audited for the binding's
		// Organization (ADR-0057 Decision 8, rate bound); the caller sees
		// the generic failure.
		if refusal := outbound.RefusalOf(err); refusal != nil {
			rid := requestID
			if rerr := s.Policy.RecordRefusal(ctx, s.Writer.Store, outbound.RefusalRecord{
				OrganizationID: first.OrganizationID, Purpose: outbound.OIDC, Phase: "connection", Refusal: refusal,
				Resource: jsvalue.Object{{Key: "oidcBindingId", Value: first.ID}}, RequestID: &rid,
			}); rerr != nil {
				s.log().Error("outbound refusal audit failed", "error", rerr)
			}
		}
		reason, ok := IsVerification(err)
		if !ok {
			reason = "verification-error"
		}
		return Issued{}, s.reject(ctx, reason, requestID)
	}
	var matched []query.OidcBinding
	var each []limits.Limits
	// Whether an identity's bindings for the issuer, matching or not, limit
	// (true) or not (false): one entry of each when they are mixed.
	kinds := map[string]map[bool]bool{}
	for _, b := range bindings {
		var extra jsvalue.Object
		if b.Claims.Valid {
			v, err := jsvalue.Parse([]byte(b.Claims.String))
			if err != nil {
				return Issued{}, err
			}
			extra, _ = v.(jsvalue.Object)
		}
		if kinds[b.IdentityID] == nil {
			kinds[b.IdentityID] = map[bool]bool{}
		}
		kinds[b.IdentityID][limits.IsLimited(extra)] = true
		plain, l := limits.Split(extra)
		if Matches(claims, b.Audience, b.Subject, plain) {
			matched, each = append(matched, b), append(each, l)
		}
	}
	if len(matched) == 0 {
		return Issued{}, s.reject(ctx, "no-matching-binding", requestID)
	}
	for _, b := range matched[1:] {
		if b.IdentityID != matched[0].IdentityID {
			return Issued{}, s.reject(ctx, "ambiguous-binding", requestID)
		}
	}
	b, limit := matched[0], each[0]
	// All limited or all unlimited, as CreateOIDCBinding keeps them: an
	// earlier server, which knows no limits, can add an unlimited binding
	// beside a limited one. No token is exchanged then, instead of one
	// without the limits of the other.
	if len(kinds[b.IdentityID]) > 1 {
		return Issued{}, s.rejectFor(ctx, &b, "mixed-bindings", requestID)
	}
	// Every matched binding's limits hold. The credential is the most
	// limited binding's, so its event names the one that says why.
	for i, l := range each[1:] {
		if l.ExerciseOnly && !limit.ExerciseOnly {
			b = matched[i+1]
		}
		combined, ok := limits.Combine(limit, l)
		if !ok {
			return Issued{}, s.rejectFor(ctx, &b, "ambiguous-binding", requestID)
		}
		limit = combined
	}
	var only *auth.ExerciseOnly
	if limit.ExerciseOnly {
		only = &auth.ExerciseOnly{OIDCBindingID: b.ID}
		if limit.RunIDClaim != "" {
			run, ok := runIDOf(claims, limit.RunIDClaim)
			if !ok {
				return Issued{}, s.rejectFor(ctx, &b, "run-id-claim", requestID)
			}
			only.RunID = &run
		}
	}
	var use *query.InsertOidcTokenUseParams
	if limit.SingleExchange {
		exp, _ := numberClaim(claims, "exp")
		at := s.now()
		if exp > float64(at.Unix()+MaxSingleExchangeLifetime) {
			return Issued{}, s.rejectFor(ctx, &b, "token-lifetime", requestID)
		}
		use = &query.InsertOidcTokenUseParams{TokenKey: tokenKey(token, claims, b.Issuer), UsedAt: at.UnixMicro(), ExpiresAt: (int64(exp) + ClockSkew + useKept) * 1_000_000}
	}
	sub, _ := claims.Get("sub")
	subject := sub.(string)
	expires := (s.now().UnixMilli() + t*1000) * 1000
	var out Issued
	// Issued under a live, held Organization (ADR-0051): verification took
	// time, and the Organization may have changed meanwhile.
	gates := []write.Gate{write.Organization(b.OrganizationID, write.Shared), write.Person(b.IdentityID, write.Shared)}
	err = s.Writer.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: b.OrganizationID}); err != nil {
			return err
		}
		q := query.New(tx)
		// The bindings as they are now: one revoked while the token was
		// verified (to be replaced by one that limits, say) gives nothing.
		live, err := q.ExchangeOidcBindings(ctx, query.ExchangeOidcBindingsParams{Organization: b.OrganizationID, Issuer: b.Issuer})
		if err != nil {
			return err
		}
		for _, m := range matched {
			if !slices.ContainsFunc(live, func(l query.OidcBinding) bool { return l.ID == m.ID }) {
				return errBindingGone
			}
		}
		if use != nil {
			if _, err := q.PruneOidcTokenUses(ctx, s.now().UnixMicro()); err != nil {
				return err
			}
			n, err := q.InsertOidcTokenUse(ctx, *use)
			if err != nil {
				return err
			}
			if n == 0 {
				return errTokenUsed
			}
		}
		name, err := write.Text("oidc:" + utf16Prefix(subject, 180))
		if err != nil {
			return err
		}
		org := b.OrganizationID
		issued, err := auth.IssueCredential(ctx, tx, s.now().UnixMicro(), auth.Issue{
			IdentityID: b.IdentityID, Kind: auth.KindOIDC, Name: &name, ExpiresAt: &expires, ActorIdentityID: &b.IdentityID,
			OrganizationID: &org, ExerciseOnly: only,
			Metadata: jsvalue.Object{{Key: "method", Value: "oidc"}, {Key: "oidcBindingId", Value: b.ID}, {Key: "issuer", Value: b.Issuer},
				{Key: "subject", Value: subject}},
		})
		if err != nil {
			return err
		}
		out = Issued{CredentialID: issued.CredentialID, Token: issued.Token, IdentityID: b.IdentityID, ExpiresAt: expires, ExerciseOnly: only}
		return nil
	})
	if errors.Is(err, errBindingGone) {
		return Issued{}, s.rejectFor(ctx, &b, "no-binding", requestID)
	}
	if errors.Is(err, errTokenUsed) {
		return Issued{}, s.rejectFor(ctx, &b, "token-already-exchanged", requestID)
	}
	return out, err
}

// pgText refuses what PostgreSQL refuses in a text parameter: U+0000 fails
// the TypeScript server's binding query, answered 500 INTERNAL.
func pgText(values ...string) error {
	for _, v := range values {
		for i := 0; i < len(v); i++ {
			if v[i] == 0 {
				return write.ErrPostgresText
			}
		}
	}
	return nil
}
