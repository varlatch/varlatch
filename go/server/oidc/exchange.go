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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/write"
)

// The exchanged credential's lifetime, in seconds.
const (
	DefaultTTL = 600
	MaxTTL     = 3600
)

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
}

// JS is the answer as the API gives it.
func (i Issued) JS() jsvalue.Object {
	return jsvalue.Object{
		{Key: "id", Value: i.CredentialID}, {Key: "token", Value: i.Token}, {Key: "expiresAt", Value: audit.ISOTime(i.ExpiresAt)},
		{Key: "identityId", Value: i.IdentityID},
	}
}

// reject is reject: every failure answers alike; the audit event has the
// reason.
func (s *Service) reject(ctx context.Context, reason, requestID string) error {
	var rid *string
	if requestID != "" {
		rid = &requestID
	}
	if err := s.Writer.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Type: "authentication.failed", Decision: audit.Deny, RequestID: rid,
			Metadata: jsvalue.Object{{Key: "method", Value: "oidc"}, {Key: "reason", Value: reason}},
		})
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
	for _, b := range bindings {
		var extra jsvalue.Object
		if b.Claims.Valid {
			v, err := jsvalue.Parse([]byte(b.Claims.String))
			if err != nil {
				return Issued{}, err
			}
			extra, _ = v.(jsvalue.Object)
		}
		if Matches(claims, b.Audience, b.Subject, extra) {
			matched = append(matched, b)
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
	b := matched[0]
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
		name, err := write.Text("oidc:" + utf16Prefix(subject, 180))
		if err != nil {
			return err
		}
		org := b.OrganizationID
		issued, err := auth.IssueCredential(ctx, tx, s.now().UnixMicro(), auth.Issue{
			IdentityID: b.IdentityID, Kind: auth.KindOIDC, Name: &name, ExpiresAt: &expires, ActorIdentityID: &b.IdentityID,
			OrganizationID: &org,
			Metadata: jsvalue.Object{{Key: "method", Value: "oidc"}, {Key: "oidcBindingId", Value: b.ID}, {Key: "issuer", Value: b.Issuer},
				{Key: "subject", Value: subject}},
		})
		if err != nil {
			return err
		}
		out = Issued{CredentialID: issued.CredentialID, Token: issued.Token, IdentityID: b.IdentityID, ExpiresAt: expires}
		return nil
	})
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
