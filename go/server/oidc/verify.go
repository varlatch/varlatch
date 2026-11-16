// SPDX-License-Identifier: AGPL-3.0-or-later

package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/varlatch/varlatch/go/lib/whatwg"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// The verifier's bounds (auth/oidc.ts: OIDC_BOUNDS and its constants).
const (
	// JWKSTTL is how long a successful JWKS is kept.
	JWKSTTL = 5 * time.Minute
	// FirstBackoff is how long a failure is kept, doubling on each
	// consecutive failure up to MaxBackoff.
	FirstBackoff = 30 * time.Second
	MaxBackoff   = 10 * time.Minute
	// RefreshInterval bounds the refreshes for a key id no cached key
	// carries: one per issuer per interval.
	RefreshInterval = time.Minute
	// MaxIssuers bounds each cache.
	MaxIssuers = 1000
	// ClockSkew is the leeway on exp and nbf, in seconds.
	ClockSkew = 60
	// FetchTimeout bounds one issuer document's request and body.
	FetchTimeout = 10 * time.Second
)

// VerificationError is OidcVerificationError: a token the verifier refused,
// with the terse reason the exchange's audit event keeps. Issuer marks
// OidcIssuerError, a failure of the issuer's own documents.
type VerificationError struct {
	Message string
	Issuer  bool
	cause   error
}

func (e *VerificationError) Error() string { return e.Message }
func (e *VerificationError) Unwrap() error { return e.cause }

func fail(message string) error { return &VerificationError{Message: message} }

func issuerFail(message string, cause error) error {
	return &VerificationError{Message: message, Issuer: true, cause: cause}
}

// typeError is a JavaScript TypeError the TypeScript verifier would throw
// (a property read of null): not a verification error, so the exchange
// audits it as "verification-error".
type typeError struct{ what string }

func (e *typeError) Error() string { return "TypeError: " + e.what }

// Response is what a Fetcher got: the status, and the body or the error
// reading it.
type Response struct {
	Status  int
	Body    []byte
	BodyErr error
}

// Fetcher is the verifier's fetch: one GET with Accept: application/json,
// no redirect followed, within FetchTimeout (the request and its body).
// An error is the request's (a refusal, a network failure, a redirect).
type Fetcher func(ctx context.Context, url string) (*Response, error)

// ordered is a JavaScript Map's part the caches use: insertion order,
// and a deleted key that is set again goes last.
type ordered[V any] struct {
	keys []string
	m    map[string]V
}

func (o *ordered[V]) get(k string) (V, bool) { v, ok := o.m[k]; return v, ok }

func (o *ordered[V]) del(k string) {
	if _, ok := o.m[k]; !ok {
		return
	}
	delete(o.m, k)
	for i, key := range o.keys {
		if key == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

func (o *ordered[V]) put(k string, v V) {
	if o.m == nil {
		o.m = map[string]V{}
	}
	if _, ok := o.m[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.m[k] = v
}

// bound is bound(): expired entries go, then the oldest, so the map holds
// at most MaxIssuers keys after one insert.
func (o *ordered[V]) bound(expired func(V) bool) {
	kept := o.keys[:0]
	for _, k := range o.keys {
		if expired(o.m[k]) {
			delete(o.m, k)
			continue
		}
		kept = append(kept, k)
	}
	o.keys = kept
	for len(o.keys) >= MaxIssuers {
		delete(o.m, o.keys[0])
		o.keys = o.keys[1:]
	}
}

type cachedJWKS struct {
	fetchedAt int64 // ms
	keys      []any
}

type failure struct {
	until, backoff int64 // ms
}

type flight struct {
	done chan struct{}
	keys []any
	err  error
}

// Verifier is auth/oidc.ts's verifyOidcToken with its bounded issuer
// state (ADR-0057 Decision 7), one per process:
//   - one discovery-and-JWKS operation at a time per issuer, its result
//     shared by concurrent callers, success or failure;
//   - a successful JWKS kept five minutes;
//   - a failure kept 30 seconds, doubling on each consecutive failure up to
//     10 minutes; a success resets it;
//   - a bad token never touches either cache;
//   - a key id no cached key carries refreshes at most once per issuer per
//     minute;
//   - each cache holds at most 1,000 issuers.
type Verifier struct {
	// Fetch gets the issuer's documents (the outbound policy's oidc client).
	Fetch Fetcher
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu          sync.Mutex
	jwks        ordered[cachedJWKS]
	failures    ordered[failure]
	lastRefresh ordered[int64]
	inFlight    map[string]*flight
}

func (v *Verifier) nowMs() int64 {
	if v.Now != nil {
		return v.Now().UnixMilli()
	}
	return time.Now().UnixMilli()
}

// CacheSizes are oidcCacheSizes, for tests.
func (v *Verifier) CacheSizes() (jwks, failures, refreshes, inFlight int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.jwks.keys), len(v.failures.keys), len(v.lastRefresh.keys), len(v.inFlight)
}

// Clear is clearJwksCache: every cached JWKS, failure and refresh record.
func (v *Verifier) Clear() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.jwks, v.failures, v.lastRefresh = ordered[cachedJWKS]{}, ordered[failure]{}, ordered[int64]{}
}

// base64url is Buffer.from(s, "base64url"): either alphabet, characters
// outside both skipped, decoding stops at the first "=", and a last lone
// character is dropped.
func base64url(s string) []byte {
	out := make([]byte, 0, len(s)*3/4)
	var acc uint32
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		var d byte
		switch {
		case c >= 'A' && c <= 'Z':
			d = c - 'A'
		case c >= 'a' && c <= 'z':
			d = c - 'a' + 26
		case c >= '0' && c <= '9':
			d = c - '0' + 52
		case c == '+' || c == '-':
			d = 62
		case c == '/' || c == '_':
			d = 63
		case c == '=':
			i = len(s)
			continue
		default:
			continue
		}
		acc = acc<<6 | uint32(d)
		n++
		if n == 4 {
			out = append(out, byte(acc>>16), byte(acc>>8), byte(acc))
			acc, n = 0, 0
		}
	}
	switch n {
	case 2:
		out = append(out, byte(acc>>4))
	case 3:
		out = append(out, byte(acc>>10), byte(acc>>2))
	}
	return out
}

// decodeUTF8 is Buffer#toString("utf8"), the WHATWG decoder without its BOM
// removal: each maximal subpart of an ill-formed sequence becomes one
// U+FFFD. (lib/contract and server/values keep the same decoder.)
func decodeUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	out := make([]byte, 0, len(b)+8)
	for i := 0; i < len(b); {
		c := b[i]
		if c < 0x80 {
			out = append(out, c)
			i++
			continue
		}
		need, lo, hi := 0, byte(0x80), byte(0xbf)
		switch {
		case c >= 0xc2 && c <= 0xdf:
			need = 1
		case c == 0xe0:
			need, lo = 2, 0xa0
		case c == 0xed:
			need, hi = 2, 0x9f
		case c >= 0xe1 && c <= 0xef:
			need = 2
		case c == 0xf0:
			need, lo = 3, 0x90
		case c == 0xf4:
			need, hi = 3, 0x8f
		case c >= 0xf1 && c <= 0xf3:
			need = 3
		default:
			out = utf8.AppendRune(out, utf8.RuneError)
			i++
			continue
		}
		j := i + 1
		for k := 0; k < need; k++ {
			if j >= len(b) || b[j] < lo || b[j] > hi {
				break
			}
			lo, hi = 0x80, 0xbf
			j++
		}
		if j-i == need+1 {
			out = append(out, b[i:j]...)
		} else {
			out = utf8.AppendRune(out, utf8.RuneError)
		}
		i = j
	}
	return string(out)
}

// parseJSON is JSON.parse of text decoded as Buffer#toString does.
func parseJSON(b []byte) (any, error) {
	return jsvalue.Parse([]byte(decodeUTF8(b)))
}

// prop is a JavaScript property read v.name: undefined (ok false) on a
// primitive or an array, a TypeError on null and undefined.
func prop(v any, name string) (any, bool, error) {
	switch o := v.(type) {
	case nil:
		return nil, false, &typeError{"Cannot read properties of null (reading '" + name + "')"}
	case jsvalue.Object:
		x, ok := o.Get(name)
		return x, ok, nil
	}
	return nil, false, nil
}

func decodeSegment(segment, what string) (any, error) {
	v, err := parseJSON(base64url(segment))
	if err != nil {
		return nil, fail("Malformed token " + what)
	}
	return v, nil
}

// DecodeUnverified is decodeUnverified: an unverified peek at the claims,
// for the binding lookup only.
func DecodeUnverified(token string) (any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fail("Malformed token")
	}
	return decodeSegment(parts[1], "payload")
}

// getJSON is getJson: one issuer document.
func (v *Verifier) getJSON(ctx context.Context, url string) (any, error) {
	res, err := v.Fetch(ctx, url)
	if err != nil {
		return nil, issuerFail("Issuer metadata fetch failed", err)
	}
	if res.Status < 200 || res.Status > 299 {
		return nil, issuerFail(fmt.Sprintf("Issuer metadata fetch failed (%d)", res.Status), nil)
	}
	if res.BodyErr != nil {
		return nil, issuerFail("Issuer metadata is not JSON", res.BodyErr)
	}
	// Response.json(): UTF-8 decode, a leading BOM removed.
	body := res.Body
	if len(body) >= 3 && body[0] == 0xef && body[1] == 0xbb && body[2] == 0xbf {
		body = body[3:]
	}
	out, err := parseJSON(body)
	if err != nil {
		return nil, issuerFail("Issuer metadata is not JSON", err)
	}
	return out, nil
}

// fetchJWKS is fetchJwks: discovery (its issuer echoed back, RFC 8414
// section 3.3), then the https jwks_uri's keys.
func (v *Verifier) fetchJWKS(ctx context.Context, issuer string) ([]any, error) {
	config, err := v.getJSON(ctx, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	iss, _, err := prop(config, "issuer")
	if err != nil {
		return nil, err
	}
	if s, ok := iss.(string); !ok || s != issuer {
		return nil, issuerFail("Issuer metadata mismatch", nil)
	}
	uri, _, _ := prop(config, "jwks_uri")
	raw, ok := uri.(string)
	if !ok {
		return nil, issuerFail("Issuer metadata missing jwks_uri", nil)
	}
	u, ok := whatwg.ParseURL(raw)
	if !ok {
		return nil, issuerFail("Issuer jwks_uri is not a URL", nil)
	}
	if u.Protocol != "https:" {
		return nil, issuerFail("Issuer jwks_uri is not https", nil)
	}
	jwks, err := v.getJSON(ctx, href(u))
	if err != nil {
		return nil, err
	}
	keysV, _, err := prop(jwks, "keys")
	if err != nil {
		return nil, err
	}
	keys, _ := keysV.([]any)
	if len(keys) == 0 {
		return nil, issuerFail("Issuer JWKS is empty", nil)
	}
	return keys, nil
}

// href is the URL's serialization (URL#toString), which fetch parses again.
func href(u whatwg.URL) string {
	out := u.Protocol + "//"
	if u.Username != "" || u.Password != "" {
		out += u.Username
		if u.Password != "" {
			out += ":" + u.Password
		}
		out += "@"
	}
	path, query := u.RequestTarget()
	out += u.Host + path
	if u.Search != "" {
		out += "?" + query
	}
	return out + u.Hash
}

// sharedFetch is sharedFetch: the one discovery-and-JWKS operation for an
// issuer, which records its success or failure. The caller holds v.mu;
// it is released while the operation runs.
func (v *Verifier) sharedFetch(issuer string) ([]any, error) {
	if f := v.inFlight[issuer]; f != nil {
		return v.wait(f)
	}
	f := &flight{done: make(chan struct{})}
	if v.inFlight == nil {
		v.inFlight = map[string]*flight{}
	}
	v.inFlight[issuer] = f
	v.mu.Unlock()
	// Shared by every caller, so no caller's context ends it: each request
	// is bounded by FetchTimeout.
	keys, err := v.fetchJWKS(context.Background(), issuer)
	v.mu.Lock()
	now := v.nowMs()
	if err == nil {
		v.failures.del(issuer)
		v.jwks.del(issuer)
		v.jwks.bound(func(c cachedJWKS) bool { return now-c.fetchedAt >= JWKSTTL.Milliseconds() })
		v.jwks.put(issuer, cachedJWKS{fetchedAt: now, keys: keys})
	} else {
		backoff := FirstBackoff.Milliseconds()
		if prev, ok := v.failures.get(issuer); ok {
			backoff = min(prev.backoff*2, MaxBackoff.Milliseconds())
		}
		v.failures.del(issuer)
		v.failures.bound(func(f failure) bool { return now >= f.until+MaxBackoff.Milliseconds() })
		v.failures.put(issuer, failure{until: now + backoff, backoff: backoff})
	}
	delete(v.inFlight, issuer)
	f.keys, f.err = keys, err
	close(f.done)
	return keys, err
}

// wait waits for another caller's operation. The caller holds v.mu; it is
// released while waiting and held again after.
func (v *Verifier) wait(f *flight) ([]any, error) {
	v.mu.Unlock()
	<-f.done
	v.mu.Lock()
	return f.keys, f.err
}

// jwksFor is jwksFor. The caller holds v.mu.
func (v *Verifier) jwksFor(issuer string) ([]any, error) {
	now := v.nowMs()
	if c, ok := v.jwks.get(issuer); ok && now-c.fetchedAt < JWKSTTL.Milliseconds() {
		return c.keys, nil
	}
	if f, ok := v.failures.get(issuer); ok && now < f.until {
		return nil, issuerFail("Issuer temporarily unavailable", nil)
	}
	return v.sharedFetch(issuer)
}

// refreshForUnknownKey is refreshForUnknownKey: one refresh for a key id no
// cached key carries, at most once per issuer per interval; nil keys and
// no error when the interval has not passed or the issuer is backing off.
// The caller holds v.mu.
func (v *Verifier) refreshForUnknownKey(issuer string) ([]any, error) {
	if f := v.inFlight[issuer]; f != nil {
		return v.wait(f)
	}
	now := v.nowMs()
	if last, ok := v.lastRefresh.get(issuer); ok && now-last < RefreshInterval.Milliseconds() {
		return nil, nil
	}
	if f, ok := v.failures.get(issuer); ok && now < f.until {
		return nil, nil
	}
	v.lastRefresh.del(issuer)
	v.lastRefresh.bound(func(at int64) bool { return now-at >= RefreshInterval.Milliseconds() })
	v.lastRefresh.put(issuer, now)
	return v.sharedFetch(issuer)
}

// truthy is JavaScript's truthiness of a JSON value.
func truthy(x any, present bool) bool {
	if !present {
		return false
	}
	switch t := x.(type) {
	case nil:
		return false
	case bool:
		return t
	case float64:
		return t != 0
	case string:
		return t != ""
	}
	return true
}

// strictEqual is === between two JSON values parsed apart: objects and
// arrays are never the same object.
func strictEqual(a any, aOK bool, b any, bOK bool) bool {
	if !aOK || !bOK {
		return !aOK && !bOK
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	}
	return false
}

// candidates is candidates: the keys of the algorithm's type whose kid
// matches when both have one. A null key is the TypeScript filter's
// TypeError.
func candidates(alg string, kid any, kidOK bool, keys []any) ([]jsvalue.Object, error) {
	kty := "EC"
	if alg == "RS256" {
		kty = "RSA"
	}
	var out []jsvalue.Object
	for _, k := range keys {
		ktyV, _, err := prop(k, "kty")
		if err != nil {
			return nil, err
		}
		o, isObject := k.(jsvalue.Object)
		if s, ok := ktyV.(string); !ok || s != kty || !isObject {
			continue
		}
		kk, kkOK := o.Get("kid")
		if !truthy(kid, kidOK) || !truthy(kk, kkOK) || strictEqual(kk, kkOK, kid, kidOK) {
			out = append(out, o)
		}
	}
	return out, nil
}

// publicKey is createPublicKey({ key: jwk, format: "jwk" }): the members a
// public key is made of, through go-jose's JWK parsing; nil when the key
// is unusable.
func publicKey(o jsvalue.Object) crypto.PublicKey {
	member := jsvalue.Object{}
	for _, name := range []string{"kty", "crv", "n", "e", "x", "y"} {
		if v, ok := o.Get(name); ok {
			member = append(member, jsvalue.Member{Key: name, Value: v})
		}
	}
	var k jose.JSONWebKey
	if err := json.Unmarshal(jsvalue.Stringify(member), &k); err != nil || !k.Valid() || !k.IsPublic() {
		return nil
	}
	return k.Key
}

// verifySignature is verifySignature: any candidate's key verifies the
// signature (RS256: RSASSA-PKCS1-v1_5; ES256: ECDSA, r and s concatenated).
func verifySignature(alg string, keys []jsvalue.Object, signingInput, signature []byte) bool {
	digest := sha256.Sum256(signingInput)
	for _, o := range keys {
		switch pub := publicKey(o).(type) {
		case *rsa.PublicKey:
			if alg == "RS256" && rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature) == nil {
				return true
			}
		case *ecdsa.PublicKey:
			size := (pub.Curve.Params().BitSize + 7) / 8
			if alg == "ES256" && len(signature) == 2*size {
				r := new(big.Int).SetBytes(signature[:size])
				s := new(big.Int).SetBytes(signature[size:])
				if ecdsa.Verify(pub, digest[:], r, s) {
					return true
				}
			}
		}
	}
	return false
}

// Verify is verifyOidcToken: the signature, issuer and clock validity of a
// compact JWS against the expected issuer's JWKS. The verified claims;
// a *VerificationError with a terse reason, or another error the exchange
// audits as "verification-error".
func (v *Verifier) Verify(token, expectedIssuer string) (jsvalue.Object, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fail("Malformed token")
	}
	header, err := decodeSegment(parts[0], "header")
	if err != nil {
		return nil, err
	}
	algV, _, err := prop(header, "alg")
	if err != nil {
		return nil, err
	}
	alg, _ := algV.(string)
	if alg != "RS256" && alg != "ES256" {
		return nil, fail("Unsupported algorithm")
	}
	kid, kidOK, _ := prop(header, "kid")
	claimsV, err := decodeSegment(parts[1], "payload")
	if err != nil {
		return nil, err
	}
	iss, _, err := prop(claimsV, "iss")
	if err != nil {
		return nil, err
	}
	if s, ok := iss.(string); !ok || s != expectedIssuer {
		return nil, fail("Issuer mismatch")
	}
	claims := claimsV.(jsvalue.Object)
	if sub, _ := claims.Get("sub"); func() bool { s, ok := sub.(string); return !ok || s == "" }() {
		return nil, fail("Missing sub")
	}
	now := float64(v.nowMs() / 1000)
	if exp, ok := numberClaim(claims, "exp"); !ok || exp <= now-ClockSkew {
		return nil, fail("Token expired")
	}
	if nbf, ok := numberClaim(claims, "nbf"); ok && nbf > now+ClockSkew {
		return nil, fail("Token not yet valid")
	}

	v.mu.Lock()
	keys, err := v.jwksFor(expectedIssuer)
	if err != nil {
		v.mu.Unlock()
		return nil, err
	}
	found, err := candidates(alg, kid, kidOK, keys)
	if err != nil {
		v.mu.Unlock()
		return nil, err
	}
	if len(found) == 0 {
		// A key id no cached key carries: perhaps a rotation. One bounded refresh.
		refreshed, err := v.refreshForUnknownKey(expectedIssuer)
		if err != nil {
			v.mu.Unlock()
			return nil, err
		}
		if refreshed != nil {
			keys = refreshed
		}
		if found, err = candidates(alg, kid, kidOK, keys); err != nil {
			v.mu.Unlock()
			return nil, err
		}
		if len(found) == 0 {
			v.mu.Unlock()
			return nil, fail("Unknown signing key")
		}
	}
	v.mu.Unlock()
	if !verifySignature(alg, found, []byte(parts[0]+"."+parts[1]), base64url(parts[2])) {
		return nil, fail("Signature verification failed")
	}
	return claims, nil
}

func numberClaim(o jsvalue.Object, name string) (float64, bool) {
	v, _ := o.Get(name)
	f, ok := v.(float64)
	return f, ok
}

// IsVerification reports whether err is the verifier's own refusal (its
// message is the audit reason).
func IsVerification(err error) (string, bool) {
	var ve *VerificationError
	if errors.As(err, &ve) {
		return ve.Message, true
	}
	return "", false
}
