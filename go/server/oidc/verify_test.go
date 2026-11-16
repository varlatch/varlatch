// SPDX-License-Identifier: AGPL-3.0-or-later

package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// signed is an RS256 token of claims by key, kid k1.
func signed(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "k1"})
	p, _ := json.Marshal(claims)
	input := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + enc.EncodeToString(sig)
}

func jwkOf(pub *rsa.PublicKey) map[string]any {
	enc := base64.RawURLEncoding
	return map[string]any{"kty": "RSA", "kid": "k1", "n": enc.EncodeToString(pub.N.Bytes()), "e": enc.EncodeToString(big.NewInt(int64(pub.E)).Bytes())}
}

// issuerFetch answers discovery and the JWKS for any issuer, counting the
// fetches; release, when set, holds each answer until it is closed.
func issuerFetch(pub *rsa.PublicKey, discovery, jwks *atomic.Int64, release chan struct{}, fail bool) Fetcher {
	return func(_ context.Context, url string) (*Response, error) {
		if release != nil {
			<-release
		}
		const suffix = "/.well-known/openid-configuration"
		if len(url) > len(suffix) && url[len(url)-len(suffix):] == suffix {
			discovery.Add(1)
			if fail {
				return &Response{Status: 503}, nil
			}
			iss := url[:len(url)-len(suffix)]
			b, _ := json.Marshal(map[string]any{"issuer": iss, "jwks_uri": iss + "/jwks"})
			return &Response{Status: 200, Body: b}, nil
		}
		jwks.Add(1)
		b, _ := json.Marshal(map[string]any{"keys": []any{jwkOf(pub)}})
		return &Response{Status: 200, Body: b}, nil
	}
}

// One discovery and one JWKS fetch for 100 concurrent verifications of
// one issuer, all with the same result; the same for a failing issuer.
func TestConcurrentVerificationsShareOneFetch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const iss = "https://ci.example"
	token := signed(t, key, map[string]any{"iss": iss, "sub": "s", "exp": time.Now().Unix() + 300})
	for _, fail := range []bool{false, true} {
		var discovery, jwks atomic.Int64
		release := make(chan struct{})
		v := &Verifier{Fetch: issuerFetch(&key.PublicKey, &discovery, &jwks, release, fail)}
		var wg sync.WaitGroup
		errs := make([]error, 100)
		for i := range errs {
			wg.Add(1)
			go func() { defer wg.Done(); _, errs[i] = v.Verify(token, iss) }()
		}
		time.Sleep(50 * time.Millisecond)
		close(release)
		wg.Wait()
		for i, err := range errs {
			if (err != nil) != fail {
				t.Fatalf("fail=%v: verification %d: %v", fail, i, err)
			}
		}
		wantJWKS := int64(1)
		if fail {
			wantJWKS = 0
		}
		if discovery.Load() != 1 || jwks.Load() != wantJWKS {
			t.Errorf("fail=%v: %d discovery, %d JWKS fetches", fail, discovery.Load(), jwks.Load())
		}
		if _, _, _, inFlight := v.CacheSizes(); inFlight != 0 {
			t.Errorf("%d operations left in flight", inFlight)
		}
	}
}

// Each cache holds at most 1,000 issuers: the oldest go first, and
// expired entries before them.
func TestCachesStayWithinTheirBound(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	var discovery, jwks atomic.Int64
	ok := &Verifier{Now: func() time.Time { return now }, Fetch: issuerFetch(&key.PublicKey, &discovery, &jwks, nil, false)}
	bad := &Verifier{Now: func() time.Time { return now }, Fetch: issuerFetch(&key.PublicKey, &discovery, &jwks, nil, true)}
	for i := range MaxIssuers + 200 {
		iss := fmt.Sprintf("https://ci%d.example", i)
		token := signed(t, key, map[string]any{"iss": iss, "sub": "s", "exp": now.Unix() + 300})
		if _, err := ok.Verify(token, iss); err != nil {
			t.Fatal(err)
		}
		if _, err := bad.Verify(token, iss); err == nil {
			t.Fatal("a failing issuer verified")
		}
	}
	if n, _, _, _ := ok.CacheSizes(); n != MaxIssuers {
		t.Errorf("%d JWKS cached", n)
	}
	if _, n, _, _ := bad.CacheSizes(); n != MaxIssuers {
		t.Errorf("%d failures kept", n)
	}
	// The first issuer was dropped: verifying it fetches again.
	before := discovery.Load()
	iss := "https://ci0.example"
	if _, err := ok.Verify(signed(t, key, map[string]any{"iss": iss, "sub": "s", "exp": now.Unix() + 300}), iss); err != nil || discovery.Load() != before+1 {
		t.Errorf("the oldest issuer: %v, %d fetches", err, discovery.Load()-before)
	}
	// Once every JWKS expired, one insert drops them all.
	now = now.Add(JWKSTTL)
	iss = "https://late.example"
	if _, err := ok.Verify(signed(t, key, map[string]any{"iss": iss, "sub": "s", "exp": now.Unix() + 300}), iss); err != nil {
		t.Fatal(err)
	}
	if n, _, _, _ := ok.CacheSizes(); n != 1 {
		t.Errorf("%d JWKS cached after they expired", n)
	}
}
