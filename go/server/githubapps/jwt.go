// SPDX-License-Identifier: AGPL-3.0-or-later

package githubapps

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	vsync "github.com/varlatch/varlatch/go/lib/sync"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
)

// The App's own requests to GitHub (ADR-0047 Decision 3, githubjwt.ts): a
// JWT signed with the App's private key (RS256), and what a refusal of it
// establishes.

// GitHubAPI is GITHUB_API.
const GitHubAPI = "https://api.github.com"

// GitHubTimeout is GITHUB_TIMEOUT_MS.
const GitHubTimeout = 10 * time.Second

// setGitHubHeaders sets GITHUB_HEADERS.
func setGitHubHeaders(h http.Header) {
	h.Set("Accept", "application/vnd.github+json")
	h.Set("X-GitHub-Api-Version", "2022-11-28")
	h.Set("User-Agent", "varlatch")
}

// Claims are a JWT's time claims, in seconds.
type Claims struct{ Iat, Exp int64 }

// AppJWTClaims is appJwtClaims: iat 60 s back for clock skew, exp 9
// minutes ahead (exp - iat is GitHub's 10-minute limit).
func AppJWTClaims(now time.Time) Claims {
	seconds := int64(math.Floor(float64(now.UnixMilli()) / 1000))
	return Claims{Iat: seconds - 60, Exp: seconds + 540}
}

// ParseRSAKey is createPrivateKey for an RSA key in PEM, as GitHub issues
// them (PKCS #1) or in PKCS #8; nil for anything else.
func ParseRSAKey(text string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil
		}
		return k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil
		}
		rk, _ := k.(*rsa.PrivateKey)
		return rk
	}
	return nil
}

// IsRSAKey is isRsaKey.
func IsRSAKey(text string) bool { return ParseRSAKey(text) != nil }

// SignAppJWT is signAppJwt: issuer is the client id, as GitHub recommends,
// or the App id when only that is known (import).
func SignAppJWT(issuer string, key *rsa.PrivateKey, now time.Time) (string, Claims, error) {
	c := AppJWTClaims(now)
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := enc.EncodeToString(jsvalue.Stringify(jsvalue.Object{{Key: "iat", Value: c.Iat}, {Key: "exp", Value: c.Exp}, {Key: "iss", Value: issuer}}))
	digest := sha256.Sum256([]byte(header + "." + payload))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", c, err
	}
	return header + "." + payload + "." + enc.EncodeToString(sig), c, nil
}

// ReadJWTRefusal is readJwtRefusal: a JWT GitHub refused (401), read as
// only the evidence allows: the JWT's own time claims judged against
// GitHub's Date header by GitHub's rules. Valid at GitHub's time: the key
// is the reason. Invalid: the clock is reason enough. No usable Date: both
// are named. GitHub's message text is never read.
func ReadJWTRefusal(res *http.Response, c Claims) vsync.AccessCheck {
	theirs, err := http.ParseTime(res.Header.Get("Date"))
	if err != nil {
		return vsync.AccessCheck{Status: vsync.StatusFailed, Where: vsync.WhereConnection, HTTPStatus: res.StatusCode,
			Message: "GitHub refused the App's signed request. Its key may have been deleted on GitHub, or this server's clock may be off; Varlatch cannot tell which."}
	}
	at := theirs.Unix()
	if c.Iat <= at && c.Exp > at && c.Exp <= at+600 {
		return vsync.AccessCheck{Status: vsync.StatusCredentialRejected, Where: vsync.WhereConnection, HTTPStatus: res.StatusCode,
			Message: "GitHub refused the App's key, though the request was valid at GitHub's time: the key was deleted on GitHub, or belongs to another App."}
	}
	diff := c.Iat + 60 - at
	off := int64(math.Max(1, math.Round(math.Abs(float64(diff))/60)))
	direction := "behind"
	if diff > 0 {
		direction = "ahead of"
	}
	unit := "minutes"
	if off == 1 {
		unit = "minute"
	}
	return vsync.AccessCheck{Status: vsync.StatusFailed, Where: vsync.WhereConnection, HTTPStatus: res.StatusCode,
		Message: fmt.Sprintf("This server's clock is about %d %s %s GitHub's, which is enough for GitHub to refuse the App's signed requests. Set the clock right, then try again: until then, Varlatch cannot tell whether GitHub also refuses the key.", off, unit, direction)}
}

// GitHubUnreachable is GITHUB_UNREACHABLE, in the outbound policy's words
// when the policy refused the request (githubUnreachable).
func GitHubUnreachable(refusal *outbound.RefusedError) vsync.AccessCheck {
	c := vsync.AccessCheck{Status: vsync.StatusUnreachable, Where: vsync.WhereConnection,
		Message: "Varlatch could not reach api.github.com. Check that this server can reach it, then try again."}
	if refusal != nil {
		c.Message = refusal.Error()
	}
	return c
}

// NotGitHub is NOT_GITHUB.
func NotGitHub(status int) vsync.AccessCheck {
	return vsync.AccessCheck{Status: vsync.StatusFailed, Where: vsync.WhereConnection, HTTPStatus: status,
		Message: "The answer from api.github.com was not GitHub's. A proxy between this server and GitHub may be in the way."}
}

// answer is a response read whole: GitHub's answers are small.
type answer struct {
	status int
	header http.Header
	body   []byte
}

func (a *answer) json() (any, bool) {
	v, err := jsvalue.Parse(a.body)
	return v, err == nil
}

// asResponse is enough of an http.Response for ReadJWTRefusal.
func (a *answer) asResponse() *http.Response {
	return &http.Response{StatusCode: a.status, Header: a.header}
}

// do sends req with GitHub's timeout; a nil answer is no answer (the
// error says why, an outbound refusal among them).
func do(c *http.Client, req *http.Request) (*answer, error) {
	ctx, cancel := context.WithTimeout(req.Context(), GitHubTimeout)
	defer cancel()
	res, err := c.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return &answer{status: res.StatusCode, header: res.Header, body: body}, nil
}

// AppRequest is appRequest: a request signed as the App. No answer is a
// nil answer, with the outbound policy's refusal when it refused it.
func AppRequest(ctx context.Context, c *http.Client, method, path, issuer string, key *rsa.PrivateKey, now time.Time, body []byte) (*answer, Claims, *outbound.RefusedError, error) {
	jwt, claims, err := SignAppJWT(issuer, key, now)
	if err != nil {
		return nil, claims, nil, err
	}
	var rd io.Reader
	if body != nil {
		rd = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, GitHubAPI+path, rd)
	if err != nil {
		return nil, claims, nil, err
	}
	setGitHubHeaders(req.Header)
	req.Header.Set("Authorization", "Bearer "+jwt)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	a, err := do(c, req)
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, claims, nil, ctx.Err()
		}
		return nil, claims, outbound.RefusalOf(err), nil
	}
	return a, claims, nil, nil
}

// safeInt is Number.isSafeInteger(v) && v > 0 for a parsed JSON number.
func safeInt(v any) (int64, bool) {
	f, ok := v.(float64)
	if !ok || f != math.Trunc(f) || f <= 0 || f > 9007199254740991 {
		return 0, false
	}
	return int64(f), true
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
