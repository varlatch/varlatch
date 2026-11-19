// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"context"
	"math"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The operations the CLI calls, as the SDK names them. Each slice adds the
// ones its commands call. Answers are JSON values (lib/jsjson), read with
// the CLI's own care for their shape.

// Meta is GET /v1/meta.
func (c *Client) Meta(ctx context.Context) (any, error) {
	return c.Request(ctx, "GET", "/v1/meta", NoBody, nil)
}

// WhoAmI is GET /v1/me: the identity the credential resolves to
// (capability identity.whoami).
func (c *Client) WhoAmI(ctx context.Context) (any, error) {
	return c.Request(ctx, "GET", "/v1/me", NoBody, nil)
}

// ListMyCredentials is GET /v1/me/credentials: the caller's own
// credentials, the one presented marked current.
func (c *Client) ListMyCredentials(ctx context.Context) (any, error) {
	return c.Request(ctx, "GET", "/v1/me/credentials", NoBody, nil)
}

// RevokeMyCredential is DELETE /v1/me/credentials/<id>.
func (c *Client) RevokeMyCredential(ctx context.Context, credentialID string) (any, error) {
	return c.Request(ctx, "DELETE", "/v1/me/credentials/"+EncodeURIComponent(credentialID), NoBody, nil)
}

// EncodeURIComponent is JavaScript's encodeURIComponent for well-formed
// text: every byte of UTF-8 percent-encoded except A-Z a-z 0-9 - _ . ! ~ *
// ' ( ). (A lone surrogate, which JavaScript refuses with a URIError, is
// encoded as U+FFFD; no path segment the CLI builds holds one.)
func EncodeURIComponent(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for _, r := range s {
		for _, c := range []byte(string(r)) {
			if c < 0x80 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-_.!~*'()", c) >= 0) {
				b.WriteByte(c)
				continue
			}
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}

// ListOrganizations is GET /v1/organizations: the Organizations the
// credential can see (login calls it to verify the credential).
func (c *Client) ListOrganizations(ctx context.Context) (any, error) {
	return c.Request(ctx, "GET", "/v1/organizations", NoBody, nil)
}

// ListEnvironments is GET /v1/organizations/<org>/projects/<project>/environments.
func (c *Client) ListEnvironments(ctx context.Context, org, project string) (any, error) {
	return c.Request(ctx, "GET", "/v1/organizations/"+EncodeURIComponent(org)+"/projects/"+EncodeURIComponent(project)+"/environments", NoBody, nil)
}

// ExchangeCliCredential is POST /v1/me/credentials/cli: the short-lived
// browser hand-off bearer (ADR-0024) traded for a longer-lived CLI
// credential; the presenting bearer is revoked.
func (c *Client) ExchangeCliCredential(ctx context.Context, input jsjson.Object) (any, error) {
	return c.Request(ctx, "POST", "/v1/me/credentials/cli", input, nil)
}

// ExchangeOidcToken is POST /v1/oidc/token: unauthenticated, the external
// OIDC token is the proof of identity (capability auth.oidc).
func (c *Client) ExchangeOidcToken(ctx context.Context, input jsjson.Object) (any, error) {
	return c.Request(ctx, "POST", "/v1/oidc/token", input, nil)
}

// GetApproval is GET /v1/me/approvals/<id>: one of the caller's own
// step-up approvals, which the CLI polls while it waits.
func (c *Client) GetApproval(ctx context.Context, approvalID string) (any, error) {
	return c.Request(ctx, "GET", "/v1/me/approvals/"+EncodeURIComponent(approvalID), NoBody, nil)
}

// CancelApproval is POST /v1/me/approvals/<id>/cancel (the CLI on Ctrl-C).
func (c *Client) CancelApproval(ctx context.Context, approvalID string) (any, error) {
	return c.Request(ctx, "POST", "/v1/me/approvals/"+EncodeURIComponent(approvalID)+"/cancel", NoBody, nil)
}

// DeviceSignInRedirectError is a device sign-in request answered with a
// redirect: the device code is a bearer, so its body is never sent on to
// another location. Location is where the server pointed, if anywhere.
type DeviceSignInRedirectError struct {
	Status      int
	Location    string
	HasLocation bool
}

func (e *DeviceSignInRedirectError) Error() string {
	to := ""
	if e.HasLocation && e.Location != "" {
		to = " to " + e.Location
	}
	return "The server answered " + strconv.Itoa(e.Status) + " with a redirect" + to + "; device sign-in follows no redirect"
}

// deviceRequest is the SDK's deviceRequest: one POST, with no credential,
// no maintenance retry and no redirect followed (a redirect is a
// DeviceSignInRedirectError).
func (c *Client) deviceRequest(ctx context.Context, path string, body any) (*Response, error) {
	var list [][2]string
	if c.opts.UserAgent != "" {
		list = append(list, [2]string{"User-Agent", c.opts.UserAgent})
	}
	list = append(list, [2]string{"Content-Type", "application/json"})
	for i, h := range list {
		value, err := headerValue(h[0], h[1])
		if err != nil {
			return nil, err
		}
		list[i][1] = value
	}
	res, err := c.transport.Do(ctx, Request{Method: "POST", URL: c.server + path, Headers: list, Body: jsjson.Stringify(body), Manual: true})
	if err != nil {
		return nil, err
	}
	if res.Status >= 300 && res.Status < 400 {
		location, ok := res.Header("Location")
		return nil, &DeviceSignInRedirectError{Status: res.Status, Location: location, HasLocation: ok}
	}
	return res, nil
}

// StartDeviceSignIn is POST /v1/auth/device: a pending device sign-in.
// Keep its deviceCode private.
func (c *Client) StartDeviceSignIn(ctx context.Context, input jsjson.Object) (any, error) {
	res, err := c.deviceRequest(ctx, "/v1/auth/device", input)
	if err != nil {
		return nil, err
	}
	return finish(res)
}

// DeviceSignInPoll is one poll's outcome: State is issued (Credential),
// pending or slow_down (Interval), denied, expired, or consumed
// (CredentialID, "" when the server named none).
type DeviceSignInPoll struct {
	State        string
	Interval     float64
	Credential   any
	CredentialID string
}

// PollDeviceSignIn is POST /v1/auth/device/token, read as the SDK's
// pollDeviceSignIn reads it.
func (c *Client) PollDeviceSignIn(ctx context.Context, deviceCode string) (DeviceSignInPoll, error) {
	res, err := c.deviceRequest(ctx, "/v1/auth/device/token", jsjson.Object{{Key: "deviceCode", Value: deviceCode}})
	if err != nil {
		return DeviceSignInPoll{}, err
	}
	if res.Status == 201 {
		credential, err := finish(res)
		if err != nil {
			return DeviceSignInPoll{}, err
		}
		return DeviceSignInPoll{State: "issued", Credential: credential}, nil
	}
	if res.Status >= 200 && res.Status <= 299 {
		requestID, ok := res.Header("X-Request-Id")
		if !ok {
			requestID = "unknown"
		}
		return DeviceSignInPoll{}, &APIError{Status: res.Status, Code: "INTERNAL", Message: "HTTP " + strconv.Itoa(res.Status) + "; not a device sign-in answer", RequestID: requestID, Details: Undefined}
	}
	_, err = finish(res)
	e, ok := err.(*APIError)
	if !ok {
		return DeviceSignInPoll{}, err
	}
	interval := func(fallback float64) float64 {
		v, _ := get(e.Details, "interval")
		if n := Number(v); !math.IsNaN(n) && !math.IsInf(n, 0) && n > 0 {
			return n
		}
		return fallback
	}
	switch {
	case e.CodeIs("AUTHORIZATION_PENDING"):
		return DeviceSignInPoll{State: "pending", Interval: interval(5)}, nil
	case e.CodeIs("SLOW_DOWN"):
		return DeviceSignInPoll{State: "slow_down", Interval: interval(10)}, nil
	case e.CodeIs("ACCESS_DENIED"):
		return DeviceSignInPoll{State: "denied"}, nil
	case e.CodeIs("EXPIRED"):
		return DeviceSignInPoll{State: "expired"}, nil
	case e.CodeIs("CONSUMED"):
		id, _ := get(e.Details, "credentialId")
		s, _ := id.(string)
		return DeviceSignInPoll{State: "consumed", CredentialID: s}, nil
	}
	return DeviceSignInPoll{}, err
}

// Number is JavaScript's Number(v) for a JSON value (Undefined is NaN).
func Number(v any) float64 {
	switch x := v.(type) {
	case nil:
		return 0
	case bool:
		if x {
			return 1
		}
		return 0
	case float64:
		return x
	case string:
		if n, ok := jsval.ToNumber(jsval.UTF16(x)); ok {
			return n
		}
		return math.NaN()
	case []any:
		if n, ok := jsval.ToNumber(jsval.UTF16(jsjson.String(x))); ok {
			return n
		}
	}
	return math.NaN()
}
