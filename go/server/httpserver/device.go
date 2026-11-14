// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Device-authorization sign-in (ADR-0043 Decision 2): the CLI's two calls
// are unauthenticated, the device code being their bearer; deciding takes
// the dashboard's session bearer of a person (a header, never an ambient
// cookie), and approving a fresh passkey assertion bound to the sign-in,
// the person and the session.

// deviceBase is where device sign-in's verification page is: the public
// URL, when it is https, or http on a loopback host (deviceSignInBase);
// nil otherwise, and device sign-in is not available.
func (s *Server) deviceBase() *url.URL {
	u := s.opts.PublicURL
	if u == nil || !(u.Scheme == "https" || u.Scheme == "http" && loopbackHosts[hostOf(u.Host)]) {
		return nil
	}
	return u
}

func (s *Server) deviceAvailable() (*url.URL, error) {
	base := s.deviceBase()
	if base == nil || s.opts.Auth == nil {
		return nil, domainerr.New("RESOURCE_NOT_FOUND", "Device sign-in is not available: this server's public URL is not HTTPS")
	}
	return base, nil
}

// devicePeer is the requesting client's address, as the request window
// counts it.
func devicePeer(ctx context.Context) string {
	if r := httpRequestOf(ctx); r != nil {
		if c, ok := r.Context().Value(clientKey{}).(string); ok {
			return c
		}
	}
	return "local"
}

// StartDeviceSignIn is POST /v1/auth/device.
func (o *operations) StartDeviceSignIn(ctx context.Context, req api.StartDeviceSignInRequestObject) (api.StartDeviceSignInResponseObject, error) {
	base, err := o.s.deviceAvailable()
	if err != nil {
		return nil, err
	}
	if err := bodyError(ctx); err != nil {
		return nil, err
	}
	var body api.StartDeviceSignInJSONBody
	if req.Body != nil {
		body = api.StartDeviceSignInJSONBody(*req.Body)
	}
	ttl, err := checkTTL(body.TtlSeconds, auth.DeviceDefaultTTL)
	if err != nil {
		return nil, err
	}
	if err := checkName(body.Name); err != nil {
		return nil, err
	}
	started, err := o.s.opts.Auth.RequestDeviceSignIn(ctx, ttl, body.Name, devicePeer(ctx), userAgentOf(ctx), requestIDOf(httpRequestOf(ctx)))
	if err != nil {
		return nil, err
	}
	return reply{status: http.StatusCreated, body: jsvalue.Object{
		{Key: "deviceCode", Value: started.DeviceCode}, {Key: "userCode", Value: started.UserCode},
		{Key: "verificationUri", Value: base.Scheme + "://" + base.Host + strings.TrimRight(base.Path, "/") + "/device"},
		{Key: "expiresIn", Value: started.ExpiresIn}, {Key: "interval", Value: started.Interval},
	}}, nil
}

// CollectDeviceSignIn is POST /v1/auth/device/token: the CLI's poll.
func (o *operations) CollectDeviceSignIn(ctx context.Context, req api.CollectDeviceSignInRequestObject) (api.CollectDeviceSignInResponseObject, error) {
	if _, err := o.s.deviceAvailable(); err != nil {
		return nil, err
	}
	if err := bodyError(ctx); err != nil {
		return nil, err
	}
	code := ""
	if req.Body != nil {
		code = req.Body.DeviceCode
	}
	if n := len(utf16(code)); n < 1 || n > 200 {
		return nil, validation("deviceCode: must be 1 to 200 characters")
	}
	out, err := o.s.opts.Auth.PollDeviceSignIn(ctx, code, userAgentOf(ctx), requestIDOf(httpRequestOf(ctx)))
	if err != nil {
		return nil, err
	}
	interval := jsvalue.Object{{Key: "interval", Value: out.Interval}}
	switch out.Kind {
	case auth.PollIssued:
		return reply{status: http.StatusCreated, body: jsvalue.Object{
			{Key: "id", Value: out.Issued.CredentialID}, {Key: "token", Value: out.Issued.Token}, {Key: "expiresAt", Value: iso(out.ExpiresAt)},
		}}, nil
	case auth.PollPending:
		return nil, &headerError{headers: retryAfter(out.Interval), err: &domainerr.Error{Code: "AUTHORIZATION_PENDING", Message: "Waiting for the person to approve this sign-in", Details: interval}}
	case auth.PollSlowDown:
		return nil, &headerError{headers: retryAfter(out.Interval), err: &domainerr.Error{Code: "SLOW_DOWN",
			Message: "Polled too soon; wait " + jsNumber(out.Interval) + " seconds between polls", Details: interval}}
	case auth.PollDenied:
		return nil, domainerr.New("ACCESS_DENIED", "The sign-in was denied")
	case auth.PollConsumed:
		return nil, &domainerr.Error{Code: "CONSUMED", Message: "The credential of this sign-in was already collected",
			Details: jsvalue.Object{{Key: "credentialId", Value: orNull(out.CredentialID, id[string])}}}
	default:
		return nil, domainerr.New("EXPIRED", "The sign-in expired, or no sign-in has this device code")
	}
}

func jsNumber(n int64) string { return string(jsvalue.Stringify(n)) }

const deviceApproverRefusal = "Only a person signed in to the dashboard may decide a device sign-in"

func (o *operations) pendingForCode(ctx context.Context, identityID, userCode string) (auth.PendingSignIn, error) {
	if n := len(utf16(userCode)); n < 1 || n > 64 {
		return auth.PendingSignIn{}, validation("userCode: must be 1 to 64 characters")
	}
	return o.s.opts.Auth.FindSignInByCode(ctx, identityID, devicePeer(ctx), userCode, requestIDOf(httpRequestOf(ctx)))
}

// LookupDeviceSignIn is POST /v1/auth/device/lookup: the typed code's
// sign-in for the confirmation screen, with a fresh approval challenge.
// Wrong codes count against the attempt limits.
func (o *operations) LookupDeviceSignIn(ctx context.Context, req api.LookupDeviceSignInRequestObject) (api.LookupDeviceSignInResponseObject, error) {
	if _, err := o.s.deviceAvailable(); err != nil {
		return nil, err
	}
	identityID, sessionID, err := dashboardSession(ctx, deviceApproverRefusal)
	if err != nil {
		return nil, err
	}
	if err := bodyError(ctx); err != nil {
		return nil, err
	}
	code := ""
	if req.Body != nil {
		code = req.Body.UserCode
	}
	signIn, err := o.pendingForCode(ctx, identityID, code)
	if err != nil {
		return nil, err
	}
	options, err := o.s.opts.Auth.ApprovalChallenge(ctx, signIn.ID, identityID, sessionID)
	if err != nil {
		return nil, err
	}
	var approval any
	if options != nil {
		pk, err := optionsJS(options)
		if err != nil {
			return nil, err
		}
		approval = jsvalue.Object{{Key: "publicKey", Value: pk}}
	}
	return ok(jsvalue.Object{
		{Key: "signIn", Value: jsvalue.Object{
			{Key: "userCode", Value: signIn.UserCode}, {Key: "ttlSeconds", Value: signIn.RequestedTTL},
			{Key: "name", Value: orNull(signIn.RequestedName, id[string])}, {Key: "requesterIp", Value: orNull(signIn.RequesterIP, id[string])},
			{Key: "requesterUserAgent", Value: orNull(signIn.RequesterUserAgent, id[string])},
			{Key: "requestedAt", Value: iso(signIn.CreatedAt)}, {Key: "expiresAt", Value: iso(signIn.ExpiresAt)},
		}},
		{Key: "approval", Value: approval},
	}), nil
}

// DecideDeviceSignIn is POST /v1/auth/device/approve: deny, or approve with
// a fresh passkey assertion.
func (o *operations) DecideDeviceSignIn(ctx context.Context, req api.DecideDeviceSignInRequestObject) (api.DecideDeviceSignInResponseObject, error) {
	if _, err := o.s.deviceAvailable(); err != nil {
		return nil, err
	}
	identityID, sessionID, err := dashboardSession(ctx, deviceApproverRefusal)
	if err != nil {
		return nil, err
	}
	if err := bodyError(ctx); err != nil {
		return nil, err
	}
	var body api.DecideDeviceSignInJSONBody
	if req.Body != nil {
		body = api.DecideDeviceSignInJSONBody(*req.Body)
	}
	if n := len(utf16(body.UserCode)); n < 1 || n > 64 {
		return nil, validation("userCode: must be 1 to 64 characters")
	}
	if body.Decision != "approve" && body.Decision != "deny" {
		return nil, validation(`decision: Invalid option: expected one of "approve"|"deny"`)
	}
	if body.Decision == "approve" && body.Assertion == nil {
		return nil, validation("assertion: approving needs a fresh passkey assertion")
	}
	signIn, err := o.pendingForCode(ctx, identityID, body.UserCode)
	if err != nil {
		return nil, err
	}
	requestID := requestIDOf(httpRequestOf(ctx))
	if body.Decision == "deny" {
		if err := o.s.opts.Auth.DenyDeviceSignIn(ctx, signIn.ID, identityID, requestID); err != nil {
			return nil, err
		}
		return ok(jsvalue.Object{{Key: "decision", Value: "denied"}}), nil
	}
	if err := o.s.opts.Auth.ApproveDeviceSignIn(ctx, signIn.ID, identityID, sessionID, rawAssertion(*body.Assertion), requestID); err != nil {
		return nil, err
	}
	return ok(jsvalue.Object{{Key: "decision", Value: "approved"}}), nil
}
