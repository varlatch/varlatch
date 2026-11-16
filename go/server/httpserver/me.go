// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// The /v1 operations of ADR-0059 step 3.4: who am I, the caller's
// credentials and passkeys, the CLI credential exchange, device sign-in,
// the profile and the caller's organizations. Their bodies are written as
// the TypeScript server writes them (member order, dates as
// toISOString), through reply.

// reply is a response an operation answers with: a status and a JSON body
// (jsvalue), or no body for 204. It implements each built operation's
// response interface.
type reply struct {
	status int
	body   any
}

func (r reply) visit(w http.ResponseWriter) error {
	if r.body == nil {
		w.WriteHeader(r.status)
		return nil
	}
	writeJS(w, r.status, r.body)
	return nil
}

func (r reply) VisitWhoamiResponse(w http.ResponseWriter) error             { return r.visit(w) }
func (r reply) VisitListMyCredentialsResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitRevokeMyCredentialResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitExchangeCliCredentialResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r reply) VisitListMyPasskeysResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitRemoveMyPasskeyResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitStartPasskeyConfirmationResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r reply) VisitConfirmMyPasskeyResponse(w http.ResponseWriter) error    { return r.visit(w) }
func (r reply) VisitStartDeviceSignInResponse(w http.ResponseWriter) error   { return r.visit(w) }
func (r reply) VisitCollectDeviceSignInResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitLookupDeviceSignInResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitDecideDeviceSignInResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitGetMyProfileResponse(w http.ResponseWriter) error        { return r.visit(w) }
func (r reply) VisitListOrganizationsResponse(w http.ResponseWriter) error   { return r.visit(w) }

func ok(body any) reply { return reply{status: http.StatusOK, body: body} }

func orNull[T any](p *T, f func(T) any) any {
	if p == nil {
		return nil
	}
	return f(*p)
}

func iso(micros int64) any { return auth.ISO(micros) }
func id[T any](v T) any    { return v }

func validation(format string, args ...any) error {
	return domainerr.New("VALIDATION_FAILED", fmt.Sprintf(format, args...))
}

// page is a list response: {items, nextCursor: null}.
func page(items []any) jsvalue.Object {
	if items == nil {
		items = []any{}
	}
	return jsvalue.Object{{Key: "items", Value: items}, {Key: "nextCursor", Value: nil}}
}

func orgJS(id, slug, name string, created int64) jsvalue.Object {
	return jsvalue.Object{{Key: "id", Value: id}, {Key: "slug", Value: slug}, {Key: "name", Value: name}, {Key: "createdAt", Value: iso(created)}}
}

// Whoami is GET /v1/me: the caller as this request authenticated it, for
// any principal, with no audit event (describing the caller exercises no
// authority).
func (o *operations) Whoami(ctx context.Context, _ api.WhoamiRequestObject) (api.WhoamiResponseObject, error) {
	p := principalOf(ctx)
	q := query.New(o.s.opts.Auth.Store().Reader())
	var email, organization any
	if p.Identity.Kind == "human" {
		row, err := q.ProfileOfIdentity(ctx, p.Identity.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if err == nil {
			email = row.Email
		}
	} else if p.Identity.OrganizationID != nil {
		org, err := q.LiveOrganization(ctx, *p.Identity.OrganizationID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if err == nil {
			organization = orgJS(org.ID, org.Slug, org.Name, org.CreatedAt)
		}
	}
	c := p.Credential
	me := jsvalue.Object{
		{Key: "identity", Value: jsvalue.Object{{Key: "id", Value: p.Identity.ID}, {Key: "name", Value: p.Identity.Name}, {Key: "kind", Value: p.Identity.Kind}, {Key: "email", Value: email}}},
		{Key: "organization", Value: organization},
		{Key: "credential", Value: jsvalue.Object{
			{Key: "id", Value: c.ID}, {Key: "name", Value: orNull(c.Name, id[string])}, {Key: "kind", Value: c.Kind},
			{Key: "expiresAt", Value: orNull(c.ExpiresAt, iso)},
		}},
		{Key: "listener", Value: listenerOf(ctx)},
	}
	// On the tailnet listener, the device this request's own connection
	// resolved to, as GET /v1/tailnet/context reports it.
	if res, on := resolutionOf(ctx); on {
		me = append(me, jsvalue.Member{Key: "tailnet", Value: res.Device()})
	}
	return ok(me), nil
}

// ListMyCredentials is GET /v1/me/credentials: the caller's credentials,
// newest first, the presenting one marked current.
func (o *operations) ListMyCredentials(ctx context.Context, _ api.ListMyCredentialsRequestObject) (api.ListMyCredentialsResponseObject, error) {
	p := principalOf(ctx)
	list, err := o.s.opts.Auth.ListOwnCredentials(ctx, p.Identity.ID)
	if err != nil {
		return nil, err
	}
	items := make([]any, 0, len(list))
	for _, c := range list {
		items = append(items, jsvalue.Object{
			{Key: "id", Value: c.ID}, {Key: "kind", Value: c.Kind}, {Key: "name", Value: orNull(c.Name, id[string])},
			{Key: "createdAt", Value: iso(c.CreatedAt)}, {Key: "expiresAt", Value: orNull(c.ExpiresAt, iso)},
			{Key: "revokedAt", Value: orNull(c.RevokedAt, iso)}, {Key: "maxUses", Value: orNull(c.MaxUses, id[int64])},
			{Key: "useCount", Value: c.UseCount}, {Key: "current", Value: c.ID == p.Credential.ID},
			{Key: "client", Value: orNull(c.Client, id[string])},
		})
	}
	return ok(page(items)), nil
}

// RevokeMyCredential is DELETE /v1/me/credentials/{credential}.
func (o *operations) RevokeMyCredential(ctx context.Context, req api.RevokeMyCredentialRequestObject) (api.RevokeMyCredentialResponseObject, error) {
	if err := o.s.opts.Auth.RevokeOwnCredential(ctx, principalOf(ctx), req.Credential); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}

func userAgentOf(ctx context.Context) *string {
	r := httpRequestOf(ctx)
	if r == nil {
		return nil
	}
	if _, ok := r.Header["User-Agent"]; !ok {
		return nil
	}
	ua := headerValue(r, "User-Agent")
	return &ua
}

// checkName is zod's string().min(1).max(200): zod 4 counts code points.
func checkName(name *string) error {
	if name == nil {
		return nil
	}
	n := codePoints(*name)
	if n < 1 || n > 200 {
		return validation("name: must be 1 to 200 characters")
	}
	return nil
}

// codePoints is a string's length as zod 4 measures it (checks.js
// $ZodCheckMaxLength: code points, not UTF-16 units). Strings here come
// from Go's JSON decoder, so they are valid UTF-8.
func codePoints(s string) int { return utf8.RuneCountInString(s) }

func checkTTL(ttl *int, def int64) (int64, error) {
	if ttl == nil {
		return def, nil
	}
	if *ttl < auth.CLIMinTTL || *ttl > auth.CLIMaxTTL {
		return 0, validation("ttlSeconds: must be an integer from %d to %d", auth.CLIMinTTL, auth.CLIMaxTTL)
	}
	return int64(*ttl), nil
}

// ExchangeCliCredential is POST /v1/me/credentials/cli (ADR-0024): the
// browser hand-off's bearer, traded once for a CLI credential.
func (o *operations) ExchangeCliCredential(ctx context.Context, req api.ExchangeCliCredentialRequestObject) (api.ExchangeCliCredentialResponseObject, error) {
	p := principalOf(ctx)
	if p.Identity.Kind != "human" || p.Credential.Kind != auth.KindBrowser {
		return nil, domainerr.New("PERMISSION_DENIED", "Only a browser session bearer may be exchanged for a CLI credential")
	}
	if err := bodyError(ctx); err != nil {
		return nil, err
	}
	var body api.ExchangeCliCredentialJSONBody
	if req.Body != nil {
		body = api.ExchangeCliCredentialJSONBody(*req.Body)
	}
	ttl, err := checkTTL(body.TtlSeconds, auth.CLIDefaultTTL)
	if err != nil {
		return nil, err
	}
	if err := checkName(body.Name); err != nil {
		return nil, err
	}
	issued, expires, err := o.s.opts.Auth.ExchangeCLI(ctx, p, ttl, body.Name, auth.ClientLabel(userAgentOf(ctx)))
	if err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return reply{status: http.StatusCreated, body: jsvalue.Object{
		{Key: "id", Value: issued.CredentialID}, {Key: "token", Value: issued.Token}, {Key: "expiresAt", Value: iso(expires)},
	}}, nil
}

func passkeyJS(p auth.OwnPasskey) jsvalue.Object {
	return jsvalue.Object{
		{Key: "id", Value: p.ID}, {Key: "name", Value: orNull(p.Name, id[string])}, {Key: "deviceType", Value: p.DeviceType},
		{Key: "backedUp", Value: p.BackedUp}, {Key: "createdAt", Value: orNull(p.CreatedAt, iso)}, {Key: "trust", Value: p.Trust},
		{Key: "trustedVia", Value: orNull(p.TrustedVia, id[string])}, {Key: "trustedAt", Value: orNull(p.TrustedAt, iso)},
		{Key: "setupGrantKind", Value: orNull(p.SetupGrantKind, id[string])},
		{Key: "confirmedByPasskeyId", Value: orNull(p.ConfirmedByPasskeyID, id[string])},
	}
}

// ListMyPasskeys is GET /v1/me/passkeys: a person's passkeys with their
// provenance; none for a machine.
func (o *operations) ListMyPasskeys(ctx context.Context, _ api.ListMyPasskeysRequestObject) (api.ListMyPasskeysResponseObject, error) {
	p := principalOf(ctx)
	items := []any{}
	if p.Identity.Kind == "human" {
		list, err := o.s.opts.Auth.ListOwnPasskeys(ctx, p.Identity.ID)
		if err != nil {
			return nil, err
		}
		for _, k := range list {
			items = append(items, passkeyJS(k))
		}
	}
	return ok(page(items)), nil
}

// dashboardSession is the person and session of a request authenticated by
// the dashboard's session bearer, which confirming and removing passkeys
// and deciding a device sign-in take.
func dashboardSession(ctx context.Context, refusal string) (string, string, error) {
	p := principalOf(ctx)
	if p.Identity.Kind != "human" || p.Credential.Kind != auth.KindBrowser || p.Credential.AuthSessionID == nil {
		return "", "", domainerr.New("PERMISSION_DENIED", refusal)
	}
	return p.Identity.ID, *p.Credential.AuthSessionID, nil
}

const passkeyOwnerRefusal = "Only a person signed in to the dashboard may change their passkeys"

// RemoveMyPasskey is DELETE /v1/me/passkeys/{passkey}: a trusted
// passkey under an enforced Security Control needs the step-up approval
// the Varlatch-Approval header names (auth.RemoveOwnPasskey).
func (o *operations) RemoveMyPasskey(ctx context.Context, req api.RemoveMyPasskeyRequestObject) (api.RemoveMyPasskeyResponseObject, error) {
	if _, _, err := dashboardSession(ctx, passkeyOwnerRefusal); err != nil {
		return nil, err
	}
	approvalID, err := approvalHeader(req.Params.VarlatchApproval)
	if err != nil {
		return nil, err
	}
	if err := o.s.opts.Auth.RemoveOwnPasskey(ctx, auth.RequesterOf(principalOf(ctx)), req.Passkey, approvalID); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}

// approvalHeader is the Varlatch-Approval header's approval id, "" when the
// request has none; one that cannot be an approval id is not found
// (approvalOf).
func approvalHeader(h *api.ApprovalHeader) (string, error) {
	if h == nil {
		return "", nil
	}
	id := auth.ParseApprovalID(string(*h))
	if id == "" {
		return "", auth.ApprovalInvalid("not-found", nil)
	}
	return id, nil
}

func optionsJS(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jsvalue.Parse(b)
}

// StartPasskeyConfirmation is POST /v1/me/passkeys/{passkey}/confirmation/options.
func (o *operations) StartPasskeyConfirmation(ctx context.Context, req api.StartPasskeyConfirmationRequestObject) (api.StartPasskeyConfirmationResponseObject, error) {
	identityID, sessionID, err := dashboardSession(ctx, passkeyOwnerRefusal)
	if err != nil {
		return nil, err
	}
	options, err := o.s.opts.Auth.StartConfirmation(ctx, identityID, sessionID, req.Passkey)
	if err != nil {
		return nil, err
	}
	pk, err := optionsJS(options)
	if err != nil {
		return nil, err
	}
	return ok(jsvalue.Object{{Key: "publicKey", Value: pk}}), nil
}

// rawAssertion re-encodes an assertion the strict handler decoded.
func rawAssertion(m map[string]any) json.RawMessage {
	b, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return b
}

// ConfirmMyPasskey is POST /v1/me/passkeys/{passkey}/confirmation.
func (o *operations) ConfirmMyPasskey(ctx context.Context, req api.ConfirmMyPasskeyRequestObject) (api.ConfirmMyPasskeyResponseObject, error) {
	identityID, sessionID, err := dashboardSession(ctx, passkeyOwnerRefusal)
	if err != nil {
		return nil, err
	}
	if err := bodyError(ctx); err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Assertion == nil {
		return nil, validation("assertion: Invalid input: expected record, received undefined")
	}
	confirmed, err := o.s.opts.Auth.Confirm(ctx, identityID, sessionID, req.Passkey, rawAssertion(req.Body.Assertion), requestIDOf(httpRequestOf(ctx)))
	if err != nil {
		return nil, err
	}
	return ok(passkeyJS(confirmed)), nil
}

// GetMyProfile is GET /v1/me/profile: a person's display name and their
// account's email and image; machines have none.
func (o *operations) GetMyProfile(ctx context.Context, _ api.GetMyProfileRequestObject) (api.GetMyProfileResponseObject, error) {
	p := principalOf(ctx)
	if p.Identity.Kind != "human" {
		return nil, domainerr.New("RESOURCE_NOT_FOUND", "Machine identities have no profile")
	}
	var email, image any
	row, err := query.New(o.s.opts.Auth.Store().Reader()).ProfileOfIdentity(ctx, p.Identity.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		email = row.Email
		if row.Image.Valid {
			image = row.Image.String
		}
	}
	return ok(jsvalue.Object{{Key: "identityId", Value: p.Identity.ID}, {Key: "name", Value: p.Identity.Name}, {Key: "email", Value: email}, {Key: "image", Value: image}}), nil
}

// ListOrganizations is GET /v1/organizations: the Organizations the caller
// is a live member of, oldest first (listOrganizationsFor). A machine
// identity is a member of none.
func (o *operations) ListOrganizations(ctx context.Context, _ api.ListOrganizationsRequestObject) (api.ListOrganizationsResponseObject, error) {
	p := principalOf(ctx)
	rows, err := query.New(o.s.opts.Auth.Store().Reader()).OrganizationsOfMember(ctx, p.Identity.ID)
	if err != nil {
		return nil, err
	}
	items := make([]any, 0, len(rows))
	for _, r := range rows {
		items = append(items, orgJS(r.ID, r.Slug, r.Name, r.CreatedAt))
	}
	return ok(page(items)), nil
}
