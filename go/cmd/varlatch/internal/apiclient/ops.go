// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"context"
	"strings"
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
