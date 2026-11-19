// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"context"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The operations `varlatch mcp`'s tools call that no other command does
// (packages/mcp-server/src/server.ts over the SDK).

// ListProjects is GET /v1/organizations/<org>/projects.
func (c *Client) ListProjects(ctx context.Context, org string) (any, error) {
	return c.Request(ctx, "GET", "/v1/organizations/"+EncodeURIComponent(org)+"/projects", NoBody, nil)
}

// ListAuditEvents is GET /v1/organizations/<org>/audit-events, with limit
// and cursor when they are truthy, serialized as URLSearchParams does.
func (c *Client) ListAuditEvents(ctx context.Context, org string, limit float64, cursor string) (any, error) {
	var params []string
	if limit != 0 {
		params = append(params, "limit="+formComponent(strconv.FormatFloat(limit, 'f', -1, 64)))
	}
	if cursor != "" {
		params = append(params, "cursor="+formComponent(cursor))
	}
	query := ""
	if len(params) > 0 {
		query = "?" + strings.Join(params, "&")
	}
	return c.Request(ctx, "GET", "/v1/organizations/"+EncodeURIComponent(org)+"/audit-events"+query, NoBody, nil)
}

// SetValueWith is PUT .../values/<item> with the body as given ({value}
// and, when given, expectedVersionId).
func (c *Client) SetValueWith(ctx context.Context, org, project, environment, item string, body jsjson.Object) (any, error) {
	return c.Request(ctx, "PUT", environmentPath(org, project, environment)+"/values/"+EncodeURIComponent(item), body, nil)
}

// formComponent is application/x-www-form-urlencoded's serialization of one
// name or value: ASCII letters, digits and *-._ as they are, a space as +,
// every other byte of its UTF-8 percent-encoded.
func formComponent(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("*-._", c) >= 0:
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}
