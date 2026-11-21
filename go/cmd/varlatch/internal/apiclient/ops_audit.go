// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"context"
	"strconv"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The operations of slice 5.7c of internal docs/design/go-cli.md (the audit
// export, deletion and freezes), as packages/sdk sends them.

// GetOrganization is GET /v1/organizations/<org>.
func (c *Client) GetOrganization(ctx context.Context, org string) (any, error) {
	return c.Request(ctx, "GET", orgPath(org), NoBody, nil)
}

// DeleteProject is DELETE /v1/organizations/<org>/projects/<project>.
func (c *Client) DeleteProject(ctx context.Context, org, project string) (any, error) {
	return c.Request(ctx, "DELETE", projectPath(org, project), NoBody, nil)
}

// OrganizationDeletion is GET .../deletion: the whole answer; the SDK
// returns its `deletion`, which the caller reads.
func (c *Client) OrganizationDeletion(ctx context.Context, org string) (any, error) {
	return c.Request(ctx, "GET", orgPath(org)+"/deletion", NoBody, nil)
}

// ScheduleOrganizationDeletion is POST .../deletion with {} or {afterDays}.
func (c *Client) ScheduleOrganizationDeletion(ctx context.Context, org string, body jsjson.Object) (any, error) {
	return c.Request(ctx, "POST", orgPath(org)+"/deletion", body, nil)
}

// ApproveOrganizationDeletion is POST .../deletion/<id>/approve with {}.
func (c *Client) ApproveOrganizationDeletion(ctx context.Context, org, deletionID string) (any, error) {
	return c.Request(ctx, "POST", orgPath(org)+"/deletion/"+EncodeURIComponent(deletionID)+"/approve", jsjson.Object{}, nil)
}

// CancelOrganizationDeletion is POST .../deletion/<id>/cancel with {}.
func (c *Client) CancelOrganizationDeletion(ctx context.Context, org, deletionID string) (any, error) {
	return c.Request(ctx, "POST", orgPath(org)+"/deletion/"+EncodeURIComponent(deletionID)+"/cancel", jsjson.Object{}, nil)
}

// FreezeOrganization is POST .../incident-freeze with {reason}.
func (c *Client) FreezeOrganization(ctx context.Context, org, reason string) (any, error) {
	return c.Request(ctx, "POST", orgPath(org)+"/incident-freeze", jsjson.Object{{Key: "reason", Value: reason}}, nil)
}

// LiftIncidentFreeze is POST .../incident-freeze/<id>/lift with {}.
func (c *Client) LiftIncidentFreeze(ctx context.Context, org, freezeID string) (any, error) {
	return c.Request(ctx, "POST", orgPath(org)+"/incident-freeze/"+EncodeURIComponent(freezeID)+"/lift", jsjson.Object{}, nil)
}

// CreateAuditExport is POST .../audit-export with the body the caller built.
func (c *Client) CreateAuditExport(ctx context.Context, org string, body jsjson.Object) (any, error) {
	return c.Request(ctx, "POST", orgPath(org)+"/audit-export", body, nil)
}

// ChangeAuditExport is PATCH .../audit-export.
func (c *Client) ChangeAuditExport(ctx context.Context, org string, body jsjson.Object) (any, error) {
	return c.Request(ctx, "PATCH", orgPath(org)+"/audit-export", body, nil)
}

// ReplaceAuditExportCredential is PUT .../audit-export/credential.
func (c *Client) ReplaceAuditExportCredential(ctx context.Context, org string, body jsjson.Object) (any, error) {
	return c.Request(ctx, "PUT", orgPath(org)+"/audit-export/credential", body, nil)
}

// RemoveAuditExport is DELETE .../audit-export?expectedVersion=<version>,
// the version as String() writes it.
func (c *Client) RemoveAuditExport(ctx context.Context, org string, expectedVersion any, present bool) (any, error) {
	version := "undefined"
	if present {
		version = jsjson.String(expectedVersion)
	}
	return c.Request(ctx, "DELETE", orgPath(org)+"/audit-export?expectedVersion="+EncodeURIComponent(version), NoBody, nil)
}

// CheckAuditExport is POST .../audit-export/check.
func (c *Client) CheckAuditExport(ctx context.Context, org string, body jsjson.Object) (any, error) {
	return c.Request(ctx, "POST", orgPath(org)+"/audit-export/check", body, nil)
}

// ExportAuditEventsNDJSON is GET .../audit-events/export: the log as NDJSON.
func (c *Client) ExportAuditEventsNDJSON(ctx context.Context, org string) (string, error) {
	return c.ndjson(ctx, orgPath(org)+"/audit-events/export")
}

// ExportDeletedOrganizationAuditEventsNDJSON is GET
// /v1/deleted-organizations/<id>/audit-events/export.
func (c *Client) ExportDeletedOrganizationAuditEventsNDJSON(ctx context.Context, organizationID string) (string, error) {
	return c.ndjson(ctx, "/v1/deleted-organizations/"+EncodeURIComponent(organizationID)+"/audit-events/export")
}

// ndjson is the SDK's ndjson(): a GET with the credential and User-Agent
// only, outside request()'s maintenance, step-up and approval handling; the
// answer's text when it is OK, else its Varlatch API error, or
// {INTERNAL, "HTTP <status>", "unknown"} when the body is not one.
func (c *Client) ndjson(ctx context.Context, path string) (string, error) {
	var list [][2]string
	if c.opts.Token != "" {
		list = append(list, [2]string{"Authorization", "Bearer " + c.opts.Token})
	}
	if c.opts.UserAgent != "" {
		list = append(list, [2]string{"User-Agent", c.opts.UserAgent})
	}
	for i, h := range list {
		value, err := headerValue(h[0], h[1])
		if err != nil {
			return "", err
		}
		list[i][1] = value
	}
	res, err := c.transport.Do(ctx, Request{Method: "GET", URL: c.server + path, Headers: list})
	if err != nil {
		return "", err
	}
	if c.opts.OnCredentialExpires != nil {
		if expiresAt, ok := res.Header(CredentialExpiresHeader); ok && expiresAt != "" {
			c.opts.OnCredentialExpires(expiresAt)
		}
	}
	if res.Status < 200 || res.Status > 299 {
		var body any = Undefined
		if res.BodyErr == nil {
			if parsed, err := jsjson.Parse([]byte(decodeBody(res.Body))); err == nil {
				body = parsed
			}
		}
		if e, ok := get(body, "error"); ok && e != nil {
			return "", newAPIError(res.Status, e)
		}
		return "", &APIError{Status: res.Status, Code: "INTERNAL", Message: "HTTP " + strconv.Itoa(res.Status), RequestID: "unknown", Details: Undefined}
	}
	if res.BodyErr != nil {
		return "", res.BodyErr
	}
	return decodeBody(res.Body), nil
}
