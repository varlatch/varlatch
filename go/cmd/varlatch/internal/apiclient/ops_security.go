// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"context"
	"strconv"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The operations of the security commands (slice 5.7b of internal
// docs/design/go-cli.md: security status, report, controls and set), as
// packages/sdk sends them.

// ListSecurityControls is GET /v1/organizations/<org>/security/controls.
func (c *Client) ListSecurityControls(ctx context.Context, org string) (any, error) {
	return c.Request(ctx, "GET", orgPath(org)+"/security/controls", NoBody, nil)
}

// ChangeSecurityControl is PATCH .../security/controls/<control> with the
// body the caller built ({mode, expectedVersion[, config]}). Loosening
// answers STEP_UP_REQUIRED, which the client's OnStepUp handles.
func (c *Client) ChangeSecurityControl(ctx context.Context, org, control string, body jsjson.Object) (any, error) {
	return c.Request(ctx, "PATCH", orgPath(org)+"/security/controls/"+EncodeURIComponent(control), body, nil)
}

// SecurityControlReport is GET .../security/control-report?days=<days>.
func (c *Client) SecurityControlReport(ctx context.Context, org string, days int) (any, error) {
	return c.Request(ctx, "GET", orgPath(org)+"/security/control-report?days="+EncodeURIComponent(strconv.Itoa(days)), NoBody, nil)
}

// MyOrganizationPermissions is GET /v1/organizations/<org>/me/permissions.
func (c *Client) MyOrganizationPermissions(ctx context.Context, org string) (any, error) {
	return c.Request(ctx, "GET", orgPath(org)+"/me/permissions", NoBody, nil)
}

// SecurityApprovalKeys is GET .../security/approval-keys.
func (c *Client) SecurityApprovalKeys(ctx context.Context, org string) (any, error) {
	return c.Request(ctx, "GET", orgPath(org)+"/security/approval-keys", NoBody, nil)
}

// CredentialReview is GET .../security/credential-review.
func (c *Client) CredentialReview(ctx context.Context, org string) (any, error) {
	return c.Request(ctx, "GET", orgPath(org)+"/security/credential-review", NoBody, nil)
}

// RefusedDestinations is GET .../security/refused-destinations.
func (c *Client) RefusedDestinations(ctx context.Context, org string) (any, error) {
	return c.Request(ctx, "GET", orgPath(org)+"/security/refused-destinations", NoBody, nil)
}

// IncidentFreeze is GET /v1/organizations/<org>/incident-freeze.
func (c *Client) IncidentFreeze(ctx context.Context, org string) (any, error) {
	return c.Request(ctx, "GET", orgPath(org)+"/incident-freeze", NoBody, nil)
}

// GetAuditExport is GET /v1/organizations/<org>/audit-export.
func (c *Client) GetAuditExport(ctx context.Context, org string) (any, error) {
	return c.Request(ctx, "GET", orgPath(org)+"/audit-export", NoBody, nil)
}
