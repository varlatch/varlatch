// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"context"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The operations of `values`, `validate` and `import` (slice 5.3a of
// internal docs/design/go-cli.md), as packages/sdk sends them.

// environmentPath is /v1/organizations/<org>/projects/<project>/environments/<environment>.
func environmentPath(org, project, environment string) string {
	return projectPath(org, project) + "/environments/" + EncodeURIComponent(environment)
}

func projectPath(org, project string) string {
	return "/v1/organizations/" + EncodeURIComponent(org) + "/projects/" + EncodeURIComponent(project)
}

// SetValue is PUT .../values/<item> with {value}.
func (c *Client) SetValue(ctx context.Context, org, project, environment, item, value string) (any, error) {
	return c.Request(ctx, "PUT", environmentPath(org, project, environment)+"/values/"+EncodeURIComponent(item), jsjson.Object{{Key: "value", Value: value}}, nil)
}

// DeleteValue is DELETE .../values/<item>.
func (c *Client) DeleteValue(ctx context.Context, org, project, environment, item string) (any, error) {
	return c.Request(ctx, "DELETE", environmentPath(org, project, environment)+"/values/"+EncodeURIComponent(item), NoBody, nil)
}

// BeginRotation is POST .../values/<item>/rotations with {value} and, when
// given, graceSeconds (ADR-0027).
func (c *Client) BeginRotation(ctx context.Context, org, project, environment, item, value string, graceSeconds *float64) (any, error) {
	body := jsjson.Object{{Key: "value", Value: value}}
	if graceSeconds != nil {
		body = append(body, jsjson.Member{Key: "graceSeconds", Value: *graceSeconds})
	}
	return c.Request(ctx, "POST", environmentPath(org, project, environment)+"/values/"+EncodeURIComponent(item)+"/rotations", body, nil)
}

// CompleteRotation is POST .../values/<item>/rotations/complete with {}.
func (c *Client) CompleteRotation(ctx context.Context, org, project, environment, item string) (any, error) {
	return c.Request(ctx, "POST", environmentPath(org, project, environment)+"/values/"+EncodeURIComponent(item)+"/rotations/complete", jsjson.Object{}, nil)
}

// EffectiveConfiguration is GET .../effective-configuration, with
// ?include=values when includeValues (non-sensitive values only).
func (c *Client) EffectiveConfiguration(ctx context.Context, org, project, environment string, includeValues bool) (any, error) {
	query := ""
	if includeValues {
		query = "?include=values"
	}
	return c.Request(ctx, "GET", environmentPath(org, project, environment)+"/effective-configuration"+query, NoBody, nil)
}

// ValidateEnvironment is POST .../validate with {}.
func (c *Client) ValidateEnvironment(ctx context.Context, org, project, environment string) (any, error) {
	return c.Request(ctx, "POST", environmentPath(org, project, environment)+"/validate", jsjson.Object{}, nil)
}

// GetActiveContract is GET /v1/organizations/<org>/projects/<project>/contract.
func (c *Client) GetActiveContract(ctx context.Context, org, project string) (any, error) {
	return c.Request(ctx, "GET", projectPath(org, project)+"/contract", NoBody, nil)
}

// PushContractRevision is POST .../contract/revisions with {contract, provenance}.
func (c *Client) PushContractRevision(ctx context.Context, org, project string, body jsjson.Object) (any, error) {
	return c.Request(ctx, "POST", projectPath(org, project)+"/contract/revisions", body, nil)
}

// ListProjectEnvironments is GET .../environments (the SDK's
// listEnvironments).
func (c *Client) ListProjectEnvironments(ctx context.Context, org, project string) (any, error) {
	return c.Request(ctx, "GET", projectPath(org, project)+"/environments", NoBody, nil)
}
