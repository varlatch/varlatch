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

// SetSeed is PUT .../values/<item> with {otpauth}: the seed of one-time
// codes in a value's place (capability values.totp, ADR-0061). A server
// without the capability refuses it for want of a value.
func (c *Client) SetSeed(ctx context.Context, org, project, environment, item, uri string) (any, error) {
	return c.Request(ctx, "PUT", environmentPath(org, project, environment)+"/values/"+EncodeURIComponent(item), jsjson.Object{{Key: "otpauth", Value: uri}}, nil)
}

// BeginSeedRotation is BeginRotation with {otpauth}, as SetSeed.
func (c *Client) BeginSeedRotation(ctx context.Context, org, project, environment, item, uri string, graceSeconds *float64) (any, error) {
	body := jsjson.Object{{Key: "otpauth", Value: uri}}
	if graceSeconds != nil {
		body = append(body, jsjson.Member{Key: "graceSeconds", Value: *graceSeconds})
	}
	return c.Request(ctx, "POST", environmentPath(org, project, environment)+"/values/"+EncodeURIComponent(item)+"/rotations", body, nil)
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

// DiscloseSecrets is POST .../disclosures: the Secrets' values, with
// {items: [...]} or {scope: "all-authorized-secrets"}.
func (c *Client) DiscloseSecrets(ctx context.Context, org, project, environment string, body jsjson.Object) (any, error) {
	return c.Request(ctx, "POST", environmentPath(org, project, environment)+"/disclosures", body, nil)
}

// StrictRetrieval is POST .../retrievals with {mode}: one strict retrieval
// ("strict", the values with their manifest and Contract) or its
// "preflight" (no Secret values), capability retrieval.strict.
func (c *Client) StrictRetrieval(ctx context.Context, org, project, environment, mode string) (any, error) {
	return c.Request(ctx, "POST", environmentPath(org, project, environment)+"/retrievals", jsjson.Object{{Key: "mode", Value: mode}}, nil)
}

// ValidateEnvironment is POST .../validate with {}.
func (c *Client) ValidateEnvironment(ctx context.Context, org, project, environment string) (any, error) {
	return c.Request(ctx, "POST", environmentPath(org, project, environment)+"/validate", jsjson.Object{}, nil)
}

// GetActiveContract is GET /v1/organizations/<org>/projects/<project>/contract.
func (c *Client) GetActiveContract(ctx context.Context, org, project string) (any, error) {
	return c.Request(ctx, "GET", projectPath(org, project)+"/contract", NoBody, nil)
}

// GetContractRevision is GET .../contract/revisions/<id>: one stored
// revision by ID, active or not (capability contracts.revision-by-id).
func (c *Client) GetContractRevision(ctx context.Context, org, project, revisionID string) (any, error) {
	return c.Request(ctx, "GET", projectPath(org, project)+"/contract/revisions/"+EncodeURIComponent(revisionID), NoBody, nil)
}

// PushContractRevision is POST .../contract/revisions with {contract, provenance}.
func (c *Client) PushContractRevision(ctx context.Context, org, project string, body jsjson.Object) (any, error) {
	return c.Request(ctx, "POST", projectPath(org, project)+"/contract/revisions", body, nil)
}

// ActivateContractRevision is POST .../contract/revisions/<id>/activate with {}.
func (c *Client) ActivateContractRevision(ctx context.Context, org, project, revisionID string) (any, error) {
	return c.Request(ctx, "POST", projectPath(org, project)+"/contract/revisions/"+EncodeURIComponent(revisionID)+"/activate", jsjson.Object{}, nil)
}
