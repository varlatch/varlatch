// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"context"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The operations of Organization administration's first part (slice 5.7a of
// internal docs/design/go-cli.md: org, project, env-create, env-delete,
// identity, credential, invite, member, tailnet, audit list), as
// packages/sdk sends them. A body is built by the caller in the order the
// TypeScript CLI builds it, since JSON.stringify keeps that order.

func orgPath(org string) string { return "/v1/organizations/" + EncodeURIComponent(org) }

func identityPath(org, identityID string) string {
	return orgPath(org) + "/identities/" + EncodeURIComponent(identityID)
}

func memberPath(org, member string) string {
	return orgPath(org) + "/members/" + EncodeURIComponent(member)
}

// CreateOrganization is POST /v1/organizations with {slug, name}.
func (c *Client) CreateOrganization(ctx context.Context, slug, name string) (any, error) {
	return c.Request(ctx, "POST", "/v1/organizations", jsjson.Object{{Key: "slug", Value: slug}, {Key: "name", Value: name}}, nil)
}

// CreateProject is POST /v1/organizations/<org>/projects with {slug, name,
// contractAuthority}.
func (c *Client) CreateProject(ctx context.Context, org, slug, name, contractAuthority string) (any, error) {
	body := jsjson.Object{{Key: "slug", Value: slug}, {Key: "name", Value: name}, {Key: "contractAuthority", Value: contractAuthority}}
	return c.Request(ctx, "POST", orgPath(org)+"/projects", body, nil)
}

// RenameProject is PATCH /v1/organizations/<org>/projects/<project> with {name}.
func (c *Client) RenameProject(ctx context.Context, org, project, name string) (any, error) {
	return c.Request(ctx, "PATCH", projectPath(org, project), jsjson.Object{{Key: "name", Value: name}}, nil)
}

// CreateEnvironment is POST .../projects/<project>/environments with the
// body the caller built ({name, tier} or {name, parentEnvironmentId[, kind]}).
func (c *Client) CreateEnvironment(ctx context.Context, org, project string, body jsjson.Object) (any, error) {
	return c.Request(ctx, "POST", projectPath(org, project)+"/environments", body, nil)
}

// DeleteEnvironment is DELETE .../projects/<project>/environments/<environment>.
func (c *Client) DeleteEnvironment(ctx context.Context, org, project, environment string) (any, error) {
	return c.Request(ctx, "DELETE", environmentPath(org, project, environment), NoBody, nil)
}

// ListIdentities is GET /v1/organizations/<org>/identities.
func (c *Client) ListIdentities(ctx context.Context, org string) (any, error) {
	return c.Request(ctx, "GET", orgPath(org)+"/identities", NoBody, nil)
}

// RenameIdentity is PATCH .../identities/<id> with {name}.
func (c *Client) RenameIdentity(ctx context.Context, org, identityID, name string) (any, error) {
	return c.Request(ctx, "PATCH", identityPath(org, identityID), jsjson.Object{{Key: "name", Value: name}}, nil)
}

// RetireIdentity is POST .../identities/<id>/retire, without a body.
func (c *Client) RetireIdentity(ctx context.Context, org, identityID string) (any, error) {
	return c.Request(ctx, "POST", identityPath(org, identityID)+"/retire", NoBody, nil)
}

// ReactivateIdentity is POST .../identities/<id>/reactivate, without a body.
func (c *Client) ReactivateIdentity(ctx context.Context, org, identityID string) (any, error) {
	return c.Request(ctx, "POST", identityPath(org, identityID)+"/reactivate", NoBody, nil)
}

// MachineReach is GET .../identities/<id>/reach (ADR-0054 Decision 8).
func (c *Client) MachineReach(ctx context.Context, org, identityID string) (any, error) {
	return c.Request(ctx, "GET", identityPath(org, identityID)+"/reach", NoBody, nil)
}

// ListIdentityCredentials is GET .../identities/<id>/credentials.
func (c *Client) ListIdentityCredentials(ctx context.Context, org, identityID string) (any, error) {
	return c.Request(ctx, "GET", identityPath(org, identityID)+"/credentials", NoBody, nil)
}

// IssueMachineCredential is POST .../identities/<id>/credentials with
// {name[, ttlSeconds][, maxUses]}.
func (c *Client) IssueMachineCredential(ctx context.Context, org, identityID string, body jsjson.Object) (any, error) {
	return c.Request(ctx, "POST", identityPath(org, identityID)+"/credentials", body, nil)
}

// RevokeIdentityCredential is DELETE .../identities/<id>/credentials/<credential>.
func (c *Client) RevokeIdentityCredential(ctx context.Context, org, identityID, credentialID string) (any, error) {
	return c.Request(ctx, "DELETE", identityPath(org, identityID)+"/credentials/"+EncodeURIComponent(credentialID), NoBody, nil)
}

// CreateInvitation is POST /v1/organizations/<org>/invitations with {name, role}.
func (c *Client) CreateInvitation(ctx context.Context, org, name string, role any) (any, error) {
	return c.Request(ctx, "POST", orgPath(org)+"/invitations", jsjson.Object{{Key: "name", Value: name}, {Key: "role", Value: role}}, nil)
}

// MemberExposure is GET .../members/<member>/exposure (ADR-0052 Decision 8).
func (c *Client) MemberExposure(ctx context.Context, org, member string) (any, error) {
	return c.Request(ctx, "GET", memberPath(org, member)+"/exposure", NoBody, nil)
}

// RemoveMember is DELETE .../members/<member> ("me" to leave).
func (c *Client) RemoveMember(ctx context.Context, org, member string) (any, error) {
	return c.Request(ctx, "DELETE", memberPath(org, member), NoBody, nil)
}

// ChangeMemberRole is PATCH .../members/<member> with {role}.
func (c *Client) ChangeMemberRole(ctx context.Context, org, member, role string) (any, error) {
	return c.Request(ctx, "PATCH", memberPath(org, member), jsjson.Object{{Key: "role", Value: role}}, nil)
}

// CreateTailnetRequirement is POST .../requirements with {kind: "tailnet",
// target, selector} (the SDK spreads the CLI's input after the kind).
func (c *Client) CreateTailnetRequirement(ctx context.Context, org string, target, selector jsjson.Object) (any, error) {
	body := jsjson.Object{{Key: "kind", Value: "tailnet"}, {Key: "target", Value: target}, {Key: "selector", Value: selector}}
	return c.Request(ctx, "POST", orgPath(org)+"/requirements", body, nil)
}

// ListRequirements is GET /v1/organizations/<org>/requirements.
func (c *Client) ListRequirements(ctx context.Context, org string) (any, error) {
	return c.Request(ctx, "GET", orgPath(org)+"/requirements", NoBody, nil)
}

// DeleteRequirement is DELETE .../requirements/<id>.
func (c *Client) DeleteRequirement(ctx context.Context, org, requirementID string) (any, error) {
	return c.Request(ctx, "DELETE", orgPath(org)+"/requirements/"+EncodeURIComponent(requirementID), NoBody, nil)
}
