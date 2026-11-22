// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"context"
	"crypto/x509"
)

// The operations of an agent-safe run (slice 5.5b of internal
// docs/design/go-cli.md: `varlatch run --agent-safe`), as packages/sdk
// sends them: a Capability issued, exercised and revoked with the Broker
// credential, and the short-lived agent-run credential of --agent-metadata.
// A body is built by the caller in the order the TypeScript CLI builds it,
// since JSON.stringify keeps that order.

func capabilitiesPath(org, project, environment string) string {
	return environmentPath(org, project, environment) + "/capabilities"
}

func agentCredentialsPath(org, identityID string) string {
	return "/v1/organizations/" + EncodeURIComponent(org) + "/identities/" + EncodeURIComponent(identityID) + "/credentials"
}

// IssueCapability is POST .../capabilities with {agentIdentityId, items,
// destinations, targets, ttlSeconds, runId[, precondition]}.
func (c *Client) IssueCapability(ctx context.Context, org, project, environment string, body any) (any, error) {
	return c.Request(ctx, "POST", capabilitiesPath(org, project, environment), body, nil)
}

// RevokeCapability is DELETE .../capabilities/<id>.
func (c *Client) RevokeCapability(ctx context.Context, org, project, environment, capabilityID string) (any, error) {
	return c.Request(ctx, "DELETE", capabilitiesPath(org, project, environment)+"/"+EncodeURIComponent(capabilityID), NoBody, nil)
}

// ExerciseCapability is POST .../capabilities/<id>/exercises with
// {capabilitySecret, destination: {host, port}, placements}.
func (c *Client) ExerciseCapability(ctx context.Context, org, project, environment, capabilityID string, body any) (any, error) {
	return c.Request(ctx, "POST", capabilitiesPath(org, project, environment)+"/"+EncodeURIComponent(capabilityID)+"/exercises", body, nil)
}

// IssueAgentCredential is POST /v1/organizations/<org>/identities/<id>/credentials
// with {ttlSeconds, runId}.
func (c *Client) IssueAgentCredential(ctx context.Context, org, identityID string, body any) (any, error) {
	return c.Request(ctx, "POST", agentCredentialsPath(org, identityID), body, nil)
}

// RevokeAgentCredential is DELETE .../identities/<id>/credentials/<credential>.
func (c *Client) RevokeAgentCredential(ctx context.Context, org, identityID, credentialID string) (any, error) {
	return c.Request(ctx, "DELETE", agentCredentialsPath(org, identityID)+"/"+EncodeURIComponent(credentialID), NoBody, nil)
}

// RootPool is the roots a run trusts, as its clients do: the system's,
// plus the certificates NODE_EXTRA_CA_CERTS names; nil is the system's. The
// Broker verifies destinations with it, as Node.js's TLS does in the
// TypeScript Broker.
func RootPool(env Env) *x509.CertPool {
	extra := ""
	if env != nil {
		extra, _ = env.LookupEnv("NODE_EXTRA_CA_CERTS")
	}
	return rootPool(extra)
}
