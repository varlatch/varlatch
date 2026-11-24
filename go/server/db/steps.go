// SPDX-License-Identifier: AGPL-3.0-or-later

package db

// releaseSteps are the schema upgrades of the released schema versions, in
// order: releaseSteps[i] upgrades version i+1 to i+2 (version.go). The
// g6fixture build adds its synthetic step after them.
var releaseSteps = []Step{
	// 2: the certificate issuance count (step 6 decision 16). A new table
	// only, so rollback-safe: schema 1's varlatchd may open the database
	// and never reads the table.
	{To: 2, CompatibleFrom: 1, SQL: `
CREATE TABLE certificate_issuances (
  id INTEGER NOT NULL PRIMARY KEY,
  name TEXT NOT NULL CONSTRAINT certificate_issuances_name_check CHECK (length(name) BETWEEN 1 AND 253 AND name = lower(name)),
  started_at INTEGER NOT NULL,
  outcome TEXT NOT NULL DEFAULT 'started' CONSTRAINT certificate_issuances_outcome_check CHECK (outcome IN ('started', 'issued', 'refused')),
  ended_at INTEGER
) STRICT;
CREATE INDEX certificate_issuances_name_started ON certificate_issuances (name, started_at);
`},
	// 3: three partial indexes for the repair of Capabilities earlier
	// retirements left live (capabilities.RevokeOfRetired): on audit_events,
	// an identity's lifecycle events and a Capability's issuance, each by
	// Organization; on capabilities, the unrevoked ones by Organization and
	// id, the repair's batch cursor. Indexes only, so rollback-safe: schema
	// 1's and 2's varlatchd may open the database, and their writes keep the
	// indexes.
	{To: 3, CompatibleFrom: 1, SQL: `
CREATE INDEX audit_events_identity_lifecycle_idx ON audit_events (organization_id, json_extract(resource, '$.identityId'), event_order)
  WHERE event_type IN ('identity.retired', 'identity.reactivated');
CREATE INDEX audit_events_capability_issued_idx ON audit_events (organization_id, json_extract(resource, '$.capabilityId'), event_order)
  WHERE event_type = 'capability.issued';
CREATE INDEX capabilities_live_idx ON capabilities (organization_id, id) WHERE revoked_at IS NULL;
`},
	// 4: exercise-only credentials and tokens exchanged once (ADR-0060). New
	// tables only, so rollback-safe: an older varlatchd never reads them.
	// What they limit fails closed there: it matches neither an
	// exercise-only credential's token_hash, nor a delegated or single-use
	// Capability's secret_hash, nor a limited binding's claims.
	{To: 4, CompatibleFrom: 1, SQL: `
CREATE TABLE exercise_credentials (
  credential_id TEXT NOT NULL PRIMARY KEY REFERENCES credentials (id),
  oidc_binding_id TEXT NOT NULL REFERENCES oidc_bindings (id),
  run_id TEXT CONSTRAINT exercise_credentials_run_id_check CHECK (length(run_id) BETWEEN 1 AND 200)
) STRICT;
CREATE TABLE oidc_token_uses (
  token_key TEXT NOT NULL PRIMARY KEY CONSTRAINT oidc_token_uses_token_key_check CHECK (length(token_key) = 64 AND token_key NOT GLOB '*[^0-9a-f]*'),
  used_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX oidc_token_uses_expires ON oidc_token_uses (expires_at);
`},
	// 5: one-time codes given (ADR-0061). A new table only, so rollback-safe:
	// an older varlatchd never reads it, and a seed's row in env_values is
	// one it reads as deleted.
	{To: 5, CompatibleFrom: 1, SQL: `
CREATE TABLE one_time_codes_given (
  version_id TEXT NOT NULL PRIMARY KEY REFERENCES value_versions (id),
  step INTEGER NOT NULL
) STRICT;
`},
	// 65: OAuth connections' tokens, and authorizations in progress
	// (ADR-0062). New tables only, so rollback-safe: an older varlatchd never
	// reads them, and a connection's row in env_values is one it reads as
	// deleted.
	{To: 6, CompatibleFrom: 1, SQL: `
CREATE TABLE oauth_connections (
  value_id TEXT NOT NULL PRIMARY KEY REFERENCES env_values (id),
  version_id TEXT NOT NULL REFERENCES value_versions (id),
  status TEXT NOT NULL CONSTRAINT oauth_connections_status_check CHECK (status IN ('not_connected', 'connected', 'failing', 'needs_reconnect', 'revoked')),
  reason TEXT,
  paused_at INTEGER,
  generation INTEGER NOT NULL DEFAULT 0,
  access_token TEXT CHECK (json_valid(access_token)),
  access_expires_at INTEGER,
  access_lifetime INTEGER,
  refresh_token TEXT CHECK (json_valid(refresh_token)),
  refresh_expires_at INTEGER,
  keepalive_at INTEGER,
  granted_scopes TEXT,
  account TEXT NOT NULL DEFAULT '',
  account_label TEXT NOT NULL DEFAULT '',
  connected_by TEXT REFERENCES identities (id),
  connected_at INTEGER,
  refreshed_at INTEGER,
  failures INTEGER NOT NULL DEFAULT 0,
  retry_at INTEGER,
  claim_id TEXT,
  claim_until INTEGER,
  unanswered INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX oauth_connections_keepalive ON oauth_connections (keepalive_at) WHERE keepalive_at IS NOT NULL;
CREATE TABLE oauth_authorizations (
  state_hash TEXT NOT NULL PRIMARY KEY CONSTRAINT oauth_authorizations_state_hash_check CHECK (length(state_hash) = 64 AND state_hash NOT GLOB '*[^0-9a-f]*'),
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  value_id TEXT NOT NULL REFERENCES env_values (id),
  version_id TEXT NOT NULL REFERENCES value_versions (id),
  identity_id TEXT NOT NULL REFERENCES identities (id),
  auth_session_id TEXT NOT NULL,
  nonce_hash TEXT NOT NULL,
  verifier TEXT NOT NULL CHECK (json_valid(verifier)),
  redirect_uri TEXT NOT NULL,
  account_change INTEGER NOT NULL CONSTRAINT oauth_authorizations_account_change_check CHECK (account_change IN (0, 1)),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX oauth_authorizations_expires ON oauth_authorizations (expires_at);
`},
	// 76: entry links (ADR-0063). A new table only, so rollback-safe: an older
	// varlatchd never reads it. A link is no more than its row: there, nobody
	// can enter a value with one.
	{To: 7, CompatibleFrom: 1, SQL: `
CREATE TABLE entry_links (
  id TEXT NOT NULL PRIMARY KEY,
  token_hash TEXT NOT NULL CONSTRAINT entry_links_token_hash_unique UNIQUE CONSTRAINT entry_links_token_hash_check CHECK (length(token_hash) = 64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  project_id TEXT NOT NULL REFERENCES projects (id),
  environment_id TEXT NOT NULL REFERENCES environments (id),
  item_name TEXT NOT NULL,
  accepts TEXT NOT NULL CONSTRAINT entry_links_accepts_check CHECK (accepts IN ('value', 'otpauth')),
  replaces INTEGER NOT NULL CONSTRAINT entry_links_replaces_check CHECK (replaces IN (0, 1)),
  bound_version_id TEXT,
  restricted_to TEXT NOT NULL CONSTRAINT entry_links_restricted_to_check CHECK (restricted_to IN ('anyone', 'member', 'identity')),
  identity_id TEXT REFERENCES identities (id),
  description TEXT,
  requested_by TEXT NOT NULL REFERENCES identities (id),
  status TEXT NOT NULL DEFAULT 'pending' CONSTRAINT entry_links_status_check CHECK (status IN ('pending', 'entered', 'cancelled')),
  reason TEXT,
  refusals INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ended_at INTEGER,
  CONSTRAINT entry_links_identity_check CHECK ((restricted_to = 'identity') = (identity_id IS NOT NULL)),
  CONSTRAINT entry_links_bound_check CHECK (replaces = 1 OR bound_version_id IS NULL),
  CONSTRAINT entry_links_ended_check CHECK ((status = 'pending') = (ended_at IS NULL))
) STRICT;
CREATE INDEX entry_links_environment ON entry_links (environment_id, created_at);
CREATE INDEX entry_links_requested_by ON entry_links (requested_by, created_at);
CREATE INDEX entry_links_expires ON entry_links (expires_at);
`},
}
