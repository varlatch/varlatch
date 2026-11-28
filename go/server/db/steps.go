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
  credential_id TEXT NOT NULL REFERENCES credentials (id),
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
	// 8: an Installation Admin's step-up approval for an upgrade the web
	// app asks the host for (ADR-0065 phase 2): approval_intents' operation
	// CHECK gains installation.upgrade. SQLite cannot change a CHECK in
	// place, so both approval tables are made again with their rows and
	// indexes, the old ones set aside first (renamed, then dropped once
	// copied, the challenges before their intents), so no row is deleted by
	// a cascade and the new tables' text is schema.sql's. Rollback-safe: an
	// older varlatchd reads and writes the same columns, and an intent of the
	// new operation is one it shows, and never consumes (no operation of its
	// own matches it).
	{To: 8, CompatibleFrom: 1, SQL: `
ALTER TABLE approval_intent_challenges RENAME TO approval_intent_challenges_v7;
ALTER TABLE approval_intents RENAME TO approval_intents_v7;
CREATE TABLE approval_intents (
  id TEXT NOT NULL PRIMARY KEY,
  credential_id TEXT NOT NULL REFERENCES credentials (id),
  identity_id TEXT NOT NULL REFERENCES identities (id),
  auth_session_id TEXT CONSTRAINT approval_intents_auth_session_id_check
    CHECK (auth_session_id IS NULL OR length(auth_session_id) BETWEEN 1 AND 200),
  organization_id TEXT REFERENCES organizations (id),
  operation TEXT NOT NULL CONSTRAINT approval_intents_operation_check CHECK (operation IN (
    'security_control.change', 'passkey.remove', 'organization.unfreeze',
    'requirement.update', 'requirement.revoke',
    'identity.create', 'credential.issue', 'identity.reactivate',
    'oidc_binding.create', 'oidc_binding.delete',
    'grant.create', 'grant.replace', 'grant.revoke',
    'role.create', 'role.update', 'role.delete',
    'group.create', 'group.update', 'group.delete', 'group.member_add', 'group.member_remove',
    'team.create', 'team.update', 'team.delete', 'team.member_add', 'team.member_remove',
    'team.project_add', 'team.project_remove',
    'member.invite_admin', 'member.promote', 'member.demote', 'member.remove',
    'webhook.create', 'webhook.update', 'webhook.delete',
    'connection.create', 'connection.replace_credential', 'connection.delete',
    'github_app.register', 'github_app.import', 'github_app.replace_key', 'github_app.remove',
    'project.delete', 'organization.delete', 'secret.export',
    'audit_export.change', 'audit_export.remove', 'installation.upgrade')),
  target TEXT NOT NULL CONSTRAINT approval_intents_target_check CHECK (json_valid(target) AND json_type(target) = 'object'),
  body_hash TEXT NOT NULL,
  query_hash TEXT NOT NULL,
  expected_version INTEGER CONSTRAINT int4_expected_version CHECK (expected_version BETWEEN -2147483648 AND 2147483647),
  summary TEXT NOT NULL CHECK (json_valid(summary)),
  origin TEXT NOT NULL CONSTRAINT approval_intents_origin_check CHECK (origin IN ('dashboard', 'cli')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  approved_at INTEGER,
  approved_with_passkey_id TEXT,
  approval_user_verified INTEGER CHECK (approval_user_verified IN (0, 1)),
  consumed_at INTEGER,
  closed_at INTEGER,
  close_reason TEXT CONSTRAINT approval_intents_close_reason_check
    CHECK (close_reason IN ('cancelled', 'reset', 'organization-deleted', 'frozen')),
  poll_interval INTEGER NOT NULL CONSTRAINT approval_intents_poll_interval_check CHECK (poll_interval > 0) CONSTRAINT int4_poll_interval CHECK (poll_interval <= 2147483647),
  last_polled_at INTEGER,
  CONSTRAINT approval_intents_check CHECK (expires_at > created_at),
  CONSTRAINT approval_intents_check1 CHECK ((origin = 'dashboard') = (auth_session_id IS NOT NULL)),
  CONSTRAINT approval_intents_check2 CHECK ((approved_at IS NULL) = (approved_with_passkey_id IS NULL)),
  CONSTRAINT approval_intents_check3 CHECK ((approved_at IS NULL) = (approval_user_verified IS NULL)),
  CONSTRAINT approval_intents_check4 CHECK (consumed_at IS NULL OR approved_at IS NOT NULL),
  CONSTRAINT approval_intents_check5 CHECK ((closed_at IS NULL) = (close_reason IS NULL)),
  CONSTRAINT approval_intents_check6 CHECK (consumed_at IS NULL OR closed_at IS NULL),
  CONSTRAINT approval_intents_check7 CHECK (operation <> 'passkey.remove' OR organization_id IS NULL),
  CONSTRAINT approval_intents_check8 CHECK (operation <> 'security_control.change' OR organization_id IS NOT NULL),
  CONSTRAINT approval_intents_unfreeze_organization CHECK (operation <> 'organization.unfreeze' OR organization_id IS NOT NULL),
  CONSTRAINT approval_intents_requirement_organization
    CHECK (operation NOT IN ('requirement.update', 'requirement.revoke') OR organization_id IS NOT NULL),
  CONSTRAINT approval_intents_admin_step_up_organization CHECK (operation NOT IN (
    'identity.create', 'credential.issue', 'identity.reactivate',
    'oidc_binding.create', 'oidc_binding.delete',
    'grant.create', 'grant.replace', 'grant.revoke',
    'role.create', 'role.update', 'role.delete',
    'group.create', 'group.update', 'group.delete', 'group.member_add', 'group.member_remove',
    'team.create', 'team.update', 'team.delete', 'team.member_add', 'team.member_remove',
    'team.project_add', 'team.project_remove',
    'member.invite_admin', 'member.promote', 'member.demote', 'member.remove',
    'webhook.create', 'webhook.update', 'webhook.delete',
    'connection.create', 'connection.replace_credential', 'connection.delete',
    'github_app.register', 'github_app.import', 'github_app.replace_key', 'github_app.remove',
    'project.delete', 'organization.delete', 'secret.export') OR organization_id IS NOT NULL),
  CONSTRAINT approval_intents_audit_export_organization
    CHECK (operation NOT IN ('audit_export.change', 'audit_export.remove') OR organization_id IS NOT NULL)
) STRICT;
CREATE TABLE approval_intent_challenges (
  id TEXT NOT NULL PRIMARY KEY,
  intent_id TEXT NOT NULL REFERENCES approval_intents (id) ON DELETE CASCADE,
  identity_id TEXT NOT NULL REFERENCES identities (id),
  auth_session_id TEXT NOT NULL
    CONSTRAINT approval_intent_challenges_auth_session_id_check CHECK (length(auth_session_id) BETWEEN 1 AND 200),
  challenge TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  CONSTRAINT approval_intent_challenges_check CHECK (expires_at > created_at)
) STRICT;
INSERT INTO approval_intents SELECT * FROM approval_intents_v7;
INSERT INTO approval_intent_challenges SELECT * FROM approval_intent_challenges_v7;
DROP TABLE approval_intent_challenges_v7;
DROP TABLE approval_intents_v7;
CREATE INDEX approval_intents_open_by_credential ON approval_intents (credential_id)
  WHERE consumed_at IS NULL AND closed_at IS NULL;
CREATE INDEX approval_intents_open_by_organization ON approval_intents (organization_id)
  WHERE consumed_at IS NULL AND closed_at IS NULL;
CREATE INDEX approval_intents_identity_created ON approval_intents (identity_id, created_at);
CREATE INDEX approval_intents_expires ON approval_intents (expires_at);
CREATE INDEX approval_intent_challenges_identity ON approval_intent_challenges (identity_id, created_at);
CREATE INDEX approval_intent_challenges_intent ON approval_intent_challenges (intent_id);
`},
}
