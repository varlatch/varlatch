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
	// exercise-only credential's token_hash, nor a single-use Capability's
	// secret_hash, nor a limited binding's claims.
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
}
