// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Removing a person from an Organization (ADR-0052).
 *
 * org_memberships.removed_at ends a membership without deleting the row, so
 * former members stay listed and named in history. A person acts in an
 * Organization only through a live row (removed_at IS NULL). version is a
 * fence: writes that give a person something removal must clean up (a
 * Grant, a group link, an invitation they issue) bump it, so they conflict
 * with a concurrent removal's update of the same row instead of slipping
 * past its snapshot.
 *
 * credentials.issued_by names who was shown a credential's token at
 * issuance, for removal's review list. Earlier credentials take it from
 * their credential.issued audit event.
 *
 * membership_removals records each removal, and removal_authority,
 * removal_requirements and removal_conditions what the person could reach
 * at that moment: per environment, the value actions their built-in role
 * and Grants granted and where each came from, and copies of the Tailnet
 * Requirements those actions were conditional on. IDs and names only.
 *
 * member_integrations is the integration index: one row per identity and
 * Sync Target or Platform Connection they created or changed, with the
 * kinds of change and the first and last time.
 *
 * The runtime role's default privileges (migration 3) cover the new tables.
 */
export const sql = /* sql */ `
ALTER TABLE org_memberships ADD COLUMN removed_at timestamptz;
ALTER TABLE org_memberships ADD COLUMN version bigint NOT NULL DEFAULT 0;
CREATE INDEX org_memberships_live_identity ON org_memberships (identity_id) WHERE removed_at IS NULL;

ALTER TABLE credentials ADD COLUMN issued_by text REFERENCES identities(id);
UPDATE credentials c SET issued_by = e.actor_identity_id
  FROM audit_events e
  WHERE e.event_type = 'credential.issued' AND e.credential_id = c.id
    AND e.actor_identity_id IS NOT NULL
    AND EXISTS (SELECT 1 FROM identities i WHERE i.id = e.actor_identity_id);
CREATE INDEX credentials_issued_by ON credentials (issued_by) WHERE issued_by IS NOT NULL;

CREATE TABLE membership_removals (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  identity_id text NOT NULL REFERENCES identities(id),
  role text NOT NULL CHECK (role IN ('admin','member')),
  actor_identity_id text NOT NULL REFERENCES identities(id),
  removed_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, identity_id)
);

CREATE TABLE removal_authority (
  removal_id text NOT NULL REFERENCES membership_removals(id),
  environment_id text NOT NULL REFERENCES environments(id),
  action text NOT NULL CHECK (action IN ('config.metadata.read','config.value.read','secret.reveal','secret.use')),
  source text NOT NULL,
  role text CHECK (role IN ('admin','member')),
  grant_id text,
  via_group_id text,
  role_id text,
  PRIMARY KEY (removal_id, environment_id, action, source)
);

CREATE TABLE removal_requirements (
  removal_id text NOT NULL REFERENCES membership_removals(id),
  requirement_id text NOT NULL,
  requirement_version integer,
  target jsonb NOT NULL,
  selector jsonb NOT NULL,
  PRIMARY KEY (removal_id, requirement_id)
);

CREATE TABLE removal_conditions (
  removal_id text NOT NULL REFERENCES membership_removals(id),
  environment_id text NOT NULL REFERENCES environments(id),
  requirement_id text NOT NULL,
  PRIMARY KEY (removal_id, environment_id, requirement_id),
  FOREIGN KEY (removal_id, requirement_id) REFERENCES removal_requirements(removal_id, requirement_id)
);

CREATE TABLE member_integrations (
  organization_id text NOT NULL REFERENCES organizations(id),
  identity_id text NOT NULL REFERENCES identities(id),
  kind text NOT NULL CHECK (kind IN ('target','connection')),
  resource_id text NOT NULL,
  changes text[] NOT NULL,
  first_at timestamptz NOT NULL,
  last_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, identity_id, kind, resource_id)
);
`;
