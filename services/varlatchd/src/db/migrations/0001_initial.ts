// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Initial Secret Plane schema (ADR-0005/0011/0012/0015/0016).
 *
 * Conventions: text IDs with typed prefixes (see ids.ts); jsonb for versioned
 * envelopes and structured records; authoritative timestamps default to now()
 * server-side. Audit tables receive INSERT/SELECT-only privileges for the
 * runtime role via migration 0002-style GRANTs applied by deployment tooling
 * (role names are deployment-specific; see infra/compose).
 */
export const sql = /* sql */ `

CREATE TABLE installation (
  id text PRIMARY KEY,
  kek_canary jsonb NOT NULL,
  bootstrapped_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT installation_singleton CHECK (id LIKE 'inst_%')
);

CREATE TABLE identities (
  id text PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('human','service','workload','ci','broker','agent')),
  name text NOT NULL,
  disabled boolean NOT NULL DEFAULT false,
  installation_admin boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE credentials (
  id text PRIMARY KEY,
  identity_id text NOT NULL REFERENCES identities(id),
  kind text NOT NULL CHECK (kind IN ('service','cli','browser')),
  name text,
  token_hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  revoked_at timestamptz
);
CREATE INDEX credentials_identity_idx ON credentials(identity_id);

CREATE TABLE setup_grants (
  id text PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('bootstrap','recover')),
  subject_identity_id text REFERENCES identities(id),
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE organizations (
  id text PRIMARY KEY,
  slug text NOT NULL UNIQUE,
  name text NOT NULL,
  wrapped_org_kek jsonb NOT NULL,
  deleted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE org_memberships (
  organization_id text NOT NULL REFERENCES organizations(id),
  identity_id text NOT NULL REFERENCES identities(id),
  role text NOT NULL CHECK (role IN ('admin','member')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, identity_id)
);

CREATE TABLE projects (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  slug text NOT NULL,
  name text NOT NULL,
  contract_authority text NOT NULL CHECK (contract_authority IN ('git','managed')),
  active_contract_revision_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, slug)
);

CREATE TABLE environments (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id),
  name text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('shared','personal','preview')),
  tier text NOT NULL CHECK (tier IN ('development','staging','production')),
  parent_environment_id text REFERENCES environments(id),
  owner_identity_id text REFERENCES identities(id),
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, name),
  -- One-level inheritance only (ADR-0012) is enforced in the domain layer;
  -- the schema guarantees referential shape.
  CONSTRAINT derived_env_kind CHECK (
    (parent_environment_id IS NULL AND kind = 'shared')
    OR (parent_environment_id IS NOT NULL AND kind IN ('personal','preview'))
  )
);

CREATE TABLE env_values (
  id text PRIMARY KEY,
  environment_id text NOT NULL REFERENCES environments(id),
  item_name text NOT NULL,
  current_version_id text,
  deleted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (environment_id, item_name)
);

CREATE TABLE value_versions (
  id text PRIMARY KEY,
  value_id text NOT NULL REFERENCES env_values(id),
  payload jsonb NOT NULL,
  wrapped_dek jsonb NOT NULL,
  previous_version_id text REFERENCES value_versions(id),
  created_by text REFERENCES identities(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX value_versions_value_idx ON value_versions(value_id);

CREATE TABLE contract_revisions (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id),
  content_hash text NOT NULL,
  contract jsonb NOT NULL,
  provenance jsonb,
  created_by text REFERENCES identities(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, content_hash)
);

CREATE TABLE varlock_env_mappings (
  project_id text NOT NULL REFERENCES projects(id),
  varlock_name text NOT NULL,
  environment_id text NOT NULL REFERENCES environments(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (project_id, varlock_name)
);

CREATE TABLE grants (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  subject_identity_id text NOT NULL REFERENCES identities(id),
  scope jsonb NOT NULL,
  actions text[] NOT NULL,
  created_by text REFERENCES identities(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE INDEX grants_subject_idx ON grants(subject_identity_id) WHERE revoked_at IS NULL;

CREATE TABLE requirements (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  kind text NOT NULL CHECK (kind IN ('tailnet')),
  target jsonb NOT NULL,
  config jsonb NOT NULL,
  created_by text REFERENCES identities(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);

CREATE TABLE audit_events (
  id text PRIMARY KEY,
  schema_version integer NOT NULL DEFAULT 1,
  event_type text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  actor_identity_id text,
  authentication_method_id text,
  credential_id text,
  organization_id text,
  action text,
  resource jsonb,
  decision text NOT NULL CHECK (decision IN ('allow','deny','info')),
  authz jsonb,
  tailnet jsonb,
  listener text CHECK (listener IN ('ordinary','tailnet')),
  request_id text,
  metadata jsonb
);
CREATE INDEX audit_events_org_time_idx ON audit_events(organization_id, occurred_at DESC, id DESC);

CREATE TABLE idempotency_keys (
  identity_id text NOT NULL REFERENCES identities(id),
  endpoint text NOT NULL,
  idempotency_key text NOT NULL,
  body_hash text NOT NULL,
  response jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (identity_id, endpoint, idempotency_key)
);
`;
