// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Custom Roles, Groups, and Teams (ADR-0028): reuse over the flat Grant
 * model. All three compile down to the Grants the evaluator already decides —
 * default-deny is unchanged. A Role is a named Action bundle a Grant may cite
 * instead of literal actions; a Group is an identity set a Grant may target as
 * its subject; a Team is a Group that also owns Projects, targetable by a
 * team-scoped Grant. loadGrants() expands all three into flat GrantRecords.
 */
export const sql = /* sql */ `
CREATE TABLE roles (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  name text NOT NULL,
  actions text[] NOT NULL,
  created_by text REFERENCES identities(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE UNIQUE INDEX roles_org_name_key ON roles(organization_id, name) WHERE revoked_at IS NULL;

CREATE TABLE groups (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  name text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('group','team')),
  created_by text REFERENCES identities(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE UNIQUE INDEX groups_org_name_key ON groups(organization_id, name) WHERE revoked_at IS NULL;

CREATE TABLE group_members (
  group_id text NOT NULL REFERENCES groups(id),
  identity_id text NOT NULL REFERENCES identities(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, identity_id)
);
CREATE INDEX group_members_identity_idx ON group_members(identity_id);

CREATE TABLE team_projects (
  team_id text NOT NULL REFERENCES groups(id),
  project_id text NOT NULL REFERENCES projects(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (team_id, project_id)
);

-- A Grant's subject is an identity OR a group; its permissions are literal
-- actions OR a role reference. Exactly one of each pair.
ALTER TABLE grants ALTER COLUMN subject_identity_id DROP NOT NULL;
ALTER TABLE grants ALTER COLUMN actions DROP NOT NULL;
ALTER TABLE grants ADD COLUMN subject_group_id text REFERENCES groups(id);
ALTER TABLE grants ADD COLUMN role_id text REFERENCES roles(id);
ALTER TABLE grants ADD CONSTRAINT grants_subject_one CHECK (
  (subject_identity_id IS NOT NULL) <> (subject_group_id IS NOT NULL)
);
ALTER TABLE grants ADD CONSTRAINT grants_permission_one CHECK (
  (actions IS NOT NULL) OR (role_id IS NOT NULL)
);
CREATE INDEX grants_subject_group_idx ON grants(subject_group_id) WHERE revoked_at IS NULL;
`;
