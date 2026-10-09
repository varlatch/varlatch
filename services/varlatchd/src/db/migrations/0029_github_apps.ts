// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * GitHub App connections (ADR-0047).
 *
 * - github_apps: a GitHub App an Organization registered (or imported), on
 *   the GitHub account it serves. GitHub's own identifiers (App id, slug,
 *   client id) and its owner as GitHub answered (login, id, type), and the
 *   App's private key, wrapped under the Organization KEK like a Platform
 *   Credential. version is the expected-version guard for key rotation
 *   (Decision 5). Removal deletes the wrapped key and keeps the row for the
 *   Connections that name it: removed_at and a NULL key go together.
 *   At most one live App per Organization and GitHub account, and a GitHub
 *   App is live in at most one Organization, so its key never rests under
 *   two KEKs that a rotation would leave apart.
 * - platform_connections.credential_kind: 'token' (a Platform Credential in
 *   credential_envelope, as before) or 'github-app' (no stored token: the
 *   App and the installation tokens are minted from, on github-actions
 *   only). The App belongs to the Connection's Organization. An App
 *   Connection never records a credential expiry (Decision 4): its tokens
 *   are minted hourly, and their expiry is not the Connection's.
 *
 * Existing Connections are personal access tokens and become 'token'. The
 * runtime role's access to the new table comes from migration 3's default
 * privileges; the existing grants on platform_connections cover its new
 * columns.
 */
export const sql = /* sql */ `
CREATE TABLE github_apps (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  github_app_id bigint NOT NULL,
  slug text NOT NULL,
  client_id text NOT NULL,
  owner_login text NOT NULL,
  owner_id bigint NOT NULL,
  owner_type text NOT NULL CHECK (owner_type IN ('organization', 'user')),
  key_envelope jsonb,
  created_by text REFERENCES identities(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  removed_at timestamptz,
  version integer NOT NULL DEFAULT 1,
  updated_at timestamptz,
  UNIQUE (id, organization_id),
  CONSTRAINT github_apps_key_until_removed
    CHECK ((removed_at IS NULL) = (key_envelope IS NOT NULL))
);
CREATE UNIQUE INDEX github_apps_live_app
  ON github_apps(github_app_id) WHERE removed_at IS NULL;
CREATE UNIQUE INDEX github_apps_live_owner
  ON github_apps(organization_id, owner_id) WHERE removed_at IS NULL;

ALTER TABLE platform_connections
  ADD COLUMN credential_kind text NOT NULL DEFAULT 'token'
    CHECK (credential_kind IN ('token', 'github-app')),
  ADD COLUMN github_app_id text,
  ADD COLUMN github_installation_id bigint,
  ALTER COLUMN credential_envelope DROP NOT NULL,
  ADD CONSTRAINT platform_connections_github_app_fk
    FOREIGN KEY (github_app_id, organization_id) REFERENCES github_apps(id, organization_id),
  ADD CONSTRAINT platform_connections_credential_kind_shape CHECK (
    (credential_kind = 'token'
      AND credential_envelope IS NOT NULL
      AND github_app_id IS NULL AND github_installation_id IS NULL)
    OR
    (credential_kind = 'github-app'
      AND platform = 'github-actions'
      AND credential_envelope IS NULL
      AND github_app_id IS NOT NULL AND github_installation_id IS NOT NULL
      AND credential_expires_at IS NULL AND credential_expiry_seen_at IS NULL)
  );
CREATE INDEX platform_connections_github_app_idx
  ON platform_connections(github_app_id) WHERE revoked_at IS NULL AND github_app_id IS NOT NULL;
`;
