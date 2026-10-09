// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * GitHub App registrations in flight (ADR-0047 Decision 1 and its
 * 2026-10-09 amendment): the manifest flow's `state`, one row per started
 * registration.
 *
 * Only the state's SHA-256 is stored. A row is bound to the actor who
 * started it, the Organization, and the GitHub account the App is meant to
 * be created on (login and type), which the owner check compares GitHub's
 * answer with. It is consumed once, atomically, and expires after an hour,
 * as GitHub's code does. Rows more than a day past their expiry are deleted
 * when a later registration starts.
 */
export const sql = /* sql */ `
CREATE TABLE github_app_registrations (
  state_hash text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  actor_identity_id text NOT NULL REFERENCES identities(id),
  account_login text NOT NULL CHECK (account_login ~ '^[A-Za-z0-9][A-Za-z0-9-]{0,38}$'),
  account_type text NOT NULL CHECK (account_type IN ('organization', 'user')),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  CHECK (expires_at > created_at)
);
CREATE INDEX github_app_registrations_expiry ON github_app_registrations(expires_at);
`;
