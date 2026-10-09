// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * When a Platform Credential expires, as the platform last said (ADR-0031,
 * amendment 2026-10-09): GitHub reports it for personal access tokens that
 * expire. Both columns are NULL until a stored credential is used and the
 * platform says, and again after a credential replacement. NULL is unknown,
 * never "does not expire": GitHub stays silent for tokens without an expiry,
 * and other platforms say nothing at all.
 *
 * The runtime role's grants on platform_connections are table grants
 * (migration 3), which cover the new columns.
 */
export const sql = /* sql */ `
ALTER TABLE platform_connections
  ADD COLUMN credential_expires_at timestamptz,
  ADD COLUMN credential_expiry_seen_at timestamptz,
  ADD CONSTRAINT platform_connections_credential_expiry_seen
    CHECK ((credential_expires_at IS NULL) = (credential_expiry_seen_at IS NULL));
`;
