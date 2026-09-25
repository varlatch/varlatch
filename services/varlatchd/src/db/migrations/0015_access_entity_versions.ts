// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * In-place updates for access entities (ADR-0029): roles, groups (incl.
 * teams), webhooks, and requirements gain a monotonic configuration version
 * for optimistic concurrency (expectedVersion -> VERSION_CONFLICT) and an
 * updated_at. Join mutations (membership, team projects) and webhook
 * delivery progress never touch the version. Grants deliberately get
 * neither: a Grant's declaration is immutable — edits are atomic
 * revoke-and-replace with linked audit events.
 */
export const sql = /* sql */ `
ALTER TABLE roles ADD COLUMN version integer NOT NULL DEFAULT 1;
ALTER TABLE roles ADD COLUMN updated_at timestamptz;

ALTER TABLE groups ADD COLUMN version integer NOT NULL DEFAULT 1;
ALTER TABLE groups ADD COLUMN updated_at timestamptz;

ALTER TABLE webhooks ADD COLUMN version integer NOT NULL DEFAULT 1;
ALTER TABLE webhooks ADD COLUMN updated_at timestamptz;

ALTER TABLE requirements ADD COLUMN version integer NOT NULL DEFAULT 1;
ALTER TABLE requirements ADD COLUMN updated_at timestamptz;
`;
