// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * What a person received, and how it is known (ADR-0052 Decisions 6, 7).
 *
 * member_exposure is the exposure index: one row per person, value version,
 * environment the version was received through, and way of receiving it
 * (revealed, delivered to a process, read for export, written), with the
 * first and last time. Live disclosures and writes upsert it in the
 * transaction of their audit event, before the event; the times only ever
 * widen. No foreign key to value_versions: the evidence outlives anything
 * that happens to the value.
 *
 * exposure_backfill builds both indexes (this one and member_integrations)
 * from the audit events recorded before live indexing began: those up to
 * until_order, the audit position when this migration ran. cursor is the
 * last event_order a batch committed, in the same transaction as its rows,
 * so a restart resumes exactly. finished_at is set when cursor reaches
 * until_order; until then a report says which period it does not cover.
 *
 * exposure_confirmations records an operator's confirmation that a version
 * was revoked or rotated at its provider: once per version, with the
 * member whose report it was confirmed from and who confirmed it.
 *
 * The runtime role's default privileges (migration 3) cover the new tables.
 */
export const sql = /* sql */ `
CREATE TABLE member_exposure (
  organization_id text NOT NULL REFERENCES organizations(id),
  identity_id text NOT NULL REFERENCES identities(id),
  version_id text NOT NULL,
  item_name text NOT NULL,
  environment_id text NOT NULL,
  way text NOT NULL CHECK (way IN ('revealed','delivered','export','written')),
  first_at timestamptz NOT NULL,
  last_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, identity_id, version_id, environment_id, way)
);

CREATE TABLE exposure_backfill (
  singleton boolean PRIMARY KEY CHECK (singleton),
  cursor bigint NOT NULL,
  until_order bigint NOT NULL,
  finished_at timestamptz
);
INSERT INTO exposure_backfill (singleton, cursor, until_order, finished_at)
  SELECT true, 0, value, CASE WHEN value = 0 THEN now() END FROM audit_position;

CREATE TABLE exposure_confirmations (
  organization_id text NOT NULL REFERENCES organizations(id),
  version_id text NOT NULL,
  identity_id text NOT NULL REFERENCES identities(id),
  actor_identity_id text NOT NULL REFERENCES identities(id),
  confirmed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, version_id)
);
`;
