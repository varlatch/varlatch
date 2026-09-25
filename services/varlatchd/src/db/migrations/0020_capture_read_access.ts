// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Online capture (ADR-0036) dumps the Secret Plane as the runtime role, so
 * varlatchd can stop — and confirm it stopped — its own dump: PostgreSQL
 * only lets superusers signal superuser backends. The dump needs SELECT on
 * every table, including the audit counter 0017 withheld entirely. Read
 * access only: the counter's value is max(event_order), which the runtime
 * role can already read, and it still cannot change audit ordering.
 */
export const sql = /* sql */ `
DO $$ BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'varlatchd_runtime') THEN
    GRANT SELECT ON audit_position TO varlatchd_runtime;
  END IF;
END $$;
`;
