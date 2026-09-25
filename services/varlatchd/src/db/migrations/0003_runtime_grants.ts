// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Structural append-only + least privilege (ADR-0016/0019): when the
 * deployment's runtime role exists, grant it normal table access but only
 * INSERT/SELECT on audit_events — the runtime identity cannot rewrite
 * history. No-op where the role doesn't exist (tests, ad-hoc databases).
 */
export const sql = /* sql */ `
DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'varlatchd_runtime') THEN
    GRANT USAGE ON SCHEMA public TO varlatchd_runtime;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO varlatchd_runtime;
    REVOKE UPDATE, DELETE ON audit_events FROM varlatchd_runtime;
    REVOKE ALL ON varlatch_migrations FROM varlatchd_runtime;
    GRANT SELECT ON varlatch_migrations TO varlatchd_runtime;
    -- Tables created by FUTURE migrations default to runtime access; any
    -- future audit-class table must explicitly revoke UPDATE/DELETE again.
    ALTER DEFAULT PRIVILEGES FOR ROLE varlatchd_migrate IN SCHEMA public
      GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO varlatchd_runtime;
  END IF;
END
$$;
`;
