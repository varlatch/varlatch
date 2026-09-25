// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * JWT signing keys for the Application Plane trust direction (ADR-0007 §2,
 * ADR-0018 §6): varlatchd mints short-lived audience-scoped JWTs that Convex
 * verifies via JWKS; varlatchd never accepts them back. Private keys are
 * stored only wrapped under the root KEK.
 */
export const sql = /* sql */ `
CREATE TABLE signing_keys (
  id text PRIMARY KEY,
  algorithm text NOT NULL CHECK (algorithm = 'ES256'),
  public_jwk jsonb NOT NULL,
  private_key_wrapped jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz
);

DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'varlatchd_runtime') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON signing_keys TO varlatchd_runtime;
  END IF;
END
$$;
`;
