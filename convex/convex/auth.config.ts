// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Trust direction (ADR-0005/0007): Convex VERIFIES varlatchd-issued JWTs and
 * never mints anything varlatchd accepts. Issuer + JWKS point at varlatchd;
 * configured per deployment via Convex env vars.
 */
export default {
  providers: [
    {
      type: "customJwt",
      issuer: process.env.VARLATCH_ISSUER!,
      jwks: process.env.VARLATCH_JWKS_URL!,
      algorithm: "ES256",
      applicationID: "convex",
    },
  ],
};
