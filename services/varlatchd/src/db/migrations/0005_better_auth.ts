// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Better Auth core + passkey tables (ADR-0008/0009). Hand-written from the
 * v1.7.3 field definitions (reviewed SQL per ADR-0008 — never auto-applied by
 * the library), plus the link table mapping Better Auth users to Varlatch
 * Identities so Better Auth IDs never leak into the domain (ADR-0008 §Replaceability).
 * Runtime grants come from 0003's default privileges.
 */
export const sql = /* sql */ `
CREATE TABLE "user" (
  "id" text PRIMARY KEY,
  "name" text NOT NULL,
  "email" text NOT NULL UNIQUE,
  "emailVerified" boolean NOT NULL DEFAULT false,
  "image" text,
  "createdAt" timestamptz NOT NULL DEFAULT now(),
  "updatedAt" timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE "session" (
  "id" text PRIMARY KEY,
  "expiresAt" timestamptz NOT NULL,
  "token" text NOT NULL UNIQUE,
  "createdAt" timestamptz NOT NULL DEFAULT now(),
  "updatedAt" timestamptz NOT NULL DEFAULT now(),
  "ipAddress" text,
  "userAgent" text,
  "userId" text NOT NULL REFERENCES "user"("id") ON DELETE CASCADE
);
CREATE INDEX "session_userId_idx" ON "session"("userId");

CREATE TABLE "account" (
  "id" text PRIMARY KEY,
  "accountId" text NOT NULL,
  "providerId" text NOT NULL,
  "userId" text NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  "accessToken" text,
  "refreshToken" text,
  "idToken" text,
  "accessTokenExpiresAt" timestamptz,
  "refreshTokenExpiresAt" timestamptz,
  "scope" text,
  "password" text,
  "createdAt" timestamptz NOT NULL DEFAULT now(),
  "updatedAt" timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX "account_userId_idx" ON "account"("userId");

CREATE TABLE "verification" (
  "id" text PRIMARY KEY,
  "identifier" text NOT NULL,
  "value" text NOT NULL,
  "expiresAt" timestamptz NOT NULL,
  "createdAt" timestamptz NOT NULL DEFAULT now(),
  "updatedAt" timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX "verification_identifier_idx" ON "verification"("identifier");

CREATE TABLE "passkey" (
  "id" text PRIMARY KEY,
  "name" text,
  "publicKey" text NOT NULL,
  "userId" text NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  "credentialID" text NOT NULL,
  "counter" integer NOT NULL,
  "deviceType" text NOT NULL,
  "backedUp" boolean NOT NULL,
  "transports" text,
  "createdAt" timestamptz,
  "aaguid" text
);
CREATE INDEX "passkey_userId_idx" ON "passkey"("userId");
CREATE INDEX "passkey_credentialID_idx" ON "passkey"("credentialID");

-- Authentication Method mapping: Better Auth user -> Varlatch Identity.
CREATE TABLE auth_user_links (
  better_auth_user_id text PRIMARY KEY REFERENCES "user"("id") ON DELETE CASCADE,
  identity_id text NOT NULL UNIQUE REFERENCES identities(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
`;
