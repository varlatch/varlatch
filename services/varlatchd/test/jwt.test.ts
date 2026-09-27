// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import {
  ensureSigningKey,
  mintConvexToken,
  publicJwks,
  verifyConvexToken,
} from "../src/auth/jwt.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
} from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

let ctx: AppCtx & { close: () => Promise<void> };
beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
});
afterEach(async () => {
  await ctx.close();
});

describe("application-plane JWT issuer", () => {
  it("mints ES256 tokens that verify against the published JWKS", async () => {
    const key = await ensureSigningKey(ctx);
    expect((await ensureSigningKey(ctx)).id).toBe(key.id); // stable
    const minted = await mintConvexToken(ctx, "https://varlatch.example", {
      sub: "idn_x",
      name: "Jeremy",
      orgIds: ["org_1"],
      installationAdmin: true,
    });
    const jwks = await publicJwks(ctx);
    expect(jwks.keys[0]).toMatchObject({ kty: "EC", crv: "P-256", alg: "ES256" });
    const payload = verifyConvexToken(jwks, minted.token, "https://varlatch.example");
    expect(payload).toMatchObject({
      sub: "idn_x",
      aud: "convex",
      orgIds: ["org_1"],
      installationAdmin: true,
    });
    // Wrong issuer or tampering fails.
    expect(verifyConvexToken(jwks, minted.token, "https://evil.example")).toBeNull();
    const tampered = minted.token.replace(/\.[^.]+$/, ".AAAA");
    expect(verifyConvexToken(jwks, tampered, "https://varlatch.example")).toBeNull();
  });

  it("exchange endpoint mints tokens; varlatchd never accepts them back", async () => {
    await ensureInstallation(ctx);
    const grant = await issueBootstrapGrant(ctx);
    const { identityId } = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
    const cred = await issueCredential(ctx.db, { identityId, kind: "cli" });
    const app = buildApp(ctx, { issuer: "https://varlatch.example" });

    const res = await app.request("/v1/tokens/convex", {
      method: "POST",
      headers: { Authorization: `Bearer ${cred.token}` },
    });
    expect(res.status).toBe(200);
    const { token } = await res.json();

    // JWKS is published after (and because) the signing key exists.
    const jwksRes = await app.request("/.well-known/jwks.json");
    expect(jwksRes.status).toBe(200);
    const payload = verifyConvexToken(await jwksRes.json(), token, "https://varlatch.example");
    expect(payload).toMatchObject({ sub: identityId, installationAdmin: true });

    // One-way trust: the JWT is not a Secret Plane credential (ADR-0007 §2).
    const rejected = await app.request("/v1/organizations", {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(rejected.status).toBe(401);
  });
});
