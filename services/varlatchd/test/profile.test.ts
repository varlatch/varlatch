// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
} from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * /v1/me/profile (UI overhaul phase 1): the human caller's display name plus
 * the Better Auth email/image behind auth_user_links, and the identities-list
 * enrichment that surfaces email/image for humans (nulls for machines).
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let adminId: string;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  adminId = consumed.identityId;
  const cred = await issueCredential(ctx.db, { identityId: adminId, kind: "cli" });
  adminToken = cred.token;
  app = buildApp(ctx);
});
afterEach(async () => {
  await ctx.close();
});

function auth(token = adminToken): HeadersInit {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

async function linkBetterAuthUser(email = "jeremy@example.com", image: string | null = null) {
  await ctx.db.query(
    `INSERT INTO "user" (id, name, email, "image") VALUES ('ba_user_1', 'Jeremy', $1, $2)`,
    [email, image],
  );
  await ctx.db.query(
    "INSERT INTO auth_user_links (better_auth_user_id, identity_id) VALUES ('ba_user_1', $1)",
    [adminId],
  );
}

async function machineToken(): Promise<string> {
  const orgRes = await app.request("/v1/organizations", {
    method: "POST",
    headers: auth(),
    body: JSON.stringify({ name: "Acme", slug: "acme" }),
  });
  expect(orgRes.status).toBe(201);
  const idnRes = await app.request("/v1/organizations/acme/identities", {
    method: "POST",
    headers: auth(),
    body: JSON.stringify({ name: "svc", kind: "service" }),
  });
  expect(idnRes.status).toBe(201);
  const created = (await idnRes.json()) as { credential: string };
  return created.credential;
}

describe("GET /v1/me/profile", () => {
  it("returns the linked Better Auth email and image for humans", async () => {
    await linkBetterAuthUser("jeremy@example.com", "https://example.com/a.png");
    const res = await app.request("/v1/me/profile", { headers: auth() });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      identityId: adminId,
      name: "Jeremy",
      email: "jeremy@example.com",
      image: "https://example.com/a.png",
    });
  });

  it("returns nulls for a human with no auth link", async () => {
    const res = await app.request("/v1/me/profile", { headers: auth() });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      identityId: adminId,
      name: "Jeremy",
      email: null,
      image: null,
    });
  });

  it("is not found for machine identities", async () => {
    const token = await machineToken();
    const res = await app.request("/v1/me/profile", { headers: auth(token) });
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("RESOURCE_NOT_FOUND");
  });
});

describe("PATCH /v1/me/profile", () => {
  it("updates the Better Auth user and the identity name", async () => {
    await linkBetterAuthUser();
    const res = await app.request("/v1/me/profile", {
      method: "PATCH",
      headers: auth(),
      body: JSON.stringify({ name: "Jeremy D", image: "data:image/png;base64,aGk=" }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      identityId: adminId,
      name: "Jeremy D",
      email: "jeremy@example.com",
      image: "data:image/png;base64,aGk=",
    });
    const idn = await ctx.db.query("SELECT name FROM identities WHERE id = $1", [adminId]);
    expect((idn.rows[0] as { name: string }).name).toBe("Jeremy D");
    const ba = await ctx.db.query(`SELECT name, "image" FROM "user" WHERE id = 'ba_user_1'`);
    expect(ba.rows[0]).toMatchObject({ name: "Jeremy D", image: "data:image/png;base64,aGk=" });
    // The org identity listing shows the updated display name + profile data.
    await machineToken(); // creates org acme as a side effect
    const list = await app.request("/v1/organizations/acme/identities", { headers: auth() });
    const items = ((await list.json()) as { items: Record<string, unknown>[] }).items;
    const me = items.find((i) => i.id === adminId);
    expect(me).toMatchObject({ name: "Jeremy D", email: "jeremy@example.com" });
    const machine = items.find((i) => i.kind === "service");
    expect(machine).toMatchObject({ email: null, image: null });
  });

  it("clears the image with null and leaves name alone", async () => {
    await linkBetterAuthUser("jeremy@example.com", "https://example.com/a.png");
    const res = await app.request("/v1/me/profile", {
      method: "PATCH",
      headers: auth(),
      body: JSON.stringify({ image: null }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ name: "Jeremy", image: null });
  });

  it("rejects non-data/https image URLs and oversized images", async () => {
    await linkBetterAuthUser();
    for (const image of ["http://insecure.example/a.png", "javascript:alert(1)", "ftp://x/a"]) {
      const res = await app.request("/v1/me/profile", {
        method: "PATCH",
        headers: auth(),
        body: JSON.stringify({ image }),
      });
      expect(res.status).toBe(422);
    }
    const big = `data:image/png;base64,${"A".repeat(103_000)}`;
    const bigRes = await app.request("/v1/me/profile", {
      method: "PATCH",
      headers: auth(),
      body: JSON.stringify({ image: big }),
    });
    expect(bigRes.status).toBe(422);
  });

  it("is not found for machine identities", async () => {
    const token = await machineToken();
    const res = await app.request("/v1/me/profile", {
      method: "PATCH",
      headers: auth(token),
      body: JSON.stringify({ name: "nope" }),
    });
    expect(res.status).toBe(404);
  });
});
