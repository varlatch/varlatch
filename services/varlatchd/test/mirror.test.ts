// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { recordAuditEvent } from "../src/audit/events.js";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
} from "../src/domain/bootstrap.js";
import {
  latestEventCursor,
  syncNewMirrorEvents,
  purgeRetiredMirrors,
  type MirrorConfig,
} from "../src/mirror/publisher.js";
import { buildApp } from "../src/http/app.js";
import { testDb } from "./helpers/pglite.js";

/**
 * Incremental mirror publishing: new audit events flow to Convex within one
 * tick, followed by a per-org changeSignal carrying the touched domains so
 * the UI can invalidate its authoritative queries.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;

const config: MirrorConfig = { convexUrl: "https://convex.test", issuer: "http://localhost" };

beforeEach(async () => {
  const db = await testDb();
  await runMigrations(db);
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  const cred = await issueCredential(ctx.db, { identityId: consumed.identityId, kind: "cli" });
  adminToken = cred.token;
  app = buildApp(ctx);
});
afterEach(async () => {
  await ctx.close();
});

async function post(path: string, body: unknown) {
  return app.request(path, {
    method: "POST",
    headers: { Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

interface Upsert {
  kind: string;
  resourceId: string;
  organizationId: string | null;
  data: Record<string, unknown>;
}

function fakeConvex(upserts: Upsert[]): typeof fetch {
  return (async (_url: unknown, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { path: string; args: Upsert };
    if (body.path === "mirror:upsert") upserts.push(body.args);
    return new Response(JSON.stringify({ status: "success" }), { status: 200 });
  }) as typeof fetch;
}

describe("incremental mirror publishing", () => {
  it("publishes a per-org changeSignal for new audit events, then goes idle", async () => {
    const cursor = await latestEventCursor(ctx);

    const orgRes = await post("/v1/organizations", { name: "Acme", slug: "acme" });
    expect(orgRes.ok).toBe(true);
    const org = (await orgRes.json()) as { id: string };
    await post("/v1/organizations/acme/projects", {
      name: "API",
      slug: "api",
      contractAuthority: "git",
    });

    const upserts: Upsert[] = [];
    const first = await syncNewMirrorEvents(ctx, config, cursor, fakeConvex(upserts));
    expect(first.pushed).toBeGreaterThan(0);

    // The events themselves are not mirrored (ADR-0036): nothing read them.
    const kinds = upserts.map((u) => u.kind);
    expect(kinds).not.toContain("auditEvent");
    const signals = upserts.filter((u) => u.kind === "changeSignal");
    expect(signals).toHaveLength(1);
    expect(signals[0]!.resourceId).toBe(org.id);
    expect(signals[0]!.data.domains).toEqual(
      expect.arrayContaining(["organization", "project"]),
    );
    expect(signals[0]!.data.lastEventId).toBeTruthy();
    // Every payload is metadata only — never values or key material.
    for (const u of signals) expect(Object.keys(u.data).sort()).toEqual(["domains", "lastEventId", "occurredAt"]);

    // Cursor advanced: a second pass with no new events pushes nothing.
    const again: Upsert[] = [];
    const second = await syncNewMirrorEvents(ctx, config, first.cursor, fakeConvex(again));
    expect(second.pushed).toBe(0);
    expect(again).toHaveLength(0);
  });

  it("skips events without an organization but still advances the cursor", async () => {
    const cursor = await latestEventCursor(ctx);
    // An org-less audit event with no actor (e.g. bootstrap/setup flows).
    await recordAuditEvent(ctx.db, { eventType: "setup.grant_rejected", decision: "deny" });
    const upserts: Upsert[] = [];
    const result = await syncNewMirrorEvents(ctx, config, cursor, fakeConvex(upserts));
    expect(upserts.filter((u) => u.kind === "changeSignal")).toHaveLength(0);
    expect(upserts.filter((u) => u.kind === "identitySignal")).toHaveLength(0);
    expect(result.cursor).not.toEqual(cursor);
  });

  it("signals the acting identity for org-less events (me-scoped credentials)", async () => {
    const cursor = await latestEventCursor(ctx);
    // Credential lifecycle events carry an actor but no organization.
    await recordAuditEvent(ctx.db, {
      eventType: "credential.revoked",
      decision: "info",
      actorIdentityId: "idn_me",
    });
    const upserts: Upsert[] = [];
    await syncNewMirrorEvents(ctx, config, cursor, fakeConvex(upserts));
    expect(upserts.filter((u) => u.kind === "changeSignal")).toHaveLength(0);
    const identity = upserts.filter((u) => u.kind === "identitySignal");
    expect(identity).toHaveLength(1);
    expect(identity[0]).toMatchObject({
      resourceId: "idn_me",
      organizationId: null,
      data: { domains: ["credential"] },
    });
    expect(identity[0]!.data.lastEventId).toBeTruthy();
  });
});

describe("retired Mirror kinds (ADR-0036)", () => {
  it("purges auditEvent Mirrors in bounded batches until Convex reports done", async () => {
    const calls: { path: string; args: unknown }[] = [];
    let remaining = 3;
    const fetchImpl = (async (_url: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { path: string; args: unknown };
      calls.push(body);
      remaining--;
      return new Response(JSON.stringify({ status: "success", value: { deleted: 256, done: remaining === 0 } }), { status: 200 });
    }) as typeof fetch;
    expect(await purgeRetiredMirrors(ctx, config, fetchImpl)).toBe(true);
    expect(calls).toHaveLength(3);
    expect(calls.every((c) => c.path === "mirror:purgeRetired" && (c.args as { kind: string }).kind === "auditEvent")).toBe(true);
  });
  it("stops after its batch limit and reports not done", async () => {
    const fetchImpl = (async () => new Response(JSON.stringify({ status: "success", value: { deleted: 256, done: false } }), { status: 200 })) as typeof fetch;
    expect(await purgeRetiredMirrors(ctx, config, fetchImpl, 2)).toBe(false);
  });
  it("fails without harm while the Convex function is not deployed", async () => {
    const fetchImpl = (async () => new Response(JSON.stringify({ status: "error", errorMessage: "Could not find public function" }), { status: 200 })) as typeof fetch;
    await expect(purgeRetiredMirrors(ctx, config, fetchImpl)).rejects.toThrow(/purgeRetired/);
  });
});

