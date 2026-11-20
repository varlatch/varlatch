// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { AUDIT_EVENT_TYPES, recordAuditEvent } from "../src/audit/events.js";
import { serializeAuditEvent } from "../src/audit/serialize.js";
import { generateKey } from "../src/crypto/aead.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { deliverWebhooksOnce } from "../src/domain/webhooks.js";
import { buildApp } from "../src/http/app.js";
import { changedDomain } from "../src/mirror/publisher.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * `installation.migrated` (ADR-0059 step 7, go-step7 slice 7.2a): a
 * database rebuilt from the Go line's bundle holds such events, so every
 * path that reads or renders an event's type lists, exports, delivers and
 * mirrors it like any other kind: the /v1 audit listing and its NDJSON
 * export, webhook delivery, the audit export's serialisation and the
 * Convex mirror's change signals. (The dashboard's description is in
 * apps/web/test/describeEvent.test.ts.)
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let token: string;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Admin" });
  token = (await issueCredential(ctx.db, { identityId: consumed.identityId, kind: "cli" })).token;
  app = buildApp(ctx);
  expect((await call("POST", "/v1/organizations", { name: "Acme", slug: "acme" })).status).toBe(201);
});
afterEach(async () => ctx.close());

function call(method: string, path: string, body?: unknown) {
  return app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

describe("installation.migrated on every path", () => {
  it("is listed, exported, delivered and mirrored like any other kind", async () => {
    const webhook = await (await call("POST", "/v1/organizations/acme/webhooks", { url: "https://sink.example/hook" })).json();
    expect(webhook.id).toBeTruthy();
    const org = ((await ctx.db.query("SELECT id FROM organizations WHERE slug = 'acme'")).rows[0] as { id: string }).id;
    await recordAuditEvent(ctx.db, {
      eventType: "installation.migrated",
      decision: "info",
      organizationId: org,
      metadata: { to: "go", release: "0.50.0" },
    });

    const listed = await (await call("GET", "/v1/organizations/acme/audit-events?eventType=installation.migrated")).json();
    expect(listed.items.map((e: { eventType: string }) => e.eventType)).toEqual(["installation.migrated"]);

    const exported = await (await call("GET", "/v1/organizations/acme/audit-events/export?eventType=installation.migrated")).text();
    const lines = exported.trim().split("\n").map((l) => JSON.parse(l));
    expect(lines.map((l: { eventType: string }) => l.eventType)).toEqual(["installation.migrated"]);

    const bodies: string[] = [];
    await deliverWebhooksOnce(ctx, (async (_url: unknown, init?: RequestInit) => {
      bodies.push(String(init?.body));
      return new Response(null, { status: 200 });
    }) as typeof fetch);
    const delivered = bodies.flatMap((b) => JSON.parse(b).events.map((e: { eventType: string }) => e.eventType));
    expect(delivered).toContain("installation.migrated");

    const row = (await ctx.db.query("SELECT * FROM audit_events WHERE event_type = 'installation.migrated'")).rows[0] as Record<string, unknown>;
    expect(serializeAuditEvent(row)).toMatchObject({ eventType: "installation.migrated", decision: "info", organizationId: org });
    expect(changedDomain("installation.migrated")).toBe("installation");
  });

  it("no path reports an unknown kind: every recorded type serialises and maps to a mirror signal", () => {
    expect(AUDIT_EVENT_TYPES).toContain("installation.migrated");
    for (const eventType of AUDIT_EVENT_TYPES) {
      const row = {
        id: "evt_x", event_order: "1", schema_version: 1, event_type: eventType, decision: "info", occurred_at: new Date(0).toISOString(),
        actor_identity_id: null, organization_id: null, resource: {}, metadata: {},
      };
      expect(serializeAuditEvent(row).eventType, eventType).toBe(eventType);
      expect(() => changedDomain(eventType), eventType).not.toThrow();
    }
  });
});
