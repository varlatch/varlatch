// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { latestEventCursor, syncNewMirrorEvents, type MirrorConfig } from "../src/mirror/publisher.js";
import { deliverWebhooksOnce } from "../src/domain/webhooks.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * Deleting a Project (ADR-0051 Decisions 2 and 3): one transaction that
 * tombstones it and its environments, erases every value version from the
 * live database, revokes what reaches it, and leaves audit intact.
 */

const ORG = "/v1/organizations/acme";
const P = `${ORG}/projects/api`;
const DEV = `${P}/environments/development`;

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let admin: string;
let orgId: string;
let projectId: string;

async function call(method: string, path: string, body?: unknown, token = admin) {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

const item = (name: string, sensitive = true) => ({ name, required: { kind: "never" }, sensitive, type: "string" });

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const setup = await issueBootstrapGrant(ctx);
  const { identityId } = await consumeSetupGrant(ctx, setup.token, { adminName: "Admin" });
  admin = (await issueCredential(ctx.db, { identityId, kind: "cli" })).token;
  app = buildApp(ctx);
  orgId = (await call("POST", "/v1/organizations", { name: "Acme", slug: "acme" })).body.id;
  projectId = (await call("POST", `${ORG}/projects`, { name: "API", slug: "api", contractAuthority: "managed" })).body.id;
  const revision = await call("POST", `${P}/contract/revisions`, { contract: { schemaVersion: 1, items: [item("TOKEN"), item("PORT", false)] } });
  await call("POST", `${P}/contract/revisions/${revision.body.id}/activate`, {});
  for (const env of ["development", "production", "staging"]) {
    const tier = env === "staging" ? "staging" : env;
    expect((await call("POST", `${P}/environments`, { name: env, tier })).status).toBe(201);
    expect((await call("PUT", `${P}/environments/${env}/values/TOKEN`, { value: `token-${env}-1111` })).status).toBe(200);
  }
  expect((await call("PUT", `${DEV}/values/PORT`, { value: "8080" })).status).toBe(200);
  expect((await call("PUT", `${DEV}/values/TOKEN`, { value: "token-development-2222" })).status).toBe(200);
  // A rotation in progress keeps a retiring version.
  expect((await call("POST", `${P}/environments/production/values/TOKEN/rotations`, { value: "token-production-2222" })).status).toBe(201);
  // An environment deleted earlier keeps its versions (ADR-0025) until the Project goes.
  expect((await call("DELETE", `${P}/environments/staging`)).status).toBe(204);
});
afterEach(async () => {
  await ctx.close();
});

async function versionsOf(project: string) {
  return (
    await ctx.db.query(
      `SELECT v.id, v.payload IS NULL AS no_payload, v.wrapped_dek IS NULL AS no_dek, v.erased_at IS NOT NULL AS erased
       FROM value_versions v JOIN env_values ev ON ev.id = v.value_id JOIN environments e ON e.id = ev.environment_id
       WHERE e.project_id = $1`,
      [project],
    )
  ).rows as { id: string; no_payload: boolean; no_dek: boolean; erased: boolean }[];
}

describe("deleting a Project", () => {
  it("is advertised, and erases every version, earlier-deleted environments included", async () => {
    expect((await call("GET", "/v1/meta")).body.capabilities).toContain("projects.delete");
    const before = await versionsOf(projectId);
    expect(before.length).toBe(6);
    expect(before.every((v) => !v.erased)).toBe(true);

    const deleted = await call("DELETE", P);
    expect(deleted.status, JSON.stringify(deleted.body)).toBe(200);
    expect(deleted.body).toMatchObject({ projectId, slug: "api", environments: 2, versionsErased: 6 });

    const after = await versionsOf(projectId);
    expect(after.every((v) => v.erased && v.no_payload && v.no_dek)).toBe(true);
    const pointers = (await ctx.db.query(
      `SELECT ev.current_version_id, ev.retiring_version_id FROM env_values ev JOIN environments e ON e.id = ev.environment_id WHERE e.project_id = $1`,
      [projectId],
    )).rows;
    expect(pointers.every((r) => (r as Record<string, unknown>).current_version_id === null && (r as Record<string, unknown>).retiring_version_id === null)).toBe(true);
    const envs = (await ctx.db.query("SELECT deleted_at FROM environments WHERE project_id = $1", [projectId])).rows as { deleted_at: unknown }[];
    expect(envs.every((e) => e.deleted_at !== null)).toBe(true);
    // Contract Revisions stay with the tombstone; the audit event comes last, with counts.
    expect((await ctx.db.query("SELECT 1 FROM contract_revisions WHERE project_id = $1", [projectId])).rows.length).toBeGreaterThan(0);
    const audit = (await ctx.db.query("SELECT metadata FROM audit_events WHERE event_type = 'project.deleted'")).rows[0] as { metadata: unknown };
    const meta = typeof audit.metadata === "string" ? JSON.parse(audit.metadata) : audit.metadata;
    expect(meta).toMatchObject({ name: "API", environments: 2, versionsErased: 6 });
    const lastEvent = (await ctx.db.query("SELECT event_type FROM audit_events ORDER BY event_order DESC LIMIT 1")).rows[0];
    expect(lastEvent).toEqual({ event_type: "project.deleted" });
  });

  it("leaves nothing reachable but audit", async () => {
    expect((await call("DELETE", P)).status).toBe(200);
    expect((await call("GET", P)).status).toBe(404);
    expect((await call("GET", `${ORG}/projects`)).body.items).toEqual([]);
    expect((await call("GET", `${DEV}`)).status).toBe(404);
    expect((await call("PUT", `${DEV}/values/PORT`, { value: "9090" })).status).toBe(404);
    expect((await call("POST", `${P}/contract/revisions`, { contract: { schemaVersion: 1, items: [] } })).status).toBe(404);
    expect((await call("DELETE", P)).status).toBe(404);
    // The audit log still names it.
    const page = await call("GET", `${ORG}/audit-events?limit=100`);
    expect(page.body.items.some((e: { eventType: string }) => e.eventType === "project.deleted")).toBe(true);
  });

  it("revokes Sync Targets, fencing a push, and removes Teams' links", async () => {
    const connection = (await call("POST", `${ORG}/platform-connections`, {
      platform: "coolify", baseIdentity: "https://coolify.example.com", name: "c", credential: "token-c",
    })).body;
    const target = await call("POST", `${DEV}/sync-targets`, { connectionId: connection.id, destination: { applicationUuid: "app1" }, mapping: { kind: "wildcard" } });
    expect(target.status, JSON.stringify(target.body)).toBe(201);
    const team = (await call("POST", `${ORG}/teams`, { name: "core" })).body;
    expect((await call("POST", `${ORG}/teams/${team.id}/projects`, { projectId })).status).toBe(204);
    const generation = Number((await ctx.db.query("SELECT generation FROM sync_targets WHERE id = $1", [target.body.id])).rows[0]!.generation);

    const deleted = await call("DELETE", P);
    expect(deleted.body).toMatchObject({ targetsRevoked: 1, teamLinksRemoved: 1 });
    const row = (await ctx.db.query("SELECT revoked_at, generation FROM sync_targets WHERE id = $1", [target.body.id])).rows[0] as { revoked_at: unknown; generation: string };
    expect(row.revoked_at).not.toBeNull();
    expect(Number(row.generation)).toBeGreaterThan(generation);
    expect((await ctx.db.query("SELECT 1 FROM team_projects WHERE team_id = $1", [team.id])).rows).toEqual([]);
    // The destination claim is released: another Target may use it.
    await call("POST", `${ORG}/projects`, { name: "Web", slug: "web", contractAuthority: "managed" });
    await call("POST", `${ORG}/projects/web/environments`, { name: "development", tier: "development" });
    const again = await call("POST", `${ORG}/projects/web/environments/development/sync-targets`, {
      connectionId: connection.id, destination: { applicationUuid: "app1" }, mapping: { kind: "wildcard" },
    });
    expect(again.status, JSON.stringify(again.body)).toBe(201);
  });

  it("frees the slug for a new Project that inherits no Grant of the old one", async () => {
    const invite = await issueInviteGrant(ctx, { organizationId: orgId, role: "member", name: "Bob" }, (await ctx.db.query("SELECT id FROM identities WHERE installation_admin")).rows[0]!.id as string);
    const bobId = (await consumeSetupGrant(ctx, invite.token, {})).identityId;
    const bob = (await issueCredential(ctx.db, { identityId: bobId, kind: "cli" })).token;
    expect((await call("POST", `${ORG}/grants`, { subjectIdentityId: bobId, scope: { kind: "project", projectId }, actions: ["project.manage"] })).status).toBe(201);
    expect((await call("DELETE", P)).status).toBe(200);

    const fresh = await call("POST", `${ORG}/projects`, { name: "API again", slug: "api", contractAuthority: "managed" });
    expect(fresh.status, JSON.stringify(fresh.body)).toBe(201);
    expect(fresh.body.id).not.toBe(projectId);
    // Bob's Grant named the old Project's ID: it permits nothing here.
    expect((await call("PATCH", P, { name: "Mine" }, bob)).status).toBe(403);
  });

  it("needs project.manage", async () => {
    const invite = await issueInviteGrant(ctx, { organizationId: orgId, role: "member", name: "Bob" }, (await ctx.db.query("SELECT id FROM identities WHERE installation_admin")).rows[0]!.id as string);
    const bobId = (await consumeSetupGrant(ctx, invite.token, {})).identityId;
    const bob = (await issueCredential(ctx.db, { identityId: bobId, kind: "cli" })).token;
    expect((await call("DELETE", P, undefined, bob)).status).toBe(403);
    expect((await versionsOf(projectId)).every((v) => !v.erased)).toBe(true);
  });

  it("does not deliver a deleted Project's events by webhook, and moves past them", async () => {
    const all = (await call("POST", `${ORG}/webhooks`, { url: "https://sink.example/all" })).body;
    const valuesOnly = (await call("POST", `${ORG}/webhooks`, { url: "https://sink.example/values", eventTypes: ["value.written"] })).body;
    // A backlog: the deleted Project's events and another Project's.
    expect((await call("PUT", `${DEV}/values/PORT`, { value: "9090" })).status).toBe(200);
    expect((await call("POST", `${ORG}/projects`, { name: "Web", slug: "web", contractAuthority: "git" })).status).toBe(201);
    expect((await call("DELETE", P)).status).toBe(200);
    const sent: { url: string; events: { eventType: string; resource: Record<string, unknown> | null }[] }[] = [];
    const fetchImpl = (async (url: unknown, init?: RequestInit) => {
      sent.push({ url: String(url), events: (JSON.parse(String(init?.body)) as { events: never[] }).events });
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
    await deliverWebhooksOnce(ctx, fetchImpl);
    const delivered = sent.flatMap((s) => s.events);
    expect(delivered.some((e) => e.eventType === "project.created")).toBe(true);
    expect(delivered.some((e) => e.eventType === "project.deleted" || e.eventType === "value.written")).toBe(false);
    // Nothing to send for the values-only hook: no request, and its cursor moved on all the same.
    expect(sent.filter((s) => s.url.endsWith("/values"))).toEqual([]);
    const position = (await ctx.db.query("SELECT value::text AS v FROM audit_position")).rows[0]!.v;
    const cursors = (await ctx.db.query("SELECT id, cursor_order::text AS c FROM webhooks WHERE id = ANY($1)", [[all.id, valuesOnly.id]])).rows as { id: string; c: string }[];
    const valuesCursor = Number(cursors.find((c) => c.id === valuesOnly.id)!.c);
    expect(valuesCursor).toBeGreaterThan(0);
    // A second pass sends nothing again.
    sent.length = 0;
    await deliverWebhooksOnce(ctx, fetchImpl);
    expect(sent).toEqual([]);
    expect(Number(position)).toBeGreaterThanOrEqual(valuesCursor);
  });

  it("removes the Project's and its environments' published metadata", async () => {
    const config: MirrorConfig = { convexUrl: "https://convex.test", issuer: "http://localhost" };
    const cursor = await latestEventCursor(ctx);
    expect((await call("DELETE", P)).status).toBe(200);
    const removed: { kind: string; resourceId: string }[] = [];
    const fetchImpl = (async (_url: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { path: string; args: { kind: string; resourceId: string } };
      if (body.path === "mirror:remove") removed.push({ kind: body.args.kind, resourceId: body.args.resourceId });
      return new Response(JSON.stringify({ status: "success" }), { status: 200 });
    }) as typeof fetch;
    await syncNewMirrorEvents(ctx, config, cursor, fetchImpl);
    expect(removed).toContainEqual({ kind: "project", resourceId: projectId });
    expect(removed.filter((r) => r.kind === "environment")).toHaveLength(3);
  });
});
