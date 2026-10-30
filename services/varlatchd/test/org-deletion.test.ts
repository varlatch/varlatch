// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { encryptGitHubAppKey } from "../src/crypto/hierarchy.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { recordAuditEvents } from "../src/audit/events.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { importGitHubApp } from "../src/domain/githubapps.js";
import { finalizeDeletion, runDueDeletions } from "../src/domain/orgdeletion.js";
import { getOrganization, orgKekOf } from "../src/domain/orgs.js";
import { createAppConnection } from "../src/domain/sync.js";
import { buildApp } from "../src/http/app.js";
import { deliverWebhooksOnce } from "../src/domain/webhooks.js";
import { latestEventCursor, syncNewMirrorEvents } from "../src/mirror/publisher.js";
import { fakeGitHubApps } from "./helpers/fake-github-app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * Deleting an Organization (ADR-0051 Decisions 4 to 8): a request that
 * freezes the Organization, a waiting period, a second admin's approval,
 * cancellation that restores what it suspended, and a finalization that
 * ends memberships, retires machines, erases values, destroys the KEK and
 * leaves the audit log to the readers fixed at that moment.
 */

const ORG = "/v1/organizations/acme";
const P = `${ORG}/projects/api`;
const DEV = `${P}/environments/development`;

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminId: string;
let admin: string;
let orgId: string;

async function call(method: string, path: string, body?: unknown, token = admin) {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

async function person(name: string, role: "admin" | "member") {
  const invite = await issueInviteGrant(ctx, { organizationId: orgId, role, name }, adminId);
  const id = (await consumeSetupGrant(ctx, invite.token, {})).identityId;
  return { id, token: (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token };
}

async function events(eventType: string) {
  return (await ctx.db.query("SELECT actor_identity_id, resource, metadata FROM audit_events WHERE event_type = $1 ORDER BY event_order", [eventType]))
    .rows as { actor_identity_id: string | null; resource: unknown; metadata: unknown }[];
}

const makeDue = () => ctx.db.query("UPDATE organization_deletions SET scheduled_at = now() - interval '8 days', run_after = now() - interval '1 minute'");

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const setup = await issueBootstrapGrant(ctx);
  adminId = (await consumeSetupGrant(ctx, setup.token, { adminName: "Admin" })).identityId;
  admin = (await issueCredential(ctx.db, { identityId: adminId, kind: "cli" })).token;
  app = buildApp(ctx);
  orgId = (await call("POST", "/v1/organizations", { name: "Acme", slug: "acme" })).body.id;
  await call("POST", `${ORG}/projects`, { name: "API", slug: "api", contractAuthority: "managed" });
  await call("POST", `${P}/environments`, { name: "development", tier: "development" });
  const revision = await call("POST", `${P}/contract/revisions`, {
    contract: { schemaVersion: 1, items: [{ name: "TOKEN", required: { kind: "never" }, sensitive: true, type: "string" }] },
  });
  await call("POST", `${P}/contract/revisions/${revision.body.id}/activate`, {});
  expect((await call("PUT", `${DEV}/values/TOKEN`, { value: "token-value-0001" })).status).toBe(200);
});
afterEach(async () => {
  await ctx.close();
});

describe("scheduling a deletion", () => {
  it("freezes the Organization and suspends what a cancel can restore", async () => {
    expect((await call("GET", "/v1/meta")).body.capabilities).toContain("organizations.delete");
    const svc = (await call("POST", `${ORG}/identities`, { name: "deployer", kind: "service" })).body;
    await call("POST", `${ORG}/grants`, { subjectIdentityId: svc.id, scope: { kind: "organization" }, actions: ["environment.read"] });
    expect((await call("GET", DEV, undefined, svc.credential)).status).toBe(200);
    const hook = (await call("POST", `${ORG}/webhooks`, { url: "https://sink.example/hooks" })).body;
    const connection = (await call("POST", `${ORG}/platform-connections`, { platform: "coolify", baseIdentity: "https://coolify.example.com", name: "c", credential: "token-c" })).body;
    const target = (await call("POST", `${DEV}/sync-targets`, { connectionId: connection.id, destination: { applicationUuid: "app1" }, mapping: { kind: "wildcard" } })).body;
    const invitation = (await call("POST", `${ORG}/invitations`, { name: "Later", role: "member" })).body;

    const scheduled = await call("POST", `${ORG}/deletion`, { afterDays: 3 });
    expect(scheduled.status, JSON.stringify(scheduled.body)).toBe(201);
    expect(scheduled.body).toMatchObject({ requestedBy: adminId, approvalRequired: false, approvedBy: null });
    const days = (Date.parse(scheduled.body.runAfter) - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(2.9);
    expect(days).toBeLessThan(3.1);
    expect((await call("GET", `${ORG}/deletion`)).body.deletion).toMatchObject({ id: scheduled.body.id });

    // Frozen: every operational write is refused, saying from when.
    const refused = await call("PUT", `${DEV}/values/TOKEN`, { value: "token-value-0002" });
    expect(refused.status).toBe(409);
    expect(refused.body.error).toMatchObject({ code: "ORGANIZATION_DELETING", details: { deletionId: scheduled.body.id, runAfter: scheduled.body.runAfter } });
    for (const [method, path, body] of [
      ["POST", `${ORG}/projects`, { name: "Web", slug: "web", contractAuthority: "git" }],
      ["POST", `${ORG}/grants`, { subjectIdentityId: adminId, scope: { kind: "organization" }, actions: ["audit.read"] }],
      ["POST", `${ORG}/invitations`, { name: "Eve", role: "member" }],
      ["POST", `${ORG}/identities`, { name: "new", kind: "service" }],
    ] as const) {
      expect((await call(method, path, body)).body.error?.code, path).toBe("ORGANIZATION_DELETING");
    }
    // Reads still work, so a last copy can be made.
    expect((await call("POST", `${DEV}/disclosures`, { items: ["TOKEN"] })).status).toBe(200);
    // Suspended and paused.
    expect((await call("GET", DEV, undefined, svc.credential)).status).toBe(401);
    expect((await ctx.db.query("SELECT suspended_by_deletion FROM webhooks WHERE id = $1", [hook.id])).rows[0]).toEqual({ suspended_by_deletion: scheduled.body.id });
    expect((await ctx.db.query("SELECT state FROM sync_targets WHERE id = $1", [target.id])).rows[0]).toEqual({ state: "paused" });
    const invitations = (await call("GET", `${ORG}/invitations?status=all`)).body.items;
    expect(invitations.find((i: { id: string }) => i.id === invitation.id)).toMatchObject({ status: "revoked" });
    expect((await events("organization.deletion_scheduled"))[0]!.metadata).toMatchObject({ targetsPaused: 1, webhooksSuspended: 1, identitiesSuspended: 1, invitationsRevoked: 1 });
    // One open request at a time.
    expect((await call("POST", `${ORG}/deletion`, {})).status).toBe(409);
  });

  it("needs a live built-in admin, and a second admin's approval when there are several", async () => {
    const second = await person("Second", "admin");
    const member = await person("Member", "member");
    await call("POST", `${ORG}/grants`, { subjectIdentityId: member.id, scope: { kind: "organization" }, actions: ["organization.manage"] });
    expect((await call("POST", `${ORG}/deletion`, {}, member.token)).status).toBe(403);
    expect((await call("POST", `${ORG}/deletion`, { afterDays: 31 })).status).toBe(422);

    const scheduled = (await call("POST", `${ORG}/deletion`, {})).body;
    expect(scheduled.approvalRequired).toBe(true);
    // Not by the requester, nor by a member.
    expect((await call("POST", `${ORG}/deletion/${scheduled.id}/approve`)).status).toBe(403);
    expect((await call("POST", `${ORG}/deletion/${scheduled.id}/approve`, undefined, member.token)).status).toBe(403);
    const approved = await call("POST", `${ORG}/deletion/${scheduled.id}/approve`, undefined, second.token);
    expect(approved.status).toBe(200);
    expect(approved.body).toMatchObject({ approvedBy: second.id });
    // An approval names its request: another ID approves nothing.
    expect((await call("POST", `${ORG}/deletion/odl_other/approve`, undefined, second.token)).status).toBe(404);
  });
});

describe("cancelling", () => {
  it("restores the machines and webhooks it suspended, never a machine retired before, and leaves Targets paused", async () => {
    const svc = (await call("POST", `${ORG}/identities`, { name: "deployer", kind: "service" })).body;
    const retired = (await call("POST", `${ORG}/identities`, { name: "old", kind: "service" })).body;
    expect((await call("POST", `${ORG}/identities/${retired.id}/retire`)).status).toBeLessThan(300);
    const hook = (await call("POST", `${ORG}/webhooks`, { url: "https://sink.example/hooks" })).body;
    const scheduled = (await call("POST", `${ORG}/deletion`, {})).body;
    // Reactivation is refused while suspended.
    expect((await call("POST", `${ORG}/identities/${svc.id}/reactivate`)).status).toBe(409);

    const cancelled = await call("POST", `${ORG}/deletion/${scheduled.id}/cancel`);
    expect(cancelled.status).toBe(200);
    expect(cancelled.body.cancelledAt).toEqual(expect.any(String));
    const rows = (await ctx.db.query("SELECT id, disabled, suspended_by_deletion FROM identities WHERE id = ANY($1) ORDER BY id", [[svc.id, retired.id]])).rows;
    expect(rows).toEqual(
      [
        { id: svc.id, disabled: false, suspended_by_deletion: null },
        { id: retired.id, disabled: true, suspended_by_deletion: null },
      ].sort((a, b) => (a.id < b.id ? -1 : 1)),
    );
    expect((await ctx.db.query("SELECT suspended_by_deletion FROM webhooks WHERE id = $1", [hook.id])).rows[0]).toEqual({ suspended_by_deletion: null });
    // No longer frozen.
    expect((await call("PUT", `${DEV}/values/TOKEN`, { value: "token-value-0003" })).status).toBe(200);
    expect((await call("POST", `${ORG}/deletion/${scheduled.id}/cancel`)).status).toBe(409);
  });
});

describe("while frozen", () => {
  it("refuses a rename, and anything that would use a stored key or call out, before it does", async () => {
    const org = await getOrganization(ctx, "acme");
    const github = fakeGitHubApps();
    const pem = github.addApp({ id: 5254113, slug: "varlatch-test", clientId: "Iv23frozen", owner: { login: "acme", id: 1, type: "Organization" }, permissions: { secrets: "write", environments: "write", metadata: "read" } });
    const installationId = github.install(5254113, { login: "acme", id: 1, type: "Organization" }, "selected", null, [{ name: "api", private: true }]);
    await ctx.db.query(
      `INSERT INTO github_apps (id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, key_envelope, created_by)
       VALUES ('gha_frozen', $1, 5254113, 'varlatch-test', 'Iv23frozen', 'acme', 1, 'organization', $2, $3)`,
      [org.id, JSON.stringify(encryptGitHubAppKey(orgKekOf(ctx, org), org.id, "gha_frozen", pem)), adminId],
    );
    await call("POST", `${ORG}/deletion`, {});

    const renamed = await call("PATCH", ORG, { name: "Renamed" });
    expect(renamed.body.error?.code).toBe("ORGANIZATION_DELETING");
    expect((await getOrganization(ctx, "acme")).name).not.toBe("Renamed");
    const outcome = (p: Promise<unknown>) => p.then(() => "done", (err: unknown) => (err as { code?: string }).code);
    expect(await outcome(createAppConnection(ctx, org, { installationId, name: "App" }, adminId, null, github.fetchImpl))).toBe("ORGANIZATION_DELETING");
    expect(await outcome(importGitHubApp(ctx, org, { appId: 5254113, privateKey: pem }, adminId, github.fetchImpl))).toBe("ORGANIZATION_DELETING");
    expect(github.calls).toEqual([]);
  });

  it("keeps a suspended machine's credentials: revoking one is refused, and a cancel restores it whole", async () => {
    const svc = (await call("POST", `${ORG}/identities`, { name: "deployer", kind: "service" })).body;
    const credentialId = (await ctx.db.query("SELECT id FROM credentials WHERE identity_id = $1", [svc.id])).rows[0]!.id as string;
    const scheduled = (await call("POST", `${ORG}/deletion`, {})).body;
    const refused = await call("DELETE", `${ORG}/identities/${svc.id}/credentials/${credentialId}`);
    expect(refused.status).toBe(409);
    expect(refused.body.error.code).toBe("ORGANIZATION_DELETING");
    await call("POST", `${ORG}/deletion/${scheduled.id}/cancel`);
    await call("POST", `${ORG}/grants`, { subjectIdentityId: svc.id, scope: { kind: "organization" }, actions: ["environment.read"] });
    expect((await call("GET", DEV, undefined, svc.credential)).status).toBe(200);
  });

  it("delivers nothing by webhook once a deletion is scheduled during the pass, nor the deletion's own events", async () => {
    await call("POST", `${ORG}/webhooks`, { url: "https://sink.example/hooks" });
    expect((await call("PUT", `${DEV}/values/TOKEN`, { value: "token-value-0005" })).status).toBe(200);
    const sent: { eventType: string }[][] = [];
    const fetchImpl = (async (_url: unknown, init?: RequestInit) => {
      sent.push((JSON.parse(String(init?.body)) as { events: { eventType: string }[] }).events);
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
    // The deletion is scheduled after the pass found the webhook, before it reads events.
    let scheduledId = "";
    let raced = false;
    const racing = {
      ...ctx.db,
      query: async (text: string, params?: unknown[]) => {
        if (!raced && /SELECT \* FROM audit_events WHERE/.test(text)) {
          raced = true;
          scheduledId = (await call("POST", `${ORG}/deletion`, {})).body.id;
        }
        return ctx.db.query(text, params);
      },
    } as typeof ctx.db;
    await deliverWebhooksOnce({ ...ctx, db: racing }, fetchImpl);
    expect(raced).toBe(true);
    expect(sent).toEqual([]);
    // After a cancel the backlog goes out, without the deletion's lifecycle events.
    await call("POST", `${ORG}/deletion/${scheduledId}/cancel`);
    await deliverWebhooksOnce(ctx, fetchImpl);
    const delivered = sent.flat().map((e) => e.eventType);
    expect(delivered).toContain("value.written");
    expect(delivered.filter((t) => t.startsWith("organization.deletion"))).toEqual([]);
  });
});

describe("finalization", () => {
  it("runs only when due and approved, and while the approver is still an admin", async () => {
    const second = await person("Second", "admin");
    const scheduled = (await call("POST", `${ORG}/deletion`, {})).body;
    expect(await runDueDeletions(ctx)).toEqual([]);
    await makeDue();
    expect(await runDueDeletions(ctx)).toEqual([]); // not approved
    await call("POST", `${ORG}/deletion/${scheduled.id}/approve`, undefined, second.token);
    // The approver loses the admin role before it runs.
    await ctx.db.query("UPDATE org_memberships SET role = 'member' WHERE identity_id = $1", [second.id]);
    expect(await runDueDeletions(ctx)).toEqual([]);
    expect((await call("GET", ORG)).status).toBe(200);
  });

  it("ends memberships, retires machines, erases values, destroys the KEK, and keeps the audit log for its readers", async () => {
    const auditor = await person("Auditor", "member");
    await call("POST", `${ORG}/grants`, { subjectIdentityId: auditor.id, scope: { kind: "organization" }, actions: ["audit.read"] });
    const plain = await person("Plain", "member");
    const svc = (await call("POST", `${ORG}/identities`, { name: "deployer", kind: "service" })).body;
    const hook = (await call("POST", `${ORG}/webhooks`, { url: "https://sink.example/hooks" })).body;
    const connection = (await call("POST", `${ORG}/platform-connections`, { platform: "coolify", baseIdentity: "https://coolify.example.com", name: "c", credential: "token-c" })).body;
    await call("POST", `${DEV}/sync-targets`, { connectionId: connection.id, destination: { applicationUuid: "app1" }, mapping: { kind: "wildcard" } });
    await call("POST", `${ORG}/deletion`, {});
    await makeDue();

    const [outcome] = await runDueDeletions(ctx);
    // organization.deleted is the finalization's last event.
    const lastEvent = (await ctx.db.query("SELECT event_type FROM audit_events ORDER BY event_order DESC LIMIT 1")).rows[0];
    expect(lastEvent).toEqual({ event_type: "organization.deleted" });
    expect(outcome).toMatchObject({ organizationId: orgId, members: 3, readers: 2, projects: 1, versionsErased: 1, targetsRevoked: 1, identitiesRetired: 1, webhooksRemoved: 1, connectionsRevoked: 1 });
    // Nothing left in the live database to decrypt with.
    const org = (await ctx.db.query("SELECT deleted_at, wrapped_org_kek, org_kek_destroyed_at FROM organizations WHERE id = $1", [orgId])).rows[0] as Record<string, unknown>;
    expect(org.deleted_at).not.toBeNull();
    expect(org.wrapped_org_kek).toBeNull();
    expect(org.org_kek_destroyed_at).not.toBeNull();
    expect(() => orgKekOf(ctx, { id: orgId, wrapped_org_kek: null } as never)).toThrow(/destroyed/);
    expect((await ctx.db.query("SELECT count(*)::int AS n FROM value_versions WHERE erased_at IS NULL")).rows[0]).toEqual({ n: 0 });
    // People keep their accounts; the Organization is gone for them.
    expect((await call("GET", ORG)).status).toBe(404);
    expect((await call("GET", "/v1/organizations", undefined, plain.token)).body.items).toEqual([]);
    expect((await call("GET", "/v1/me", undefined, plain.token)).status).toBe(200);
    expect((await call("GET", DEV, undefined, svc.credential)).status).toBe(401);
    expect((await ctx.db.query("SELECT revoked_at FROM webhooks WHERE id = $1", [hook.id])).rows[0]).not.toEqual({ revoked_at: null });
    await expect(getOrganization(ctx, orgId)).rejects.toThrow();
    // Membership events with the finalization mark, then organization.deleted, last.
    const removed = await events("membership.removed");
    expect(removed).toHaveLength(3);
    expect(removed.every((e) => (typeof e.metadata === "string" ? JSON.parse(e.metadata) : e.metadata).finalization === true)).toBe(true);

    // The audit tombstone: readers fixed at deletion (admin and auditor), nobody else.
    const exported = await call("GET", `/v1/deleted-organizations/${orgId}/audit-events?limit=500`, undefined, auditor.token);
    expect(exported.status).toBe(200);
    expect(exported.body.items.some((e: { eventType: string }) => e.eventType === "organization.deleted")).toBe(true);
    expect((await call("GET", `/v1/deleted-organizations/${orgId}/audit-events`, undefined, plain.token)).status).toBe(404);
    // The export streams the same log, oldest first, to the same readers.
    const ndjson = async (token: string) => app.request(`/v1/deleted-organizations/${orgId}/audit-events/export`, { headers: { Authorization: `Bearer ${token}` } });
    const stream = await ndjson(auditor.token);
    expect(stream.headers.get("Content-Type")).toBe("application/x-ndjson");
    const lines = (await stream.text()).trim().split("\n").map((l) => JSON.parse(l) as { eventType: string });
    expect(lines.length).toBe(exported.body.items.length);
    expect(lines[0]!.eventType).toBe("organization.created");
    expect(lines[lines.length - 1]!.eventType).toBe("organization.deleted");
    expect((await ndjson(plain.token)).status).toBe(404);
    // An Installation Admin sees the tombstone and its readers, and can remove one.
    const listed = await call("GET", "/v1/installation/deleted-organizations");
    expect(listed.body.items).toEqual([
      expect.objectContaining({ id: orgId, slug: "acme", readers: expect.arrayContaining([expect.objectContaining({ identityId: auditor.id, removedAt: null })]) }),
    ]);
    expect((await call("DELETE", `/v1/installation/deleted-organizations/${orgId}/readers/${auditor.id}`)).status).toBe(204);
    expect((await call("GET", `/v1/deleted-organizations/${orgId}/audit-events`, undefined, auditor.token)).status).toBe(404);
    expect((await call("DELETE", `/v1/installation/deleted-organizations/${orgId}/readers/${auditor.id}`, undefined, plain.token)).status).toBe(403);
    // A second run finds nothing to do.
    expect(await runDueDeletions(ctx)).toEqual([]);
    // Later events naming the deleted Organization publish no change signal for it.
    const cursor = await latestEventCursor(ctx);
    expect((await call("DELETE", `/v1/installation/deleted-organizations/${orgId}/readers/${adminId}`)).status).toBe(204);
    const upserts: { kind: string; resourceId: string }[] = [];
    const fetchImpl = (async (_url: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { path: string; args: { kind: string; resourceId: string } };
      if (body.path === "mirror:upsert") upserts.push(body.args);
      return new Response(JSON.stringify({ status: "success" }), { status: 200 });
    }) as typeof fetch;
    await syncNewMirrorEvents(ctx, { convexUrl: "https://convex.test", issuer: "http://localhost" }, cursor, fetchImpl);
    expect(upserts.filter((u) => u.kind === "changeSignal" && u.resourceId === orgId)).toEqual([]);
  });

  it("rolls back whole on a failure: the Organization stays frozen and nothing is erased", async () => {
    const scheduled = (await call("POST", `${ORG}/deletion`, {})).body;
    await makeDue();
    const failing = {
      ...ctx.db,
      query: (text: string, params?: unknown[]) =>
        /UPDATE organizations SET deleted_at/.test(text) ? Promise.reject(new Error("injected failure")) : ctx.db.query(text, params),
    } as typeof ctx.db;
    await expect(finalizeDeletion({ ...ctx, db: failing }, scheduled.id, orgId)).rejects.toThrow("injected failure");
    expect((await ctx.db.query("SELECT deleted_at, wrapped_org_kek IS NOT NULL AS kek FROM organizations WHERE id = $1", [orgId])).rows[0]).toEqual({ deleted_at: null, kek: true });
    expect((await ctx.db.query("SELECT completed_at FROM organization_deletions WHERE id = $1", [scheduled.id])).rows[0]).toEqual({ completed_at: null });
    expect((await ctx.db.query("SELECT count(*)::int AS n FROM value_versions WHERE erased_at IS NOT NULL")).rows[0]).toEqual({ n: 0 });
    expect((await ctx.db.query("SELECT count(*)::int AS n FROM org_memberships WHERE removed_at IS NOT NULL")).rows[0]).toEqual({ n: 0 });
    expect((await ctx.db.query("SELECT count(*)::int AS n FROM audit_tombstone_readers")).rows[0]).toEqual({ n: 0 });
    // Still frozen, and the next run completes it.
    expect((await call("PUT", `${DEV}/values/TOKEN`, { value: "token-value-0009" })).body.error.code).toBe("ORGANIZATION_DELETING");
    expect((await runDueDeletions(ctx)).map((o) => o.deletionId)).toEqual([scheduled.id]);
  });

  it("runs without approval when there was one admin, after the waiting period", async () => {
    const scheduled = (await call("POST", `${ORG}/deletion`, {})).body;
    expect(scheduled.approvalRequired).toBe(false);
    expect(await runDueDeletions(ctx)).toEqual([]);
    await makeDue();
    expect((await runDueDeletions(ctx)).map((o) => o.deletionId)).toEqual([scheduled.id]);
  });
});

describe("the audit log export", () => {
  const filler = (n: number, tag: string) =>
    Array.from({ length: n }, (_, i) => ({ eventType: "test.filler", decision: "info" as const, actorIdentityId: adminId, organizationId: orgId, metadata: { tag, i } }));

  /**
   * Reads the stream's first chunk, appends events, then reads the rest:
   * every event is there once, oldest first, and nothing recorded after
   * the export started.
   */
  async function exportWhileAppending(path: string, token: string) {
    const res = await app.request(path, { headers: { Authorization: `Bearer ${token}` } });
    expect(res.status).toBe(200);
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    let text = "";
    const first = await reader.read();
    text += decoder.decode(first.value, { stream: true });
    await recordAuditEvents(ctx.db, filler(300, "late"));
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      text += decoder.decode(next.value, { stream: true });
    }
    return text.trim().split("\n").map((line) => JSON.parse(line) as { eventId: string; eventType: string; metadata: { tag?: string } | null });
  }

  it("streams every event in batches, oldest first, up to the moment it started; the deleted Organization's export too", async () => {
    await recordAuditEvents(ctx.db, filler(600, "early"));
    const live = await exportWhileAppending(`${ORG}/audit-events/export`, admin);
    const ordered = (await ctx.db.query("SELECT id FROM audit_events WHERE organization_id = $1 ORDER BY event_order", [orgId])).rows.map((r) => r.id as string);
    // The 600 fillers need three batches of 250; the late ones are not in it.
    expect(live.filter((e) => e.metadata?.tag === "early")).toHaveLength(600);
    expect(live.some((e) => e.metadata?.tag === "late")).toBe(false);
    expect(live.map((e) => e.eventId)).toEqual(ordered.slice(0, live.length));
    expect(new Set(live.map((e) => e.eventId)).size).toBe(live.length);

    await call("POST", `${ORG}/deletion`, {});
    await makeDue();
    expect(await runDueDeletions(ctx)).toHaveLength(1);
    const before = (await ctx.db.query("SELECT count(*)::int AS n FROM audit_events WHERE organization_id = $1", [orgId])).rows[0]!.n as number;
    const tombstone = await exportWhileAppending(`/v1/deleted-organizations/${orgId}/audit-events/export`, admin);
    expect(tombstone).toHaveLength(before);
    expect(tombstone[tombstone.length - 1]!.eventType).toBe("organization.deleted");
    expect(tombstone.filter((e) => e.metadata?.tag === "late")).toHaveLength(300);
  });
});
