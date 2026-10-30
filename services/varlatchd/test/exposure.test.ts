// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { exposureFromEvent, integrationFromEvent, parseItems } from "../src/audit/exposure.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { backfillExposureOnce } from "../src/domain/exposure.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { traceLog, traced, type TraceLog } from "./helpers/trace.js";

/**
 * The exposure index and report (ADR-0052 Decisions 6 and 7): what a person
 * received, observed in audit; what they could reach at removal; which
 * versions Varlatch still serves; and an operator's confirmation.
 */

const ORG = "/v1/organizations/acme";
const P = `${ORG}/projects/api`;
const PROD = `${P}/environments/production`;
const DEV = `${P}/environments/development`;

let log: TraceLog;
let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let admin: { id: string; token: string };
let bob: { id: string; token: string };
let orgId: string;
let prodId: string;
let devId: string;

async function call(method: string, path: string, body?: unknown, token = admin.token) {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

async function exposureRows(identityId: string) {
  return (
    await ctx.db.query(
      "SELECT item_name, version_id, environment_id, way FROM member_exposure WHERE identity_id = $1 ORDER BY item_name, version_id, environment_id, way",
      [identityId],
    )
  ).rows as { item_name: string; version_id: string; environment_id: string; way: string }[];
}

async function versionOf(env: string, name: string, column = "current_version_id"): Promise<string> {
  const res = await ctx.db.query(
    `SELECT v.${column} AS id FROM env_values v JOIN environments e ON e.id = v.environment_id WHERE e.name = $1 AND v.item_name = $2`,
    [env, name],
  );
  return (res.rows[0] as { id: string }).id;
}

beforeEach(async () => {
  log = traceLog();
  const db = traced(await migratedTestDb(), log);
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const setup = await issueBootstrapGrant(ctx);
  const { identityId } = await consumeSetupGrant(ctx, setup.token, { adminName: "Admin" });
  admin = { id: identityId, token: (await issueCredential(ctx.db, { identityId, kind: "cli" })).token };
  app = buildApp(ctx);
  orgId = (await call("POST", "/v1/organizations", { name: "Acme", slug: "acme" })).body.id;
  await call("POST", `${ORG}/projects`, { name: "API", slug: "api", contractAuthority: "managed" });
  prodId = (await call("POST", `${P}/environments`, { name: "production", tier: "production" })).body.id;
  devId = (await call("POST", `${P}/environments`, { name: "development", tier: "development" })).body.id;
  const revision = await call("POST", `${P}/contract/revisions`, {
    contract: {
      schemaVersion: 1,
      items: [
        { name: "TOKEN", required: { kind: "never" }, sensitive: true, type: "string", rotationHint: "Issue a new token in the provider console, then revoke the old one." },
        { name: "DB_HOST", required: { kind: "never" }, sensitive: false, type: "string" },
      ],
    },
  });
  await call("POST", `${P}/contract/revisions/${revision.body.id}/activate`, {});
  for (const env of [PROD, DEV]) {
    expect((await call("PUT", `${env}/values/TOKEN`, { value: `token-${env.endsWith("production") ? "prod" : "dev"}-1111` })).status).toBe(200);
    expect((await call("PUT", `${env}/values/DB_HOST`, { value: "db.internal" })).status).toBe(200);
  }
  const invite = await issueInviteGrant(ctx, { organizationId: orgId, role: "member", name: "Bob" }, admin.id);
  const bobId = (await consumeSetupGrant(ctx, invite.token, {})).identityId;
  bob = { id: bobId, token: (await issueCredential(ctx.db, { identityId: bobId, kind: "cli" })).token };
  // Bob may reveal production's Secrets too.
  expect(
    (
      await call("POST", `${ORG}/grants`, {
        subjectIdentityId: bob.id,
        scope: { kind: "environments", projectId: revision.body.projectId ?? (await call("GET", P)).body.id, selector: { kind: "environments", environmentIds: [prodId] } },
        actions: ["secret.reveal", "secret.use", "config.value.read", "config.metadata.read"],
      })
    ).status,
  ).toBe(201);
});
afterEach(async () => {
  await ctx.close();
});

describe("the extraction rules", () => {
  it("read every version of an items list, retiring ones included", () => {
    expect(parseItems("A@ver_1,B@ver_2+ver_3")).toEqual([
      { itemName: "A", versionId: "ver_1" },
      { itemName: "B", versionId: "ver_2" },
      { itemName: "B", versionId: "ver_3" },
    ]);
    expect(parseItems("")).toEqual([]);
    expect(parseItems(undefined)).toEqual([]);
  });

  it("classify the way of receiving, and skip validations and events without an actor", () => {
    const base = { actorIdentityId: "idn_b", organizationId: "org_a", resource: { environmentId: "env_p" } };
    const way = (eventType: string, metadata: Record<string, unknown>) => exposureFromEvent({ ...base, eventType, metadata })?.way ?? null;
    expect(way("secret.disclosed", { mode: "requested", items: "A@v" })).toBe("revealed");
    expect(way("secret.disclosed", { mode: "strict-retrieval", items: "A@v" })).toBe("delivered");
    expect(way("secret.disclosed", { mode: "all-authorized-secrets", purpose: "scan", items: "A@v" })).toBe("delivered");
    expect(way("value.disclosed", { items: "A@v", purpose: "export" })).toBe("export");
    expect(way("value.disclosed", { mode: "reference-expansion", items: "A@v" })).toBe("revealed");
    expect(way("secret.validated", { items: "A@v" })).toBeNull();
    expect(exposureFromEvent({ ...base, eventType: "value.written", resource: { environmentId: "env_p", itemName: "A", versionId: "v" } })).toMatchObject({
      way: "written",
      items: [{ itemName: "A", versionId: "v" }],
    });
    expect(exposureFromEvent({ eventType: "secret.disclosed", organizationId: "org_a", resource: { environmentId: "e" }, metadata: { items: "A@v" } })).toBeNull();
    expect(integrationFromEvent({ ...base, eventType: "sync.target_updated", resource: { targetId: "snt" }, metadata: { destinationChanged: true, connectionRepointed: false } })).toMatchObject({
      changes: ["destination_changed"],
    });
    expect(integrationFromEvent({ ...base, eventType: "sync.target_updated", resource: { targetId: "snt" }, metadata: { destinationChanged: false } })).toBeNull();
  });
});

describe("live indexing", () => {
  it("records each way of receiving, per disclosure environment, before the audit event", async () => {
    log.reset();
    expect((await call("POST", `${PROD}/disclosures`, { items: ["TOKEN"] }, bob.token)).status).toBe(200);
    // The index is written in the disclosure's transaction, before its audit event.
    const sql = log.entries.filter((e) => e.kind === "sql").map((e) => (e as { text: string }).text);
    const indexAt = sql.findIndex((t) => t.includes("INSERT INTO member_exposure"));
    const auditAt = sql.findIndex((t) => t.includes("INSERT INTO audit_events"));
    expect(indexAt).toBeGreaterThanOrEqual(0);
    expect(indexAt).toBeLessThan(auditAt);

    expect((await call("POST", `${PROD}/retrievals`, { mode: "strict" }, bob.token)).status).toBe(200);
    expect((await call("POST", `${PROD}/disclosures`, { items: ["TOKEN"], purpose: "export" }, bob.token)).status).toBe(200);
    expect((await call("GET", `${DEV}/effective-configuration?include=values`, undefined, bob.token)).status).toBe(200);
    expect((await call("PUT", `${DEV}/values/DB_HOST`, { value: "db2.internal" }, bob.token)).status).toBe(200);

    const token = await versionOf("production", "TOKEN");
    const rows = await exposureRows(bob.id);
    expect(rows).toEqual(
      expect.arrayContaining([
        { item_name: "TOKEN", version_id: token, environment_id: prodId, way: "revealed" },
        { item_name: "TOKEN", version_id: token, environment_id: prodId, way: "delivered" },
        { item_name: "TOKEN", version_id: token, environment_id: prodId, way: "export" },
        { item_name: "DB_HOST", version_id: await versionOf("development", "DB_HOST", "current_version_id"), environment_id: devId, way: "written" },
      ]),
    );
    // A disclosure again widens the times; it adds no row.
    const before = rows.length;
    expect((await call("POST", `${PROD}/disclosures`, { items: ["TOKEN"] }, bob.token)).status).toBe(200);
    expect(await exposureRows(bob.id)).toHaveLength(before);
  });

  it("indexes everything a transaction indexes before its first audit insert, in one statement", async () => {
    // A strict retrieval records two events (plain values and Secrets) in one transaction.
    log.reset();
    expect((await call("POST", `${PROD}/retrievals`, { mode: "strict" }, bob.token)).status).toBe(200);
    const sql = log.entries.filter((e) => e.kind === "sql").map((e) => (e as { text: string }).text);
    const indexes = sql.flatMap((t, i) => (t.includes("INSERT INTO member_exposure") ? [i] : []));
    const audits = sql.flatMap((t, i) => (t.includes("INSERT INTO audit_events") ? [i] : []));
    expect(indexes).toHaveLength(1);
    expect(audits.length).toBeGreaterThanOrEqual(2);
    expect(indexes[0]!).toBeLessThan(audits[0]!);
    expect((await exposureRows(bob.id)).map((r) => `${r.item_name} ${r.way}`).sort()).toEqual(["DB_HOST delivered", "TOKEN delivered"]);
  });

  it("keeps an inherited version's receipts through each environment apart", async () => {
    const personal = await call("POST", `${P}/environments`, { name: "development/bob", kind: "personal", parentEnvironmentId: devId }, bob.token);
    expect(personal.status, JSON.stringify(personal.body)).toBe(201);
    expect((await call("POST", `${DEV}/disclosures`, { items: ["TOKEN"] }, bob.token)).status).toBe(200);
    expect((await call("POST", `${P}/environments/${encodeURIComponent("development/bob")}/disclosures`, { items: ["TOKEN"] }, bob.token)).status).toBe(200);
    const version = await versionOf("development", "TOKEN");
    const rows = (await exposureRows(bob.id)).filter((r) => r.version_id === version);
    expect(rows.map((r) => r.environment_id).sort()).toEqual([devId, personal.body.id].sort());
    const report = await call("GET", `${ORG}/members/${bob.id}/exposure`);
    const entry = report.body.received.find((r: { versionId: string }) => r.versionId === version);
    // Owned by development, received through both.
    expect(entry).toMatchObject({ owningEnvironmentId: devId, state: "served", servedAs: "current" });
    expect(entry.receipts.map((r: { environmentId: string }) => r.environmentId).sort()).toEqual([devId, personal.body.id].sort());
  });

  it("does not index a machine's deliveries", async () => {
    const svc = (await call("POST", `${ORG}/identities`, { name: "ci", kind: "service" })).body;
    await call("POST", `${ORG}/grants`, { subjectIdentityId: svc.id, scope: { kind: "organization" }, actions: ["secret.reveal", "config.metadata.read"] });
    expect((await call("POST", `${PROD}/disclosures`, { items: ["TOKEN"] }, svc.credential)).status).toBe(200);
    expect(await exposureRows(svc.id)).toEqual([]);
  });
});

describe("the report", () => {
  it("says which versions Varlatch still serves, with the rotation hint, and what was replaced", async () => {
    expect((await call("POST", `${PROD}/disclosures`, { items: ["TOKEN"] }, bob.token)).status).toBe(200);
    const first = await versionOf("production", "TOKEN");
    let report = await call("GET", `${ORG}/members/${bob.id}/exposure`);
    expect(report.status).toBe(200);
    expect(report.body.coverage).toEqual({ complete: true });
    expect(report.body.received).toEqual([
      expect.objectContaining({
        itemName: "TOKEN",
        versionId: first,
        owningEnvironmentId: prodId,
        state: "served",
        servedAs: "current",
        rotationHint: "Issue a new token in the provider console, then revoke the old one.",
        receipts: [expect.objectContaining({ environmentId: prodId, way: "revealed" })],
      }),
    ]);
    // A rotation keeps the old version served until its deadline.
    expect((await call("POST", `${PROD}/values/TOKEN/rotations`, { value: "token-prod-2222" })).status).toBe(201);
    report = await call("GET", `${ORG}/members/${bob.id}/exposure`);
    expect(report.body.received[0]).toMatchObject({ state: "served", servedAs: "retiring", retiringUntil: expect.any(String) });
    // After the deadline it is no longer served: replaced, which is not "safe".
    await ctx.db.query("UPDATE env_values SET rotation_deadline = now() - interval '1 minute' WHERE retiring_version_id = $1", [first]);
    report = await call("GET", `${ORG}/members/${bob.id}/exposure`);
    expect(report.body.received[0]).toMatchObject({ state: "not-served", served: false, notServedBecause: "replaced" });
    // Values never appear.
    expect(JSON.stringify(report.body)).not.toMatch(/token-prod/);
  });

  it("covers former members, with their authority at removal and the integrations they set up", async () => {
    await call("POST", `${ORG}/requirements`, {
      kind: "tailnet",
      target: { kind: "tier", tier: "production" },
      selector: { tailnet: "example.ts.net", tags: ["tag:prod"] },
    });
    expect((await call("POST", `${ORG}/webhooks`, { url: "https://sink.example/hook" })).status).toBe(201);
    expect((await call("DELETE", `${ORG}/members/${bob.id}`)).status).toBe(200);
    const report = await call("GET", `${ORG}/members/${bob.id}/exposure`);
    expect(report.status).toBe(200);
    expect(report.body.member).toMatchObject({ identityId: bob.id, role: null, removedAt: expect.any(String) });
    const prod = report.body.authorityAtRemoval.environments.find((e: { environmentId: string }) => e.environmentId === prodId);
    expect(prod.actions.map((a: { action: string }) => a.action).sort()).toEqual(["config.metadata.read", "config.value.read", "secret.reveal", "secret.use"]);
    expect(prod.conditionalOn).toHaveLength(1);
    expect(report.body.authorityAtRemoval.requirements[0].selector).toEqual({ tailnet: "example.ts.net", tags: ["tag:prod"] });
    expect(report.body.indirect).toEqual(expect.objectContaining({ webhooks: [] }));
  });

  it("needs audit.read, and hides the Organization from those who cannot see it", async () => {
    expect((await call("GET", `${ORG}/members/${admin.id}/exposure`, undefined, bob.token)).status).toBe(403);
    await call("POST", "/v1/organizations", { name: "Other", slug: "other" });
    expect((await call("GET", `/v1/organizations/other/members/${admin.id}/exposure`, undefined, bob.token)).status).toBe(404);
    expect((await call("GET", `${ORG}/members/idn_nobody/exposure`)).status).toBe(404);
  });
});

describe("confirming revocation at the provider", () => {
  it("is recorded once per version, by someone who may write the value, and shown in the report", async () => {
    expect((await call("POST", `${PROD}/disclosures`, { items: ["TOKEN"] }, bob.token)).status).toBe(200);
    const version = await versionOf("production", "TOKEN");
    const path = `${ORG}/members/${bob.id}/exposure/confirmations`;
    // Bob may reveal production's TOKEN but not write it.
    expect((await call("POST", path, { versionId: version }, bob.token)).status).toBe(403);
    // Only a version in this member's exposure.
    expect((await call("POST", path, { versionId: await versionOf("development", "TOKEN") })).status).toBe(404);
    const confirmed = await call("POST", path, { versionId: version });
    expect(confirmed.status).toBe(201);
    expect(confirmed.body).toMatchObject({ versionId: version, actorIdentityId: admin.id });
    expect((await call("POST", path, { versionId: version })).status).toBe(200);
    const audit = (await ctx.db.query("SELECT actor_identity_id, resource FROM audit_events WHERE event_type = 'exposure.revocation_confirmed'")).rows;
    expect(audit).toHaveLength(1);
    const report = await call("GET", `${ORG}/members/${bob.id}/exposure`);
    expect(report.body.received[0]).toMatchObject({ state: "revocation-confirmed", served: true, confirmation: { actorIdentityId: admin.id } });
  });

  it("for a deleted value, only a live Organization Admin", async () => {
    expect((await call("POST", `${PROD}/disclosures`, { items: ["TOKEN"] }, bob.token)).status).toBe(200);
    const version = await versionOf("production", "TOKEN");
    expect((await call("DELETE", `${PROD}/values/TOKEN`)).status).toBe(204);
    // Someone who could write the value while it lived is not enough now.
    const carolInvite = await issueInviteGrant(ctx, { organizationId: orgId, role: "member", name: "Carol" }, admin.id);
    const carolId = (await consumeSetupGrant(ctx, carolInvite.token, {})).identityId;
    const carol = (await issueCredential(ctx.db, { identityId: carolId, kind: "cli" })).token;
    await call("POST", `${ORG}/grants`, { subjectIdentityId: carolId, scope: { kind: "organization" }, actions: ["config.value.write", "audit.read"] });
    const path = `${ORG}/members/${bob.id}/exposure/confirmations`;
    expect((await call("POST", path, { versionId: version }, carol)).status).toBe(403);
    expect((await call("POST", path, { versionId: version })).status).toBe(201);
    const report = await call("GET", `${ORG}/members/${bob.id}/exposure`);
    expect(report.body.received[0]).toMatchObject({ served: false, notServedBecause: "value-deleted", state: "revocation-confirmed" });
  });
});

describe("the backfill", () => {
  async function restartBackfill() {
    await ctx.db.query("DELETE FROM member_exposure");
    await ctx.db.query("DELETE FROM member_integrations");
    await ctx.db.query("UPDATE exposure_backfill SET cursor = 0, until_order = (SELECT value FROM audit_position), finished_at = NULL");
  }

  it("rebuilds the same rows from audit events, in batches that resume, and only widens times", async () => {
    expect((await call("POST", `${PROD}/disclosures`, { items: ["TOKEN"] }, bob.token)).status).toBe(200);
    expect((await call("POST", `${PROD}/values/TOKEN/rotations`, { value: "token-prod-3333" })).status).toBe(201);
    expect((await call("POST", `${PROD}/disclosures`, { items: ["TOKEN"] }, bob.token)).status).toBe(200);
    expect((await call("PUT", `${DEV}/values/DB_HOST`, { value: "db3.internal" }, bob.token)).status).toBe(200);
    const live = await exposureRows(bob.id);
    const liveTimes = (await ctx.db.query("SELECT version_id, way, environment_id, first_at FROM member_exposure ORDER BY 1,2,3")).rows;
    // The rotation's disclosure names both versions (primary+retiring).
    expect(live.filter((r) => r.item_name === "TOKEN" && r.way === "revealed")).toHaveLength(2);

    await restartBackfill();
    let report = await call("GET", `${ORG}/members/${bob.id}/exposure`);
    expect(report.body.coverage).toMatchObject({ complete: false, from: expect.any(String), to: expect.any(String) });

    // One event per batch: each batch commits its rows with its cursor.
    let batches = 0;
    for (;;) {
      const { done } = await backfillExposureOnce(ctx, { events: 1, items: 100 });
      batches++;
      if (done) break;
      expect(batches).toBeLessThan(200);
    }
    expect(batches).toBeGreaterThan(3);
    expect(await exposureRows(bob.id)).toEqual(live);
    expect((await ctx.db.query("SELECT version_id, way, environment_id, first_at FROM member_exposure ORDER BY 1,2,3")).rows).toEqual(liveTimes);
    report = await call("GET", `${ORG}/members/${bob.id}/exposure`);
    expect(report.body.coverage).toEqual({ complete: true });
    // Running again, or replaying, changes nothing.
    expect(await backfillExposureOnce(ctx)).toEqual({ done: true, events: 0 });
  });

  it("caps the items of a batch, and overlaps harmlessly with live indexing", async () => {
    for (let i = 0; i < 3; i++) expect((await call("POST", `${PROD}/disclosures`, { items: ["TOKEN"] }, bob.token)).status).toBe(200);
    await restartBackfill();
    // Live indexing during the backfill.
    expect((await call("POST", `${PROD}/disclosures`, { items: ["TOKEN"] }, bob.token)).status).toBe(200);
    const first = await backfillExposureOnce(ctx, { events: 100, items: 1 });
    expect(first).toMatchObject({ done: false, events: 1 });
    while (!(await backfillExposureOnce(ctx, { events: 100, items: 1 })).done) {
      /* next batch */
    }
    const rows = (await ctx.db.query("SELECT first_at, last_at FROM member_exposure WHERE identity_id = $1 AND way = 'revealed'", [bob.id])).rows as {
      first_at: Date;
      last_at: Date;
    }[];
    expect(rows).toHaveLength(1);
    // The backfill moved first_at back to the first disclosure; live indexing set last_at.
    expect(new Date(rows[0]!.first_at).getTime()).toBeLessThan(new Date(rows[0]!.last_at).getTime());
  });

  it("reads a bounded range of audit positions per batch, moving past events it does not index", async () => {
    const { recordAuditEvent } = await import("../src/audit/events.js");
    for (let i = 0; i < 30; i++) await recordAuditEvent(ctx.db, { eventType: "test.noise", decision: "info" });
    expect((await call("POST", `${PROD}/disclosures`, { items: ["TOKEN"] }, bob.token)).status).toBe(200);
    for (let i = 0; i < 30; i++) await recordAuditEvent(ctx.db, { eventType: "test.noise", decision: "info" });
    const live = await exposureRows(bob.id);
    await restartBackfill();
    const position = Number((await ctx.db.query("SELECT value::int AS v FROM audit_position")).rows[0]!.v);
    let batches = 0;
    let previous = 0;
    for (;;) {
      const { done } = await backfillExposureOnce(ctx, { span: 10 });
      batches++;
      const cursor = Number((await ctx.db.query("SELECT cursor::int AS c FROM exposure_backfill")).rows[0]!.c);
      // Every batch moves on, at most one span, matching events or not.
      expect(cursor).toBeGreaterThan(previous);
      expect(cursor - previous).toBeLessThanOrEqual(10);
      previous = cursor;
      if (done) break;
    }
    expect(previous).toBe(position);
    expect(batches).toBeGreaterThanOrEqual(Math.ceil(position / 10));
    expect(await exposureRows(bob.id)).toEqual(live);
  });

  it("keeps looking after it finishes, so a restored unfinished backfill resumes", async () => {
    const { startExposureBackfillLoop } = await import("../src/domain/exposure.js");
    expect((await call("POST", `${PROD}/disclosures`, { items: ["TOKEN"] }, bob.token)).status).toBe(200);
    const live = await exposureRows(bob.id);
    const stop = startExposureBackfillLoop(ctx, { busyMs: 5, idleMs: 5 });
    try {
      // Finished state: nothing to do. Then an archive from before it finished comes back.
      await new Promise((r) => setTimeout(r, 30));
      await restartBackfill();
      for (let i = 0; i < 200; i++) {
        const state = (await ctx.db.query("SELECT finished_at FROM exposure_backfill")).rows[0] as { finished_at: unknown };
        if (state.finished_at) break;
        await new Promise((r) => setTimeout(r, 10));
      }
    } finally {
      stop();
    }
    expect((await ctx.db.query("SELECT finished_at FROM exposure_backfill")).rows[0]).not.toEqual({ finished_at: null });
    expect(await exposureRows(bob.id)).toEqual(live);
  });

  it("skips events whose Organization or identity no longer exists, and goes on", async () => {
    expect((await call("POST", `${PROD}/disclosures`, { items: ["TOKEN"] }, bob.token)).status).toBe(200);
    const live = await exposureRows(bob.id);
    // Audit events carry no foreign keys: an event may name what is gone.
    await ctx.db.query(
      `INSERT INTO audit_events (id, event_type, decision, actor_identity_id, organization_id, resource, metadata) VALUES
       ('evt_gone_org', 'secret.disclosed', 'allow', $1, 'org_gone', '{"environmentId":"env_gone"}', '{"mode":"requested","items":"TOKEN@ver_gone"}'),
       ('evt_gone_idn', 'secret.disclosed', 'allow', 'idn_gone', $2, '{"environmentId":"env_gone"}', '{"mode":"requested","items":"TOKEN@ver_gone"}')`,
      [bob.id, orgId],
    );
    await restartBackfill();
    while (!(await backfillExposureOnce(ctx)).done) {
      /* next batch */
    }
    expect(await exposureRows(bob.id)).toEqual(live);
  });

  it("rebuilds the integration index from Sync Target and Connection events", async () => {
    await ctx.db.query("UPDATE org_memberships SET role = 'admin' WHERE identity_id = $1", [bob.id]);
    const connection = (await call("POST", `${ORG}/platform-connections`, {
      platform: "coolify", baseIdentity: "https://coolify.example.com", name: "c", credential: "token-c",
    }, bob.token)).body;
    const target = await call("POST", `${DEV}/sync-targets`, { connectionId: connection.id, destination: { applicationUuid: "app1" }, mapping: { kind: "wildcard" } }, bob.token);
    expect(target.status, JSON.stringify(target.body)).toBe(201);
    const moved = await call("PATCH", `${DEV}/sync-targets/${target.body.id}`, { expectedVersion: target.body.version, destination: { applicationUuid: "app2" } }, bob.token);
    expect(moved.status, JSON.stringify(moved.body)).toBe(200);
    const live = (await ctx.db.query("SELECT kind, resource_id, changes FROM member_integrations ORDER BY kind, resource_id")).rows;
    await restartBackfill();
    while (!(await backfillExposureOnce(ctx)).done) {
      /* next batch */
    }
    expect((await ctx.db.query("SELECT kind, resource_id, changes FROM member_integrations ORDER BY kind, resource_id")).rows).toEqual(live);
    expect(live).toContainEqual({ kind: "target", resource_id: target.body.id, changes: ["created", "destination_changed"] });
  });
});
