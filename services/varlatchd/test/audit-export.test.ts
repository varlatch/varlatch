// SPDX-License-Identifier: AGPL-3.0-or-later
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import { gunzipSync } from "node:zlib";
import {
  CreateBucketCommand,
  GetObjectCommand,
  GetObjectRetentionCommand,
  ListBucketsCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { decryptAuditExportDrainCredential } from "../src/crypto/hierarchy.js";
import { withApproval, type ProtectedGate, type Requester } from "../src/domain/approvals.js";
import {
  abandonExpiredDrains,
  AUDIT_EXPORT_LIMITS,
  auditExportLag,
  changeAuditExport,
  checkAuditExport,
  classifyChange,
  createAuditExport,
  discardPlan,
  exportOnce,
  OBJECT_CONFLICT,
  recordRestore,
  removeAuditExport,
  replaceAuditExportCredential,
  restartStream,
  runAuditExportsOnce,
  setAuditExportTestHooks,
  UNSUPPORTED_FORMAT,
  type AuditExportDestination,
  type AuditExportRetention,
  type CreateInput,
} from "../src/domain/auditexport.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { DomainError } from "../src/domain/errors.js";
import { finalizeDeletion } from "../src/domain/orgdeletion.js";
import { getOrganization, type OrgRow } from "../src/domain/orgs.js";
import { buildApp } from "../src/http/app.js";
import { OutboundPolicy } from "../src/net/outbound.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * The audit export (ADR-0056), against MinIO with Object Lock (the
 * Chainguard build, pinned by digest: MinIO withdrew its own images), on
 * PGlite under the lock-order check. One container per file, named for this
 * run and removed with `docker rm -fv`. Skipped where Docker is not
 * available.
 *
 * Covered here from the ADR's test list: the copy (once, in order, chain
 * intact, no other Organization); leases and fencing (a second worker, a
 * lost lease, a destination change, a credential replacement and a removal
 * between upload and commit); a lost success response with and without a
 * read key; a plan uploaded unchanged by a later attempt; an unsupported
 * format and discard-plan; recovery after the retention deadline, raced,
 * and with a lost response (the overlap); heartbeats; the probe
 * (conditional creation, Object Lock, verified or not); an object conflict;
 * a restore; retention headers on every write; the outbound policy;
 * approvals; the freeze and a pending deletion; the deletion drain and its
 * deadline; status; the switch off.
 */

const MINIO_IMAGE = "cgr.dev/chainguard/minio@sha256:6a1d0b45c8669726bba580ced0bfa4cb9fdeed1ed636dfabd81d1577beb6937b";
const ROOT_USER = "vltaudittest";
const ROOT_PASSWORD = randomBytes(18).toString("hex");
const LOCKED = "audit-lock";
const UNLOCKED = "audit-nolock";
const OTHER = "audit-other";

const docker = (() => {
  try {
    execFileSync("docker", ["info"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

let container = "";
let endpoint = "";
let admin: S3Client;

const ORG = "/v1/organizations/acme";

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let org: OrgRow;
let person: { id: string; cli: string; cliId: string; web: string; key: SoftAuthenticator };
let prefix: string;
let n = 0;

async function call(method: string, path: string, token: string, body?: unknown) {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

const rows = async (sql: string, params: unknown[] = []) => (await ctx.db.query(sql, params)).rows as any[];
const json = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v);
const requester = (): Requester => ({ identityId: person.id, identityKind: "human", credentialId: person.cliId, credentialKind: "cli" });
const credential = () => ({ accessKeyId: ROOT_USER, secretAccessKey: ROOT_PASSWORD });
const destination = (over: Partial<AuditExportDestination> = {}): AuditExportDestination => ({
  endpoint, region: "us-east-1", bucket: LOCKED, prefix, pathStyle: true, ...over,
});
const governance: AuditExportRetention = { mode: "governance", days: 1 };

async function events(eventType: string) {
  return (await rows("SELECT actor_identity_id, organization_id, resource, metadata FROM audit_events WHERE event_type = $1 ORDER BY event_order", [eventType]))
    .map((r) => ({ actor: r.actor_identity_id as string | null, org: r.organization_id as string, resource: json(r.resource), metadata: json(r.metadata) as Record<string, any> }));
}
const exportRow = async (id: string) => (await rows("SELECT * FROM audit_exports WHERE id = $1", [id]))[0];
const pendingPlan = async (id: string) => (await rows("SELECT * FROM audit_export_plans WHERE export_id = $1", [id]))[0];

/** Run the export until it has nothing to do. */
async function drain(id: string) {
  for (let i = 0; i < 30; i++) {
    const r = await exportOnce(ctx, id);
    if (r.outcome !== "done") return r;
  }
  throw new Error("export did not drain");
}

/** Run a protected operation as the person: asked, approved with the passkey, repeated. */
async function withStepUp<T>(run: (gate: ProtectedGate) => Promise<T>): Promise<T> {
  const first = await withApproval(ctx, { requester: requester(), approvalId: null, publicUrl: PUBLIC_URL }, run).catch((e: unknown) => e);
  if (!(first instanceof DomainError) || first.code !== "STEP_UP_REQUIRED") {
    if (first instanceof Error) throw first;
    return first as T;
  }
  const id = (first.details as { approval: { id: string } }).approval.id;
  await approve(id);
  return withApproval(ctx, { requester: requester(), approvalId: id, publicUrl: PUBLIC_URL }, run);
}
async function askApproval(run: (gate: ProtectedGate) => Promise<unknown>): Promise<string> {
  const err = await withApproval(ctx, { requester: requester(), approvalId: null, publicUrl: PUBLIC_URL }, run).catch((e: unknown) => e);
  expect(err).toBeInstanceOf(DomainError);
  expect((err as DomainError).code).toBe("STEP_UP_REQUIRED");
  return ((err as DomainError).details as { approval: { id: string } }).approval.id;
}
async function approve(approvalId: string) {
  const started = await call("POST", `/v1/me/approvals/${approvalId}/options`, person.web);
  expect(started.status, JSON.stringify(started.body)).toBe(200);
  const done = await call("POST", `/v1/me/approvals/${approvalId}/approve`, person.web, {
    assertion: person.key.assert(started.body.publicKey.challenge, { userVerified: true }),
  });
  expect(done.status, JSON.stringify(done.body)).toBe(200);
}

const create = (over: Partial<CreateInput> = {}) =>
  createAuditExport(ctx, requester(), org, { destination: destination(), credential: credential(), retention: governance, from: "beginning", ...over });

// ---- The bucket, as a reader sees it.
async function listed(bucket: string, under: string): Promise<string[]> {
  const out: string[] = [];
  let token: string | undefined;
  do {
    const page = await admin.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: under, ContinuationToken: token }));
    out.push(...(page.Contents ?? []).map((o) => o.Key as string));
    token = page.NextContinuationToken;
  } while (token);
  return out.sort();
}
async function body(bucket: string, key: string): Promise<Buffer> {
  const got = await admin.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  return Buffer.from(await got.Body!.transformToByteArray());
}
interface Batch { header: Record<string, any>; lines: Record<string, any>[]; key: string }
async function batches(bucket: string, streamId: string): Promise<Batch[]> {
  const keys = (await listed(bucket, `${prefix}varlatch-audit/${org.id}/${streamId}/`)).filter((k) => k.endsWith(".ndjson.gz"));
  const out: Batch[] = [];
  for (const key of keys) {
    const [head, ...lines] = gunzipSync(await body(bucket, key)).toString("utf8").trim().split("\n").map((l) => JSON.parse(l));
    out.push({ header: head, lines, key });
  }
  return out;
}
async function manifest(bucket: string, streamId: string) {
  return JSON.parse((await body(bucket, `${prefix}varlatch-audit/${org.id}/${streamId}/stream.json`)).toString("utf8"));
}
const orgEvents = async (upTo?: string) =>
  (await rows(
    `SELECT id, event_order::text AS position FROM audit_events WHERE organization_id = $1 ${upTo ? "AND event_order <= $2" : ""} ORDER BY event_order`,
    upTo ? [org.id, upTo] : [org.id],
  )) as { id: string; position: string }[];

beforeAll(async () => {
  if (!docker) return;
  container = `vlt-aex-${process.pid}-${randomBytes(4).toString("hex")}`;
  execFileSync("docker", ["run", "-d", "--rm", "--name", container, "-p", "127.0.0.1::9000",
    "-e", `MINIO_ROOT_USER=${ROOT_USER}`, "-e", `MINIO_ROOT_PASSWORD=${ROOT_PASSWORD}`,
    MINIO_IMAGE, "server", "/data"], { stdio: ["ignore", "ignore", "pipe"] });
  const port = execFileSync("docker", ["port", container, "9000/tcp"]).toString().trim().split("\n")[0]!.split(":").pop();
  endpoint = `http://127.0.0.1:${port}`;
  admin = new S3Client({ endpoint, region: "us-east-1", forcePathStyle: true, credentials: credential() });
  for (let i = 0; ; i++) {
    try {
      await admin.send(new ListBucketsCommand({}));
      break;
    } catch (err) {
      if (i > 100) throw err;
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  await admin.send(new CreateBucketCommand({ Bucket: LOCKED, ObjectLockEnabledForBucket: true }));
  await admin.send(new CreateBucketCommand({ Bucket: OTHER, ObjectLockEnabledForBucket: true }));
  await admin.send(new CreateBucketCommand({ Bucket: UNLOCKED }));
}, 120_000);

afterAll(() => {
  admin?.destroy();
  if (container) {
    try {
      execFileSync("docker", ["rm", "-fv", container], { stdio: "ignore" });
    } catch {
      /* gone */
    }
  }
});

beforeEach(async () => {
  const db = await migratedTestDb();
  // MinIO listens on loopback, which only an allow list entry opens (ADR-0057 Decision 5).
  ctx = { db, rootKek: generateKey(), close: db.close, outbound: new OutboundPolicy("127.0.0.1/32:*") };
  await ensureInstallation(ctx);
  const { identityId } = await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" });
  app = buildApp(ctx, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7" });
  const cli = await issueCredential(ctx.db, { identityId, kind: "cli", name: "test cli" });
  const key = await registerSoftPasskey(ctx.db, identityId, { ...RP, trust: "trusted" });
  await ctx.db.query(
    `INSERT INTO "session" (id, "expiresAt", token, "userId")
     SELECT $1, now() + interval '1 day', $1, better_auth_user_id FROM auth_user_links WHERE identity_id = $2`,
    [`session-${identityId}`, identityId],
  );
  const web = await issueCredential(ctx.db, { identityId, kind: "browser", expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(), authSessionId: `session-${identityId}` });
  person = { id: identityId, cli: cli.token, cliId: cli.credentialId, web: web.token, key };
  const created = await call("POST", "/v1/organizations", person.cli, { name: "Acme", slug: "acme" });
  expect(created.status).toBe(201);
  org = await getOrganization(ctx, "acme");
  prefix = `run-${process.pid}-${n++}/`;
});

afterEach(async () => {
  setAuditExportTestHooks(null);
  await ctx.close();
});

describe("audit export, nothing configured", () => {
  it("does nothing until an export exists: no rows, no request, no audit event", async () => {
    const before = await rows("SELECT count(*)::int AS n, max(event_order)::text AS m FROM audit_events");
    await runAuditExportsOnce(ctx);
    await abandonExpiredDrains(ctx.db);
    expect(await rows("SELECT count(*)::int AS n, max(event_order)::text AS m FROM audit_events")).toEqual(before);
    expect(await rows("SELECT count(*)::int AS n FROM audit_exports")).toEqual([{ n: 0 }]);
  });

  it("classifies changes field by field", () => {
    const d = destination();
    const r = (mode: "compliance" | "governance", days: number) => ({ mode, days });
    expect(classifyChange({ destination: d, retention: null }, { destination: d, retention: r("governance", 1) }).loosened).toBe(false);
    expect(classifyChange({ destination: d, retention: r("governance", 10) }, { destination: d, retention: r("compliance", 20) }).loosened).toBe(false);
    expect(classifyChange({ destination: d, retention: r("compliance", 10) }, { destination: d, retention: r("governance", 10) }).loosened).toBe(true);
    expect(classifyChange({ destination: d, retention: r("compliance", 10) }, { destination: d, retention: r("compliance", 9) }).loosened).toBe(true);
    expect(classifyChange({ destination: d, retention: r("compliance", 10) }, { destination: d, retention: null }).loosened).toBe(true);
    const moved = classifyChange({ destination: d, retention: null }, { destination: { ...d, bucket: "elsewhere" }, retention: r("compliance", 400) });
    expect(moved).toMatchObject({ destinationChanged: true, loosened: true });
    expect(moved.changes.map((c) => [c.field, c.loosens])).toEqual([["bucket", true], ["retention", false]]);
  });
});

describe.skipIf(!docker)("audit export against MinIO with Object Lock", { timeout: 60_000 }, () => {
  it("exports every event of the Organization once, in order, with the chain intact, and none of another", async () => {
    const limits = AUDIT_EXPORT_LIMITS as { batchEvents: number };
    const saved = limits.batchEvents;
    limits.batchEvents = 3;
    try {
      // Another Organization's events stay out.
      expect((await call("POST", "/v1/organizations", person.cli, { name: "Other", slug: "other" })).status).toBe(201);
      for (const name of ["one", "two", "three", "four"]) {
        expect((await call("POST", `${ORG}/projects`, person.cli, { name, slug: name, contractAuthority: "managed" })).status).toBe(201);
      }
      const view = await create();
      expect(view).toMatchObject({ state: "active", cursor: "0", lockVerified: true, keyCanRead: true });
      expect(await drain(view.id)).toMatchObject({ outcome: "idle" });
      const row = await exportRow(view.id);
      const expected = await orgEvents(String(row.cursor_order));
      // Everything up to the creation's own events, the stream_started included.
      expect(expected.map((e) => e.id)).toEqual(expect.arrayContaining((await events("audit_export.created")).map(() => expect.any(String))));
      const got = await batches(LOCKED, view.streamId);
      expect(got.length).toBeGreaterThan(1);
      const lines = got.flatMap((b) => b.lines);
      expect(lines.map((l) => l.eventId)).toEqual(expected.map((e) => e.id));
      expect(lines.map((l) => l.position)).toEqual(expected.map((e) => e.position));
      expect(new Set(lines.map((l) => l.organizationId))).toEqual(new Set([org.id]));
      // previousLastOrder chains each batch to the one before.
      let previous = "0";
      for (const b of got) {
        expect(b.header).toMatchObject({ kind: "batch", organizationId: org.id, streamId: view.streamId, previousLastOrder: previous, count: b.lines.length });
        previous = b.header.lastOrder;
      }
      // The serializeAuditEvent shape, as webhooks and `varlatch audit export` emit.
      expect(Object.keys(lines[0]!)).toEqual(expect.arrayContaining(["schemaVersion", "eventId", "eventType", "occurredAt", "organizationId", "metadata"]));
      expect(await manifest(LOCKED, view.streamId)).toMatchObject({ kind: "stream", reason: "created", startOrder: "0", previousStreamId: null });
      const keys = await listed(LOCKED, `${prefix}varlatch-audit/${org.id}/${view.streamId}/heartbeat/`);
      expect(keys).toHaveLength(1);
      // Retention headers on every write, as planned.
      for (const key of await listed(LOCKED, `${prefix}varlatch-audit/${org.id}/${view.streamId}/`)) {
        const r = await admin.send(new GetObjectRetentionCommand({ Bucket: LOCKED, Key: key }));
        expect(r.Retention?.Mode, key).toBe("GOVERNANCE");
      }
      // No audit event per object: only state changes.
      expect((await rows("SELECT count(*)::int AS n FROM audit_events WHERE event_type LIKE 'audit_export.%'"))[0].n).toBe(2);
      expect(await auditExportLag(ctx, view.id)).toEqual({ pending: 0, oldestPendingAt: null });
    } finally {
      limits.batchEvents = saved;
    }
  });

  it("starts at the creation event with from now", async () => {
    const view = await create({ from: "now" });
    const created = (await rows("SELECT event_order::text AS o FROM audit_events WHERE event_type = 'audit_export.created'"))[0].o;
    expect(view.cursor).toBe(created);
    await drain(view.id);
    const lines = (await batches(LOCKED, view.streamId)).flatMap((b) => b.lines);
    expect(lines.map((l) => l.eventType)).toEqual(["audit_export.stream_started"]);
  });

  it("refuses a second export, a machine, and creation while switched off, sending nothing", async () => {
    await create();
    await expect(create()).rejects.toMatchObject({ code: "VALIDATION_FAILED", details: { reason: "export-exists" } });
    const machine: Requester = { identityId: person.id, identityKind: "service", credentialId: person.cliId, credentialKind: "service" };
    await expect(createAuditExport(ctx, machine, org, { destination: destination(), credential: credential(), retention: null, from: "now" }))
      .rejects.toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "machine-credential" } });
    const off = { ...ctx, auditExport: false };
    prefix = `${prefix}off/`;
    await expect(createAuditExport(off, requester(), org, { destination: destination(), credential: credential(), retention: null, from: "now" }))
      .rejects.toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "audit-export-off" } });
    expect(await listed(LOCKED, prefix)).toEqual([]);
  });

  it("a second worker finds the lease held; a worker that lost its lease uploads but cannot commit", async () => {
    const view = await create();
    await ctx.db.query("UPDATE audit_exports SET lease_expires_at = now() + interval '5 minutes' WHERE id = $1", [view.id]);
    expect(await exportOnce(ctx, view.id)).toEqual({ committed: 0, outcome: "busy" });
    await ctx.db.query("UPDATE audit_exports SET lease_expires_at = NULL WHERE id = $1", [view.id]);
    // Another process takes over (its lease generation) between upload and commit.
    let once = true;
    setAuditExportTestHooks({
      beforeCommit: async () => {
        if (!once) return;
        once = false;
        await ctx.db.query("UPDATE audit_exports SET generation = generation + 1 WHERE id = $1", [view.id]);
      },
    });
    const planned = await pendingPlan(view.id);
    expect(await exportOnce(ctx, view.id)).toMatchObject({ committed: 0, outcome: "lost" });
    expect((await pendingPlan(view.id)).id).toBe(planned.id);
    expect(String((await exportRow(view.id)).cursor_order)).toBe("0");
    // The next holder uploads the same plan (412, same content) and commits it.
    await drain(view.id);
    const keys = await listed(LOCKED, `${prefix}varlatch-audit/${org.id}/${view.streamId}/`);
    expect(keys.filter((k) => k.endsWith("stream.json"))).toHaveLength(1);
    // Each name written once, the cursor never went back, every event once.
    expect((await batches(LOCKED, view.streamId)).flatMap((b) => b.lines).map((l) => l.eventId))
      .toEqual((await orgEvents(String((await exportRow(view.id)).cursor_order))).map((e) => e.id));
  });

  it("a destination change between upload and commit: the old commit is refused and the new stream starts at the old cursor", async () => {
    const view = await create();
    await drain(view.id);
    const cursor = String((await exportRow(view.id)).cursor_order);
    await call("POST", `${ORG}/projects`, person.cli, { name: "late", slug: "late", contractAuthority: "managed" });
    const newPrefix = `${prefix}moved/`;
    const change = (gate: ProtectedGate) => changeAuditExport(ctx, gate, org, view.id, { destination: { bucket: OTHER, prefix: newPrefix }, expectedVersion: 1 });
    const approvalId = await askApproval(change);
    await approve(approvalId);
    let landed = "";
    setAuditExportTestHooks({
      beforeCommit: async (plan) => {
        if (landed) return;
        landed = plan.object_name;
        await withApproval(ctx, { requester: requester(), approvalId, publicUrl: PUBLIC_URL }, change);
      },
    });
    expect(await exportOnce(ctx, view.id)).toMatchObject({ outcome: "lost" });
    const moved = await exportRow(view.id);
    expect(moved).toMatchObject({ bucket: OTHER, prefix: newPrefix, version: 2 });
    expect(String(moved.cursor_order)).toBe(cursor);
    expect(moved.stream_id).not.toBe(view.streamId);
    // The old object stays in the old stream.
    expect(await listed(LOCKED, landed)).toEqual([landed]);
    setAuditExportTestHooks(null);
    await drain(view.id);
    const savedPrefix = prefix;
    prefix = newPrefix;
    try {
      expect(await manifest(OTHER, moved.stream_id)).toMatchObject({ reason: "destination_changed", previousStreamId: view.streamId, startOrder: cursor });
      const lines = (await batches(OTHER, moved.stream_id)).flatMap((b) => b.lines);
      expect(lines.map((l) => l.position)).toEqual((await orgEvents()).filter((e) => BigInt(e.position) > BigInt(cursor)).map((e) => e.position));
    } finally {
      prefix = savedPrefix;
    }
    expect((await events("audit_export.changed"))[0]!.metadata).toMatchObject({ loosened: true, approvalId });
  });

  it("a credential replacement keeps the plan, which the next lease holder commits under its recorded name", async () => {
    const view = await create();
    const replace = (gate: ProtectedGate) => replaceAuditExportCredential(ctx, gate, org, view.id, { credential: credential(), expectedVersion: 1 });
    const approvalId = await askApproval(replace);
    await approve(approvalId);
    const plan = await pendingPlan(view.id);
    let done = false;
    setAuditExportTestHooks({
      beforeCommit: async () => {
        if (done) return;
        done = true;
        await withApproval(ctx, { requester: requester(), approvalId, publicUrl: PUBLIC_URL }, replace);
      },
    });
    expect(await exportOnce(ctx, view.id)).toMatchObject({ outcome: "lost" });
    expect((await pendingPlan(view.id)).id).toBe(plan.id);
    expect((await exportRow(view.id)).stream_id).toBe(view.streamId);
    await drain(view.id);
    expect(await pendingPlan(view.id)).toBeUndefined();
    expect(await listed(LOCKED, plan.object_name)).toEqual([plan.object_name]);
    expect(await events("audit_export.credential_replaced")).toHaveLength(1);
  });

  it("a removal between upload and commit: nothing commits, the plan and the key are gone", async () => {
    const view = await create();
    const remove = (gate: ProtectedGate) => removeAuditExport(ctx, gate, org, view.id, { expectedVersion: 1 });
    const approvalId = await askApproval(remove);
    await approve(approvalId);
    setAuditExportTestHooks({
      beforeCommit: async () => {
        await withApproval(ctx, { requester: requester(), approvalId, publicUrl: PUBLIC_URL }, remove);
        setAuditExportTestHooks(null);
      },
    });
    expect(await exportOnce(ctx, view.id)).toMatchObject({ outcome: "lost" });
    expect(await exportRow(view.id)).toMatchObject({ state: "removed", credential_envelope: null });
    expect(await pendingPlan(view.id)).toBeUndefined();
    const before = await listed(LOCKED, prefix);
    await runAuditExportsOnce(ctx);
    expect(await listed(LOCKED, prefix)).toEqual(before);
  });

  it("a lost success response: the retry gets 412 and commits, with a read key and without one", async () => {
    const view = await create();
    for (const canRead of [true, false]) {
      let lose = true;
      setAuditExportTestHooks({
        afterUpload: () => {
          if (lose) {
            lose = false;
            throw Object.assign(new Error("socket hang up"), { code: "ECONNRESET" });
          }
        },
      });
      await call("POST", `${ORG}/projects`, person.cli, { name: `p${canRead}`, slug: `p-${canRead}`, contractAuthority: "managed" });
      const r = await exportOnce(ctx, view.id);
      expect(r.outcome).toBe("failed");
      expect((await exportRow(view.id)).last_error).toBe("Upload failed (connection reset)");
      if (!canRead) await ctx.db.query("UPDATE audit_exports SET key_can_read = false WHERE id = $1", [view.id]);
      setAuditExportTestHooks(null);
      await drain(view.id);
      expect(await pendingPlan(view.id)).toBeUndefined();
      expect((await exportRow(view.id)).key_can_read).toBe(canRead);
    }
    const lines = (await batches(LOCKED, view.streamId)).flatMap((b) => b.lines);
    expect(lines.map((l) => l.eventId)).toEqual((await orgEvents(String((await exportRow(view.id)).cursor_order))).map((e) => e.id));
  });

  it("uploads a stored plan unchanged on a later attempt: bytes, name and retention", async () => {
    const view = await create();
    await drain(view.id);
    await call("POST", `${ORG}/projects`, person.cli, { name: "later", slug: "later", contractAuthority: "managed" });
    setAuditExportTestHooks({ beforeUpload: () => { throw Object.assign(new Error("down"), { code: "ECONNREFUSED" }); } });
    await exportOnce(ctx, view.id);
    const plan = await pendingPlan(view.id);
    expect(plan.kind).toBe("batch");
    setAuditExportTestHooks(null);
    await drain(view.id);
    const stored = Buffer.from(plan.body);
    expect((await body(LOCKED, plan.object_name)).equals(stored)).toBe(true);
    const retention = await admin.send(new GetObjectRetentionCommand({ Bucket: LOCKED, Key: plan.object_name }));
    expect(retention.Retention?.RetainUntilDate?.toISOString().slice(0, 19)).toBe(new Date(plan.retain_until).toISOString().slice(0, 19));
  });

  it("stops on a plan in a format this release cannot upload; discard-plan restarts the stream, and refuses a plan it could upload", async () => {
    const view = await create();
    await expect(discardPlan(ctx, view.id, "expired")).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    await expect(discardPlan(ctx, view.id, "unsupported-format")).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    await ctx.db.query("UPDATE audit_export_plans SET format_version = 99 WHERE export_id = $1", [view.id]);
    expect(await exportOnce(ctx, view.id)).toMatchObject({ outcome: "stopped" });
    expect(await exportRow(view.id)).toMatchObject({ stopped_reason: "unsupported_format", last_error: UNSUPPORTED_FORMAT(99) });
    expect(await exportOnce(ctx, view.id)).toMatchObject({ outcome: "busy" });
    const { streamId } = await discardPlan(ctx, view.id, "unsupported-format");
    expect(streamId).not.toBe(view.streamId);
    expect((await events("audit_export.stream_started")).at(-1)!.metadata).toMatchObject({ reason: "plan_discarded", cause: "unsupported-format", previousStreamId: view.streamId });
    await drain(view.id);
    expect(await manifest(LOCKED, streamId)).toMatchObject({ reason: "plan_discarded", cause: "unsupported-format", possibleOverlap: null });
    expect((await batches(LOCKED, streamId)).flatMap((b) => b.lines).map((l) => l.eventId)).toEqual((await orgEvents(String((await exportRow(view.id)).cursor_order))).map((e) => e.id));
  });

  it("restarts the stream after the retention deadline instead of uploading, once even when raced, keeping the committed cursor", async () => {
    const view = await create();
    await drain(view.id);
    const cursor = String((await exportRow(view.id)).cursor_order);
    await call("POST", `${ORG}/projects`, person.cli, { name: "gap", slug: "gap", contractAuthority: "managed" });
    setAuditExportTestHooks({ beforeUpload: () => { throw Object.assign(new Error("down"), { code: "ECONNREFUSED" }); } });
    await exportOnce(ctx, view.id);
    setAuditExportTestHooks(null);
    // A one-day plan after a two-day outage: its retention ends within the hour.
    await ctx.db.query("UPDATE audit_export_plans SET retain_until = now() + interval '30 minutes' WHERE export_id = $1", [view.id]);
    const plan = await pendingPlan(view.id);
    const raced = await Promise.all([restartStream(ctx, view.id, plan.id, "plan_expired"), restartStream(ctx, view.id, plan.id, "plan_expired")]);
    expect(raced.filter(Boolean)).toHaveLength(1);
    expect((await events("audit_export.stream_started")).filter((e) => e.metadata.reason === "plan_expired")).toHaveLength(1);
    const row = await exportRow(view.id);
    expect(String(row.cursor_order)).toBe(cursor);
    await drain(view.id);
    const lines = (await batches(LOCKED, row.stream_id)).flatMap((b) => b.lines);
    expect(lines.map((l) => l.position)).toEqual((await orgEvents(String((await exportRow(view.id)).cursor_order))).filter((e) => BigInt(e.position) > BigInt(cursor)).map((e) => e.position));
    expect(await listed(LOCKED, plan.object_name)).toEqual([]);
  });

  it("an expired plan whose upload landed: the object stays, the manifest records the overlap, de-duplicating yields every event once", async () => {
    const view = await create();
    await drain(view.id);
    await call("POST", `${ORG}/projects`, person.cli, { name: "lost", slug: "lost", contractAuthority: "managed" });
    setAuditExportTestHooks({ afterUpload: () => { throw Object.assign(new Error("timeout"), { name: "TimeoutError" }); } });
    await exportOnce(ctx, view.id);
    setAuditExportTestHooks(null);
    const plan = await pendingPlan(view.id);
    expect(await listed(LOCKED, plan.object_name)).toEqual([plan.object_name]);
    await ctx.db.query("UPDATE audit_export_plans SET retain_until = now() + interval '10 minutes' WHERE export_id = $1", [view.id]);
    expect(await exportOnce(ctx, view.id)).toMatchObject({ outcome: "restarted" });
    const next = (await exportRow(view.id)).stream_id;
    await drain(view.id);
    expect(await manifest(LOCKED, next)).toMatchObject({
      reason: "plan_expired", previousStreamId: view.streamId,
      possibleOverlap: { firstOrder: String(plan.first_order), lastOrder: String(plan.last_order) },
    });
    const all = [...(await batches(LOCKED, view.streamId)), ...(await batches(LOCKED, next))].flatMap((b) => b.lines);
    expect(all.length).toBeGreaterThan(new Set(all.map((l) => l.position)).size);
    const unique = [...new Map(all.map((l) => [l.position, l.eventId])).entries()].sort((a, b) => (BigInt(a[0]) < BigInt(b[0]) ? -1 : 1));
    expect(unique.map(([, id]) => id)).toEqual((await orgEvents(String((await exportRow(view.id)).cursor_order))).map((e) => e.id));
  });

  it("a heartbeat retried later sends the planned object unchanged", async () => {
    const view = await create();
    let first = true;
    setAuditExportTestHooks({
      beforeUpload: (plan) => {
        if (plan.kind === "heartbeat" && first) {
          first = false;
          throw Object.assign(new Error("down"), { code: "ECONNREFUSED" });
        }
      },
    });
    await exportOnce(ctx, view.id);
    const heartbeat = await pendingPlan(view.id);
    expect(heartbeat.kind).toBe("heartbeat");
    await drain(view.id);
    expect((await body(LOCKED, heartbeat.object_name)).equals(Buffer.from(heartbeat.body))).toBe(true);
    expect(heartbeat.object_name).toMatch(/heartbeat\/\d{4}-\d{2}-\d{2}T\d{2}\.json$/);
  });

  it("stops on an object under the planned name with other content, overwriting nothing", async () => {
    const view = await create();
    setAuditExportTestHooks({ beforeUpload: () => { throw Object.assign(new Error("down"), { code: "ECONNREFUSED" }); } });
    await exportOnce(ctx, view.id);
    setAuditExportTestHooks(null);
    const plan = await pendingPlan(view.id);
    await admin.send(new PutObjectCommand({ Bucket: LOCKED, Key: plan.object_name, Body: "someone else's" }));
    expect(await exportOnce(ctx, view.id)).toMatchObject({ outcome: "stopped" });
    expect(await exportRow(view.id)).toMatchObject({ stopped_reason: "object_conflict", last_error: OBJECT_CONFLICT });
    expect((await body(LOCKED, plan.object_name)).toString()).toBe("someone else's");
  });

  it("refuses a destination that overwrites on If-None-Match, and a bucket without Object Lock when retention is set", async () => {
    const fake = await fakeStore({ conditional: false });
    try {
      await expect(create({ destination: destination({ endpoint: fake.url }) })).rejects.toMatchObject({
        code: "VALIDATION_FAILED",
        message: "This destination overwrote an existing object; audit export needs conditional writes (If-None-Match)",
      });
    } finally {
      await fake.close();
    }
    const refused = await create({ destination: destination({ bucket: UNLOCKED }) }).catch((e: unknown) => e as DomainError);
    expect(refused).toMatchObject({ code: "VALIDATION_FAILED" });
    expect((refused as DomainError).message).toMatch(/^The test write failed \(S3 error \w+, HTTP 4\d\d\)/);
    // Without retention, the same bucket is fine.
    expect(await create({ destination: destination({ bucket: UNLOCKED }), retention: null })).toMatchObject({ lockVerified: null });
  });

  it("reports Object Lock verified only for a read-back or a verified provider", async () => {
    expect(await checkAuditExport(ctx, requester(), org, { destination: destination(), credential: credential(), retention: governance }))
      .toEqual({ ok: true, message: null, conditionalCreation: true, objectLock: "verified", keyCanRead: true });
    const fake = await fakeStore({ conditional: true });
    try {
      expect(await checkAuditExport(ctx, requester(), org, { destination: destination({ endpoint: fake.url }), credential: credential(), retention: governance }))
        .toEqual({ ok: true, message: null, conditionalCreation: true, objectLock: "accepted", keyCanRead: false });
      setAuditExportTestHooks({ verifiedProvider: (e) => e === fake.url });
      expect((await checkAuditExport(ctx, requester(), org, { destination: destination({ endpoint: fake.url }), credential: credential(), retention: governance })).objectLock)
        .toBe("verified");
    } finally {
      await fake.close();
    }
    // The check records nothing.
    expect(await events("audit_export.created")).toEqual([]);
    // The stored key is checked only against the export's own destination.
    await create();
    expect(await checkAuditExport(ctx, requester(), org, { destination: destination(), retention: governance }))
      .toMatchObject({ ok: true, conditionalCreation: true });
    const elsewhere = await fakeStore({ conditional: true });
    try {
      await expect(checkAuditExport(ctx, requester(), org, { destination: destination({ endpoint: elsewhere.url }), retention: governance }))
        .rejects.toMatchObject({ code: "VALIDATION_FAILED", details: { reason: "stored-key-other-destination" } });
      expect(elsewhere.requests).toBe(0);
    } finally {
      await elsewhere.close();
    }
  });

  it("a restore starts a new stream; the old stream's objects stay", async () => {
    const view = await create();
    await drain(view.id);
    const old = await listed(LOCKED, `${prefix}varlatch-audit/${org.id}/${view.streamId}/`);
    setAuditExportTestHooks({ beforeUpload: () => { throw Object.assign(new Error("down"), { code: "ECONNREFUSED" }); } });
    await call("POST", `${ORG}/projects`, person.cli, { name: "pre", slug: "pre", contractAuthority: "managed" });
    await exportOnce(ctx, view.id);
    setAuditExportTestHooks(null);
    expect(await pendingPlan(view.id)).toBeDefined();
    await recordRestore(ctx.db, { eventType: "installation.restored", decision: "info", metadata: { archiveId: "a" } });
    const row = await exportRow(view.id);
    expect(row.stream_id).not.toBe(view.streamId);
    expect((await pendingPlan(view.id)).kind).toBe("manifest");
    const types = (await rows("SELECT event_type FROM audit_events ORDER BY event_order DESC LIMIT 2")).map((r) => r.event_type).reverse();
    expect(types).toEqual(["installation.restored", "audit_export.stream_started"]);
    await drain(view.id);
    expect(await manifest(LOCKED, row.stream_id)).toMatchObject({ reason: "restored", previousStreamId: view.streamId });
    expect(await listed(LOCKED, `${prefix}varlatch-audit/${org.id}/${view.streamId}/`)).toEqual(expect.arrayContaining(old));
  });

  it("refuses private, loopback, mapped and private-resolving destinations under the outbound policy", async () => {
    ctx.outbound = new OutboundPolicy([]);
    for (const url of [endpoint, endpoint.replace("127.0.0.1", "[::ffff:127.0.0.1]"), "https://169.254.169.254", "https://10.1.2.3"]) {
      await expect(create({ destination: destination({ endpoint: url }) }), url).rejects.toMatchObject({ code: "VALIDATION_FAILED", details: { outbound: expect.any(String) } });
    }
    ctx.outbound = new OutboundPolicy([], { resolve: async () => [{ address: "10.0.0.5", family: 4 }] });
    await expect(create({ destination: destination({ endpoint: "https://s3.internal.example" }) })).rejects.toMatchObject({ details: { outbound: "private_address" } });
    const refusals = await events("outbound.refused");
    expect(refusals.length).toBe(5);
    expect(refusals.every((e) => e.metadata.purpose === "audit_export" && e.metadata.phase === "configuration")).toBe(true);
    expect(await rows("SELECT count(*)::int AS n FROM audit_exports")).toEqual([{ n: 0 }]);
  });

  it("never follows a redirect: the probe fails and the redirect target receives nothing", async () => {
    const target = await fakeStore({ conditional: true });
    const redirecting = await fakeStore({ conditional: true, redirectTo: target.url });
    try {
      const err = await create({ destination: destination({ endpoint: redirecting.url }) }).catch((e: unknown) => e as DomainError);
      expect(err).toMatchObject({ code: "VALIDATION_FAILED" });
      expect((err as DomainError).message).toMatch(/^The test write failed/);
      expect(redirecting.requests).toBeGreaterThan(0);
      expect(target.requests).toBe(0);
    } finally {
      await redirecting.close();
      await target.close();
    }
    expect(await rows("SELECT count(*)::int AS n FROM audit_exports")).toEqual([{ n: 0 }]);
  });

  it("asks an approval for loosening, removal and a new key, never for creation or tightening, and refuses machines", async () => {
    const view = await create();
    // Tightening: governance 1 day to compliance 2 days, no approval.
    const tightened = await withApproval(ctx, { requester: requester(), approvalId: null, publicUrl: PUBLIC_URL }, (gate) =>
      changeAuditExport(ctx, gate, org, view.id, { retention: { mode: "compliance", days: 2 }, expectedVersion: 1 }));
    expect(tightened).toMatchObject({ changed: true, loosened: false });
    // Loosening asks, whatever the controls' modes (all off here).
    expect(await rows("SELECT count(*)::int AS n FROM security_controls WHERE organization_id = $1 AND mode <> 'off'", [org.id])).toEqual([{ n: 0 }]);
    const shorten = (gate: ProtectedGate) => changeAuditExport(ctx, gate, org, view.id, { retention: { mode: "compliance", days: 1 }, expectedVersion: 2 });
    const asked = await askApproval(shorten);
    const intent = (await rows("SELECT operation, summary FROM approval_intents WHERE id = $1", [asked]))[0];
    expect(intent.operation).toBe("audit_export.change");
    expect(JSON.stringify(json(intent.summary))).not.toContain(ROOT_PASSWORD);
    await approve(asked);
    expect(await withApproval(ctx, { requester: requester(), approvalId: asked, publicUrl: PUBLIC_URL }, shorten)).toMatchObject({ loosened: true });
    // A machine is refused outright.
    const machine = { requester: { ...requester(), identityKind: "service", credentialKind: "service" }, approvalId: null } as unknown as ProtectedGate;
    await expect(changeAuditExport(ctx, machine, org, view.id, { retention: null, expectedVersion: 3 })).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    // A new key and the removal ask too.
    const replaceAsked = await askApproval((gate) => replaceAuditExportCredential(ctx, gate, org, view.id, { credential: credential(), expectedVersion: 3 }));
    expect((await rows("SELECT operation FROM approval_intents WHERE id = $1", [replaceAsked]))[0].operation).toBe("audit_export.change");
    const removed = await withStepUp((gate) => removeAuditExport(ctx, gate, org, view.id, { expectedVersion: 3 }));
    expect(removed.state).toBe("removed");
    expect((await events("audit_export.removed"))[0]!.metadata.approvalId).toEqual(expect.stringMatching(/^apr_/));
  });

  it("refuses changes while frozen and while a deletion is pending; delivery continues in both", async () => {
    const view = await create();
    const member = await issueInviteGrant(ctx, { organizationId: org.id, role: "admin", name: "Second" }, person.id);
    await consumeSetupGrant(ctx, member.token, {});
    const scheduled = await call("POST", `${ORG}/deletion`, person.cli, {});
    expect(scheduled.status, JSON.stringify(scheduled.body)).toBeLessThan(300);
    await expect(withApproval(ctx, { requester: requester(), approvalId: null, publicUrl: PUBLIC_URL }, (gate) =>
      changeAuditExport(ctx, gate, org, view.id, { retention: { mode: "compliance", days: 5 }, expectedVersion: 1 }))).rejects.toMatchObject({ code: "ORGANIZATION_DELETING" });
    expect((await drain(view.id)).outcome).toBe("idle");
    expect(await pendingPlan(view.id)).toBeUndefined();
    await call("POST", `${ORG}/deletion/${scheduled.body.id}/cancel`, person.cli, {});
    const frozen = await call("POST", `${ORG}/incident-freeze`, person.cli, { reason: "A CI token leaked" });
    expect(frozen.status, JSON.stringify(frozen.body)).toBeLessThan(300);
    await expect(withApproval(ctx, { requester: requester(), approvalId: null, publicUrl: PUBLIC_URL }, (gate) =>
      removeAuditExport(ctx, gate, org, view.id, { expectedVersion: 1 }))).rejects.toMatchObject({ code: "ORGANIZATION_FROZEN" });
    const before = String((await exportRow(view.id)).cursor_order);
    await drain(view.id);
    expect(BigInt((await exportRow(view.id)).cursor_order)).toBeGreaterThan(BigInt(before));
  });

  it("delivers the batch holding organization.deleted after the KEK is destroyed, then completes", async () => {
    const view = await create();
    await drain(view.id);
    const scheduled = await call("POST", `${ORG}/deletion`, person.cli, {});
    expect(scheduled.status, JSON.stringify(scheduled.body)).toBeLessThan(300);
    await ctx.db.query("UPDATE organization_deletions SET scheduled_at = now() - interval '8 days', run_after = now() - interval '1 minute'");
    expect(await finalizeDeletion(ctx, scheduled.body.id, org.id)).not.toBeNull();
    const draining = await exportRow(view.id);
    expect(draining.state).toBe("draining");
    expect(new Date(draining.drain_deadline).getTime() - Date.now()).toBeGreaterThan(29 * 86_400_000);
    expect((await rows("SELECT wrapped_org_kek FROM organizations WHERE id = $1", [org.id]))[0].wrapped_org_kek).toBeNull();
    // Under the Root KEK, purpose audit-export-drain.
    expect(JSON.parse(decryptAuditExportDrainCredential(ctx.rootKek, org.id, view.id, json(draining.credential_envelope)))).toEqual(credential());
    await drain(view.id);
    expect(await exportRow(view.id)).toMatchObject({ state: "completed", credential_envelope: null });
    const lines = (await batches(LOCKED, view.streamId)).flatMap((b) => b.lines);
    expect(lines.map((l) => l.eventType)).toContain("organization.deleted");
    expect(await events("audit_export.completed")).toHaveLength(1);
  });

  it("abandons a drain at its fixed deadline, also with the export switched off", async () => {
    const view = await create();
    const scheduled = await call("POST", `${ORG}/deletion`, person.cli, {});
    await ctx.db.query("UPDATE organization_deletions SET scheduled_at = now() - interval '8 days', run_after = now() - interval '1 minute'");
    await finalizeDeletion(ctx, scheduled.body.id, org.id);
    expect(await abandonExpiredDrains(ctx.db)).toEqual([]);
    await ctx.db.query("UPDATE audit_exports SET drain_deadline = now() - interval '1 second' WHERE id = $1", [view.id]);
    const off = { ...ctx, auditExport: false };
    expect(await abandonExpiredDrains(off.db)).toEqual([view.id]);
    expect(await exportRow(view.id)).toMatchObject({ state: "abandoned", credential_envelope: null });
    expect(await pendingPlan(view.id)).toBeUndefined();
    expect(await events("audit_export.abandoned")).toHaveLength(1);
  });

  it("records failing once per episode and recovered on the next success, in fixed words", async () => {
    const view = await create();
    setAuditExportTestHooks({ beforeUpload: () => { throw Object.assign(new Error(`AccessDenied ${ROOT_PASSWORD}`), { name: "AccessDenied", $metadata: { httpStatusCode: 403 } }); } });
    await exportOnce(ctx, view.id);
    const row = await exportRow(view.id);
    expect(row.last_error).toBe("Upload failed (S3 error AccessDenied, HTTP 403): the key may not do this; check that it can access this bucket");
    expect(await events("audit_export.failing")).toEqual([]);
    await ctx.db.query("UPDATE audit_exports SET failing_since = now() - interval '16 minutes' WHERE id = $1", [view.id]);
    await exportOnce(ctx, view.id);
    await exportOnce(ctx, view.id);
    expect(await events("audit_export.failing")).toHaveLength(1);
    expect((await auditExportLag(ctx, view.id)).pending).toBeGreaterThan(0);
    setAuditExportTestHooks(null);
    await drain(view.id);
    expect(await events("audit_export.recovered")).toHaveLength(1);
    expect(await exportRow(view.id)).toMatchObject({ failing_since: null, failing_recorded: false, last_error: null });
    expect(JSON.stringify(await rows("SELECT metadata FROM audit_events"))).not.toContain(ROOT_PASSWORD);
  });
});

/**
 * A store that accepts everything: with `conditional`, a second write of a
 * name is refused with 412, as conditional creation needs; without, it
 * overwrites. GetObjectRetention answers 403, as for a write-only key.
 * With `redirectTo`, every request is answered with a 307 there.
 */
async function fakeStore(options: { conditional: boolean; redirectTo?: string }): Promise<{ url: string; requests: number; close: () => Promise<void> }> {
  const seen = new Set<string>();
  const counted = { requests: 0 };
  const server: Server = createServer((req, res) => {
    counted.requests++;
    req.resume();
    req.on("end", () => {
      const key = (req.url ?? "").split("?")[0]!;
      if (options.redirectTo) {
        res.writeHead(307, { Location: `${options.redirectTo}${req.url ?? "/"}` });
        res.end();
        return;
      }
      if (req.method === "PUT") {
        if (options.conditional && seen.has(key)) {
          res.writeHead(412, { "content-type": "application/xml" });
          res.end('<?xml version="1.0"?><Error><Code>PreconditionFailed</Code></Error>');
          return;
        }
        seen.add(key);
        res.writeHead(200, { ETag: '"0"' });
        res.end();
        return;
      }
      res.writeHead(403, { "content-type": "application/xml" });
      res.end('<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>');
    });
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
  const port = (server.address() as { port: number }).port;
  return {
    url: `http://127.0.0.1:${port}`,
    get requests() { return counted.requests; },
    close: () => new Promise<void>((done) => server.close(() => done())),
  };
}
