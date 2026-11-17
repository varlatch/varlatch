// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.11b's parity fixture (ADR-0059 step 4, feature-parity decisions 3
 * and 9): the audit export worker, its stream restarts, the host's
 * discard-plan and the drains, as this server runs them. A database built
 * through this server's own /v1 API and recorder (Organizations acme, beta
 * and gamma, each with an export to the local S3 server of
 * helpers/audit-export-fake.ts; acme's log with varied events; gamma's
 * export already draining, its key sealed again under the Root KEK, its
 * Organization deleted), then a table of steps, each with what it did:
 * the objects uploaded (name, content type, retention, checksum, the body,
 * decompressed for a batch), the exchanges with the destination, the
 * exports and pending plans afterwards, and the audit events it wrote.
 * go/server/auditexport's worker parity test runs the same steps against
 * the Go worker and requires the same.
 *
 * Both sides normalize with the kit's Normalizer (new IDs, new times) and
 * an hour name becomes {hour}: the TypeScript worker plans on the
 * database clock, the Go worker on varlatchd's. Steps that need time to
 * pass set the rows' times instead (aging a failure, a plan's retention, a
 * drain's deadline), and heartbeats are turned off after the first run, so
 * an hour that turns during a run changes nothing. A batch is compared
 * decompressed: its gzip bytes are zlib's, which differ between zlib
 * builds (Node's is Chromium's), and are only ever uploaded as stored.
 *
 * gamma's drain copy is sealed here; the Go worker opening it to send the
 * key is G3 at the database level for drain copies, ts-to-go. With
 * VARLATCH_GO_SEALED_AUDIT_EXPORT_WORKER=<file>, a file the Go tests wrote
 * (go test ./server/auditexport -run TestGoSealedWorkerFixture -args
 * -write-go-sealed-worker=<file>), with every key, export credential and
 * drain copy sealed by Go, gives this server the same steps (go-to-ts).
 *
 * After a change, regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-audit-export-worker-fixture.test.ts
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { describe, expect, it, vi } from "vitest";
import { recordAuditEvents, type AuditEventType } from "../src/audit/events.js";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { withTx } from "../src/db/tx.js";
import { discardPlan, exportOnce, rewrapForDrain } from "../src/domain/auditexport.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { DomainError } from "../src/domain/errors.js";
import { BUCKET, ENDPOINT, FakeS3, FixturePolicy, KEY_GOOD } from "./helpers/audit-export-fake.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { exportRows, loadRows, Normalizer, onClock, onRecordedClock, type Row, type Table } from "./go-fixture-kit.js";

const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const FILE = new URL("../../../go/server/paritytest/testdata/audit-export-worker-v0.22.0.json", import.meta.url);
const PUBLIC_URL = "http://127.0.0.1:8686";

const TABLES: Table[] = [
  { name: "installation", orderBy: "id", random: ["kek_canary"] },
  { name: "identities", orderBy: "id" },
  { name: "organizations", orderBy: "id", random: ["wrapped_org_kek"] },
  { name: "org_memberships", orderBy: "organization_id, identity_id" },
  { name: "audit_events", orderBy: "event_order" },
  { name: "audit_exports", orderBy: "id", random: ["credential_envelope"] },
  { name: "audit_export_plans", orderBy: "id", random: ["body", "sha256", "md5"] },
];

/** One step: an action, by the Organization's slug. */
export type Step = { name: string } & (
  | { run: string }
  | { record: string; events: { type: string; metadata: unknown }[] }
  | { down: boolean }
  | { heartbeatsOff: true }
  | { age: "failing" | "plan" | "drain"; org: string }
  | { format: number; org: string }
  | { plant: "pending" | "other"; org: string }
  | { discard: string; reason: "expired" | "unsupported-format" }
  | { drain: string }
);

const renamed = (n: number) => ({ type: "organization.renamed", metadata: { from: `Acme ${n}`, to: `Acme ${n + 1}` } });

/** The table of steps. */
export function steps(): Step[] {
  return [
    { name: "acme's first run: its manifest, the hour's heartbeat, the log", run: "acme" },
    { name: "heartbeats off", heartbeatsOff: true },
    { name: "beta's first run, from its creation", run: "beta" },
    { name: "a quiet run", run: "acme" },
    { name: "three events", record: "acme", events: [renamed(1), renamed(2), { type: "project.created", metadata: { name: "p", n: [1, 2.5, -3e-7, 1e21] } }] },
    { name: "the next batch", run: "acme" },
    { name: "the destination goes down", down: true },
    { name: "two events", record: "acme", events: [renamed(3), renamed(4)] },
    { name: "a failed upload", run: "acme" },
    { name: "failing for 20 minutes", age: "failing", org: "acme" },
    { name: "failing is recorded", run: "acme" },
    { name: "failing once", run: "acme" },
    { name: "the destination is back", down: false },
    { name: "recovered", run: "acme" },
    { name: "discard-plan, no plan", discard: "acme", reason: "expired" },
    { name: "down again", down: true },
    { name: "one event", record: "acme", events: [renamed(5)] },
    { name: "a batch planned, not uploaded", run: "acme" },
    { name: "back again", down: false },
    { name: "discard-plan, not expired", discard: "acme", reason: "expired" },
    { name: "discard-plan, a format this release uploads", discard: "acme", reason: "unsupported-format" },
    { name: "the plan's retention ends within the hour", age: "plan", org: "acme" },
    { name: "the stream restarts", run: "acme" },
    { name: "the new stream", run: "acme" },
    { name: "down, for a format", down: true },
    { name: "an event for it", record: "acme", events: [renamed(6)] },
    { name: "planned", run: "acme" },
    { name: "up", down: false },
    { name: "the plan in format 2", format: 2, org: "acme" },
    { name: "stopped: a format this release cannot upload", run: "acme" },
    { name: "discard-plan, unsupported format", discard: "acme", reason: "unsupported-format" },
    { name: "after the discard", run: "acme" },
    { name: "down, for a landed upload", down: true },
    { name: "an event to land", record: "acme", events: [renamed(7)] },
    { name: "planned to land", run: "acme" },
    { name: "up to land", down: false },
    { name: "the plan's object is already there", plant: "pending", org: "acme" },
    { name: "a 412 for the same content", run: "acme" },
    { name: "an event in beta", record: "beta", events: [renamed(8)] },
    { name: "down for beta", down: true },
    { name: "beta planned", run: "beta" },
    { name: "up for beta", down: false },
    { name: "other content under beta's name", plant: "other", org: "beta" },
    { name: "beta stops on the conflict", run: "beta" },
    { name: "gamma's drain completes with the drain copy", run: "gamma" },
    { name: "acme deleted: its export drains", drain: "acme" },
    { name: "acme's deletion event", record: "acme", events: [{ type: "organization.deleted", metadata: { slug: "acme" } }] },
    { name: "acme's drain completes", run: "acme" },
    { name: "beta deleted: its export drains", drain: "beta" },
    { name: "beta's deadline passes", age: "drain", org: "beta" },
    { name: "beta's drain is abandoned", run: "beta" },
    { name: "nothing left to run", run: "beta" },
  ];
}

export type WorkerFixture = {
  comment: string;
  ref: string;
  serverVersion: string;
  rootKek: string;
  credentials: Record<string, { accessKeyId: string; secretAccessKey: string }>;
  rows: Record<string, Row[]>;
  steps: Step[];
  results: unknown[];
};

const HOUR = /\b\d{4}-\d\d-\d\dT\d\d([^\d:]|$)/g;
const hours = (v: unknown): unknown =>
  typeof v === "string" ? v.replace(HOUR, "{hour}$1")
  : Array.isArray(v) ? v.map(hours)
  : v !== null && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, hours(x)]))
  : v;

const sha256 = (b: Buffer) => createHash("sha256").update(b).digest("hex");

/**
 * The steps run on the file's rows: each step's result, normalized. The
 * replay runs on the recording's time moved on by the time it has taken,
 * so that the rows' lifetimes mean what they meant when the fixture was
 * recorded, whatever the date (a plan recorded with a day to run expired
 * in real time the day after: varlatch run 44049762382). See
 * onRecordedClock.
 */
function replay(f: Pick<WorkerFixture, "rows" | "rootKek" | "steps">): Promise<unknown[]> {
  return onRecordedClock(f.rows, () => replayOnce(f));
}

async function replayOnce(f: Pick<WorkerFixture, "rows" | "rootKek" | "steps">): Promise<unknown[]> {
  const fake = new FakeS3();
  await fake.start();
  const db = await loadRows(f.rows, TABLES);
  await db.query("UPDATE audit_position SET value = (SELECT coalesce(max(event_order), 0) FROM audit_events) WHERE singleton");
  const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex"), outbound: new FixturePolicy(fake), auditExport: true };
  const n = new Normalizer(f.rows);
  const orgOf = (slug: string) => f.rows.organizations!.find((o) => o.slug === slug)!.id as string;
  const exportOf = async (slug: string) =>
    ((await db.query("SELECT id FROM audit_exports WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 1", [orgOf(slug)])).rows[0] as { id: string }).id;
  const out: unknown[] = [];
  try {
    for (const step of f.steps) {
      const requests = fake.requests.length;
      const uploads = fake.uploads.length;
      const events = Number(((await db.query("SELECT coalesce(max(event_order), 0) AS m FROM audit_events")).rows[0] as { m: unknown }).m);
      let result: unknown = null;
      if ("run" in step) result = await exportOnce(ctx, await exportOf(step.run));
      else if ("record" in step) {
        await recordAuditEvents(db, step.events.map((e) => ({
          eventType: e.type as AuditEventType, decision: "info" as const, organizationId: orgOf(step.record), metadata: e.metadata as Record<string, unknown>,
        })));
      } else if ("down" in step) fake.down = step.down;
      else if ("heartbeatsOff" in step) await db.query("UPDATE audit_exports SET last_heartbeat_hour = '2100-01-01T00:00:00Z'");
      else if ("age" in step) {
        const id = await exportOf(step.org);
        if (step.age === "failing") await db.query("UPDATE audit_exports SET failing_since = now() - interval '20 minutes' WHERE id = $1", [id]);
        if (step.age === "plan") await db.query("UPDATE audit_export_plans SET retain_until = now() + interval '30 minutes' WHERE export_id = $1", [id]);
        if (step.age === "drain") await db.query("UPDATE audit_exports SET drain_deadline = now() - interval '1 second' WHERE id = $1", [id]);
      } else if ("format" in step) {
        await db.query("UPDATE audit_export_plans SET format_version = $2 WHERE export_id = $1", [await exportOf(step.org), step.format]);
      } else if ("plant" in step) {
        const plan = (await db.query("SELECT object_name, body, sha256 FROM audit_export_plans WHERE export_id = $1", [await exportOf(step.org)])).rows[0] as
          { object_name: string; body: Uint8Array; sha256: string };
        const body = step.plant === "pending" ? Buffer.from(plan.body) : Buffer.from("other content");
        fake.plant(BUCKET, plan.object_name, { body, sha256: step.plant === "pending" ? plan.sha256 : sha256(body) });
      } else if ("discard" in step) {
        try {
          result = await discardPlan(ctx, await exportOf(step.discard), step.reason);
        } catch (err) {
          if (!(err instanceof DomainError)) throw err;
          result = { error: err.code, message: err.message };
        }
      } else if ("drain" in step) {
        const drained = await withTx(db, (tx) => rewrapForDrain(ctx, tx, orgOf(step.drain)));
        await db.query("UPDATE organizations SET deleted_at = now(), wrapped_org_kek = NULL, org_kek_destroyed_at = now() WHERE id = $1", [orgOf(step.drain)]);
        result = { drained };
      }
      const objects = fake.uploads.slice(uploads).map((name) => {
        const o = fake.objects.get(name)!;
        const gz = o.contentType === "application/gzip";
        return {
          // The retention's date as an instant: SDKs write its fraction their own way.
          name: name.slice(BUCKET.length + 1), contentType: o.contentType, mode: o.mode, until: o.until && new Date(o.until).toISOString(), checksum: o.sha256 === sha256(o.body),
          body: (gz ? gunzipSync(o.body) : o.body).toString("utf8"),
        };
      });
      const exports = ((await db.query(
        `SELECT organization_id, state, stream_id, cursor_order::text AS cursor, generation::text AS generation, version, stopped_reason, last_error,
           failing_recorded, key_can_read, retention_readable, failing_since IS NOT NULL AS failing, lease_expires_at IS NOT NULL AS leased,
           last_heartbeat_hour IS NOT NULL AS heartbeat, last_success_at IS NOT NULL AS succeeded, credential_envelope IS NOT NULL AS keyed,
           drain_deadline IS NOT NULL AS drain
         FROM audit_exports ORDER BY organization_id, created_at`,
      )).rows as Row[]);
      const plans = ((await db.query(
        `SELECT x.organization_id, p.kind, p.stream_id, p.object_name, p.format_version, p.retention_mode, p.first_order::text AS first_order,
           p.last_order::text AS last_order, p.event_count, p.heartbeat_hour IS NOT NULL AS heartbeat, p.retain_until IS NOT NULL AS retained
         FROM audit_export_plans p JOIN audit_exports x ON x.id = p.export_id ORDER BY x.organization_id`,
      )).rows as Row[]);
      const recorded = ((await db.query(
        "SELECT event_type, organization_id, resource, metadata FROM audit_events WHERE event_order > $1 ORDER BY event_order",
        [events],
      )).rows as Row[]);
      out.push(n.value(hours({
        step: step.name, result, exchanges: fake.requests.slice(requests), objects, exports, plans, events: recorded,
      })));
    }
    return out;
  } finally {
    await db.close();
    await fake.stop();
  }
}

/** The database: alice, acme (a varied log, an export from the beginning), beta (from now) and gamma (draining). */
async function build(fake: FakeS3) {
  const db = await migratedTestDb();
  const ctx = { db, rootKek: generateKey(), close: db.close, outbound: new FixturePolicy(fake), auditExport: true };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId: alice } = await consumeSetupGrant(ctx, grant.token, { adminName: "Alice" });
  const token = (await issueCredential(ctx.db, { identityId: alice, kind: "cli" })).token;
  const app = buildApp(ctx, { publicUrl: PUBLIC_URL });
  const call = async (method: string, path: string, body?: unknown) => {
    const res = await app.request(path, {
      method, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    if (res.status >= 300) throw new Error(`${method} ${path}: ${res.status} ${text}`);
    return text ? JSON.parse(text) : null;
  };
  const orgs: Record<string, string> = {};
  for (const slug of ["acme", "beta", "gamma"]) orgs[slug] = (await call("POST", "/v1/organizations", { name: slug, slug })).id;
  // A varied log: Unicode and line separators, numbers JSON writes its own
  // way, nested values, and a webhook event whose URL serialization redacts.
  await recordAuditEvents(db, [
    { eventType: "organization.renamed", decision: "info", organizationId: orgs.acme!, actorIdentityId: alice, metadata: { from: "acme", to: "Acme ✓   \"quoted\" \\ é" } },
    { eventType: "project.created", decision: "info", organizationId: orgs.acme!, metadata: { numbers: [1, 2.5, -3e-7, 1e21, 0.1], nested: { z: 1, a: [true, null, {}] } } },
    { eventType: "webhook.created", decision: "info", organizationId: orgs.acme!, metadata: { url: "https://hooks.example.test/in/abc?token=secret-value", events: ["*"] } },
  ]);
  const destination = { endpoint: ENDPOINT, region: "us-east-1", bucket: BUCKET, prefix: "logs", pathStyle: true };
  const good = { accessKeyId: KEY_GOOD, secretAccessKey: "fixture-secret" };
  const credentials: Record<string, typeof good> = {};
  const create = async (slug: string, body: Record<string, unknown>) => {
    const created = await call("POST", `/v1/organizations/${slug}/audit-export`, { destination, credential: good, ...body });
    credentials[created.id] = good;
  };
  await create("acme", { retention: { mode: "governance", days: 1 }, from: "beginning" });
  await create("beta", { from: "now" });
  await create("gamma", { retention: { mode: "compliance", days: 1 }, from: "beginning" });
  // gamma's Organization deleted: its export drains with its key under the Root KEK.
  await withTx(db, (tx) => rewrapForDrain(ctx, tx, orgs.gamma!));
  await db.query("UPDATE organizations SET deleted_at = now(), wrapped_org_kek = NULL, org_kek_destroyed_at = now() WHERE id = $1", [orgs.gamma]);
  await recordAuditEvents(db, [{ eventType: "organization.deleted", decision: "info", organizationId: orgs.gamma!, metadata: { slug: "gamma" } }]);
  return { ctx, credentials };
}

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the worker fixture", () => {
  it("builds the database, runs the steps, and writes the file", async () => {
    const fake = new FakeS3();
    await fake.start();
    const { ctx, credentials } = await build(fake);
    try {
      const draft: WorkerFixture = {
        comment: "Written by services/varlatchd/test/go-audit-export-worker-fixture.test.ts from the TypeScript server's own worker; do not edit.",
        ref: "v0.22.0",
        serverVersion: SERVER_VERSION,
        rootKek: ctx.rootKek.toString("hex"),
        credentials,
        rows: await exportRows(ctx.db, TABLES),
        steps: steps(),
        results: [],
      };
      draft.results = await replay(draft);
      writeFileSync(FILE, JSON.stringify(draft, null, 2) + "\n");
    } finally {
      await ctx.close();
      await fake.stop();
    }
  }, 600_000);
});

async function expectFixture(f: WorkerFixture) {
  expect(f.serverVersion).toBe(SERVER_VERSION);
  expect(f.steps).toEqual(steps());
  const got = await replay(f);
  for (let i = 0; i < f.results.length; i++) expect(got[i], f.steps[i]!.name).toEqual(f.results[i]);
  expect(got.length).toBe(f.results.length);
}

describe("the audit export worker fixture is this server's worker", () => {
  it("audit-export-worker-v0.22.0.json", async () => {
    const f = JSON.parse(readFileSync(FILE, "utf8")) as WorkerFixture;
    expect(f.ref).toBe("v0.22.0");
    await expectFixture(f);
  }, 300_000);
  it("gives the same results with the date 30 days on (no lifetime in the fixture runs on today's date)", async () => {
    const f = JSON.parse(readFileSync(FILE, "utf8")) as WorkerFixture;
    const wall = Date;
    await onClock(() => wall.now() + 30 * 24 * 3_600_000, () => expectFixture(f));
    expect(Date).toBe(wall);
  }, 300_000);
  const goSealed = process.env.VARLATCH_GO_SEALED_AUDIT_EXPORT_WORKER;
  it.skipIf(!goSealed)("export credentials and drain copies the Go server sealed open here with the same steps", async () => {
    if (!existsSync(goSealed!)) throw new Error(`${goSealed}: no such file`);
    const f = JSON.parse(readFileSync(goSealed!, "utf8")) as WorkerFixture;
    expect(f.comment).toMatch(/Go/);
    expect(f.ref).toBe("go");
    await expectFixture(f);
  }, 300_000);
});
