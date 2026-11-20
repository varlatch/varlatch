// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Maintenance, readGate } from "@varlatch/backup";
import { issueCredential } from "../src/auth/credentials.js";
import { recordAuditEvent } from "../src/audit/events.js";
import { serializeAuditEvent } from "../src/audit/serialize.js";
import { releaseHeldSnapshot } from "../src/backup/control.js";
import { generateKey } from "../src/crypto/aead.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { deliverWebhooksOnce } from "../src/domain/webhooks.js";
import { buildApp } from "../src/http/app.js";
import { loadManifest } from "../src/migration/bundle.js";
import { encodeRow, type ColumnType, type Value } from "../src/migration/canonical.js";
import { exportSource } from "../src/migration/export.js";
import { IMPORT_LOCK, ImportRefused, importReverse, MAX_LINE, readReverseBundle } from "../src/migration/import.js";
import { MIGRATIONS } from "../src/db/migrations/index.js";
import { changedDomain, syncAllMirrors } from "../src/mirror/publisher.js";
import { PUBLIC_URL } from "./helpers/device-sign-in.js";
import { seedInstallation, type Seeded } from "./helpers/migration-seed.js";

/**
 * `admin migration import` (ADR-0059 step 7, go-step7 slice 7.2c, decision
 * 16), against a real PostgreSQL server. The reverse bundle here is the
 * TypeScript export of a seeded installation turned into one: its rows are
 * in this schema's columns already, as varlatchd's export --reverse writes
 * them, with no session and installation.migrated last. (The cross-check
 * with varlatchd's own reverse bundle is by hand, in the PR.)
 */
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("the migration's import", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let source: ReturnType<typeof createPgQuerier>;
  let target: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx & { db: ReturnType<typeof createPgQuerier> };
  let dir: string;
  let seeded: Seeded;
  let targetUrl: string;
  let token: string;
  const names = { source: `varlatch_import_src_${process.pid}`, target: `varlatch_import_dst_${process.pid}` };

  const databaseUrl = (name: string) => {
    const u = new URL(url!);
    u.pathname = `/${name}`;
    return u.toString();
  };

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    for (const name of Object.values(names)) {
      await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      await admin.query(`CREATE DATABASE ${name}`);
    }
    source = createPgQuerier(databaseUrl(names.source));
    targetUrl = databaseUrl(names.target);
    target = createPgQuerier(targetUrl);
    const c = await source.connect();
    try {
      await runMigrations(c);
    } finally {
      c.release();
    }
    dir = mkdtempSync(join(tmpdir(), "varlatch-import-"));
    ctx = { db: source, rootKek: generateKey(), maintenance: new Maintenance(join(dir, "source-state")) };
    seeded = await seedInstallation(ctx);
    await source.query("UPDATE exposure_backfill SET finished_at = now()");
    token = (await issueCredential(source, { identityId: seeded.admin, kind: "cli", name: "after the move" })).token;
    // What varlatchd's export --reverse does to its copy: every browser
    // session ends (the trigger revokes its credentials), then
    // installation.migrated, last.
    await source.query("DELETE FROM session");
    await recordAuditEvent(source, {
      eventType: "installation.migrated",
      decision: "info",
      // varlatchd's metadata (go/server/migration/migrate): the frozen point is an object.
      metadata: { direction: "reverse", sourceRelease: "0.50.0", manifestVersion: 1, frozenPoint: { auditPosition: 1 }, sessionsEnded: 2, credentialsRevoked: 2 } as unknown as Record<string, number>,
    });
  }, 180_000);
  afterEach(async () => {
    await releaseHeldSnapshot();
    await source.end();
    await target.end();
    for (const name of Object.values(names)) await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
    await admin.end();
    rmSync(dir, { recursive: true, force: true });
    // Dropping databases WITH (FORCE) can take a while on a busy server.
  }, 120_000);

  /** A dry-run export of db: the forward bundle. */
  const exportOf = async (db: ReturnType<typeof createPgQuerier>) => {
    const out = new PassThrough();
    const chunks: Buffer[] = [];
    out.on("data", (c: Buffer) => chunks.push(c));
    await exportSource(db, { gate: null, dryRun: true, out, rootKek: null, runKey: null });
    return Buffer.concat(chunks).toString("utf8");
  };

  /** Lines (no end line) to a bundle: the end line counted and hashed as bundle-v1 does. */
  const finish = (lines: string[]) => {
    const tables = lines.filter((l) => l.startsWith('{"table":'));
    const rows = tables.reduce((n, l) => n + (JSON.parse(l) as { rows: number }).rows, 0);
    const digests = Number(/^\{"digests":(\d+)\}$/.exec(lines.find((l) => l.startsWith('{"digests":'))!)![1]);
    const decisions = Number(/^\{"decisions":(\d+),/.exec(lines.find((l) => l.startsWith('{"decisions":'))!)![1]);
    const body = lines.join("\n") + "\n";
    const sha = createHash("sha256").update(body).digest("hex");
    return `${body}{"end":{"tables":${tables.length},"rows":${rows},"digests":${digests},"decisions":${decisions},"sha256":"${sha}"}}\n`;
  };

  /** The forward bundle as varlatchd's reverse one: its header, and empty check sections (until slice 7.6). */
  const reverseOf = (forward: string) => {
    const lines = forward.split("\n").slice(0, -2); // no end line, no trailing ""
    const position = (JSON.parse(lines[0]!) as { frozenPoint: { auditPosition: number } }).frozenPoint.auditPosition;
    lines[0] = `{"bundle":"varlatch-migration","format":1,"manifest":1,"encoding":"canonical-v1","direction":"reverse","release":"0.50.0","frozenPoint":{"auditPosition":${position}},"sequences":[]}`;
    const sections = lines.findIndex((l) => l.startsWith('{"digests":'));
    return finish([...lines.slice(0, sections), '{"digests":0}', '{"decisions":0,"at":1795000000000000}']);
  };

  const write = (name: string, text: string) => {
    const path = join(dir, name);
    writeFileSync(path, text, { mode: 0o600 });
    return path;
  };

  /** The rows of a forward bundle, header and sections aside. */
  const tablesOf = (bundle: string) => {
    const lines = bundle.split("\n");
    return lines.slice(1, lines.findIndex((l) => l.startsWith('{"digests":'))).join("\n");
  };

  const relations = async (db: ReturnType<typeof createPgQuerier>) =>
    ((await db.query(`SELECT count(*)::int AS n FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r'`)).rows[0] as { n: number }).n;

  it("rebuilds a database that holds every row as the bundle does, keeps audit positions and cursors, and serves", async () => {
    const forward = await exportOf(source);
    const path = write("reverse.jsonl", reverseOf(forward));
    const result = await importReverse(target, { path, rootKek: ctx.rootKek });
    expect(result.alreadyImported).toBe(false);

    // Every row, column and order (requirements' physical order included) as the source holds it.
    expect(tablesOf(await exportOf(target))).toBe(tablesOf(forward));
    // The audit continues where the bundle ends; installation.migrated is last.
    const last = ((await target.query("SELECT event_order::text AS p, event_type FROM audit_events ORDER BY event_order DESC LIMIT 1")).rows[0]) as { p: string; event_type: string };
    expect(last).toEqual({ p: result.bundle.auditPosition, event_type: "installation.migrated" });
    expect(((await target.query("SELECT value::text AS v FROM audit_position")).rows[0] as { v: string }).v).toBe(last.p);
    await recordAuditEvent(target, { eventType: "organization.renamed", decision: "allow", organizationId: seeded.acme });
    expect(((await target.query("SELECT max(event_order)::text AS p FROM audit_events")).rows[0] as { p: string }).p).toBe(String(BigInt(last.p) + 1n));
    // The audit cursors are where the source left them.
    for (const q of ["SELECT cursor_order::text AS c FROM webhooks ORDER BY id", "SELECT cursor_order::text AS c FROM audit_exports ORDER BY id", "SELECT cursor_order::text AS c FROM sync_cursor"]) {
      expect((await target.query(q)).rows, q).toEqual((await source.query(q)).rows);
    }
    // The schema is this release's; its triggers and foreign keys are back.
    const triggers = "SELECT count(*)::int AS n FROM pg_trigger WHERE NOT tgisinternal AND tgenabled = 'O'";
    expect((await target.query(triggers)).rows).toEqual((await source.query(triggers)).rows);
    const fks = "SELECT conrelid::regclass::text AS t, conname, pg_get_constraintdef(oid) AS d FROM pg_constraint WHERE contype = 'f' ORDER BY 1, 2";
    expect((await target.query(fks)).rows).toEqual((await source.query(fks)).rows);

    // It serves: a credential from before the move reads the Organization and reveals its values.
    const targetCtx: AppCtx = { db: target, rootKek: ctx.rootKek };
    const app = buildApp(targetCtx, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7" });
    const call = (method: string, path: string, body?: unknown) =>
      app.request(path, { method, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const orgs = await (await call("GET", "/v1/organizations")).json() as { items: { slug: string }[] };
    expect(orgs.items.map((o) => o.slug)).toContain("acme");
    const retrieval = await call("POST", "/v1/organizations/acme/projects/api/environments/production/retrievals", { mode: "strict" });
    expect(retrieval.status).toBe(200);
    expect(await retrieval.text()).toContain(seeded.value.plaintext);

    // The Application Plane is rebuilt from it: the publisher publishes every read model.
    const upserts: { kind: string; resourceId: string }[] = [];
    const convex = (async (_url: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { path: string; args: { kind: string; resourceId: string } };
      if (body.path === "mirror:upsert") upserts.push(body.args);
      return new Response(JSON.stringify({ status: "success", value: null }), { status: 200 });
    }) as typeof fetch;
    await syncAllMirrors(targetCtx, { convexUrl: "http://convex.invalid", issuer: PUBLIC_URL }, convex);
    expect(upserts).toContainEqual(expect.objectContaining({ kind: "organization", resourceId: seeded.acme }));
    expect(upserts.filter((u) => u.kind === "environment").length).toBeGreaterThanOrEqual(3);

    // installation.migrated in the rebuilt database: every path that reads an event's type takes it.
    const row = (await target.query("SELECT * FROM audit_events WHERE event_type = 'installation.migrated'")).rows[0] as Record<string, unknown>;
    expect(serializeAuditEvent(row)).toMatchObject({ eventType: "installation.migrated", decision: "info" });
    expect(changedDomain("installation.migrated")).toBe("installation");
    await deliverWebhooksOnce(targetCtx, (async () => new Response(null, { status: 200 })) as typeof fetch);
    const listed = await call("GET", "/v1/organizations/acme/audit-events");
    expect(listed.status).toBe(200);
  }, 180_000);

  it("refuses a damaged, cut short or forward bundle before it writes anything", async () => {
    const good = reverseOf(await exportOf(source));
    const lines = good.split("\n");
    const row = lines.findIndex((l) => l.startsWith('["org_') && l.includes('"Acme"'));
    expect(row).toBeGreaterThan(0);
    const damaged = [...lines];
    damaged[row] = damaged[row]!.replace("Acme", "Acmf");
    for (const [name, text, why] of [
      ["damaged", damaged.join("\n"), /the end line does not hold/],
      ["cut", lines.slice(0, -2).join("\n") + "\n", /cut short/],
      ["cut-mid-line", good.slice(0, good.length - 10), /cut short/],
      ["after", good + "{}\n", /text after its end line/],
      ["crlf", good.replace("\n", "\r\n"), /carriage return/],
      ["forward", await exportOf(source), /a forward bundle/],
    ] as const) {
      const err = await importReverse(target, { path: write(`${name}.jsonl`, text), rootKek: ctx.rootKek }).catch((e: unknown) => e);
      expect(err, name).toBeInstanceOf(ImportRefused);
      expect((err as Error).message, name).toMatch(why);
      expect((err as Error).message, name).not.toContain("Acm");
    }
    expect(await relations(target)).toBe(0);
  }, 180_000);

  it("refuses a bundle carrying a session, and the wrong Root KEK, before it writes anything", async () => {
    const good = reverseOf(await exportOf(source));
    const lines = good.split("\n").slice(0, -2);
    const at = lines.findIndex((l) => l === '{"table":"session","rows":0}');
    const session = loadManifest().tables.find((t) => t.source === "session")!;
    const marker = ["a", "session", "token"].join("-");
    const sample: Record<ColumnType, Value> = { text: "x", "timestamp with time zone": 1795000000000000n, integer: 1n, bigint: 1n, boolean: false, jsonb: "{}", "text[]": [], bytea: new Uint8Array() };
    const values = session.columns.map((c) => (c.source === "token" ? marker : sample[c.type as ColumnType]));
    lines.splice(at, 1, '{"table":"session","rows":1}', encodeRow(session.columns.map((c) => c.type as ColumnType), values));
    const carried = await importReverse(target, { path: write("session.jsonl", finish(lines)), rootKek: ctx.rootKek }).catch((e: unknown) => e);
    expect((carried as Error).message).toMatch(/carries browser sessions/);
    expect((carried as Error).message).not.toContain(marker);

    const wrong = await importReverse(target, { path: write("good.jsonl", good), rootKek: generateKey() }).catch((e: unknown) => e);
    expect(wrong).toBeInstanceOf(ImportRefused);
    expect((wrong as Error).message).toMatch(/Root KEK does not open the installation's canary/);
    expect(await relations(target)).toBe(0);
  }, 180_000);

  it("refuses a database that is not empty, and loads nothing of a bundle whose foreign keys do not hold", async () => {
    const good = reverseOf(await exportOf(source));
    const path = write("good.jsonl", good);
    // The source moved on after its export: not the bundle's rows any more.
    await recordAuditEvent(source, { eventType: "organization.renamed", decision: "allow", organizationId: seeded.acme });
    const full = await importReverse(source, { path, rootKek: ctx.rootKek }).catch((e: unknown) => e);
    expect((full as Error).message).toMatch(/the database is not empty/);

    // An environment whose project is not in the bundle: canonical and counted, but its key does not hold.
    const lines = good.split("\n").slice(0, -2);
    const env = lines.findIndex((l) => l.startsWith('["env_'));
    const project = /"(prj_[a-z0-9]+)"/.exec(lines[env]!)![1]!;
    lines[env] = lines[env]!.replace(`"${project}"`, `"prj_${"z".repeat(project.length - 4)}"`);
    const broken = await importReverse(target, { path: write("broken.jsonl", finish(lines)), rootKek: ctx.rootKek }).catch((e: unknown) => e);
    expect(broken).toBeInstanceOf(ImportRefused);
    expect((broken as Error).message).toMatch(/^a foreign key does not hold in the bundle's rows: environments\./);
    // Rolled back: the schema, and no row. The import runs again.
    expect(((await target.query("SELECT count(*)::int AS n FROM installation")).rows[0] as { n: number }).n).toBe(0);
    expect((await importReverse(target, { path, rootKek: ctx.rootKek })).alreadyImported).toBe(false);
    // Run again once it committed: it finds its own rows and finishes.
    expect((await importReverse(target, { path, rootKek: ctx.rootKek })).alreadyImported).toBe(true);
    // Another bundle of the same installation and audit is not taken for it:
    // a table's count differs (here, its Role left out).
    const other = good.split("\n").slice(0, -2);
    const roles = other.indexOf('{"table":"roles","rows":1}');
    expect(roles).toBeGreaterThan(0);
    other.splice(roles, 2, '{"table":"roles","rows":0}');
    const different = await importReverse(target, { path: write("other.jsonl", finish(other)), rootKek: ctx.rootKek }).catch((e: unknown) => e);
    expect((different as Error).message).toMatch(/the database is not empty/);
  }, 180_000);

  it("refuses a second import while one holds the database, cleanly", async () => {
    const path = write("reverse.jsonl", reverseOf(await exportOf(source)));
    // The lock another import holds, from its first look to its commit.
    const other = await target.connect();
    try {
      await other.query("SELECT pg_advisory_lock($1::bigint)", [IMPORT_LOCK.toString()]);
      const err = await importReverse(target, { path, rootKek: ctx.rootKek }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ImportRefused);
      expect((err as Error).message).toBe("another import is running on this database; nothing was loaded");
      expect(await relations(target)).toBe(0);
      await other.query("SELECT pg_advisory_unlock($1::bigint)", [IMPORT_LOCK.toString()]);
    } finally {
      other.release();
    }
    // Two at once: one loads, the other refuses (or, if it starts after the commit, finds the rows).
    const both = await Promise.allSettled([importReverse(target, { path, rootKek: ctx.rootKek }), importReverse(target, { path, rootKek: ctx.rootKek })]);
    const loaded = both.filter((r) => r.status === "fulfilled" && !r.value.alreadyImported);
    expect(loaded.length).toBe(1);
    for (const r of both) {
      if (r.status === "rejected") {
        expect(r.reason).toBeInstanceOf(ImportRefused);
        expect((r.reason as Error).message).toBe("another import is running on this database; nothing was loaded");
      }
    }
  }, 180_000);

  it("refuses an older schema that holds rows as it is: no migration runs on it first", async () => {
    // The first 30 migrations, as an earlier release left them, and a row.
    const c = await target.connect();
    try {
      await c.query("CREATE TABLE varlatch_migrations (id integer PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())");
      for (const m of MIGRATIONS.slice(0, 30)) {
        await c.query(m.sql);
        await c.query("INSERT INTO varlatch_migrations (id, name) VALUES ($1, $2)", [m.id, m.name]);
      }
    } finally {
      c.release();
    }
    await target.query(`INSERT INTO installation (id, kek_canary) VALUES ('inst_earlier', '{}'::jsonb)`);
    const level = "SELECT max(id) AS id, count(*)::int AS n FROM varlatch_migrations";
    const before = { level: (await target.query(level)).rows, tables: await relations(target) };
    const path = write("reverse.jsonl", reverseOf(await exportOf(source)));
    const err = await importReverse(target, { path, rootKek: ctx.rootKek }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ImportRefused);
    expect((err as Error).message).toMatch(/the database is not empty \(installation hold rows\)/);
    expect({ level: (await target.query(level)).rows, tables: await relations(target) }).toEqual(before);
    expect(before.level).toEqual([{ id: 30, n: 30 }]);
  }, 180_000);

  it("as a command: under the migrated-out gate it imports and lifts the gate; under another gate it refuses", async () => {
    const cli = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
    if (!existsSync(cli)) return; // CI builds before it tests
    const path = write("reverse.jsonl", reverseOf(await exportOf(source)));
    const kekFile = join(dir, "root-kek");
    writeFileSync(kekFile, ctx.rootKek.toString("hex") + "\n", { mode: 0o600 });
    const state = join(dir, "target-state");
    const m = new Maintenance(state);
    const env = { PATH: process.env.PATH ?? "", VARLATCH_DATABASE_URL: targetUrl, VARLATCH_KEK_FILE: kekFile, VARLATCH_STATE_DIR: state };
    const run = () => spawnSync(process.execPath, [cli, "admin", "migration", "import", "--in", path], { env, encoding: "utf8" });

    const barrier = m.beginMigration();
    const refused = run();
    expect(refused.status).toBe(1);
    expect(refused.stderr).toMatch(/a migration gate is open/);
    m.freezeMigration(barrier.id, "1");
    m.markMigratedOut(barrier.id);

    const done = run();
    expect(done.status, done.stderr).toBe(0);
    const summary = JSON.parse(done.stdout) as { migratedOutGate: string; alreadyImported: boolean; installationId: string };
    expect(summary).toMatchObject({ migratedOutGate: "lifted", alreadyImported: false });
    expect(readGate(state)).toBeNull();
    for (const secret of [...seeded.secrets, token, ctx.rootKek.toString("hex")]) expect((done.stdout + done.stderr).includes(secret)).toBe(false);
  }, 180_000);
});

describe("the import's reader", () => {
  it("refuses a line of 64 MiB or more, as varlatchd's reader does, before holding it whole", async () => {
    const dir = mkdtempSync(join(tmpdir(), "varlatch-import-line-"));
    try {
      const path = join(dir, "long.jsonl");
      // One byte short of the limit, ended: read, then refused as no header.
      writeFileSync(path, Buffer.concat([Buffer.alloc(MAX_LINE - 1, 0x61), Buffer.from("\n")]));
      await expect(readReverseBundle(path, loadManifest())).rejects.toThrow(/^line 1 is not a bundle's header$/);
      // At the limit, ended or not: refused by its length.
      writeFileSync(path, Buffer.concat([Buffer.alloc(MAX_LINE, 0x61), Buffer.from("\n")]));
      await expect(readReverseBundle(path, loadManifest())).rejects.toThrow(/a line of 64 MiB or more/);
      writeFileSync(path, Buffer.alloc(MAX_LINE, 0x61));
      await expect(readReverseBundle(path, loadManifest())).rejects.toThrow(/a line of 64 MiB or more/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
