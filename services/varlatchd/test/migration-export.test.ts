// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHmac, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Maintenance } from "@varlatch/backup";
import { migrationBarrier, releaseHeldSnapshot } from "../src/backup/control.js";
import { recordAuditEvent } from "../src/audit/events.js";
import { generateKey } from "../src/crypto/aead.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { compareDigests, idsText } from "../src/migration/bundle.js";
import { digestInput, jsonbKeyOrder } from "../src/migration/canonical.js";
import { exportSource, ExportRefused } from "../src/migration/export.js";
import { readBundle } from "./helpers/bundle-read.js";
import { seedInstallation, type Seeded } from "./helpers/migration-seed.js";

/**
 * `admin migration export` (ADR-0059 step 7, go-step7 slice 7.2b), against
 * a real PostgreSQL server: the barrier's exported snapshot needs two
 * sessions. The installation is seeded through /v1 (helpers/migration-seed.ts).
 */
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("the migration's export", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx & { db: ReturnType<typeof createPgQuerier> };
  let dir: string;
  let seeded: Seeded;
  let databaseUrl: string;
  const database = `varlatch_export_${process.pid}`;

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!);
    target.pathname = `/${database}`;
    databaseUrl = target.toString();
    db = createPgQuerier(databaseUrl);
    const c = await db.connect();
    try {
      await runMigrations(c);
    } finally {
      c.release();
    }
    dir = mkdtempSync(join(tmpdir(), "varlatch-export-"));
    ctx = { db, rootKek: generateKey(), maintenance: new Maintenance(dir) };
    seeded = await seedInstallation(ctx);
    // The exposure backfill runs in the daemon; here it is finished by hand.
    await db.query("UPDATE exposure_backfill SET finished_at = now()");
  }, 120_000);
  afterEach(async () => {
    await releaseHeldSnapshot();
    await db.end();
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.end();
    rmSync(dir, { recursive: true, force: true });
  });

  const run = async (opts: { dryRun?: boolean; runKey?: Buffer | null } = {}) => {
    const out = new PassThrough();
    const bundle: Buffer[] = [];
    out.on("data", (c: Buffer) => bundle.push(c));
    const result = await exportSource(db, {
      gate: ctx.maintenance!.gate, dryRun: opts.dryRun ?? false, out, rootKek: ctx.rootKek, runKey: opts.runKey === undefined ? null : opts.runKey,
    });
    return { result, bundle: Buffer.concat(bundle).toString("utf8") };
  };
  /** The credential the decision table names an identity by: its first. */
  const credentialOf = async (identity: string) =>
    ((await db.query(`SELECT id FROM credentials WHERE identity_id = $1 ORDER BY id COLLATE "C" LIMIT 1`, [identity])).rows[0] as { id: string }).id;

  it("writes the same bytes twice at the frozen point, even after a write behind its back, and holds no secret", async () => {
    const barrier = await migrationBarrier(ctx, ctx.maintenance!, 60_000);
    expect(barrier.gate.frozenSnapshot).toMatch(/^[0-9A-F]+-[0-9A-F]+-[0-9]+$/i);
    const runKey = randomBytes(32);
    const first = await run({ runKey });
    const second = await run({ runKey });
    expect(second.bundle).toBe(first.bundle);
    // A write that bypasses the barrier is not in the frozen snapshot.
    await db.query("UPDATE organizations SET name = 'Changed' WHERE slug = 'acme'");
    expect((await run({ runKey })).bundle).toBe(first.bundle);

    // Opt-in, for the by-hand cross-check with varlatchd's import (until
    // 7.3b automates it): a directory to keep this bundle and the test's
    // throwaway Root KEK and run key in, all 0600. Unset in CI.
    const keep = process.env.VARLATCH_TEST_EXPORT_KEEP;
    if (keep) {
      writeFileSync(join(keep, "bundle.jsonl"), first.bundle, { mode: 0o600 });
      writeFileSync(join(keep, "root-kek"), ctx.rootKek.toString("hex") + "\n", { mode: 0o600 });
      writeFileSync(join(keep, "run-key"), runKey.toString("hex") + "\n", { mode: 0o600 });
    }
    const header = JSON.parse(first.bundle.split("\n")[0]!);
    expect(header.frozenPoint).toEqual({ auditPosition: Number(barrier.gate.frozenPosition), snapshot: barrier.gate.frozenSnapshot });
    // Every seeded secret, the run key and the Root KEK: not in the bundle.
    for (const secret of [...seeded.secrets, runKey.toString("hex"), ctx.rootKek.toString("hex"), ctx.rootKek.toString("base64")]) {
      expect(first.bundle.includes(secret), "a secret in the bundle").toBe(false);
    }
    // The end line counts what is there.
    const parts = readBundle(first.bundle);
    expect(parts.end).toEqual({ ...first.result.bundle });
    expect(parts.digests.length).toBe(first.result.bundle.digests);
    expect(parts.decisions.length).toBe(first.result.bundle.decisions);
    // The sessions are there, without their tokens.
    const sessionLine = first.bundle.split("\n").findIndex((l) => l.startsWith('{"table":"session",'));
    expect(JSON.parse(first.bundle.split("\n")[sessionLine]!).rows).toBe(2);
    // Most of the manifest's tables hold rows (the rest are listed here).
    const tables = first.bundle.split("\n").filter((l) => l.startsWith('{"table":')).map((l) => JSON.parse(l) as { table: string; rows: number });
    const empty = tables.filter((t) => t.rows === 0).map((t) => t.table);
    expect(tables.length - empty.length, `empty: ${empty.join(", ")}`).toBeGreaterThanOrEqual(48);
  }, 120_000);

  it("digests every item, each the HMAC of decision 7's input under the run key, sorted as BUNDLE.md says", async () => {
    await migrationBarrier(ctx, ctx.maintenance!, 60_000);
    const runKey = randomBytes(32);
    const { bundle } = await run({ runKey });
    const { digests, digestLines } = readBundle(bundle);
    const classes = new Set(digests.map((d) => d.class));
    for (const c of ["kek-canary", "org-kek", "dek", "value", "webhook-secret", "platform-credential", "github-app-key", "audit-export-credential", "audit-export-drain", "jwt-signing-key"]) {
      expect(classes.has(c), c).toBe(true);
    }
    const ids = { organizationId: seeded.value.organizationId, secretId: seeded.value.valueId, versionId: seeded.value.versionId };
    const expected = createHmac("sha256", runKey).update(digestInput("value", ids, Buffer.from(seeded.value.plaintext))).digest("hex");
    expect(digests).toContainEqual({ class: "value", ids, hmac: expected });
    // By class, then by ids as written, each item once; ids in jsonb's member order.
    for (let i = 1; i < digests.length; i++) expect(compareDigests(digests[i - 1]!, digests[i]!), digestLines[i]).toBeLessThan(0);
    for (const [i, d] of digests.entries()) {
      expect(Object.keys(d.ids)).toEqual(Object.keys(d.ids).sort(jsonbKeyOrder));
      expect(digestLines[i]).toBe(`{"class":"${d.class}","ids":${idsText(d.ids)},"hmac":"${d.hmac}"}`);
    }
    expect(digestLines.find((l) => l.includes('"class":"value"'))).toMatch(/^\{"class":"value","ids":\{"secretId":"[^"]+","versionId":"[^"]+","organizationId":"[^"]+"\},"hmac":"[0-9a-f]{64}"\}$/);
    // An item that does not open (here: the wrong Root KEK) refuses the
    // export by where it is, never by a value, and writes nothing.
    const wrong = generateKey();
    const out = new PassThrough();
    const written: Buffer[] = [];
    out.on("data", (c: Buffer) => written.push(c));
    const err = await exportSource(db, { gate: ctx.maintenance!.gate, dryRun: false, out, rootKek: wrong, runKey }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ExportRefused);
    expect((err as Error).message).toMatch(/^the kek-canary item in installation\.kek_canary \(installationId inst_[a-z0-9]+\) does not open/);
    for (const key of [wrong, ctx.rootKek, runKey]) expect((err as Error).message).not.toContain(key.toString("hex"));
    expect(Buffer.concat(written).length).toBe(0);
    // Without a run key, an empty digest section.
    const plain = await run();
    expect(plain.result.bundle.digests).toBe(0);
    expect(plain.bundle).toContain('\n{"digests":0}\n');
  }, 120_000);

  it("writes the old evaluator's decisions as BUNDLE.md spells them, at the frozen point's moment", async () => {
    await migrationBarrier(ctx, ctx.maintenance!, 60_000);
    const { bundle } = await run();
    const { decisions, at } = readBundle(bundle);
    const last = (await db.query("SELECT (extract(epoch FROM occurred_at) * 1000000)::bigint::text AS at FROM audit_events ORDER BY event_order DESC LIMIT 1")).rows[0] as { at: string };
    expect(at).toBe(BigInt(last.at));
    const [admin, member, service] = await Promise.all([credentialOf(seeded.admin), credentialOf(seeded.member), credentialOf(seeded.service)]);
    const find = (q: Partial<Record<string, unknown>>) => {
      const hit = decisions.filter((d) => Object.entries(q).every(([k, v]) => JSON.stringify((d as unknown as Record<string, unknown>)[k]) === JSON.stringify(v)));
      expect(hit.length, JSON.stringify(q)).toBeGreaterThan(0);
      return hit[0]!;
    };
    const onOrg = { project: null, environment: null, tailnet: null };
    expect(find({ credential: admin, state: "active", organization: seeded.acme, ...onOrg, action: "organization.manage" })).toMatchObject({ allowed: true, code: null });
    expect(find({ credential: member, state: "active", organization: seeded.acme, ...onOrg, action: "organization.manage" })).toMatchObject({ allowed: false, code: "PERMISSION_DENIED" });
    expect(find({ credential: service, state: "active", organization: seeded.beta, ...onOrg, action: "organization.read" })).toMatchObject({ allowed: false, code: "RESOURCE_NOT_FOUND" });
    for (const state of ["expired", "revoked"]) {
      expect(decisions.filter((d) => d.state === state).every((d) => !d.allowed && d.code === "UNAUTHENTICATED")).toBe(true);
      expect(find({ credential: admin, state, organization: seeded.acme, ...onOrg, action: "organization.read" }).code).toBe("UNAUTHENTICATED");
    }
    // The staging tailnet Requirement: without Tailnet Context, with one its
    // selector names, and with one it does not.
    const staging = (await db.query("SELECT id FROM environments WHERE name = 'staging' LIMIT 1")).rows[0] as { id: string };
    const reveal = { credential: admin, state: "active", environment: staging.id, action: "secret.reveal" };
    expect(find({ ...reveal, tailnet: null })).toMatchObject({ allowed: false, code: "TAILNET_CONTEXT_REQUIRED" });
    const contexts = decisions.filter((d) => d.credential === admin && d.environment === staging.id && d.action === "secret.reveal" && d.tailnet);
    expect(contexts.map((d) => d.allowed ? "allowed" : d.code).sort()).toEqual(["TAILNET_CONTEXT_UNAVAILABLE", "allowed"]);
    // Every line is as BUNDLE.md writes it: members in order, nulls as null.
    const lines = bundle.split("\n");
    const first = lines.findIndex((l) => l.startsWith('{"decisions":'));
    expect(lines[first]).toBe(`{"decisions":${decisions.length},"at":${at}}`);
    for (const l of lines.slice(first + 1, first + 1 + decisions.length)) {
      expect(l).toMatch(/^\{"credential":"[^"]+","state":"(active|expired|revoked)","organization":"[^"]+","project":(null|"[^"]+"),"environment":(null|"[^"]+"),"action":"[a-z.]+","tailnet":(null|\{"tailnet":"[^"]+","nodeId":"[^"]+","tags":\[[^\]]*\],"userLogin":(null|"[^"]*")\}),"allowed":(true|false),"code":(null|"[A-Z_]+")\}$/);
    }
  }, 120_000);

  it("after a barrier run with no daemon, reads its own snapshot behind the frozen position", async () => {
    const barrier = await migrationBarrier(ctx, ctx.maintenance!, 60_000, { hold: false });
    expect(barrier.gate.frozenSnapshot ?? null).toBeNull();
    const first = await run();
    expect(first.result.frozenPoint.auditPosition).toBe(barrier.gate.frozenPosition);
    // Its own snapshot each time: the same rows, under another snapshot id.
    const strip = (b: string) => b.split("\n").slice(1, -2).join("\n");
    expect(strip((await run()).bundle)).toBe(strip(first.bundle));
    // A write behind the barrier's back moves the last audit position: refused.
    await recordAuditEvent(db, { eventType: "organization.renamed", decision: "allow", organizationId: seeded.acme });
    await expect(run()).rejects.toThrow(/not the frozen/);
  }, 120_000);

  it("names what fixes a held snapshot that is gone, and the barrier run again holds a new one", async () => {
    const barrier = await migrationBarrier(ctx, ctx.maintenance!, 60_000);
    const before = barrier.gate.frozenSnapshot;
    // What idle_in_transaction_session_timeout does to the held transaction.
    const ended = await admin.query(
      `SELECT pg_terminate_backend(pid) AS ended FROM pg_stat_activity WHERE datname = $1 AND state = 'idle in transaction'`,
      [database],
    );
    expect(ended.rows.length).toBe(1);
    await expect(run()).rejects.toThrow(/the snapshot the barrier holds is gone .* run varlatchd admin migration barrier again/);
    const again = await migrationBarrier(ctx, ctx.maintenance!, 60_000);
    expect(again.gate.frozenSnapshot).toMatch(/^[0-9A-F]+-[0-9A-F]+-[0-9]+$/i);
    expect(again.gate.frozenSnapshot).not.toBe(before);
    expect(again.gate.frozenPosition).toBe(barrier.gate.frozenPosition);
    expect((await run()).result.frozenPoint.snapshot).toBe(again.gate.frozenSnapshot);
  }, 120_000);

  it("refuses without the barrier unless asked for a dry run, and a dry run reads a consistent snapshot", async () => {
    await expect(run()).rejects.toThrow(/no migration barrier is held/);
    const dry = await run({ dryRun: true });
    expect(dry.bundle.split("\n")[0]).toContain('"direction":"forward"');
    const last = ((await db.query("SELECT max(event_order)::text AS p FROM audit_events")).rows[0] as { p: string }).p;
    expect(dry.result.frozenPoint.auditPosition).toBe(last);
  }, 120_000);

  it("checks the frozen position when it reads its own snapshot, and refuses a draining barrier", async () => {
    const m = ctx.maintenance!;
    const gate = m.beginMigration();
    await expect(run()).rejects.toThrow(/has not drained yet/);
    const last = ((await db.query("SELECT max(event_order)::text AS p FROM audit_events")).rows[0] as { p: string }).p;
    m.freezeMigration(gate.id, String(BigInt(last) - 1n));
    await expect(run()).rejects.toThrow(/not the frozen/);
    m.releaseMigration(gate.id);
  }, 120_000);

  it("preflight refuses each failure by name, lists cross-organization grants, and never shows a value", async () => {
    const inexact = "1e400";
    await db.query("UPDATE exposure_backfill SET finished_at = NULL");
    await db.query("UPDATE installation SET key_rotation_state = 'rewrapping'");
    await db.query(`INSERT INTO "account" (id, "accountId", "providerId", "userId", "createdAt", "updatedAt")
      SELECT 'acc_1', 'a', 'credential', "userId", now(), now() FROM "session" LIMIT 1`);
    await db.query(`UPDATE idempotency_keys SET response = '{"n": ${inexact}}'::jsonb`);
    const group = (await db.query("SELECT id FROM groups LIMIT 1")).rows[0] as { id: string };
    await db.query(
      `INSERT INTO grants (id, organization_id, subject_group_id, scope, actions, created_by)
       SELECT 'grt_crossorg', $1, $2, '{"kind":"organization"}'::jsonb, ARRAY['organization.read'], $3`,
      [seeded.beta, group.id, seeded.admin],
    );
    const out = new PassThrough();
    const bundle: Buffer[] = [];
    out.on("data", (c: Buffer) => bundle.push(c));
    const err = await exportSource(db, { gate: null, dryRun: true, out, rootKek: null, runKey: null }).catch((e) => e);
    expect(err).toBeInstanceOf(ExportRefused);
    expect(Buffer.concat(bundle).length).toBe(0);
    const failures = (err as ExportRefused).preflight!.failures;
    expect(failures.map((f) => f.check).sort()).toEqual(["account", "exposure-backfill", "key-rotation", "row"]);
    expect(failures.filter((f) => f.check === "row").map((f) => [f.table, f.column, f.reason])).toEqual([
      ["idempotency_keys", "response", "jsonb-number-not-exact"],
    ]);
    const text = JSON.stringify(failures) + (err as Error).message;
    expect(text).not.toContain(inexact);
    expect((err as ExportRefused).preflight!.crossOrganizationGrants).toEqual([
      { grantId: "grt_crossorg", organizationId: seeded.beta, names: "group", namedId: group.id, namedOrganizationId: seeded.acme },
    ]);
  }, 120_000);

  it("as a command: the run key only on a pipe, files only once complete (0600), nothing secret printed", () => {
    const cli = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
    if (!existsSync(cli)) return; // CI builds before it tests
    const kekFile = join(dir, "root-kek");
    writeFileSync(kekFile, ctx.rootKek.toString("hex") + "\n", { mode: 0o600 });
    const env = { PATH: process.env.PATH ?? "", VARLATCH_DATABASE_URL: databaseUrl, VARLATCH_KEK_FILE: kekFile, VARLATCH_STATE_DIR: dir };
    const exportTo = (name: string, input: string, extra: string[] = []) => spawnSync(
      process.execPath,
      [cli, "admin", "migration", "export", "--out", join(dir, `${name}.jsonl`), "--dry-run", ...extra],
      { env, input, encoding: "utf8" },
    );
    const runKey = randomBytes(32).toString("hex");
    // An export killed earlier left its .partial: it goes, never becomes the bundle.
    writeFileSync(join(dir, "good.jsonl.partial"), "cut short\n");
    const done = exportTo("good", `${runKey}\n`, ["--digests"]);
    expect(done.status, done.stderr).toBe(0);
    const summary = JSON.parse(done.stdout);
    expect(summary.bundle.digests).toBeGreaterThan(0);
    expect(statSync(join(dir, "good.jsonl")).mode & 0o777).toBe(0o600);
    expect(existsSync(join(dir, "good.jsonl.partial"))).toBe(false);
    for (const secret of [...seeded.secrets, runKey]) expect((done.stdout + done.stderr).includes(secret)).toBe(false);

    const badKey = exportTo("badkey", "not a key\n", ["--digests"]);
    expect(badKey.status).toBe(1);
    expect(badKey.stderr).toMatch(/not 64 lowercase hex digits/);
    expect(badKey.stderr).not.toContain("not a key");

    return db.query("UPDATE exposure_backfill SET finished_at = NULL").then(() => {
      const refused = exportTo("refused", "");
      expect(refused.status).toBe(1);
      expect(refused.stderr).toMatch(/exposure backfill has not finished/);
      expect(readdirSync(dir).filter((f) => f.startsWith("refused") || f.startsWith("badkey"))).toEqual([]);
    });
  }, 120_000);
});
