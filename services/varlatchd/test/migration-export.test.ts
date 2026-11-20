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
import { generateKey } from "../src/crypto/aead.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { digestInput } from "../src/migration/canonical.js";
import { exportSource, ExportRefused } from "../src/migration/export.js";
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
    const report = new PassThrough();
    const bundle: Buffer[] = [];
    const lines: Buffer[] = [];
    out.on("data", (c: Buffer) => bundle.push(c));
    report.on("data", (c: Buffer) => lines.push(c));
    const result = await exportSource(db, {
      gate: ctx.maintenance!.gate, dryRun: opts.dryRun ?? false, out, report, rootKek: ctx.rootKek, runKey: opts.runKey === undefined ? null : opts.runKey,
    });
    return { result, bundle: Buffer.concat(bundle).toString("utf8"), report: Buffer.concat(lines).toString("utf8") };
  };

  it("writes the same bytes twice at the frozen point, even after a write behind its back, and holds no secret", async () => {
    const barrier = await migrationBarrier(ctx, ctx.maintenance!, 60_000);
    expect(barrier.gate.frozenSnapshot).toMatch(/^[0-9A-F]+-[0-9A-F]+-[0-9]+$/i);
    const runKey = randomBytes(32);
    const first = await run({ runKey });
    const second = await run({ runKey });
    expect(second.bundle).toBe(first.bundle);
    expect(second.report).toBe(first.report);
    // A write that bypasses the barrier is not in the frozen snapshot.
    await db.query("UPDATE organizations SET name = 'Changed' WHERE slug = 'acme'");
    expect((await run({ runKey })).bundle).toBe(first.bundle);

    // For a cross-check by hand against varlatchd's import (go-step7 7.3b):
    // the bundle and this test's throwaway Root KEK, when asked for.
    // Opt-in, for the by-hand cross-check with varlatchd's import (until
    // 7.3b automates it): a directory to keep this bundle and the test's
    // throwaway Root KEK in, both 0600. Unset in CI.
    const keep = process.env.VARLATCH_TEST_EXPORT_KEEP;
    if (keep) {
      writeFileSync(join(keep, "bundle.jsonl"), first.bundle, { mode: 0o600 });
      writeFileSync(join(keep, "root-kek"), ctx.rootKek.toString("hex") + "\n", { mode: 0o600 });
    }
    const header = JSON.parse(first.bundle.split("\n")[0]!);
    expect(header.frozenPoint).toEqual({ auditPosition: Number(barrier.gate.frozenPosition), snapshot: barrier.gate.frozenSnapshot });
    // Every seeded secret, the run key and the Root KEK: in neither output.
    for (const secret of [...seeded.secrets, runKey.toString("hex"), ctx.rootKek.toString("hex"), ctx.rootKek.toString("base64")]) {
      expect(first.bundle.includes(secret), "a secret in the bundle").toBe(false);
      expect(first.report.includes(secret), "a secret in the report").toBe(false);
    }
    // The sessions are there, without their tokens.
    const sessionLine = first.bundle.split("\n").findIndex((l) => l.startsWith('{"table":"session",'));
    expect(JSON.parse(first.bundle.split("\n")[sessionLine]!).rows).toBe(2);
    // Most of the manifest's tables hold rows (the rest are listed here).
    const tables = first.bundle.split("\n").filter((l) => l.startsWith('{"table":')).map((l) => JSON.parse(l) as { table: string; rows: number });
    const empty = tables.filter((t) => t.rows === 0).map((t) => t.table);
    expect(tables.length - empty.length, `empty: ${empty.join(", ")}`).toBeGreaterThanOrEqual(41);
  }, 120_000);

  it("reports a digest per item, each the HMAC of decision 7's input under the run key", async () => {
    await migrationBarrier(ctx, ctx.maintenance!, 60_000);
    const runKey = randomBytes(32);
    const { report, result } = await run({ runKey });
    const digests = report.split("\n").filter((l) => l.startsWith('{"digest":')).map((l) => JSON.parse(l).digest as { class: string; ids: Record<string, string>; hmac: string });
    expect(result.digests).toBe(digests.length);
    const classes = new Set(digests.map((d) => d.class));
    for (const c of ["kek-canary", "org-kek", "dek", "value", "webhook-secret", "platform-credential", "github-app-key", "audit-export-credential", "audit-export-drain", "jwt-signing-key"]) {
      expect(classes.has(c), c).toBe(true);
    }
    const ids = { organizationId: seeded.value.organizationId, secretId: seeded.value.valueId, versionId: seeded.value.versionId };
    const expected = createHmac("sha256", runKey).update(digestInput("value", ids, Buffer.from(seeded.value.plaintext))).digest("hex");
    expect(digests).toContainEqual({ class: "value", ids, hmac: expected });
    // Without a run key, no digest.
    expect((await run()).result.digests).toBe(0);
  }, 120_000);

  it("writes the decision table from the old evaluator", async () => {
    await migrationBarrier(ctx, ctx.maintenance!, 60_000);
    const { report } = await run();
    const decisions = report.split("\n").filter((l) => l.startsWith('{"decision":')).map((l) => JSON.parse(l).decision);
    const find = (q: Record<string, unknown>) => decisions.filter((d) => Object.entries(q).every(([k, v]) => d[k] === v));
    expect(find({ identityId: seeded.admin, organizationId: seeded.acme, projectId: null, action: "organization.manage" })[0]?.outcome).toBe("allow");
    expect(find({ identityId: seeded.member, organizationId: seeded.acme, projectId: null, action: "organization.manage" })[0]?.outcome).toBe("no-grant");
    expect(find({ identityId: seeded.service, organizationId: seeded.beta, action: "organization.read" })[0]?.outcome).toBe("not-found");
    expect(find({ identityId: seeded.admin, credential: "revoked" })[0]?.outcome).toBe("unauthenticated");
    // The staging tailnet Requirement: no request here has Tailnet Context.
    const staging = (await db.query("SELECT id FROM environments WHERE name = 'staging'")).rows[0] as { id: string };
    expect(find({ identityId: seeded.admin, environmentId: staging.id, action: "secret.reveal" })[0]?.outcome).toBe("requirement-failed");
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
    const report = new PassThrough();
    const lines: Buffer[] = [];
    report.on("data", (c: Buffer) => lines.push(c));
    const out = new PassThrough();
    const bundle: Buffer[] = [];
    out.on("data", (c: Buffer) => bundle.push(c));
    const err = await exportSource(db, { gate: null, dryRun: true, out, report, rootKek: null, runKey: null }).catch((e) => e);
    expect(err).toBeInstanceOf(ExportRefused);
    expect(Buffer.concat(bundle).length).toBe(0);
    const failures = (err as ExportRefused).preflight!.failures;
    expect(failures.map((f) => f.check).sort()).toEqual(["account", "exposure-backfill", "key-rotation", "row"]);
    expect(failures.filter((f) => f.check === "row").map((f) => [f.table, f.column, f.reason])).toEqual([
      ["idempotency_keys", "response", "jsonb-number-not-exact"],
    ]);
    const text = JSON.stringify(failures) + Buffer.concat(lines).toString("utf8") + (err as Error).message;
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
      [cli, "admin", "migration", "export", "--out", join(dir, `${name}.jsonl`), "--report", join(dir, `${name}.report.jsonl`), "--dry-run", ...extra],
      { env, input, encoding: "utf8" },
    );
    const runKey = randomBytes(32).toString("hex");
    const done = exportTo("good", `${runKey}\n`, ["--digests"]);
    expect(done.status, done.stderr).toBe(0);
    const summary = JSON.parse(done.stdout);
    expect(summary.digests).toBeGreaterThan(0);
    for (const f of ["good.jsonl", "good.report.jsonl"]) expect(statSync(join(dir, f)).mode & 0o777).toBe(0o600);
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
