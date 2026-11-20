// SPDX-License-Identifier: AGPL-3.0-or-later
import { spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { EMBEDDED_RELEASE, Maintenance, describeComponents, sealArchive, type Bek, type Manifest } from "@varlatch/backup";
import { archiveMetadata } from "../src/backup/metadata.js";
import { generateKey } from "../src/crypto/aead.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { seedInstallation } from "./helpers/migration-seed.js";

/**
 * The backup converter's archives (ADR-0059 step 7, go-step7 decision 18,
 * slice 7.7b): what varlatchd's `TestConvertArchives` converts, written to
 * VARLATCH_TEST_CONVERTER_OUT with a cases.json naming each one, its keys
 * and what it is. Opt-in: it needs VARLATCH_TEST_DATABASE_URL (a
 * PostgreSQL 17 server it may create databases and roles on) and Docker.
 *
 *   - format 2 of the seeded installation (helpers/migration-seed.ts), as
 *     this release writes it, sealed with a key-file BEK;
 *   - format 1 of the same installation (its Application Plane components
 *     an empty database's dump and an empty tar), sealed with a passphrase
 *     BEK, with a key file for the converter's output;
 *   - format 1 of a 0.7.0 installation, the oldest restore source this
 *     release lists: its database made by the published 0.7.0 image (by
 *     digest), bootstrapped and given data through its own /v1, then
 *     dumped. 0.7.0's own CLI wrote format 1 with the same seal; here this
 *     release's packages/backup seals it, with 0.7.0's release record.
 *
 * Every key is made here; every container has a name of its own and is
 * removed with docker rm -fv.
 */
const out = process.env.VARLATCH_TEST_CONVERTER_OUT;
const url = process.env.VARLATCH_TEST_DATABASE_URL;

const POSTGRES = "postgres:17.6@sha256:00bc86618629af00d2937fdc5a5d63db3ff8450acf52f0636ec813c7f4902929";
const fixture = JSON.parse(readFileSync(new URL("../../../scripts/fixtures/v0.7.0/varlatch-release.json", import.meta.url), "utf8")) as {
  images: { varlatchd: { digest: string } };
};
const V070 = process.env.VARLATCH_TEST_LEGACY_IMAGE ?? fixture.images.varlatchd.digest;

const suffix = randomBytes(5).toString("hex");
const containerName = (role: string) => `vl-convgen-${suffix}-${role}`;

function docker(args: string[], opts: { input?: string; env?: Record<string, string> } = {}): Buffer {
  const r = spawnSync("docker", args, { input: opts.input, env: { ...process.env, ...opts.env }, maxBuffer: 1 << 30 });
  if (r.status !== 0) throw new Error(`docker ${args[0]} failed: ${r.stderr.toString().slice(-500)}`);
  return r.stdout;
}

describe.skipIf(!out || !url)("the backup converter's archives", () => {
  it("writes format 1 and 2 archives of the seeded installation and a format 1 archive of a 0.7.0 installation", async () => {
    mkdirSync(out!, { recursive: true, mode: 0o700 });
    const scratch = mkdtempSync(join(tmpdir(), "varlatch-convgen-"));
    const admin = createPgQuerier(url!);
    const databases = [`convgen_seed_${suffix}`, `convgen_empty_${suffix}`, `convgen_v070_${suffix}`];
    const dbUrl = (name: string) => {
      const u = new URL(url!);
      u.pathname = `/${name}`;
      return u;
    };
    // The server's password reaches containers in a file, never an argument.
    const envFile = join(scratch, "pg.env");
    const credentials = (name: string) => {
      const u = dbUrl(name);
      writeFileSync(envFile, `PGHOST=${u.hostname}\nPGPORT=${u.port || "5432"}\nPGUSER=${decodeURIComponent(u.username)}\nPGPASSWORD=${decodeURIComponent(u.password)}\nPGDATABASE=${name}\n`, { mode: 0o600 });
      return envFile;
    };
    const dump = (name: string, file: string) => {
      writeFileSync(file, docker(["run", "--rm", "--name", containerName("dump"), "--network", "host", "--env-file", credentials(name), POSTGRES, "pg_dump", "-Fc"]));
    };
    const started: string[] = [];
    const write = (name: string, text: string | Buffer) => writeFileSync(join(out!, name), text, { mode: 0o600 });
    try {
      for (const d of databases) {
        await admin.query(`DROP DATABASE IF EXISTS ${d} WITH (FORCE)`);
        await admin.query(`CREATE DATABASE ${d}`);
      }
      const rootKek = generateKey();
      write("root-kek", rootKek.toString("hex") + "\n");
      const keyBek = randomBytes(32);
      write("bek-key", keyBek.toString("hex") + "\n");
      const passphrase = randomBytes(18).toString("base64url");
      write("bek-passphrase", passphrase + "\n");
      write("out-bek", randomBytes(32).toString("hex") + "\n");
      const bekKey: Bek = { kind: "key", material: Buffer.from(keyBek) };
      const bekPassphrase: Bek = { kind: "passphrase", material: Buffer.from(passphrase) };
      const cases: object[] = [];

      // The seeded installation, its exposure backfill finished as the daemon finishes it.
      const seedDb = createPgQuerier(dbUrl(databases[0]!).toString());
      const c = await seedDb.connect();
      try {
        await runMigrations(c);
      } finally {
        c.release();
      }
      const ctx: AppCtx & { db: typeof seedDb } = { db: seedDb, rootKek, maintenance: new Maintenance(join(scratch, "state")) };
      await seedInstallation(ctx);
      await seedDb.query("UPDATE exposure_backfill SET finished_at = now()");
      const metadata = await archiveMetadata(ctx);
      await seedDb.end();
      const seeded = join(scratch, "seeded");
      mkdirSync(seeded);
      dump(databases[0]!, join(seeded, "secret-plane.dump"));
      const seal = async (dir: string, format: 1 | 2, meta: Omit<Manifest, "formatVersion" | "archiveId" | "createdAt" | "components">, bek: Bek, name: string) => {
        const manifest = { ...meta, formatVersion: format, archiveId: randomUUID(), createdAt: new Date().toISOString(), components: await describeComponents(dir, format) } as Manifest;
        await sealArchive(dir, manifest, bek, join(out!, name));
        return manifest;
      };
      await seal(seeded, 2, metadata, bekKey, "seeded-format2.vltbak");
      cases.push({ name: "seeded installation, format 2", archive: "seeded-format2.vltbak", kekFile: "root-kek", bekFile: "bek-key", format: 2, release: EMBEDDED_RELEASE.version, installationId: metadata.installationId });
      // Format 1: both planes, the Application Plane's components an empty database's dump and an empty tar.
      dump(databases[1]!, join(seeded, "application-plane.dump"));
      writeFileSync(join(seeded, "convex-storage.tar"), Buffer.alloc(1024));
      await seal(seeded, 1, metadata, bekPassphrase, "seeded-format1.vltbak");
      cases.push({ name: "seeded installation, format 1, passphrase BEK", archive: "seeded-format1.vltbak", kekFile: "root-kek", bekFile: "bek-passphrase", outBekFile: "out-bek", format: 1, release: EMBEDDED_RELEASE.version, installationId: metadata.installationId });

      // A 0.7.0 installation, made by its own image.
      await admin.query(`DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'varlatchd_runtime') THEN CREATE ROLE varlatchd_runtime; END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'varlatchd_migrate') THEN CREATE ROLE varlatchd_migrate; END IF;
      END $$`);
      const v070Env = join(scratch, "v070.env");
      const v070Url = dbUrl(databases[2]!);
      const port = 20000 + Math.floor(Math.random() * 20000);
      writeFileSync(v070Env, `VARLATCH_DATABASE_URL=${v070Url.toString()}\nVARLATCH_KEK_FILE=/run/varlatch/root-kek\nVARLATCH_PORT=${port}\nVARLATCH_PUBLIC_URL=http://127.0.0.1:${port}\n`, { mode: 0o600 });
      const user = `${process.getuid!()}:${process.getgid!()}`;
      const common = ["--network", "host", "--user", user, "--env-file", v070Env, "-v", `${join(out!, "root-kek")}:/run/varlatch/root-kek:ro`];
      docker(["run", "--rm", "--name", containerName("v070-migrate"), ...common, V070, "migrate"]);
      const server = containerName("v070-serve");
      started.push(server);
      docker(["run", "-d", "--name", server, ...common, V070, "serve"]);
      const base = `http://127.0.0.1:${port}`;
      let ready = false;
      for (let n = 0; n < 120 && !ready; n++) {
        ready = await fetch(`${base}/readyz`).then((r) => r.ok, () => false);
        if (!ready) await new Promise((r) => setTimeout(r, 500));
      }
      expect(ready, "0.7.0 never became ready").toBe(true);
      const token = /vlt_cli_\S+/.exec(docker(["exec", server, "node", "dist/cli.js", "admin", "bootstrap", "--cli-credential"]).toString())?.[0];
      expect(token).toBeTruthy();
      const call = async (method: string, path: string, body?: unknown) => {
        const r = await fetch(`${base}${path}`, { method, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", Connection: "close" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
        if (!r.ok) throw new Error(`0.7.0 ${method} ${path}: ${r.status} ${(await r.text()).slice(0, 300)}`);
        return r.json().catch(() => null);
      };
      await call("POST", "/v1/organizations", { name: "Old Acme", slug: "old-acme" });
      // As the seed does it today, which 0.7.0's /v1 already took.
      const project = "/v1/organizations/old-acme/projects";
      await call("POST", project, { name: "API", slug: "api", contractAuthority: "managed" });
      await call("POST", `${project}/api/environments`, { name: "production", tier: "production" });
      const revision = (await call("POST", `${project}/api/contract/revisions`, {
        contract: { schemaVersion: 1, items: [{ name: "DB_PASS", required: { kind: "never" }, sensitive: true, type: "string" }] },
      })) as { id: string };
      await call("POST", `${project}/api/contract/revisions/${revision.id}/activate`, {});
      for (let n = 0; n < 2; n++) {
        await call("PUT", `${project}/api/environments/production/values/DB_PASS`, { value: `old-${randomBytes(8).toString("hex")}` });
      }
      docker(["rm", "-fv", server]);
      started.splice(started.indexOf(server), 1);

      const v070Db = createPgQuerier(v070Url.toString());
      const inst = (await v070Db.query("SELECT * FROM installation")).rows[0] as { id: string; kek_canary: unknown; root_kek_version?: number };
      const migrationVersion = ((await v070Db.query("SELECT max(id)::int AS n FROM varlatch_migrations")).rows[0] as { n: number }).n;
      await v070Db.end();
      const oldDir = join(scratch, "v070");
      mkdirSync(oldDir);
      dump(databases[2]!, join(oldDir, "secret-plane.dump"));
      dump(databases[1]!, join(oldDir, "application-plane.dump"));
      writeFileSync(join(oldDir, "convex-storage.tar"), Buffer.alloc(1024));
      const version = inst.root_kek_version ?? 1;
      await seal(oldDir, 1, {
        installationId: inst.id,
        release: { schemaVersion: 1, version: "0.7.0", apiMajor: 1, migrationVersion, supportedPostgresMajor: 17 },
        requiredKeyVersions: [version],
        canaries: [{ version, envelope: typeof inst.kek_canary === "string" ? JSON.parse(inst.kek_canary) : inst.kek_canary }],
      } as Omit<Manifest, "formatVersion" | "archiveId" | "createdAt" | "components">, bekKey, "v070-format1.vltbak");
      expect(migrationVersion).toBe(16);
      cases.push({ name: "0.7.0 installation, format 1", archive: "v070-format1.vltbak", kekFile: "root-kek", bekFile: "bek-key", format: 1, release: "0.7.0", installationId: inst.id });

      write("cases.json", JSON.stringify(cases, null, 2) + "\n");
      rootKek.fill(0);
      keyBek.fill(0);
    } finally {
      for (const n of started) spawnSync("docker", ["rm", "-fv", n]);
      for (const d of databases) await admin.query(`DROP DATABASE IF EXISTS ${d} WITH (FORCE)`).catch(() => {});
      await admin.end();
      rmSync(scratch, { recursive: true, force: true });
    }
  }, 900_000);
});
