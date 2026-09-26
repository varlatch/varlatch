// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  migrationStatus,
  runMigrations,
  schemaIsCurrent,
  type Querier,
} from "../src/db/migrate.js";
import { newId } from "../src/db/ids.js";
import { testDb } from "./helpers/pglite.js";

let db: Awaited<ReturnType<typeof testDb>>;
beforeEach(async () => {
  db = await testDb();
});
afterEach(async () => {
  await db.close();
});

describe("migration runner", () => {
  it("applies pending migrations and becomes current", async () => {
    expect(await schemaIsCurrent(db)).toBe(false);
    const { applied } = await runMigrations(db);
    expect(applied.length).toBeGreaterThan(0);
    expect(applied[0]?.id).toBe(1);
    expect(await schemaIsCurrent(db)).toBe(true);
    // Idempotent second run applies nothing.
    expect((await runMigrations(db)).applied).toEqual([]);
  });

  it("refuses to run against a newer schema", async () => {
    await runMigrations(db);
    await db.query(
      "INSERT INTO varlatch_migrations (id, name) VALUES ($1, $2)",
      [999, "from-the-future"],
    );
    await expect(runMigrations(db)).rejects.toThrow(/newer than this binary/);
    expect(await schemaIsCurrent(db)).toBe(false);
  });

  it("rolls back a failing migration atomically", async () => {
    const broken: Querier = {
      query: db.query,
      exec: db.exec,
    };
    await runMigrations(db);
    const status = await migrationStatus(broken);
    expect(status.pending).toEqual([]);
  });
});

describe("initial schema", () => {
  beforeEach(async () => {
    await runMigrations(db);
  });

  it("enforces derived-environment kind constraint", async () => {
    const inst = newId("installation");
    await db.query("INSERT INTO installation (id, kek_canary) VALUES ($1, $2)", [
      inst,
      JSON.stringify({}),
    ]);
    const org = newId("organization");
    await db.query(
      "INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ($1,$2,$3,$4)",
      [org, "acme", "Acme", JSON.stringify({})],
    );
    const prj = newId("project");
    await db.query(
      "INSERT INTO projects (id, organization_id, slug, name, contract_authority) VALUES ($1,$2,$3,$4,'git')",
      [prj, org, "api", "API"],
    );
    // Root environment must be kind=shared.
    await expect(
      db.query(
        "INSERT INTO environments (id, project_id, name, kind, tier) VALUES ($1,$2,'dev','personal','development')",
        [newId("environment")],
      ),
    ).rejects.toThrow();
    const root = newId("environment");
    await db.query(
      "INSERT INTO environments (id, project_id, name, kind, tier) VALUES ($1,$2,'dev','shared','development')",
      [root, prj],
    );
    // Derived must not be shared.
    await expect(
      db.query(
        "INSERT INTO environments (id, project_id, name, kind, tier, parent_environment_id) VALUES ($1,$2,'dev/x','shared','development',$3)",
        [newId("environment"), prj, root],
      ),
    ).rejects.toThrow();
    await db.query(
      "INSERT INTO environments (id, project_id, name, kind, tier, parent_environment_id) VALUES ($1,$2,'dev/jeremy','personal','development',$3)",
      [newId("environment"), prj, root],
    );
  });

  it("deduplicates contract revisions per project by content hash", async () => {
    const org = newId("organization");
    await db.query(
      "INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ($1,'a','A',$2)",
      [org, JSON.stringify({})],
    );
    const prj = newId("project");
    await db.query(
      "INSERT INTO projects (id, organization_id, slug, name, contract_authority) VALUES ($1,$2,'p','P','git')",
      [prj, org],
    );
    await db.query(
      "INSERT INTO contract_revisions (id, project_id, content_hash, contract) VALUES ($1,$2,'sha256:x',$3)",
      [newId("contractRevision"), prj, JSON.stringify({})],
    );
    await expect(
      db.query(
        "INSERT INTO contract_revisions (id, project_id, content_hash, contract) VALUES ($1,$2,'sha256:x',$3)",
        [newId("contractRevision"), prj, JSON.stringify({})],
      ),
    ).rejects.toThrow();
  });
});

describe("ids", () => {
  it("generates prefixed unique ids", () => {
    const a = newId("organization");
    const b = newId("organization");
    expect(a).toMatch(/^org_[a-z2-7]{26}$/);
    expect(a).not.toBe(b);
  });
});

import { MIGRATIONS } from "../src/db/migrations/index.js";

it("upgrades existing audit history and removes legacy idempotency hashes", async () => {
  await db.exec!("CREATE TABLE varlatch_migrations (id integer PRIMARY KEY, name text NOT NULL)");
  for (const migration of MIGRATIONS.filter(m => m.id < 17)) {
    await db.exec!(migration.sql);
    await db.query("INSERT INTO varlatch_migrations VALUES ($1,$2)", [migration.id, migration.name]);
  }
  await db.query("INSERT INTO identities(id,kind,name) VALUES ('legacy','human','Legacy')");
  await db.query("INSERT INTO idempotency_keys(identity_id,endpoint,idempotency_key,body_hash,response) VALUES ('legacy','write','key','guessable','{}')");
  await db.query(`INSERT INTO audit_events(id,event_type,decision,occurred_at) VALUES
    ('older','test','info','2026-01-01T00:00:00.123455Z'), ('newer','test','info','2026-01-01T00:00:00.123456Z')`);
  expect((await runMigrations(db)).applied.map(m => m.id)).toEqual([17, 18, 19, 20, 21, 22]);
  expect((await db.query("SELECT id FROM audit_events ORDER BY event_order")).rows).toEqual([{ id: "older" }, { id: "newer" }]);
  expect((await db.query("SELECT * FROM idempotency_keys")).rows).toEqual([]);
  await db.query("INSERT INTO audit_events(id,event_type,decision) VALUES ('latest','test','info')");
  expect((await db.query("SELECT id FROM audit_events ORDER BY event_order DESC LIMIT 1")).rows).toEqual([{ id: "latest" }]);
});

it("drops the environment-name mapping, leaving contract revisions and audit history unchanged", async () => {
  await db.exec!("CREATE TABLE varlatch_migrations (id integer PRIMARY KEY, name text NOT NULL)");
  for (const migration of MIGRATIONS.filter(m => m.id <= 20)) {
    await db.exec!(migration.sql);
    await db.query("INSERT INTO varlatch_migrations VALUES ($1,$2)", [migration.id, migration.name]);
  }
  await db.query("INSERT INTO identities(id,kind,name) VALUES ('idn_admin','human','Admin')");
  await db.query("INSERT INTO organizations(id,slug,name,wrapped_org_kek) VALUES ('org_a','acme','Acme','{}')");
  await db.query("INSERT INTO projects(id,organization_id,slug,name,contract_authority) VALUES ('prj_a','org_a','api','API','git')");
  await db.query("INSERT INTO environments(id,project_id,name,kind,tier) VALUES ('env_prod','prj_a','production','shared','production')");
  const contract = { schemaVersion: 1, items: [{ name: "KEY", required: { kind: "selector", selector: { kind: "environments", environmentIds: ["env_prod"] } }, sensitive: true, type: "string" }] };
  await db.query("INSERT INTO contract_revisions(id,project_id,content_hash,contract) VALUES ('rev_1','prj_a','sha256:abc',$1)", [JSON.stringify(contract)]);
  await db.query("INSERT INTO varlock_env_mappings(project_id,varlock_name,environment_id) VALUES ('prj_a','prod','env_prod'),('prj_a','production','env_prod')");
  await db.query(`INSERT INTO audit_events(id,event_type,decision,organization_id,action,metadata) VALUES
    ('evt_set','contract.varlock_mapping_set','allow','org_a','contract.activate','{"varlockName":"prod"}'),
    ('evt_removed','contract.varlock_mapping_removed','allow','org_a','contract.activate','{"varlockName":"old"}')`);
  const revisions = async () => (await db.query("SELECT id, content_hash, contract FROM contract_revisions ORDER BY id")).rows;
  const audit = async () => (await db.query("SELECT id, event_type, decision, organization_id, action, metadata, occurred_at, event_order FROM audit_events ORDER BY event_order")).rows;
  const beforeRevisions = await revisions();
  const beforeAudit = await audit();

  expect((await runMigrations(db)).applied.map(m => m.id)).toEqual([21, 22]);
  expect((await db.query("SELECT to_regclass('varlock_env_mappings') AS t")).rows).toEqual([{ t: null }]);
  expect(await revisions()).toEqual(beforeRevisions);
  expect(await audit()).toEqual(beforeAudit);
  expect((await runMigrations(db)).applied).toEqual([]);
});

