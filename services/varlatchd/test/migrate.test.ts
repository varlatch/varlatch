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
  expect((await runMigrations(db)).applied.map(m => m.id)).toEqual([17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29]);
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

  expect((await runMigrations(db)).applied.map(m => m.id)).toEqual([21, 22, 23, 24, 25, 26, 27, 28, 29]);
  expect((await db.query("SELECT to_regclass('varlock_env_mappings') AS t")).rows).toEqual([{ t: null }]);
  expect(await revisions()).toEqual(beforeRevisions);
  expect(await audit()).toEqual(beforeAudit);
  expect((await runMigrations(db)).applied).toEqual([]);
});

it("adds the audit client column, leaving history as it was", async () => {
  await db.exec!("CREATE TABLE varlatch_migrations (id integer PRIMARY KEY, name text NOT NULL)");
  for (const migration of MIGRATIONS.filter(m => m.id <= 26)) {
    await db.exec!(migration.sql);
    await db.query("INSERT INTO varlatch_migrations VALUES ($1,$2)", [migration.id, migration.name]);
  }
  await db.query(`INSERT INTO audit_events(id,event_type,decision,actor_identity_id,credential_id) VALUES
    ('evt_denied','authorization.denied','deny','idn_a','crd_a'), ('evt_written','value.written','info','idn_a',NULL)`);
  const audit = async () => (await db.query("SELECT id, event_type, decision, actor_identity_id, credential_id, occurred_at, event_order FROM audit_events ORDER BY event_order")).rows;
  const before = await audit();

  expect((await runMigrations(db)).applied.map(m => m.id)).toEqual([27, 28, 29]);
  expect(await audit()).toEqual(before);
  // History is not backfilled: no request recorded a client for it.
  expect((await db.query("SELECT id, client FROM audit_events ORDER BY event_order")).rows).toEqual([
    { id: "evt_denied", client: null },
    { id: "evt_written", client: null },
  ]);
  await db.query("INSERT INTO audit_events(id,event_type,decision,client) VALUES ('evt_new','value.written','info','varlatch CLI 0.16.0 on Linux, assisted')");
  for (const client of ["", "x".repeat(65)]) {
    await expect(
      db.query("INSERT INTO audit_events(id,event_type,decision,client) VALUES ($1,'value.written','info',$2)", [newId("auditEvent"), client]),
    ).rejects.toThrow(/check constraint/);
  }
  expect((await runMigrations(db)).applied).toEqual([]);
});

it("adds credential expiry to connections, unknown for every existing one", async () => {
  await db.exec!("CREATE TABLE varlatch_migrations (id integer PRIMARY KEY, name text NOT NULL)");
  for (const migration of MIGRATIONS.filter(m => m.id <= 27)) {
    await db.exec!(migration.sql);
    await db.query("INSERT INTO varlatch_migrations VALUES ($1,$2)", [migration.id, migration.name]);
  }
  await db.query("INSERT INTO identities(id,kind,name) VALUES ('idn_admin','human','Admin')");
  await db.query("INSERT INTO organizations(id,slug,name,wrapped_org_kek) VALUES ('org_a','acme','Acme','{}')");
  await db.query(`INSERT INTO platform_connections(id,organization_id,platform,base_identity,name,credential_envelope,created_by)
    VALUES ('pcn_a','org_a','github-actions','acme','GitHub','{}','idn_admin')`);

  expect((await runMigrations(db)).applied.map(m => m.id)).toEqual([28, 29]);
  expect((await db.query("SELECT id, version, credential_expires_at, credential_expiry_seen_at FROM platform_connections")).rows).toEqual([
    { id: "pcn_a", version: 1, credential_expires_at: null, credential_expiry_seen_at: null },
  ]);
  // A date always comes with when it was seen.
  await expect(db.query("UPDATE platform_connections SET credential_expires_at = now()")).rejects.toThrow();
  await db.query("UPDATE platform_connections SET credential_expires_at = now(), credential_expiry_seen_at = now()");
});

it("adds GitHub Apps and a credential kind; existing connections are tokens", async () => {
  await db.exec!("CREATE TABLE varlatch_migrations (id integer PRIMARY KEY, name text NOT NULL)");
  for (const migration of MIGRATIONS.filter(m => m.id <= 28)) {
    await db.exec!(migration.sql);
    await db.query("INSERT INTO varlatch_migrations VALUES ($1,$2)", [migration.id, migration.name]);
  }
  await db.query("INSERT INTO identities(id,kind,name) VALUES ('idn_admin','human','Admin')");
  await db.query("INSERT INTO organizations(id,slug,name,wrapped_org_kek) VALUES ('org_a','acme','Acme','{}'), ('org_b','beta','Beta','{}')");
  await db.query(`INSERT INTO platform_connections(id,organization_id,platform,base_identity,name,credential_envelope,created_by,credential_expires_at,credential_expiry_seen_at)
    VALUES ('pcn_token','org_a','github-actions','acme','GitHub','{}','idn_admin','2027-01-01T00:00:00Z','2026-10-09T00:00:00Z')`);

  expect((await runMigrations(db)).applied.map(m => m.id)).toEqual([29]);
  expect((await db.query("SELECT id, version, credential_kind, github_app_id, github_installation_id, credential_expires_at IS NOT NULL AS has_expiry FROM platform_connections")).rows).toEqual([
    { id: "pcn_token", version: 1, credential_kind: "token", github_app_id: null, github_installation_id: null, has_expiry: true },
  ]);

  const app = (id: string, org: string, githubAppId: number, ownerId: number, removed = false) =>
    db.query(
      `INSERT INTO github_apps(id,organization_id,github_app_id,slug,client_id,owner_login,owner_id,owner_type,key_envelope,removed_at,created_by)
       VALUES ($1,$2,$3,'varlatch-acme','Iv23li','acme',$4,'organization',$5,$6,'idn_admin')`,
      [id, org, githubAppId, ownerId, removed ? null : "{}", removed ? new Date() : null],
    );
  await app("gha_a", "org_a", 5254113, 1009);
  // A live App holds its wrapped key; a removed one does not.
  await expect(db.query("UPDATE github_apps SET removed_at = now() WHERE id = 'gha_a'")).rejects.toThrow(/github_apps_key_until_removed/);
  await expect(db.query("UPDATE github_apps SET key_envelope = NULL WHERE id = 'gha_a'")).rejects.toThrow(/github_apps_key_until_removed/);
  await expect(
    db.query("INSERT INTO github_apps(id,organization_id,github_app_id,slug,client_id,owner_login,owner_id,owner_type,key_envelope) VALUES ('gha_x','org_a',1,'s','c','acme',1,'Organization','{}')"),
  ).rejects.toThrow(/check constraint/);
  // One live App per Organization, whichever GitHub account it is on; a GitHub App is live in one Organization.
  await expect(app("gha_same_owner", "org_a", 999, 1009)).rejects.toThrow(/github_apps_live_org/);
  await expect(app("gha_other_account", "org_a", 999, 2000)).rejects.toThrow(/github_apps_live_org/);
  await expect(app("gha_same_app", "org_b", 5254113, 2000)).rejects.toThrow(/github_apps_live_app/);
  // A removed App blocks neither: not its Organization, not its GitHub App id.
  await app("gha_a_earlier", "org_a", 777, 2000, true);
  await app("gha_removed", "org_b", 5254113, 1009, true);
  await app("gha_b", "org_b", 888, 2000);

  const connection = (id: string, values: Record<string, unknown>) => {
    const row = {
      organization_id: "org_a", platform: "github-actions", base_identity: "acme", name: id,
      credential_kind: "github-app", credential_envelope: null, github_app_id: "gha_a", github_installation_id: 169698431,
      credential_expires_at: null, credential_expiry_seen_at: null, ...values,
    };
    const columns = Object.keys(row);
    return db.query(
      `INSERT INTO platform_connections(id,${columns.join(",")}) VALUES ($1,${columns.map((_, i) => `$${i + 2}`).join(",")})`,
      [id, ...Object.values(row)],
    );
  };
  await connection("pcn_app", {});
  expect((await db.query("SELECT credential_kind, credential_envelope, github_app_id, github_installation_id FROM platform_connections WHERE id = 'pcn_app'")).rows).toEqual([
    { credential_kind: "github-app", credential_envelope: null, github_app_id: "gha_a", github_installation_id: 169698431 },
  ]);
  // An App Connection stores no token, names its App and installation, is GitHub only, and never records an expiry.
  for (const [label, values] of [
    ["a stored token", { credential_envelope: "{}" }],
    ["no App", { github_app_id: null }],
    ["no installation", { github_installation_id: null }],
    ["another platform", { platform: "coolify" }],
    ["an expiry", { credential_expires_at: "2027-01-01T00:00:00Z", credential_expiry_seen_at: "2026-10-09T00:00:00Z" }],
    ["an unknown kind", { credential_kind: "oauth" }],
  ] as const) {
    await expect(connection(`pcn_bad_${label}`, values), label).rejects.toThrow(/check constraint/);
  }
  // A token Connection stores its token and names no App.
  await expect(connection("pcn_token_no_envelope", { credential_kind: "token", github_app_id: null, github_installation_id: null })).rejects.toThrow(/check constraint/);
  await expect(connection("pcn_token_with_app", { credential_kind: "token", credential_envelope: "{}" })).rejects.toThrow(/check constraint/);
  // The App belongs to the Connection's Organization.
  await expect(connection("pcn_cross_org", { organization_id: "org_b", github_app_id: "gha_a" })).rejects.toThrow(/platform_connections_github_app_fk/);
  await expect(connection("pcn_no_such_app", { github_app_id: "gha_missing" })).rejects.toThrow(/platform_connections_github_app_fk/);
  expect((await runMigrations(db)).applied).toEqual([]);
});
